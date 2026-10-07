// SPDX-License-Identifier: MIT OR Apache-2.0
// DarkClient (§6.7). Fixture mode only for now: real mode lands with the contracts.
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import { sha256 } from '@noble/hashes/sha2';
import { DarkError, isDarkError } from './errors.ts';
import { deriveDarkKeys, checkRegistryKey, type DarkKeys } from './keys.ts';
import { G, H, mul, decode, type AffinePoint, type Pt } from './grumpkin.ts';
import {
  encrypt, decryptAmount, decryptToPoint, discreteLog, hedgedScalar, contextBytes, assertHintPrivacy,
  TAG_TRANSFER_R, TAG_HINT_K, MAX_AMOUNT, type Ciphertext,
} from './elgamal.ts';
import { sealBalance, openBalance, type AeContext } from './hint.ts';
import { deployments, isDeployed, ZERO_ADDRESS, type BetaNoticeState, type Deployment } from './deployments.ts';
import { FixtureDarkProver, type CircuitId, type DarkProver, type ProgressFn, type Hex } from './prover.ts';

/** §7.1 sync status. */
export type DarkStatus = 'idle' | 'not_deployed' | 'syncing' | 'unregistered' | 'ready' | 'error';

/** §7.3 owner action lifecycle. */
export type ActionState =
  | 'idle' | 'building' | 'proving' | 'simulating' | 'submitted'
  | 'soft_confirmed' | 'final' | 'stale' | 'reverted' | 'dropped'
  // Submitted, then we lost sight of it. NOT the same as reverted: the transaction may still land,
  // so the UI must not invite a retry.
  | 'unknown';

export type ActionKind = 'register' | 'deposit' | 'applyPending' | 'transfer' | 'withdraw';

export interface ActionEvent {
  kind: ActionKind;
  state: ActionState;
  /** Proving progress in [0, 1] while state === 'proving'. */
  progress?: number;
  txHash?: Hex;
  reason?: string;
}

export interface Caps {
  minDeposit: bigint;
  maxDeposit: bigint;
  maxAccountInflow: bigint;
  minTransfer: bigint;
  maxTransfer: bigint;
  tvlCap: bigint;
}

export interface Balances {
  available: bigint;
  pending: bigint;
  pendingCount: number;
  nonce: bigint;
  /**
   * §2: true while ANYONE watching the chain can compute the exact balance — i.e. while no stored
   * ciphertext carries randomness. A deposit adds `(x·G, identity)`, so a deposit-and-withdraw-only
   * account stays public; the first confidential transfer **in or out** normally makes it false,
   * because neither `transfer` nor `withdraw` ever removes randomness from `D` on purpose.
   *
   * Not for good, though: a sender picks its own r, so a counterparty that supplied ALL of the
   * randomness in `D` can send r' = n − r and cancel it. The flag is computed on available + pending
   * for that reason, and turns true again when that happens; the protocol cannot prevent it today.
   *
   * False does not mean nobody knows it: a counterparty who knows the amount and the prior public
   * balance can still compute it. The copy must not say "only you" on the strength of this flag.
   */
  balancePublic: boolean;
}

export interface HistoryEntry {
  kind: 'deposit' | 'withdraw' | 'transfer_in' | 'transfer_out' | 'apply_pending';
  /**
   * `null` when the amount could not be recovered — a sender hint that will not open. Callers must
   * render that as unknown; showing it as 0 would be a quiet lie in the user's own history.
   */
  amount: bigint | null;
  counterparty?: Hex;
  /** true for deposits and withdrawals, whose amounts are on-chain in the clear. */
  amountPublic: boolean;
  block: bigint;
  txHash: Hex;
}

export interface Disclosure {
  id: string;
  kind: 'balance_exact' | 'balance_range' | 'transfer_exact' | 'flow_total_exact' | 'flow_total_range';
  label: string;
  url: string;
  createdAt: number;
  expiresAt: number;
  revoked: boolean;
}

export interface DarkClientOptions {
  mode: 'fixture' | 'live';
  chainId: number;
  account: Hex;
  /** secp256k1 private key. Fixture mode derives the same keys the real client would. */
  privateKey?: Uint8Array | Hex;
  prover?: DarkProver;
  onAction?: (e: ActionEvent) => void;
  /** Fixture only: starting available balance in micro-USDG. */
  initialAvailable?: bigint;
}

const DEFAULT_CAPS: Caps = {
  minDeposit: 1_000_000n,
  maxDeposit: 2_500_000_000n,
  maxAccountInflow: 10_000_000_000n,
  minTransfer: 1n,
  maxTransfer: 2_500_000_000n,
  tvlCap: 250_000_000_000n,
};

const FIXTURE_VAULT = '0x00000000000000000000000000000000000d4a11' as Hex;

/** A deterministic 32-byte seed for a fixture counterparty, so the same address always has the same key. */
const keccakLikeSeed = (address: string): string => bytesToHex(sha256(utf8ToBytes(`dark-fixture/${address.toLowerCase()}`)));

/**
 * Fixture-only: the `DarkClient` fixture needs deterministic keys with no secret supplied. A LIVE
 * client must never take this path — see `requireKeyBytes`.
 */
function toKeyBytes(pk: Uint8Array | Hex | undefined): Uint8Array {
  if (!pk) return new Uint8Array(32).fill(1);
  return typeof pk === 'string' ? hexToBytes(pk.slice(2)) : pk;
}

/**
 * The account secret, or a hard stop.
 *
 * Without this, omitting `privateKey` derived `s` and `k_ae` from a constant, so every such account
 * shared one publicly derivable key: anyone could open their hints and `aeBalance` and read their
 * balances, and `register()` would publish the shared key on chain. The option reads as optional
 * because a `walletClient` can replace *signing* — but the secret is what the DARK-CB-1 keys come
 * from, and nothing else can stand in for it.
 */
function requireKeyBytes(pk: Uint8Array | Hex | undefined): Uint8Array {
  if (!pk) {
    throw new DarkError(
      'MISSING_ACCOUNT_SECRET',
      'LiveDarkClient needs `privateKey`: it derives the account\'s DARK-CB-1 keys. A walletClient only replaces signing.',
    );
  }
  return toKeyBytes(pk);
}

let txCounter = 0;
const fakeTx = (): Hex => `0x${(++txCounter).toString(16).padStart(64, '0')}` as Hex;

export class DarkClient {
  readonly chainId: number;
  readonly account: Hex;
  readonly mode: 'fixture' | 'live';
  readonly keys: DarkKeys;
  readonly prover: DarkProver;

  private status: DarkStatus;
  private readonly onAction?: (e: ActionEvent) => void;

  // Fixture state. In live mode all of this comes from getAccount/caps/tvl.
  private registered = false;
  private available: bigint;
  private pending = 0n;
  private pendingCount = 0;
  private nonce = 0n;
  private netInflow = 0n;
  private tvlValue = 0n;
  /** §2: set by the first confidential transfer in OR out; never cleared. */
  private everPrivate = false;
  private ae: Uint8Array | null = null;
  private readonly entries: HistoryEntry[] = [];
  private readonly disclosures = new Map<string, Disclosure>();
  private block = 1_000n;

  /** Fixture only: the addresses this fixture world considers registered. */
  private readonly fixtureRegistered = new Set<string>();
  constructor(opts: DarkClientOptions) {
    this.mode = opts.mode;
    this.chainId = opts.chainId;
    this.account = opts.account;
    this.onAction = opts.onAction;
    this.prover = opts.prover ?? new FixtureDarkProver();
    this.keys = deriveDarkKeys(toKeyBytes(opts.privateKey), opts.chainId);
    this.available = opts.initialAvailable ?? 0n;
    if (this.available > 0n) {
      this.netInflow = this.available;
      this.tvlValue = this.available;
      this.entries.push({
        kind: 'deposit', amount: this.available, amountPublic: true, block: this.block, txHash: fakeTx(),
      });
    }
    this.status = isDeployed(this.chainId) || this.mode === 'fixture' ? 'idle' : 'not_deployed';
  }

  // ---- reads -------------------------------------------------------------

  get betaNotice(): BetaNoticeState {
    return deployments[this.chainId]?.betaNoticeState ?? 'pre_audit';
  }

  get publicKey(): AffinePoint {
    return this.keys.publicKey;
  }

  getStatus(): DarkStatus {
    return this.status;
  }

  isRegistered(): boolean {
    return this.registered;
  }

  async caps(): Promise<Caps> {
    this.live();
    return { ...DEFAULT_CAPS };
  }

  async tvl(): Promise<bigint> {
    this.live();
    return this.tvlValue;
  }

  /**
   * §6.7 step 5. Opens aeBalance, then *verifies* value*G == C - s*D, and falls back
   * to a BSGS bounded by tvl() (never tvlCap) when the hint is missing or lying.
   */
  async getBalances(): Promise<Balances> {
    this.live();
    this.status = this.registered ? 'ready' : 'unregistered';
    const ct = this.availableCiphertext();
    const hint = this.ae ? openBalance(this.keys.kAe, this.ae, this.aeContext()) : null;
    let available: bigint | null = null;
    if (hint && mul(G, hint.value).equals(decryptToPoint(ct.c, ct.d, this.keys.s))) available = hint.value;
    if (available === null) {
      available = decryptAmount(ct.c, ct.d, this.keys.s, this.tvlValue);
    }
    if (available === null) throw new DarkError('DECRYPTION_FAILED', 'could not recover the available balance');
    return {
      available,
      pending: this.pending,
      pendingCount: this.pendingCount,
      nonce: this.nonce,
      balancePublic: !this.everPrivate,
    };
  }

  async history(): Promise<HistoryEntry[]> {
    this.live();
    return [...this.entries];
  }

  // ---- owner actions -----------------------------------------------------

  async register(onProgress?: ProgressFn): Promise<Hex> {
    this.live();
    if (this.registered) return fakeTx();
    // §6.4: a live client compares the derived P against registry.keyOf first.
    checkRegistryKey(this.keys.publicKey, this.keys.publicKey);
    const tx = await this.run('register', 'dark_register', onProgress);
    this.registered = true;
    this.status = 'ready';
    return tx;
  }

  async deposit(amount: bigint, onProgress?: ProgressFn): Promise<Hex> {
    this.live();
    this.requireRegistered();
    const caps = await this.caps();
    if (amount < caps.minDeposit || amount > caps.maxDeposit) {
      throw new DarkError('CAP_EXCEEDED', 'deposit outside [minDeposit, maxDeposit]');
    }
    if (this.netInflow + amount > caps.maxAccountInflow) {
      throw new DarkError('CAP_EXCEEDED', 'account inflow cap exceeded');
    }
    if (this.tvlValue + amount > caps.tvlCap) throw new DarkError('CAP_EXCEEDED', 'TVL cap exceeded');
    // Deposits carry no proof; the state walk stops at simulating.
    const tx = await this.run('deposit', null, onProgress);
    this.available += amount;
    this.netInflow += amount;
    this.tvlValue += amount;
    this.bump();
    this.entries.push({ kind: 'deposit', amount, amountPublic: true, block: this.block, txHash: tx });
    return tx;
  }

  async applyPending(onProgress?: ProgressFn): Promise<Hex> {
    this.live();
    this.requireRegistered();
    if (this.pendingCount === 0) throw new DarkError('STALE_STATE', 'nothing pending to apply');
    const amount = this.pending;
    const tx = await this.run('applyPending', null, onProgress);
    this.available += amount;
    this.pending = 0n;
    this.pendingCount = 0;
    this.bump();
    this.entries.push({ kind: 'apply_pending', amount, amountPublic: false, block: this.block, txHash: tx });
    return tx;
  }

  /** §6.7 step 3. `to` must be registered; there is never a silent public fallback. */
  /** Third argument is a private note for the recipient, matching the live client. */
  async transfer(to: Hex, amount: bigint, note = '', onProgress?: ProgressFn): Promise<Hex> {
    this.live();
    this.requireRegistered();
    if (to.toLowerCase() === this.account.toLowerCase()) {
      throw new DarkError('AMOUNT_OUT_OF_RANGE', 'self-transfer');
    }
    // Fixture mode has no registry to read, so it keeps its own: only addresses it has been told
    // about are registered, and their keys are derived deterministically from the address. That
    // keeps "recipient is not registered" — a state real screens must handle — testable without a
    // chain, while the method signature matches the live client exactly.
    if (!this.fixtureRegistered.has(to.toLowerCase())) {
      throw new DarkError('RECIPIENT_NOT_REGISTERED', `${to} has no registered key`);
    }
    const recipientKey = deriveDarkKeys(hexToBytes(keccakLikeSeed(to)), this.chainId).publicKey;
    const caps = await this.caps();
    const { available } = await this.getBalances();
    if (amount < caps.minTransfer || amount > caps.maxTransfer || amount >= MAX_AMOUNT) {
      throw new DarkError('AMOUNT_OUT_OF_RANGE', 'transfer outside [minTransfer, maxTransfer]');
    }
    if (amount > available) throw new DarkError('INSUFFICIENT_BALANCE', 'available balance too low');

    const Pr = decode(recipientKey);
    const ctx = contextBytes({
      chainId: this.chainId, vault: FIXTURE_VAULT, from: this.account, to, fromNonce: this.nonce,
    });
    const r = hedgedScalar(TAG_TRANSFER_R, this.keys.s, ctx);
    const k = hedgedScalar(TAG_HINT_K, this.keys.s, ctx);
    const { C, D } = encrypt(amount, [this.keys.P, Pr], r);
    // §6.3: k must never equal r, or the hint leaks the amount and its own key.
    assertHintPrivacy({ C, amount, Re: mul(H, k), K: mul(Pr, k), Dr: D[1] });

    const tx = await this.run('transfer', 'dark_transfer', onProgress);
    this.available -= amount;
    // The outgoing ciphertext carries fresh randomness, so from here nobody but the two parties can
    // compute the balance — the same as a received transfer (§2).
    this.everPrivate = true;
    this.bump();
    this.entries.push({ kind: 'transfer_out', amount, counterparty: to, amountPublic: false, block: this.block, txHash: tx });
    return tx;
  }

  /** §6.7 step 4. Works while the vault is paused; amount and destination are public. */
  async withdraw(amount: bigint, to?: Hex, onProgress?: ProgressFn): Promise<Hex> {
    this.live();
    this.requireRegistered();
    const { available } = await this.getBalances();
    if (amount <= 0n || amount >= MAX_AMOUNT) throw new DarkError('AMOUNT_OUT_OF_RANGE', 'withdraw amount invalid');
    if (amount > available) throw new DarkError('INSUFFICIENT_BALANCE', 'available balance too low');
    const tx = await this.run('withdraw', 'dark_withdraw', onProgress);
    this.available -= amount;
    this.netInflow -= amount;
    this.tvlValue -= amount;
    this.bump();
    this.entries.push({
      kind: 'withdraw', amount, counterparty: to ?? this.account, amountPublic: true, block: this.block, txHash: tx,
    });
    return tx;
  }

  // ---- disclosures -------------------------------------------------------

  async createDisclosure(kind: Disclosure['kind'], label: string, ttlDays = 30): Promise<Disclosure> {
    this.live();
    if (label.length > 64) throw new DarkError('AMOUNT_OUT_OF_RANGE', 'label longer than 64 chars');
    if (ttlDays < 1 || ttlDays > 365) throw new DarkError('AMOUNT_OUT_OF_RANGE', 'expiry outside 1..365 days');
    const prefix = this.chainId === 4663 ? '' : 't_';
    const id = `${prefix}${Math.random().toString(36).slice(2, 12)}`;
    const now = Date.now();
    const d: Disclosure = {
      id,
      kind,
      label,
      // The fragment key never reaches a server; fixture mode fakes one.
      url: `https://darkwallet.cash/d/${id}#k=${Math.random().toString(36).slice(2)}`,
      createdAt: now,
      expiresAt: now + ttlDays * 86_400_000,
      revoked: false,
    };
    this.disclosures.set(id, d);
    return d;
  }

  async revokeDisclosure(id: string): Promise<void> {
    this.live();
    const d = this.disclosures.get(id);
    if (!d) throw new DarkError('STALE_STATE', `unknown disclosure ${id}`);
    d.revoked = true;
  }

  async listDisclosures(): Promise<Disclosure[]> {
    this.live();
    return [...this.disclosures.values()];
  }

  // ---- internals ---------------------------------------------------------

  private live(): void {
    if (this.mode !== 'fixture') {
      throw new DarkError('NOT_IMPLEMENTED', 'live mode lands with the contracts');
    }
    if (!isDeployed(this.chainId) && this.mode !== 'fixture') {
      throw new DarkError('NOT_DEPLOYED', `no Dark deployment on chain ${this.chainId}`);
    }
  }

  private requireRegistered(): void {
    if (!this.registered) throw new DarkError('NOT_REGISTERED', 'register the account first');
  }

  private aeContext(): AeContext {
    return { chainId: this.chainId, vault: FIXTURE_VAULT, account: this.account };
  }

  /** The fixture's encrypted available balance, re-randomized on every state change. */
  private availableCiphertext(): Ciphertext {
    const rho = hedgedScalar(
      TAG_TRANSFER_R,
      this.keys.s,
      contextBytes({
        chainId: this.chainId, vault: FIXTURE_VAULT, from: this.account, to: this.account, fromNonce: this.nonce,
      }),
      new Uint8Array(32),
    );
    const e = encrypt(this.available, [this.keys.P], rho);
    return { c: e.C, d: e.D[0] };
  }

  private bump(): void {
    this.nonce += 1n;
    this.block += 1n;
    this.ae = sealBalance(this.keys.kAe, { value: this.available, nonceAfter: this.nonce }, this.aeContext());
  }

  /** Walk the §7.3 states for one action, proving when the action needs a proof. */
  private async run(kind: ActionKind, circuit: Parameters<DarkProver['prove']>[0] | null, onProgress?: ProgressFn): Promise<Hex> {
    const emit = (state: ActionState, extra: Partial<ActionEvent> = {}) =>
      this.onAction?.({ kind, state, ...extra });
    emit('building');
    if (circuit) {
      emit('proving', { progress: 0 });
      await this.prover.prove(circuit, {}, (f, stage) => {
        onProgress?.(f, stage);
        emit('proving', { progress: f });
      });
    }
    emit('simulating');
    const txHash = fakeTx();
    emit('submitted', { txHash });
    emit('soft_confirmed', { txHash });
    emit('final', { txHash });
    return txHash;
  }

  /** Fixture helper: credit an inbound confidential transfer into pending. */
  /** Fixture only: mark `address` as registered, so transfers to it are allowed. */
  registerFixtureAccount(address: Hex): void {
    this.fixtureRegistered.add(address.toLowerCase());
  }

  receiveFixtureTransfer(from: Hex, amount: bigint): void {
    this.pending += amount;
    this.pendingCount += 1;
    this.everPrivate = true;
    this.block += 1n;
    this.entries.push({
      kind: 'transfer_in', amount, counterparty: from, amountPublic: false, block: this.block, txHash: fakeTx(),
    });
  }
}

// ============================================================================================
// Live mode (§7). viem is loaded on demand so the fixture client, the key maths and the
// disclosure vectors keep working in an environment that has no viem installed.
// ============================================================================================

import type { Address, PublicClient, WalletClient, Log } from 'viem';
import { GROUP_N, Point, add as ptAdd, sub as ptSub, encode as ptEncode } from './grumpkin.ts';
import { addCiphertexts, subCiphertexts } from './elgamal.ts';
import {
  sealHint, sealSenderHint, openHint, openSenderHint, AE_BALANCE_BYTES,
} from './hint.ts';
import { buildPublicInputs, assertPublicInputsEqual } from './publicInputs.ts';
import {
  buildRegisterWitness, buildTransferWitness, buildWithdrawWitness, type Witness,
} from './witness.ts';
import { darkVaultAbi, darkKeyRegistryAbi } from './deployments.ts';

/** Canonical Multicall3, same address on every chain that has it. */
export const MULTICALL3 = '0xcA11bde05977b3631167028862bE2a173976CA11' as const;

export interface AccountView {
  available: Ciphertext;
  pending: Ciphertext;
  nonce: bigint;
  pendingCount: bigint;
  netInflow: bigint;
  aeBalance: Hex;
}

/** Everything §7 step 0 reads, at one block. */
export interface Snapshot {
  block: bigint;
  account: AccountView;
  caps: Caps;
  tvl: bigint;
  /** `registry.keyOf(account)`, or null when the account is not registered. */
  registryKey: AffinePoint | null;
  paused: boolean;
}

/**
 * Where disclosures are stored, and how to prove who is storing them. The blob is ciphertext and the
 * key never leaves the device, so this server holds something it cannot read — but it still has to
 * know who uploaded it, which is what the SIWE bearer token is for. `token` is called per request so
 * the app can refresh an expired session without rebuilding the client.
 */
export interface DarkApi {
  baseUrl: string;
  token(): string | null | Promise<string | null>;
}

export interface LiveDarkClientOptions {
  chainId: number;
  account: Address;
  /**
   * secp256k1 key. **Required**: it derives the account's `s` and `k_ae`. A `walletClient` replaces
   * only signing, never this — a client built without it would have no account keys of its own.
   */
  privateKey: Uint8Array | Hex;
  prover: DarkProver;
  /** $DARK_RPC_URL, else `deployments[chainId].rpcUrl`. Never hard-code a keyed URL. */
  rpcUrl?: string;
  walletClient?: WalletClient;
  publicClient?: PublicClient;
  /** Pass `null` to skip Multicall3 and read each call pinned to the same block instead. */
  multicallAddress?: Address | null;
  onAction?: (e: ActionEvent) => void;
  /** BSGS memory cap; 2^20 entries by default (§7 step 5). */
  bsgsTableBits?: number;
  /** Required only for the disclosure methods; everything else works without it. */
  api?: DarkApi;
  /**
   * Second source for recipient keys, which `transfer()` cross-checks before encrypting to one
   * (§6.3). Every private send makes one `registry.keyOf(recipient)` read here, from the user's IP.
   * Left undefined, the source contacted is:
   * - `rpcUrl` is anything but the chain's public RPC (Dark's relay, a custom node) → the chain's
   *   public RPC (Robinhood's endpoint), which then sees the recipient address;
   * - `rpcUrl` IS the chain's public RPC and `api` is set → Dark's relay (`<api>/v1/rpc`), so Dark
   *   still sees one recipient lookup per send even though the user picked the public RPC;
   * - neither → no check.
   * Pass a URL to choose the source yourself. `null` disables the check — for tests and single-RPC
   * dev setups only.
   */
  keyCheckRpcUrl?: string | null;
  /** A ready client for the same purpose (tests); takes precedence over `keyCheckRpcUrl`. */
  keyCheckClient?: PublicClient | null;
}

const point = (p: { x: bigint; y: bigint }) => (p.x === 0n && p.y === 0n ? Point.ZERO : decode(p));
/** `newDisclosureId`: `t_` on testnet, then 12 random bytes as base64url. */
const REVOKE_ID_RE = /^(t_)?[A-Za-z0-9_-]{16}$/;

const ct = (c: { c: AffinePoint; d: AffinePoint }): Ciphertext => ({ c: point(c.c), d: point(c.d) });

/**
 * §2, read off the ciphertext rather than reconstructed from history: the balance is public exactly
 * when `available.D` is the identity (a deposit-only ciphertext `(v·G, identity)` that anyone can
 * BSGS) and nothing is pending. It used to track only a *received* transfer (§18b),
 * so an account that had sent privately still reported a public balance, even though the new
 * ciphertext carries the transfer's randomness and nobody can compute it. The disclosure viewer
 * already judged `public_balance` from `D = identity`; the two now agree. As a bonus this needs no
 * full-history log scan.
 */
function isPublicBalance(s: Snapshot): boolean {
  // On the sum, which is what an observer can BSGS: a sole counterparty can send r' = n − r so that
  // pending.D cancels available.D, and each half alone still looks randomised.
  return ptAdd(s.account.available.d, s.account.pending.d).is0();
}
const hexBytes = (h: Hex): Uint8Array =>
  Uint8Array.from((h.slice(2).match(/../g) ?? []), (b) => parseInt(b, 16));
const toHex = (b: Uint8Array): Hex => `0x${[...b].map((x) => x.toString(16).padStart(2, '0')).join('')}`;

/**
 * §13 `stale`: a revert that means "the state under this proof moved" (a nonce or `available` that
 * changed under an in-flight proof). The vault ABI carries no error items, so viem reports a custom
 * error as its bare selector; match those as well as the names. The deployed bb verifiers never
 * return false: a stale public input changes the transcript and reverts in the verifier with
 * SumcheckFailed, so the vault's InvalidProof() is unreachable. ShpleminiFailed (reached only after
 * the sumcheck passed) and PublicInputsLengthWrong (fixed per circuit) mean a bad proof or a
 * vault/verifier mismatch, not stale state, and stay generic failures.
 */
const STALE_REVERT = new RegExp([
  'PendingChanged', 'InvalidProof', 'nonce',
  '0x6d3256ff', // PendingChanged(uint64,uint64)
  '0x09bde339', // InvalidProof()
  '0x9fc3a218', // SumcheckFailed()
].join('|'), 'i');

/**
 * The real `DarkClient` (§7). Every owner action walks the §13 states, re-derives its own
 * public inputs before trusting a proof, and simulates before sending.
 */
export class LiveDarkClient {
  readonly chainId: number;
  readonly account: Address;
  readonly keys: DarkKeys;
  readonly prover: DarkProver;
  readonly deployment: Deployment;

  private readonly onAction?: (e: ActionEvent) => void;
  private readonly bsgsTableBits: number;
  private readonly multicallAddress: Address | null;
  private readonly api?: DarkApi;
  /** id → revoke token, kept by the device that created the link (§7.7 step 9). */
  private readonly revokeTokens = new Map<string, string>();
  private pub!: PublicClient;
  private keyCheck: PublicClient | null = null;
  private wallet?: WalletClient;
  private status: DarkStatus = 'idle';

  private constructor(opts: LiveDarkClientOptions) {
    const d = deployments[opts.chainId];
    if (!d || !isDeployed(opts.chainId)) {
      throw new DarkError('NOT_DEPLOYED', `no Dark deployment on chain ${opts.chainId}`, { chainId: opts.chainId });
    }
    this.deployment = d;
    this.chainId = opts.chainId;
    this.account = opts.account;
    this.prover = opts.prover;
    this.onAction = opts.onAction;
    this.bsgsTableBits = opts.bsgsTableBits ?? 20;
    this.multicallAddress = opts.multicallAddress === undefined ? MULTICALL3 : opts.multicallAddress;
    this.api = opts.api;
    this.keys = deriveDarkKeys(requireKeyBytes(opts.privateKey), opts.chainId);
  }

  static async create(opts: LiveDarkClientOptions): Promise<LiveDarkClient> {
    const c = new LiveDarkClient(opts);

    // The secret must belong to the account it claims. `account` and `privateKey` can be updated in
    // separate renders, so a client can otherwise be built with A's key for B's address — which
    // surfaces much later as the KEY_DERIVATION_MISMATCH hard stop, after the user has done things.
    // This also rejects an all-zero key, which `requireKeyBytes` accepts because it is not absent
    //. Checked here rather than in the constructor because deriving the address is async.
    const { privateKeyToAccount } = await import('viem/accounts');
    const derived = privateKeyToAccount(
      (typeof opts.privateKey === 'string' ? opts.privateKey : toHex32Prefixed(opts.privateKey)) as Hex,
    ).address;
    if (derived.toLowerCase() !== opts.account.toLowerCase()) {
      throw new DarkError(
        'KEY_DERIVATION_MISMATCH',
        'the supplied secret does not belong to this account: it derives a different address',
      );
    }

    const { createPublicClient, createWalletClient, http, defineChain } = await import('viem');
    const chain = defineChain({
      id: opts.chainId,
      name: `robinhood-${opts.chainId}`,
      nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
      rpcUrls: { default: { http: [c.rpcUrl(opts.rpcUrl)] } },
    });
    // cacheTime: 0 -- viem caches `eth_blockNumber` for 4 s by default, and `sync()` pins every
    // read to that number. After a write, a cached block predates the receipt and the account
    // reads back as unregistered / stale. Read-after-write is the normal case here.
    c.pub = (opts.publicClient
      ?? createPublicClient({ chain, cacheTime: 0, transport: http(c.rpcUrl(opts.rpcUrl)) })) as PublicClient;
    if (opts.keyCheckClient !== undefined) c.keyCheck = opts.keyCheckClient;
    else {
      const second = opts.keyCheckRpcUrl === undefined ? c.secondRpcUrl(opts.rpcUrl) : opts.keyCheckRpcUrl;
      c.keyCheck = second ? (createPublicClient({ chain, cacheTime: 0, transport: http(second) }) as PublicClient) : null;
    }
    if (opts.walletClient) c.wallet = opts.walletClient;
    else if (opts.privateKey) {
      const { privateKeyToAccount } = await import('viem/accounts');
      const key = toKeyBytes(opts.privateKey);
      c.wallet = createWalletClient({ account: privateKeyToAccount(toHex(key)), chain, transport: http(c.rpcUrl(opts.rpcUrl)) });
    }
    return c;
  }

  private rpcUrl(given?: string): string {
    return given ?? process.env?.DARK_RPC_URL ?? this.deployment.rpcUrl;
  }

  /** The independent source for recipient keys (see `transfer()`), or null when there is none. */
  private secondRpcUrl(given?: string): string | null {
    if (this.rpcUrl(given) !== this.deployment.rpcUrl) return this.deployment.rpcUrl;
    return this.api ? `${this.api.baseUrl.replace(/\/$/, '')}/v1/rpc` : null;
  }

  get betaNotice(): BetaNoticeState {
    return this.deployment.betaNoticeState;
  }

  get publicKey(): AffinePoint {
    return this.keys.publicKey;
  }

  getStatus(): DarkStatus {
    return this.status;
  }

  // ---- reads ---------------------------------------------------------------------------

  /**
   * §7 step 0: `getAccount`, `caps`, `tvl`, `paused` and `registry.keyOf` at one block, then
   * the s*P == H / derived-P check. A registry key that is not the derived one is a terminal
   * hard stop (§11 `key_mismatch`), never a silently different account.
   */
  async sync(blockNumber?: bigint): Promise<Snapshot> {
    this.status = 'syncing';
    try {
      return await this.syncInner(blockNumber);
    } catch (e) {
      // Leaving `syncing` behind after a failure made the UI show a spinner for a state that had
      // already ended.
      this.status = 'idle';
      throw e;
    }
  }

  private async readPinned(
    calls: readonly unknown[],
    block: bigint,
    retryLag: boolean,
  ): Promise<{ status: string; result?: unknown; error?: unknown }[]> {
    for (let attempt = 0; ; attempt++) {
      const canRetry = retryLag && attempt < RPC_LAG_RETRIES;
      try {
        let results: { status: string; result?: unknown; error?: unknown }[];
        if (this.multicallAddress) {
          results = await this.pub.multicall({
            contracts: calls as never,
            blockNumber: block,
            allowFailure: true,
            multicallAddress: this.multicallAddress,
          });
          // With allowFailure, a transport-level problem also arrives as per-call `failure`. The four
          // vault reads (0..3) cannot legitimately revert, so a failure there is the transport, not
          // the contract; keyOf (4) may revert NotRegistered and is judged by the caller.
          if (canRetry && results.slice(0, 4).some((r) => r.status !== 'success')) {
            await sleep(RPC_LAG_BACKOFF_MS[attempt]!);
            continue;
          }
        } else {
          // Same atomicity: every call is pinned to the same block, just in more round trips.
          // A revert and a timeout are different facts. Swallowing both into `failure` made an RPC
          // blip show a registered account as unregistered, which invites a pointless re-register
          // whose proof cannot land. Only a revert is a `failure` here; anything else is
          // rethrown.
          results = await Promise.all(calls.map(async (c) => {
            try {
              return { status: 'success', result: await this.pub.readContract({ ...(c as unknown as Record<string, unknown>), blockNumber: block } as never) };
            } catch (e) {
              const message = (e as Error)?.message ?? '';
              if (/revert|NotRegistered|execution reverted/i.test(message)) return { status: 'failure' };
              throw new DarkError('STALE_STATE', `vault read failed at block ${block}: ${message.split('\n')[0]}`);
            }
          }));
        }
        return results;
      } catch (e) {
        if (canRetry && e instanceof DarkError && e.code === 'STALE_STATE') {
          await sleep(RPC_LAG_BACKOFF_MS[attempt]!);
          continue;
        }
        throw e;
      }
    }
  }

  private async syncInner(blockNumber?: bigint): Promise<Snapshot> {
    const block = blockNumber ?? (await this.pub.getBlockNumber());
    const vault = this.deployment.vault as Address;
    const calls = [
      { address: vault, abi: darkVaultAbi, functionName: 'getAccount', args: [this.account] },
      { address: vault, abi: darkVaultAbi, functionName: 'caps' },
      { address: vault, abi: darkVaultAbi, functionName: 'tvl' },
      { address: vault, abi: darkVaultAbi, functionName: 'paused' },
      { address: this.deployment.registry as Address, abi: darkKeyRegistryAbi, functionName: 'keyOf', args: [this.account] },
    ] as const;

    // Retried at the SAME block when we chose the block ourselves: a load-balanced RPC can hand out a
    // head from one replica and route the reads to another that has not seen it yet (a load test on
    // the public RPC hit exactly this). Same block, so the "one block" semantics hold; a
    // caller-pinned block that does not exist is a real error and is not retried. Only the reads are
    // retried — the key-derivation hard stop below them never is.
    const results = await this.readPinned(calls, block, blockNumber === undefined);

    const need = (i: number, what: string) => {
      if (results[i].status !== 'success') {
        const why = (results[i].error as Error | undefined)?.message?.split('\n')[0] ?? 'unknown';
        throw new DarkError('STALE_STATE', `vault read failed at block ${block}: ${what}: ${why}`, {
          block: String(block), call: what,
        });
      }
      return results[i].result;
    };

    const raw = need(0, 'getAccount') as {
      available: { c: AffinePoint; d: AffinePoint };
      pending: { c: AffinePoint; d: AffinePoint };
      nonce: bigint; pendingCount: bigint; netInflow: bigint; aeBalance: Hex;
    };
    const capsRaw = need(1, 'caps') as Caps;
    const snapshot: Snapshot = {
      block,
      account: {
        available: ct(raw.available),
        pending: ct(raw.pending),
        nonce: BigInt(raw.nonce),
        pendingCount: BigInt(raw.pendingCount),
        netInflow: BigInt(raw.netInflow),
        aeBalance: raw.aeBalance,
      },
      caps: {
        minDeposit: BigInt(capsRaw.minDeposit), maxDeposit: BigInt(capsRaw.maxDeposit),
        maxAccountInflow: BigInt(capsRaw.maxAccountInflow), minTransfer: BigInt(capsRaw.minTransfer),
        maxTransfer: BigInt(capsRaw.maxTransfer), tvlCap: BigInt(capsRaw.tvlCap),
      },
      // Clamped: this is the BSGS bound, and it comes off the RPC.
      tvl: capBsgsBound(need(2, 'tvl') as bigint, HARD_MAX_TVL),
      // keyOf reverts NotRegistered, which is a legitimate "not registered yet", not an outage.
      registryKey: results[4].status === 'success' ? (results[4].result as AffinePoint) : null,
      paused: need(3, 'paused') as boolean,
    };

    if (snapshot.registryKey) {
      // §4 / §11: terminal hard stop. No proof is ever built against a key we do not own.
      checkRegistryKey(this.keys.publicKey, snapshot.registryKey);
      this.status = 'ready';
    } else {
      this.status = 'unregistered';
    }
    return snapshot;
  }

  async caps(): Promise<Caps> {
    return (await this.sync()).caps;
  }

  async tvl(): Promise<bigint> {
    return (await this.sync()).tvl;
  }

  async isRegistered(): Promise<boolean> {
    return (await this.sync()).registryKey !== null;
  }

  /**
   * §7 step 5, normative. `available` comes from `aeBalance` **only after** value*G == C - s*D
   * is checked; otherwise a BSGS bounded by `tvl()` -- the vault's real liability -- never by
   * `tvlCap`, so exit still works with every cap tightened to 0.
   */
  async getBalances(snapshot?: Snapshot): Promise<Balances> {
    const s = snapshot ?? (await this.sync());
    const available = this.openAvailable(s);
    const pending = await this.openPending(s);
    return {
      available,
      pending,
      pendingCount: Number(s.account.pendingCount),
      nonce: s.account.nonce,
      balancePublic: isPublicBalance(s),
    };
  }

  private openAvailable(s: Snapshot): bigint {
    const { c, d } = s.account.available;
    const target = decryptToPoint(c, d, this.keys.s);
    const blob = hexBytes(s.account.aeBalance);
    if (blob.length === AE_BALANCE_BYTES) {
      const hint = openBalance(this.keys.kAe, blob, this.aeContext());
      // The hint is owner-written but chain-stored: always verify before believing it.
      if (hint && mul(G, hint.value).equals(target)) return hint.value;
    }
    const found = discreteLog(target, s.tvl, this.bsgsTableBits);
    if (found === null) {
      throw new DarkError('DECRYPTION_FAILED', 'available balance did not open under tvl()', { tvl: String(s.tvl) });
    }
    return found;
  }

  /**
   * Pending = the verified hint amounts since the last `PendingApplied`. A failed or lying hint
   * falls back to a per-transfer BSGS bounded by the `maxTransfer` in force at that transfer's
   * block, never the current cap, and the total is checked against the pending ciphertext.
   */
  private async openPending(s: Snapshot): Promise<bigint> {
    const target = decryptToPoint(s.account.pending.c, s.account.pending.d, this.keys.s);
    if (s.account.pendingCount === 0n) return 0n;

    const from = await this.lastApplyBlock(s.block);
    const logs = await this.logsFor('ConfidentialTransfer', { to: this.account }, from, s.block);
    // One transfer that will not open (a garbage hint above a cap tightened later in its block, an
    // RPC that hides a CapsUpdated) must not wedge the whole pending balance: it voids the walk,
    // and the aggregate fallback below opens the total.
    let total: bigint | null = 0n;
    for (const l of logs) {
      const a = await this.amountFromIncomingOrNull(l, s);
      total = total === null || a === null ? null : total + a;
    }
    if (total !== null && mul(G, total).equals(target)) return total;

    // The per-transfer walk disagrees with the chain (a missing log, a lying sender we could not
    // bound): fall back to one BSGS over the aggregate, bounded by tvl.
    const found = discreteLog(target, s.tvl, this.bsgsTableBits);
    if (found === null) throw new DarkError('DECRYPTION_FAILED', 'pending balance did not open under tvl()');
    return found;
  }

  private async lastApplyBlock(head: bigint): Promise<bigint> {
    const logs = await this.logsFor('PendingApplied', { account: this.account }, this.deployment.deployBlock, head);
    const last = logs.at(-1)?.blockNumber;
    return last === null || last === undefined ? this.deployment.deployBlock : last;
  }

  /** One incoming transfer's amount: the hint, verified; else BSGS under that block's cap. */
  private async amountFromIncoming(log: DecodedLog, s: Snapshot): Promise<bigint> {
    const a = log.args as {
      from: Address; to: Address; fromNonceAfter: bigint; transferCt: readonly bigint[]; hint: Hex;
    };
    const C = point({ x: a.transferCt[0], y: a.transferCt[1] });
    const Dr = point({ x: a.transferCt[4], y: a.transferCt[5] });
    const target = decryptToPoint(C, Dr, this.keys.s);
    const tctx = {
      chainId: this.chainId, vault: this.deployment.vault, from: a.from, to: a.to,
      // The event carries the post-state nonce; the hint was built against the pre-state one.
      fromNonce: a.fromNonceAfter - 1n,
    };
    const opened = openHint(hexBytes(a.hint), this.keys.s, tctx);
    if (opened && mul(G, opened.amount).equals(target)) return opened.amount;
    // §7 step 5: bound by the maxTransfer in force at that transfer's block, not the current one.
    const bound = await this.maxTransferAt(log.blockNumber ?? s.block);
    const found = discreteLog(target, bound, this.bsgsTableBits);
    if (found === null) {
      throw new DarkError('DECRYPTION_FAILED', 'an incoming transfer did not open under its block\'s maxTransfer');
    }
    return found;
  }

  /** `amountFromIncoming`, with an amount that will not open as `null` (unknown), not a throw. */
  private async amountFromIncomingOrNull(log: DecodedLog, s: Snapshot): Promise<bigint | null> {
    try {
      return await this.amountFromIncoming(log, s);
    } catch (e) {
      if (isDarkError(e) && e.code === 'DECRYPTION_FAILED') return null;
      throw e;
    }
  }

  /** HARD_MAX_TRANSFER when no `CapsUpdated` covers that block (§7 step 5). */
  private async maxTransferAt(block: bigint): Promise<bigint> {
    const logs = await this.logsFor('CapsUpdated', {}, this.deployment.deployBlock, block);
    const last = logs.at(-1);
    if (!last) return HARD_MAX_TRANSFER;
    return capBsgsBound(BigInt((last.args as { newCaps: Caps }).newCaps.maxTransfer), HARD_MAX_TRANSFER);
  }

  // ---- history -------------------------------------------------------------------------

  /**
   * §7 step 6, direct RPC: topic-filtered `eth_getLogs` from `deployBlock`, halving the range on
   * the 10,000-log cap. Sent amounts come from `senderHint`, received from `hint`, both verified.
   */
  async history(): Promise<HistoryEntry[]> {
    const head = await this.pub.getBlockNumber();
    const from = this.deployment.deployBlock;
    const [deposits, withdrawals, applies, out, incoming] = await Promise.all([
      this.logsFor('Deposited', { account: this.account }, from, head),
      this.logsFor('Withdrawn', { account: this.account }, from, head),
      this.logsFor('PendingApplied', { account: this.account }, from, head),
      this.logsFor('ConfidentialTransfer', { from: this.account }, from, head),
      this.logsFor('ConfidentialTransfer', { to: this.account }, from, head),
    ]);

    const entries: (HistoryEntry & { logIndex: number })[] = [];
    const push = (l: DecodedLog, e: Omit<HistoryEntry, 'block' | 'txHash'>) =>
      entries.push({ ...e, block: l.blockNumber ?? 0n, txHash: (l.transactionHash ?? '0x') as Hex, logIndex: l.logIndex ?? 0 });

    for (const l of deposits) push(l, { kind: 'deposit', amount: (l.args as { amount: bigint }).amount, amountPublic: true });
    for (const l of withdrawals) {
      const a = l.args as { amount: bigint; to: Address };
      push(l, { kind: 'withdraw', amount: a.amount, counterparty: a.to, amountPublic: true });
    }
    for (const l of out) {
      const a = l.args as { to: Address; from: Address; fromNonceAfter: bigint; senderHint: Hex };
      const opened = openSenderHint(this.keys.kAe, hexBytes(a.senderHint), {
        chainId: this.chainId, vault: this.deployment.vault, from: a.from, to: a.to, fromNonce: a.fromNonceAfter - 1n,
      });
      // `null`, never 0n: a hint that will not open (corrupt event, format change, wrong k_ae) is an
      // amount we do not know, and showing it as a zero-value transfer is a quiet lie in the user's
      // own history. The incoming path verifies too, and reports `null` rather than guessing.
      push(l, { kind: 'transfer_out', amount: opened?.amount ?? null, counterparty: a.to, amountPublic: false });
    }
    for (const l of incoming) {
      const a = l.args as { from: Address };
      push(l, { kind: 'transfer_in', amount: await this.amountFromIncomingOrNull(l, { block: l.blockNumber ?? head } as Snapshot), counterparty: a.from, amountPublic: false });
    }
    for (const l of applies) push(l, { kind: 'apply_pending', amount: 0n, amountPublic: false });

    entries.sort((x, y) => (x.block === y.block ? x.logIndex - y.logIndex : Number(x.block - y.block)));
    // An `apply_pending` moves exactly the transfers received since the previous one. If any of
    // those amounts is unknown, so is the total — it is reported as unknown rather than as a
    // confident sum that is quietly short.
    let acc: bigint | null = 0n;
    for (const e of entries) {
      if (e.kind === 'transfer_in') acc = acc === null || e.amount === null ? null : acc + e.amount;
      if (e.kind === 'apply_pending') {
        e.amount = acc;
        acc = 0n;
      }
    }
    return entries.map(({ logIndex: _i, ...e }) => e);
  }

  private eventAbi(name: string) {
    const e = darkVaultAbi.find((x) => x.type === 'event' && x.name === name);
    if (!e) throw new DarkError('NOT_IMPLEMENTED', `no ABI for event ${name}`);
    return e;
  }

  private logsFor(name: string, args: Record<string, unknown>, from: bigint, to: bigint): Promise<DecodedLog[]> {
    return this.getLogsChunked(
      { address: this.deployment.vault as Address, event: this.eventAbi(name) as never, args: args as never },
      from,
      to,
    );
  }

  /**
   * Halve the range whenever the node refuses it (the 10,000-log cap).
   *
   * Sequential, depth-capped, and it distinguishes a rate limit from a size refusal. The
   * previous version ran both halves through `Promise.all` and recursed without a limit, so one
   * request against a throttled endpoint became 2^depth CONCURRENT requests against the endpoint
   * that was already refusing — and since a 429 body matches the size-refusal pattern, being rate
   * limited made the client hit harder. Halving cannot fix a rate limit; only waiting can.
   */
  private async getLogsChunked(params: object, from: bigint, to: bigint, depth = 0): Promise<DecodedLog[]> {
    for (let attempt = 0; ; attempt++) {
      try {
        return (await this.pub.getLogs({ ...(params as Record<string, unknown>), fromBlock: from, toBlock: to } as never)) as DecodedLog[];
      } catch (e) {
        if (isRateLimited(e)) {
          if (attempt >= RATE_LIMIT_RETRIES) {
            throw new DarkError('STALE_STATE', 'the RPC endpoint is rate limiting log queries; try again shortly');
          }
          // Same range, just later. Splitting here would multiply the requests being refused.
          await sleep(RATE_LIMIT_BACKOFF_MS[attempt]!);
          continue;
        }
        if (from >= to || !isRangeError(e)) throw e;
        if (depth >= MAX_CHUNK_DEPTH) {
          throw new DarkError('STALE_STATE', `log range still refused after ${MAX_CHUNK_DEPTH} splits; the endpoint is not serving this query`);
        }
        // One half at a time: a struggling endpoint should see one request, not a doubling tree.
        const mid = from + (to - from) / 2n;
        const a = await this.getLogsChunked(params, from, mid, depth + 1);
        const b = await this.getLogsChunked(params, mid + 1n, to, depth + 1);
        return [...a, ...b];
      }
    }
  }

  // ---- owner actions -------------------------------------------------------------------

  /** §7 step 1. `dark_register`, then `DarkKeyRegistry.register(P, proof)`. */
  async register(onProgress?: ProgressFn): Promise<Hex> {
    const s = await this.sync();
    if (s.registryKey) return '0x' as Hex; // already registered; sync() already proved it is ours
    const witness = buildRegisterWitness({
      chainId: this.chainId,
      registry: this.deployment.registry,
      account: this.account,
      s: this.keys.s,
      pk: this.keys.P,
    });
    const proof = await this.proveChecked('register', 'dark_register', witness, onProgress);
    return this.send('register', {
      address: this.deployment.registry as Address,
      abi: darkKeyRegistryAbi,
      functionName: 'register',
      args: [this.keys.publicKey, proof],
    });
  }

  /** §7 step 2. Exact approve, then deposit. No proof: the amount is public. */
  async deposit(amount: bigint, onProgress?: ProgressFn): Promise<Hex> {
    const s = await this.requireRegistered();
    if (amount < s.caps.minDeposit || amount > s.caps.maxDeposit) {
      throw new DarkError('CAP_EXCEEDED', 'deposit outside [minDeposit, maxDeposit]');
    }
    if (s.account.netInflow + amount > s.caps.maxAccountInflow) {
      throw new DarkError('CAP_EXCEEDED', 'account inflow cap exceeded');
    }
    if (s.tvl + amount > s.caps.tvlCap) throw new DarkError('CAP_EXCEEDED', 'TVL cap exceeded');
    if (s.paused) throw new DarkError('STALE_STATE', 'the vault is paused: deposits are blocked');

    const balance = this.openAvailable(s);
    onProgress?.(0.5, 'approve');
    const { erc20Abi } = await import('viem');
    await this.send('deposit', {
      address: this.deployment.usdg as Address,
      abi: erc20Abi,
      functionName: 'approve',
      args: [this.deployment.vault, amount], // exact, per §7 step 2.3
    }, true);
    return this.send('deposit', {
      address: this.deployment.vault as Address,
      abi: darkVaultAbi,
      functionName: 'deposit',
      args: [amount, this.seal(balance + amount, s.account.nonce + 1n)],
    });
  }

  /** §7 / §12. Never pausable: this is half the exit guarantee. */
  async applyPending(onProgress?: ProgressFn): Promise<Hex> {
    const s = await this.requireRegistered();
    if (s.account.pendingCount === 0n) throw new DarkError('STALE_STATE', 'nothing pending to apply');
    const pending = await this.openPending(s);
    const balance = this.openAvailable(s);
    onProgress?.(1, 'done');
    return this.send('applyPending', {
      address: this.deployment.vault as Address,
      abi: darkVaultAbi,
      functionName: 'applyPending',
      args: [s.account.pendingCount, this.seal(balance + pending, s.account.nonce + 1n)],
    });
  }

  /** §7 step 3. `to` must be registered; there is never a silent public fallback. */
  /**
   * NOTE: the third argument is a private note for the recipient, NOT a recipient key. The fixture
   * client took a key there, so a screen built against the fixture passed one and it was stringified
   * into "[object Object]" and sealed into both hints, where the recipient would read it.
   * Both clients now take a note, and the shared surface says so.
   */
  async transfer(to: Address, amount: bigint, note = '', onProgress?: ProgressFn): Promise<Hex> {
    let s = await this.requireRegistered();
    if (to.toLowerCase() === this.account.toLowerCase()) {
      throw new DarkError('AMOUNT_OUT_OF_RANGE', 'self-transfer');
    }
    if (s.paused) throw new DarkError('STALE_STATE', 'the vault is paused: transfers are blocked');

    const recipientKey = await this.keyOf(to, s.block);
    if (!recipientKey) throw new DarkError('RECIPIENT_NOT_REGISTERED', `${to} has no registered key`);
    // The recipient key decides who can read the amount and the note, so one RPC's word is not
    // enough: an RPC that answered with its own key would receive a hint it can open, and the vault
    // would reject the transfer only after that hint had been built and handed to it. A second,
    // independent source must return the same key (register-once, so `latest` is exact).
    if (this.keyCheck) {
      const second = await this.keyOfVia(this.keyCheck, to);
      if (!second || second.x !== recipientKey.x || second.y !== recipientKey.y) {
        throw new DarkError(
          'RPC_DISAGREEMENT',
          'the two RPC sources disagree about the recipient key; nothing was encrypted or sent',
        );
      }
    }
    if (amount < s.caps.minTransfer || amount > s.caps.maxTransfer || amount >= MAX_AMOUNT) {
      throw new DarkError('AMOUNT_OUT_OF_RANGE', 'transfer outside [minTransfer, maxTransfer]');
    }

    // §7 step 3.2: apply pending first when available alone does not cover the amount.
    if (this.openAvailable(s) < amount && s.account.pendingCount > 0n) {
      await this.applyPending();
      s = await this.sync();
    }
    const balance = this.openAvailable(s);
    if (amount > balance) throw new DarkError('INSUFFICIENT_BALANCE', 'available balance too low');

    const Pr = decode(recipientKey);
    const tctx = {
      chainId: this.chainId, vault: this.deployment.vault, from: this.account, to, fromNonce: s.account.nonce,
    };
    const context = contextBytes(tctx);
    // Separate tags AND separate CSPRNG draws (§3): r and k must never coincide.
    const r = hedgedScalar(TAG_TRANSFER_R, this.keys.s, context);
    const k = hedgedScalar(TAG_HINT_K, this.keys.s, context);
    const { C, D } = encrypt(amount, [this.keys.P, Pr], r);
    assertHintPrivacy({ C, amount, Re: mul(H, k), K: mul(Pr, k), Dr: D[1] });

    const witness = buildTransferWitness({
      chainId: this.chainId, vault: this.deployment.vault, sender: this.account, recipient: to,
      senderNonce: s.account.nonce, s: this.keys.s, r, amount, balance,
      pkS: this.keys.P, pkR: Pr, avail: s.account.available,
      ct: { c: C, ds: D[0], dr: D[1] },
      minTransfer: s.caps.minTransfer, maxTransfer: s.caps.maxTransfer,
    });
    const proof = await this.proveChecked('transfer', 'dark_transfer', witness, onProgress);
    const p = (x: Pt) => ptEncode(x);
    return this.send('transfer', {
      address: this.deployment.vault as Address,
      abi: darkVaultAbi,
      functionName: 'transfer',
      args: [
        to,
        { c: p(C), dSender: p(D[0]), dRecipient: p(D[1]) },
        proof,
        toHex(sealHint(k, Pr, tctx, amount, note)),
        toHex(sealSenderHint(this.keys.kAe, tctx, amount, note)),
        this.seal(balance - amount, s.account.nonce + 1n),
      ],
    });
  }

  /** §7 step 4. Works while the vault is paused; the amount and destination are public. */
  async withdraw(amount: bigint, to?: Address, onProgress?: ProgressFn): Promise<Hex> {
    const s = await this.requireRegistered();
    const dest = to ?? this.account;
    if (amount <= 0n || amount >= MAX_AMOUNT) throw new DarkError('AMOUNT_OUT_OF_RANGE', 'withdraw amount invalid');
    if (dest === ZERO_ADDRESS || dest.toLowerCase() === this.deployment.vault.toLowerCase()) {
      throw new DarkError('AMOUNT_OUT_OF_RANGE', 'bad withdraw recipient');
    }
    const balance = this.openAvailable(s);
    if (amount > balance) throw new DarkError('INSUFFICIENT_BALANCE', 'available balance too low');

    const witness = buildWithdrawWitness({
      chainId: this.chainId, vault: this.deployment.vault, account: this.account, to: dest,
      nonce: s.account.nonce, s: this.keys.s, amount, balance,
      pk: this.keys.P, avail: s.account.available,
    });
    const proof = await this.proveChecked('withdraw', 'dark_withdraw', witness, onProgress);
    return this.send('withdraw', {
      address: this.deployment.vault as Address,
      abi: darkVaultAbi,
      functionName: 'withdraw',
      args: [amount, dest, proof, this.seal(balance - amount, s.account.nonce + 1n)],
    });
  }

  // ---- internals -----------------------------------------------------------------------

  /**
   * `registry.keyOf`, or null when the account genuinely is not registered.
   *
   * Only a revert counts as "not registered". Swallowing every error meant an RPC timeout during
   * `transfer()` told the user the RECIPIENT was unregistered — false, and not retryable — and made
   * `sync()` report a registered account as unregistered, inviting a pointless re-register.
   */
  async keyOf(who: Address, blockNumber?: bigint): Promise<AffinePoint | null> {
    return this.keyOfVia(this.pub, who, blockNumber);
  }

  private async keyOfVia(client: PublicClient, who: Address, blockNumber?: bigint): Promise<AffinePoint | null> {
    try {
      return (await client.readContract({
        address: this.deployment.registry as Address,
        abi: darkKeyRegistryAbi,
        functionName: 'keyOf',
        args: [who],
        blockNumber,
      })) as AffinePoint;
    } catch (e) {
      const message = (e as Error)?.message ?? '';
      const reverted = /revert|NotRegistered|execution reverted/i.test(message);
      if (!reverted) {
        throw new DarkError('STALE_STATE', `could not read the key registry: ${message.split('\n')[0]}`);
      }
      return null;
    }
  }

  private async requireRegistered(): Promise<Snapshot> {
    const s = await this.sync();
    if (!s.registryKey) throw new DarkError('NOT_REGISTERED', 'register the account first');
    return s;
  }

  private aeContext(): AeContext {
    return { chainId: this.chainId, vault: this.deployment.vault, account: this.account };
  }

  private seal(value: bigint, nonceAfter: bigint): Hex {
    return toHex(sealBalance(this.keys.kAe, { value, nonceAfter }, this.aeContext()));
  }

  /**
   * §7: "every prover returns {proof, publicInputs, ms}; the SDK re-derives the public inputs
   * and rejects the proof on any mismatch". The SDK's own derivation is what gets sent on.
   */
  private async proveChecked(
    kind: ActionKind, circuit: CircuitId, witness: Witness, onProgress?: ProgressFn,
  ): Promise<Hex> {
    this.emit(kind, 'building');
    const expected = buildPublicInputs(circuit, witness);
    this.emit(kind, 'proving', { progress: 0 });
    const result = await this.prover.prove(circuit, witness, (f, stage) => {
      onProgress?.(f, stage);
      this.emit(kind, 'proving', { progress: f });
    });
    assertPublicInputsEqual(circuit, result.publicInputs, expected);
    return toHex(result.proof);
  }

  /** §13 simulating -> submitted -> soft_confirmed -> final, with a bounded `stale` retry. */
  private async send(kind: ActionKind, call: object, quiet = false): Promise<Hex> {
    if (!this.wallet) throw new DarkError('NOT_IMPLEMENTED', 'no walletClient: this client can only read');
    const account = this.wallet.account;
    let submitted: Hex | undefined;
    {
      if (!quiet) this.emit(kind, 'simulating');
      try {
        const { request } = await this.pub.simulateContract({ ...(call as Record<string, unknown>), account } as never);
        const txHash = await this.wallet.writeContract(request as never);
        submitted = txHash as Hex;
        if (!quiet) this.emit(kind, 'submitted', { txHash });
        const receipt = await this.pub.waitForTransactionReceipt({ hash: txHash });
        if (receipt.status !== 'success') {
          this.emit(kind, 'reverted', { txHash, reason: 'transaction reverted' });
          throw new DarkError('STALE_STATE', `${kind} reverted on chain`, { txHash });
        }
        if (!quiet) {
          this.emit(kind, 'soft_confirmed', { txHash });
          this.emit(kind, 'final', { txHash });
        }
        return txHash;
      } catch (e) {
        const reason = (e as Error).message ?? String(e);
        // Once the transaction is out, we no longer know it failed — only that we stopped watching.
        // Calling that `reverted` invites the user to retry and pay twice.
        if (submitted) {
          this.emit(kind, 'unknown', { txHash: submitted, reason });
          throw new DarkError(
            'STALE_STATE',
            `${kind} was submitted but its outcome is unknown: ${reason.split('\n')[0]}`,
            { kind, txHash: submitted },
          );
        }
        // A transfer that landed under an in-flight proof, or a nonce that moved.
        //
        // This used to `continue`, which re-simulated the IDENTICAL call — same proof, same public
        // inputs, same sealed aeBalance, all built from the snapshot that is now stale. It failed
        // the same way every time and then surfaced as STALE_STATE anyway. Rebuilding
        // needs a fresh sync and a fresh proof, which only the caller can do, so say so plainly on
        // the first failure instead of pretending to recover.
        // The revert text only (shortMessage leaves out the call's arguments, which an address
        // could spell a selector in), and never for register: its public inputs read no state.
        const revertText = (e as { shortMessage?: string }).shortMessage ?? reason;
        if (kind !== 'register' && STALE_REVERT.test(revertText)) {
          this.emit(kind, 'stale', { reason });
          throw new DarkError(
            'STALE_STATE',
            `${kind} was built against state that has since moved; sync and try the action again`,
            { kind },
          );
        }
        if (e instanceof DarkError) throw e;
        this.emit(kind, 'reverted', { reason });
        throw new DarkError('STALE_STATE', `${kind} failed: ${reason.split('\n')[0]}`, { kind });
      }
    }
  }

  // ---- disclosures ---------------------------------------------------------------------

  private requireApi(): DarkApi {
    if (!this.api) {
      throw new DarkError('NOT_IMPLEMENTED', 'this client has no `api`: disclosures need somewhere to store the sealed blob');
    }
    return this.api;
  }

  private async apiFetch(path: string, init: RequestInit & { auth?: boolean } = {}): Promise<Response> {
    const api = this.requireApi();
    const { auth, headers: given, ...rest } = init;
    const headers: Record<string, string> = { ...((given as Record<string, string>) ?? {}) };
    if (auth !== false) {
      const token = await api.token();
      if (!token) throw new DarkError('NOT_IMPLEMENTED', 'no session token: sign in before using disclosures');
      headers.authorization = `Bearer ${token}`;
    }
    return fetch(`${api.baseUrl.replace(/\/$/, '')}${path}`, { ...rest, headers });
  }

  /**
   * §7.7: prove one fact about this account's balance, seal the document under a fresh key, and
   * store only the ciphertext. The key goes in the link's fragment and never reaches the server, so
   * what is stored is opaque to whoever stores it.
   *
   * Exact kinds only for now — a range kind needs a Honk proof from the device prover.
   */
  async createDisclosure(kind: Disclosure['kind'], label: string, ttlDays = 30): Promise<Disclosure> {
    if (label.length > 64) throw new DarkError('AMOUNT_OUT_OF_RANGE', 'label longer than 64 chars');
    if (ttlDays < 1 || ttlDays > 365) throw new DarkError('AMOUNT_OUT_OF_RANGE', 'expiry outside 1..365 days');
    if (kind !== 'balance_exact') {
      throw new DarkError('NOT_IMPLEMENTED', `${kind} disclosures are not implemented yet; balance_exact is`);
    }
    if (!this.wallet) throw new DarkError('NOT_IMPLEMENTED', 'no walletClient: the document must be signed by the account');

    const d = await import('./disclosure.ts');
    const s = await this.sync();
    const value = (await this.getBalances(s)).available;
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + Math.round(ttlDays * 86_400);
    const id = d.newDisclosureId(this.chainId);

    const doc = await d.signDisclosure(
      d.buildExactDisclosure({
        context: {
          chainId: this.chainId, vault: this.deployment.vault, registry: this.deployment.registry,
          account: this.account, kind: 'balance_exact', component: 'available',
          block: s.block, lo: value, hi: value, createdAt: now, expiresAt, id, label,
        },
        pk: this.keys.P, ciphertext: s.account.available, value, s: this.keys.s,
      }),
      (typedData) =>
        this.wallet!.signTypedData({
          ...(typedData as unknown as Record<string, unknown>),
          account: this.wallet!.account,
        } as never),
    );

    const { blob, key } = d.sealDisclosure(doc, id);
    const revokeToken = toHex32(crypto.getRandomValues(new Uint8Array(32)));
    const res = await this.apiFetch('/v1/disclosures', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        id,
        blob: d.base64url(blob).replace(/-/g, '+').replace(/_/g, '/'),
        expiresAt: new Date(expiresAt * 1000).toISOString(),
        revokeTokenHash: sha256Hex(revokeToken),
      }),
    });
    if (!res.ok) throw new DarkError('STALE_STATE', `the disclosure could not be stored (${res.status})`);

    // The revoke token is kept by the device that made the link, so it can revoke without a session.
    this.revokeTokens.set(id, revokeToken);
    return {
      id, kind, label, url: d.disclosureLink(id, key),
      createdAt: now * 1000, expiresAt: expiresAt * 1000, revoked: false,
    };
  }

  /**
   * Revoke: the blob is purged and the link starts answering 410. Anyone who already opened it may
   * have saved the proof, and a saved proof stays valid — the UI must say so (§7.7 step 9).
   */
  async revokeDisclosure(id: string): Promise<void> {
    const token = this.revokeTokens.get(id);
    const res = await this.apiFetch(`/v1/disclosures/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      // The revoke token works without a session, which is the point of keeping it on the device.
      ...(token ? { headers: { 'x-revoke-token': token }, auth: false } : {}),
    });
    if (!res.ok) throw new DarkError('STALE_STATE', `the disclosure could not be revoked (${res.status})`);
    this.revokeTokens.delete(id);
  }

  /**
   * The revoke token for every disclosure this client created and has not revoked, keyed by id.
   *
   * Without these, a restart loses them — they lived only in memory — and the user can never revoke
   * a link they shared again, which is the one control they have over it. So the app must persist
   * them: call this after `createDisclosure` and after `revokeDisclosure`, and store the result.
   *
   * **They are secrets.** Anyone holding a token can revoke that link with no session, so keep them
   * in the encrypted vault next to the wallet keys — never in plain storage, a log or a crash report.
   */
  exportRevokeTokens(): Record<string, string> {
    return Object.fromEntries(this.revokeTokens);
  }

  /**
   * Restore tokens saved by `exportRevokeTokens`, e.g. after the app restarts or on a new session.
   * All-or-nothing: every entry is validated before any is applied, so a corrupted vault cannot leave
   * the client half-restored. Entries replace any token already held for the same id.
   */
  importRevokeTokens(tokens: Record<string, string>): void {
    const entries = Object.entries(tokens ?? {});
    for (const [id, token] of entries) {
      if (!REVOKE_ID_RE.test(id)) throw new TypeError(`importRevokeTokens: not a disclosure id: ${JSON.stringify(id).slice(0, 40)}`);
      // Never echo the token itself: this message can end up in a crash report.
      if (typeof token !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(token)) {
        throw new TypeError(`importRevokeTokens: the token for ${id} is not 32 bytes of hex`);
      }
    }
    for (const [id, token] of entries) this.revokeTokens.set(id, token.toLowerCase());
  }

  /** The server holds ids and lifecycle only; labels live inside the blobs, which it cannot read. */
  async listDisclosures(): Promise<Disclosure[]> {
    const res = await this.apiFetch('/v1/disclosures');
    if (!res.ok) throw new DarkError('STALE_STATE', `the disclosure list could not be read (${res.status})`);
    const body = (await res.json()) as { disclosures: { id: string; status: string; createdAt: string; expiresAt: string }[] };
    return body.disclosures.map((r) => ({
      id: r.id,
      kind: 'balance_exact' as const,
      // Deliberately empty: the label is inside the sealed document, and the server cannot read it.
      label: '',
      url: '',
      createdAt: Date.parse(r.createdAt),
      expiresAt: Date.parse(r.expiresAt),
      revoked: r.status === 'revoked',
    }));
  }

  private emit(kind: ActionKind, state: ActionState, extra: Partial<ActionEvent> = {}): void {
    this.onAction?.({ kind, state, ...extra });
  }
}

/** §5: the v1 vault's immutable ceiling, the bound used when no CapsUpdated covers a block. */
export const HARD_MAX_TRANSFER = 2_500_000_000n;
/** `DarkVault.HARD_MAX_TVL` (250,000e6), immutable in the contract. */
export const HARD_MAX_TVL = 250_000_000_000n;

/**
 * Clamp a BSGS search bound to the protocol's immutable ceiling.
 *
 * `discreteLog`'s memory is capped by `bsgsTableBits`, but its TIME is linear in the bound: the
 * final pass runs `bound / 2^tableBits` giant steps. Both bounds we pass it — `tvl()` and the
 * `maxTransfer` decoded from a `CapsUpdated` log — arrive over the same RPC transport that §2's
 * threat table already says may "serve wrong data". An absurd value there is not a wrong balance,
 * it is a wallet that hangs forever trying to decrypt one.
 *
 * That matters precisely because §18.10 promises balance recovery and exit keep working when every
 * Dark server is hostile or down. The old code guarded only against a bound that was too LOW (which
 * fails to decrypt and is noticed); a bound that is too HIGH hangs the exact self-rescue path the
 * guarantee exists for.
 *
 * The ceiling is a local constant, deliberately. Reading `HARD_MAX_TVL()` from the chain would ask
 * the same untrusted transport for the number meant to police it.
 */
export function capBsgsBound(bound: bigint, ceiling: bigint): bigint {
  return bound > ceiling ? ceiling : bound;
}

interface DecodedLog extends Log {
  args?: unknown;
}

const RANGE_ERROR = /10,?000|too many|exceed|block range|query returned more|limit|range is too large/i;
export const isRangeError = (e: unknown): boolean => RANGE_ERROR.test((e as Error)?.message ?? '');

// Checked BEFORE isRangeError, because "too many requests" also matches the size pattern and the two
// call for opposite responses: a size refusal wants a smaller range, a rate limit wants a pause.
const RATE_LIMITED = /\b429\b|rate limit|too many requests/i;
export const isRateLimited = (e: unknown): boolean => RATE_LIMITED.test((e as Error)?.message ?? '');

export const toHex32Prefixed = (b: Uint8Array): string => `0x${toHex32(b)}`;
const toHex32 = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

/**
 * sha256 of the token's HEX TEXT — the same bytes the Dark API hashes.
 *
 * This hashed the decoded bytes instead, so every revoke-token digest disagreed with the server's
 * and revoking from the device that made the link always 404'd, leaving the link live with no way
 * to take it down. `@noble/hashes` rather than `crypto.subtle` because Hermes, which the
 * app runs on, has no WebCrypto.
 */
function sha256Hex(tokenHex: string): string {
  return bytesToHex(sha256(utf8ToBytes(tokenHex)));
}

export const MAX_CHUNK_DEPTH = 12; // 4,096 sub-ranges; deeper means the endpoint is refusing for another reason
const RATE_LIMIT_RETRIES = 3;
const RATE_LIMIT_BACKOFF_MS = [250, 750, 2_000];
// A load test on the public RPC: getBlockNumber answered from a replica that had the block, the reads
// went to one that did not yet ("Missing or invalid parameters"). It catches up within a second.
const RPC_LAG_RETRIES = 3;
const RPC_LAG_BACKOFF_MS = [250, 500, 1_000];
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
