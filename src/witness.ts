// SPDX-License-Identifier: MIT OR Apache-2.0
// Witness builders for the four circuits (§6). Same logic as circuits/tools/gen_prover.mjs,
// which is how the committed Prover.toml fixtures are produced -- keeping both on this module
// is the point: if the SDK's maths and the circuits' maths diverge, `nargo execute` fails.
//
// Encoding: every scalar (`s`, `r`) is a 128-bit lo/hi limb pair, because the Grumpkin group
// order n is larger than Noir's Field modulus (§6, §19). Points are (x, y) with the (0,0)
// identity sentinel (§19).
import { DarkError } from './errors.ts';
import { G, H, GROUP_N, add, mul, sub, encode, type Pt } from './grumpkin.ts';
import { MAX_AMOUNT, decryptToPoint, type Ciphertext } from './elgamal.ts';
import type { CircuitId, Hex } from './prover.ts';

/** A point as the Noir prover file takes it. */
export interface WitnessPoint {
  x: string;
  y: string;
}

/** Noir `main()` arguments by parameter name; the public ones feed `buildPublicInputs`. */
export type Witness = Record<string, string | WitnessPoint>;

const hex = (v: bigint): string => `0x${v.toString(16).padStart(64, '0')}`;

const bad = (msg: string, detail?: unknown): never => {
  throw new DarkError('PUBLIC_INPUT_MISMATCH', `witness: ${msg}`, detail);
};

/** A Grumpkin scalar as the 128-bit limb pair Noir's `EmbeddedCurveScalar` takes. */
export function scalarLimbs(name: string, s: bigint): Witness {
  if (s <= 0n || s >= GROUP_N) bad(`${name} is outside [1, n)`);
  return { [`${name}_lo`]: hex(s & ((1n << 128n) - 1n)), [`${name}_hi`]: hex(s >> 128n) };
}

const point = (p: Pt): WitnessPoint => {
  const { x, y } = encode(p);
  return { x: hex(x), y: hex(y) };
};

const addr = (a: Hex | string): string => hex(BigInt(a));

function u48(name: string, v: bigint): string {
  if (v < 0n || v >= MAX_AMOUNT) bad(`${name} is outside [0, 2^48)`, { name, value: String(v) });
  return v.toString(10);
}

function field(name: string, v: bigint | number): string {
  const n = BigInt(v);
  if (n < 0n) bad(`${name} is negative`);
  return hex(n);
}

// --- dark_register ---------------------------------------------------------------------------

export interface RegisterWitnessArgs {
  chainId: number;
  registry: Hex;
  account: Hex;
  /** ElGamal secret. */
  s: bigint;
  /** P = s^-1 * H. */
  pk: Pt;
}

/** Knowledge of the s behind this key: s * pk == H (§6). */
export function buildRegisterWitness(a: RegisterWitnessArgs): Witness {
  if (!mul(a.pk, a.s).equals(H)) bad('s * pk != H (key derivation and registry key disagree)');
  return {
    ...scalarLimbs('s', a.s),
    chain_id: field('chain_id', a.chainId),
    registry: addr(a.registry),
    account: addr(a.account),
    pk: point(a.pk),
  };
}

// --- dark_transfer ---------------------------------------------------------------------------

export interface TransferWitnessArgs {
  chainId: number;
  vault: Hex;
  sender: Hex;
  recipient: Hex;
  /** The sender's on-chain nonce, read at the same block as `avail`. */
  senderNonce: bigint;
  s: bigint;
  /** Hedged transfer randomness (§3); the circuit enforces r != 0 via ct_ds != identity. */
  r: bigint;
  /** Plaintext amount. */
  amount: bigint;
  /** The sender's decrypted available balance, so w = balance - amount. */
  balance: bigint;
  pkS: Pt;
  pkR: Pt;
  /** The stored `available` ciphertext under pk_s. */
  avail: Ciphertext;
  /** C_t = a*G + r*H, D_s = r*pk_s, D_r = r*pk_r -- what the tx carries. */
  ct: { c: Pt; ds: Pt; dr: Pt };
  minTransfer: bigint;
  maxTransfer: bigint;
}

/**
 * Spend proof (§6). Every circuit relation is re-checked here first: a mismatch that would
 * make `nargo execute` fail after 3 s of proving is caught in microseconds instead.
 */
export function buildTransferWitness(a: TransferWitnessArgs): Witness {
  if (!mul(a.pkS, a.s).equals(H)) bad('s * pk_s != H');
  if (a.amount < a.minTransfer || a.amount > a.maxTransfer) {
    bad('amount outside [min_transfer, max_transfer]', { amount: String(a.amount) });
  }
  if (a.balance < a.amount) bad('balance does not cover the amount');
  const w = a.balance - a.amount;
  if (!add(mul(G, a.amount), mul(H, a.r)).equals(a.ct.c)) bad('ct_c != a*G + r*H');
  if (!mul(a.pkS, a.r).equals(a.ct.ds)) bad('ct_ds != r*pk_s');
  if (!mul(a.pkR, a.r).equals(a.ct.dr)) bad('ct_dr != r*pk_r');
  if (a.ct.ds.is0()) bad('ct_ds is the identity: r is zero mod n');
  if (!decryptToPoint(sub(a.avail.c, a.ct.c), sub(a.avail.d, a.ct.ds), a.s).equals(mul(G, w))) {
    bad('remainder is not w*G (stale available ciphertext?)');
  }
  return {
    ...scalarLimbs('s', a.s),
    ...scalarLimbs('r', a.r),
    a: u48('a', a.amount),
    w: u48('w', w),
    chain_id: field('chain_id', a.chainId),
    vault: addr(a.vault),
    sender: addr(a.sender),
    recipient: addr(a.recipient),
    sender_nonce: field('sender_nonce', a.senderNonce),
    pk_s: point(a.pkS),
    pk_r: point(a.pkR),
    avail_c: point(a.avail.c),
    avail_d: point(a.avail.d),
    ct_c: point(a.ct.c),
    ct_ds: point(a.ct.ds),
    ct_dr: point(a.ct.dr),
    min_transfer: field('min_transfer', a.minTransfer),
    max_transfer: field('max_transfer', a.maxTransfer),
  };
}

// --- dark_withdraw ---------------------------------------------------------------------------

export interface WithdrawWitnessArgs {
  chainId: number;
  vault: Hex;
  account: Hex;
  to: Hex;
  nonce: bigint;
  s: bigint;
  /** Public withdraw amount, 1 <= amount < 2^48. */
  amount: bigint;
  balance: bigint;
  pk: Pt;
  avail: Ciphertext;
}

/** Exit proof (§6). `to` is binding: the proof is only good for that recipient. */
export function buildWithdrawWitness(a: WithdrawWitnessArgs): Witness {
  if (!mul(a.pk, a.s).equals(H)) bad('s * pk != H');
  if (a.amount <= 0n) bad('withdraw amount is zero');
  if (a.balance < a.amount) bad('balance does not cover the amount');
  const w = a.balance - a.amount;
  if (!decryptToPoint(sub(a.avail.c, mul(G, a.amount)), a.avail.d, a.s).equals(mul(G, w))) {
    bad('remainder is not w*G (stale available ciphertext?)');
  }
  return {
    ...scalarLimbs('s', a.s),
    w: u48('w', w),
    chain_id: field('chain_id', a.chainId),
    vault: addr(a.vault),
    account: addr(a.account),
    to: addr(a.to),
    nonce: field('nonce', a.nonce),
    pk: point(a.pk),
    avail_c: point(a.avail.c),
    avail_d: point(a.avail.d),
    amount: u48('amount', a.amount),
  };
}

// --- dark_disclose_range ---------------------------------------------------------------------

export interface DiscloseRangeWitnessArgs {
  /** keccak256(abi.encode(...)) mod r, from `disclosureContextHash` (§7.7). */
  contextHash: bigint;
  s: bigint;
  /** The plaintext behind (c, d). */
  value: bigint;
  pk: Pt;
  /** May be a viewer-recomputed sum ciphertext, which is how flow totals reuse this circuit. */
  ciphertext: Ciphertext;
  lo: bigint;
  hi: bigint;
}

/** Range disclosure (§6), off-chain only. */
export function buildDiscloseRangeWitness(a: DiscloseRangeWitnessArgs): Witness {
  if (!mul(a.pk, a.s).equals(H)) bad('s * pk != H');
  if (a.lo > a.value || a.value > a.hi) bad('value outside [lo, hi]');
  if (!decryptToPoint(a.ciphertext.c, a.ciphertext.d, a.s).equals(mul(G, a.value))) {
    bad('c - s*d != v*G');
  }
  return {
    ...scalarLimbs('s', a.s),
    v: u48('v', a.value),
    context_hash: field('context_hash', a.contextHash),
    pk: point(a.pk),
    c: point(a.ciphertext.c),
    d: point(a.ciphertext.d),
    lo: u48('lo', a.lo),
    hi: u48('hi', a.hi),
  };
}

/**
 * Serialize a witness as a Noir prover file. Scalars and points first, because a `[table]`
 * header ends the top-level key/value section in TOML.
 */
export function witnessToToml(witness: Witness, header = '# Generated by @darkwalletrh/dark-sdk.'): string {
  let scalars = '';
  let tables = '';
  for (const [key, value] of Object.entries(witness)) {
    if (typeof value === 'string') scalars += `${key} = "${value}"\n`;
    else tables += `\n[${key}]\nx = "${value.x}"\ny = "${value.y}"\n`;
  }
  return `${header}\n${scalars}${tables}`;
}

/** The Noir package a circuit id belongs to, and its crate directory under `circuits/`. */
export const circuitCrate: Record<CircuitId, string> = {
  dark_register: 'register',
  dark_transfer: 'transfer',
  dark_withdraw: 'withdraw',
  dark_disclose_range: 'disclose_range',
};
