// LiveDarkClient against a scripted chain: the point is the SDK's own logic (§7 step 5
// decryption, §7 step 6 log paging, §13 state walk, the public-input re-derivation), not viem.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { LiveDarkClient, MULTICALL3, HARD_MAX_TRANSFER } from '../src/client.ts';
import { FixtureDarkProver, type DarkProver, type ProofResult } from '../src/prover.ts';
import { deriveDarkKeys } from '../src/keys.ts';
import { G, H, mul, encode, Point } from '../src/grumpkin.ts';
import { encrypt, hedgedScalar, contextBytes, TAG_TRANSFER_R, TAG_HINT_K } from '../src/elgamal.ts';
import { sealBalance, sealHint, sealSenderHint } from '../src/hint.ts';
import { deployments } from '../src/deployments.ts';
import { isDarkError } from '../src/errors.ts';

const CHAIN_ID = 46630;
const D = deployments[CHAIN_ID];
const SK = `0x${'11'.repeat(32)}` as const;
const OTHER_SK = `0x${'22'.repeat(32)}` as const;
const ACCOUNT = '0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A' as const;
const PEER = '0x000000000000000000000000000000000000cAFe' as const;
const keys = deriveDarkKeys(Uint8Array.from(Buffer.from(SK.slice(2), 'hex')), CHAIN_ID);
const peerKeys = deriveDarkKeys(Uint8Array.from(Buffer.from(OTHER_SK.slice(2), 'hex')), CHAIN_ID);

const BALANCE = 500_000000n;
const NONCE = 4n;
const HEAD = D.deployBlock + 5_000n;
const toHex = (b: Uint8Array) => `0x${Buffer.from(b).toString('hex')}` as const;

const CAPS = {
  minDeposit: 1_000000n, maxDeposit: 2_500_000000n, maxAccountInflow: 10_000_000000n,
  minTransfer: 10000n, maxTransfer: 2_500_000000n, tvlCap: 250_000_000000n,
};

const avail = (() => {
  const e = encrypt(BALANCE, [keys.P], 0x1234n);
  return { c: encode(e.C), d: encode(e.D[0]) };
})();

const aeCtx = { chainId: CHAIN_ID, vault: D.vault, account: ACCOUNT };

interface ChainOverrides {
  aeBalance?: `0x${string}`;
  pending?: { c: { x: bigint; y: bigint }; d: { x: bigint; y: bigint } };
  pendingCount?: bigint;
  registryKey?: { x: bigint; y: bigint } | null;
  peerRegistered?: boolean;
  logs?: Record<string, unknown[]>;
  tvl?: bigint;
  /** Throw a node-style range error whenever the requested span exceeds this. */
  maxSpan?: bigint;
  /** Make the first N multicalls answer like a replica that has not seen the block yet. */
  lagging?: number;
  /** Override the stored available ciphertext (encoded points). */
  available?: { c: { x: bigint; y: bigint }; d: { x: bigint; y: bigint } };
}

function fakeChain(over: ChainOverrides = {}) {
  const calls = { getLogs: 0, multicall: 0, write: 0 };
  const accountView = {
    available: over.available ?? avail,
    pending: over.pending ?? { c: { x: 0n, y: 0n }, d: { x: 0n, y: 0n } },
    nonce: NONCE,
    pendingCount: over.pendingCount ?? 0n,
    netInflow: BALANCE,
    aeBalance: over.aeBalance
      ?? toHex(sealBalance(keys.kAe, { value: BALANCE, nonceAfter: NONCE }, aeCtx)),
  };
  const key = over.registryKey === undefined ? keys.publicKey : over.registryKey;
  const pub = {
    async getBlockNumber() {
      return HEAD;
    },
    async multicall({ blockNumber }: { blockNumber: bigint }) {
      calls.multicall++;
      assert.equal(blockNumber, HEAD, 'reads must be pinned to one block');
      // The R3 drill: the public RPC returned -32602 for reads at a block one replica had not seen.
      // The assertion above doubles as "a retry stays on the same block".
      if (over.lagging && calls.multicall <= over.lagging) {
        return Array.from({ length: 5 }, () => ({ status: 'failure', error: new Error('Missing or invalid parameters') }));
      }
      return [
        { status: 'success', result: accountView },
        { status: 'success', result: CAPS },
        { status: 'success', result: over.tvl ?? 1_000_000000n },
        { status: 'success', result: false },
        key ? { status: 'success', result: key } : { status: 'failure' },
      ];
    },
    async readContract({ functionName, args }: { functionName: string; args: unknown[] }) {
      if (functionName === 'keyOf') {
        if ((args[0] as string).toLowerCase() === PEER.toLowerCase()) {
          if (over.peerRegistered === false) throw new Error('NotRegistered');
          return peerKeys.publicKey;
        }
        if (!key) throw new Error('NotRegistered');
        return key;
      }
      throw new Error(`unexpected readContract ${functionName}`);
    },
    async getLogs({ event, args, fromBlock, toBlock }: { event: { name: string }; args?: Record<string, string>; fromBlock: bigint; toBlock: bigint }) {
      calls.getLogs++;
      if (over.maxSpan !== undefined && toBlock - fromBlock > over.maxSpan) {
        throw new Error('query returned more than 10000 results');
      }
      // The node filters on the indexed topics; so must the fake, or `from` and `to` collide.
      return (over.logs?.[event.name] ?? []).filter((raw) => {
        const l = raw as { blockNumber: bigint; args: Record<string, string> };
        if (l.blockNumber < fromBlock || l.blockNumber > toBlock) return false;
        return Object.entries(args ?? {}).every(([k, v]) => String(l.args[k]).toLowerCase() === String(v).toLowerCase());
      });
    },
    async simulateContract(req: object) {
      return { request: req };
    },
    async waitForTransactionReceipt() {
      return { status: 'success' };
    },
  };
  const wallet = {
    account: { address: ACCOUNT },
    async writeContract(req: unknown) {
      calls.write++;
      lastWrite = req;
      return `0x${'ab'.repeat(32)}` as const;
    },
  };
  return { pub, wallet, calls };
}

let lastWrite: unknown;

const client = (over: ChainOverrides = {}, prover: DarkProver = new FixtureDarkProver(), events?: unknown[]) => {
  const f = fakeChain(over);
  return LiveDarkClient.create({
    chainId: CHAIN_ID,
    account: ACCOUNT,
    privateKey: SK,
    prover,
    publicClient: f.pub as never,
    walletClient: f.wallet as never,
    onAction: events ? (e) => events.push(e) : undefined,
  }).then((c) => ({ c, ...f }));
};

// --- deployment gating -------------------------------------------------------------------

test('an undeployed chain is NOT_DEPLOYED before anything else happens', async () => {
  await assert.rejects(
    LiveDarkClient.create({ chainId: 1, account: ACCOUNT, privateKey: SK, prover: new FixtureDarkProver() }),
    (e: unknown) => isDarkError(e) && e.code === 'NOT_DEPLOYED',
  );
});

// --- §7 step 0 sync ----------------------------------------------------------------------

test('sync reads everything at one block through Multicall3', async () => {
  const { c, calls } = await client();
  const s = await c.sync();
  assert.equal(calls.multicall, 1);
  assert.equal(s.block, HEAD);
  assert.equal(s.account.nonce, NONCE);
  assert.deepEqual(s.caps, CAPS);
  assert.deepEqual(s.registryKey, keys.publicKey);
  assert.equal(c.getStatus(), 'ready');
  assert.equal(MULTICALL3, '0xcA11bde05977b3631167028862bE2a173976CA11');
});

test('a registry key that is not the derived one is a terminal hard stop', async () => {
  const { c } = await client({ registryKey: peerKeys.publicKey });
  await assert.rejects(c.sync(), (e: Error & { code?: string }) => e.code === 'KEY_DERIVATION_MISMATCH');
});

test('no registry key means unregistered, not an outage', async () => {
  const { c } = await client({ registryKey: null });
  const s = await c.sync();
  assert.equal(s.registryKey, null);
  assert.equal(c.getStatus(), 'unregistered');
  await assert.rejects(c.withdraw(1n), (e: unknown) => isDarkError(e) && e.code === 'NOT_REGISTERED');
});

// --- §7 step 5 decryption ----------------------------------------------------------------

test('the aeBalance hint is used only after value*G == C - s*D checks out', async () => {
  const { c } = await client();
  assert.equal((await c.getBalances()).available, BALANCE);

  // A hint sealed with the right key but the wrong value must NOT be believed.
  const lying = toHex(sealBalance(keys.kAe, { value: 1n, nonceAfter: NONCE }, aeCtx));
  const { c: c2 } = await client({ aeBalance: lying });
  assert.equal((await c2.getBalances()).available, BALANCE, 'fell for a lying aeBalance');

  // Garbage and empty blobs both fall through to BSGS bounded by tvl() (§7 step 5 drill).
  for (const ae of ['0x', `0x${'ff'.repeat(56)}`] as const) {
    const { c: c3 } = await client({ aeBalance: ae });
    assert.equal((await c3.getBalances()).available, BALANCE);
  }
});

test('a replica that has not seen the block yet is retried at the same block', async () => {
  // Two lagging answers, then the real one: the read resolves, the balance is right, and exactly
  // one call was made per attempt — no extra reads, no different block (the fake asserts HEAD).
  const { c, calls } = await client({ lagging: 2 });
  assert.equal((await c.getBalances()).available, BALANCE);
  assert.equal(calls.multicall, 3, 'one initial read plus two retries');
});

test('the lag retry is bounded, and a caller-pinned block is never retried', async () => {
  const { c, calls } = await client({ lagging: 10 });
  await assert.rejects(c.getBalances(), (e: unknown) => isDarkError(e) && e.code === 'STALE_STATE');
  assert.equal(calls.multicall, 4, 'one initial read plus RPC_LAG_RETRIES = 3, then give up');

  // A block the caller chose is a fact, not a race: no retry at all.
  const pinned = await client({ lagging: 1 });
  await assert.rejects(pinned.c.sync(HEAD), (e: unknown) => isDarkError(e) && e.code === 'STALE_STATE');
  assert.equal(pinned.calls.multicall, 1, 'a pinned block is read once');
});

// §2 balancePublic, read off the ciphertext. The deposit-only case is (v·G, identity): anyone can BSGS it.
const ZERO_POINT = { x: 0n, y: 0n };
const depositOnly = { c: encode(mul(G, BALANCE)), d: ZERO_POINT };

test('a deposit-and-withdraw-only balance is public: anyone can compute it', async () => {
  const { c } = await client({ available: depositOnly, aeBalance: '0x' });
  const b = await c.getBalances();
  assert.equal(b.available, BALANCE);
  assert.equal(b.balancePublic, true);
});

test('a private send OUT makes the balance non-public', async () => {
  // Deposit 50, withdraw 20, send 10 privately: the remaining ciphertext is (20·G - C_t, -D_s), and
  // D_s = r·P carries the transfer's randomness, so nobody without s can compute it any more. The
  // old rule only counted a RECEIVED transfer and kept reporting this balance as public.
  const r = 0x5eedn;
  const sent = encrypt(10_000000n, [keys.P], r);
  const cAfter = mul(G, 30_000000n).subtract(sent.C);
  const dAfter = Point.ZERO.subtract(sent.D[0]);
  const { c } = await client({ available: { c: encode(cAfter), d: encode(dAfter) }, aeBalance: '0x', tvl: 100_000000n });
  const b = await c.getBalances();
  assert.equal(b.available, 20_000000n, 'the owner still decrypts it');
  assert.equal(b.balancePublic, false, 'a private send out is not a public balance');
});

test('balancePublic is sticky: withdrawing everything after a private inflow does not restore it', async () => {
  // Applied inflow, then withdrew to zero: C = 0·G + ρ·H, D = ρ·P — still randomised.
  const e = encrypt(0n, [keys.P], 0x77n);
  const { c } = await client({ available: { c: encode(e.C), d: encode(e.D[0]) }, aeBalance: '0x' });
  assert.equal((await c.getBalances()).balancePublic, false);
});

test('a deposit-only balance with a transfer still pending is not public', async () => {
  const pend = encrypt(5_000000n, [keys.P], 0x99n);
  const { c } = await client({
    available: depositOnly, aeBalance: '0x',
    pending: { c: encode(pend.C), d: encode(pend.D[0]) }, pendingCount: 0n,
  });
  assert.equal((await c.getBalances()).balancePublic, false, 'pending ciphertext is randomised');
});

test('BSGS is bounded by tvl(), never tvlCap, so a tightened vault still opens', async () => {
  // tvl below the real balance is an unsound vault; the client says so instead of hanging.
  const { c } = await client({ aeBalance: '0x', tvl: 1n });
  await assert.rejects(c.getBalances(), (e: unknown) => isDarkError(e) && e.code === 'DECRYPTION_FAILED');
});

// The timeout is the point: unclamped, this needs ~2^180 giant steps, so a reverted fix would
// HANG CI rather than fail it. Runs in ~5 s clamped, so 60 s is slack without being useless.
test('an absurd tvl from the RPC cannot hang balance decryption', { timeout: 60_000 }, async () => {
  // The clamp's own unit tests live in bsgs-bound.test.ts, but they exercise capBsgsBound() as a
  // pure function. This one goes through LiveDarkClient.sync(), so it fails if the CALL SITE is
  // reverted — which is the part of the fix that actually matters and was previously untested
  //: every existing tvl case sat below the ceiling, so dropping the wrapper changed nothing.
  //
  // Unclamped, the final BSGS pass would need ~2^236 giant steps and this test would never finish.
  // A timeout is the assertion: it has to resolve, and the value has to still be right.
  const { c } = await client({ aeBalance: '0x', tvl: (1n << 200n) });
  const balances = await c.getBalances();
  assert.equal(balances.available, BALANCE, 'clamping must not cost correctness');
});

test('pending is the sum of verified hints since the last PendingApplied', async () => {
  const AMOUNT = 25_000000n;
  const tctx = { chainId: CHAIN_ID, vault: D.vault, from: PEER, to: ACCOUNT, fromNonce: 9n };
  const ctxb = contextBytes(tctx);
  const r = hedgedScalar(TAG_TRANSFER_R, peerKeys.s, ctxb);
  const k = hedgedScalar(TAG_HINT_K, peerKeys.s, ctxb);
  const e = encrypt(AMOUNT, [peerKeys.P, keys.P], r);
  const pending = { c: encode(e.C), d: encode(e.D[1]) };
  const log = {
    blockNumber: D.deployBlock + 10n,
    logIndex: 0,
    transactionHash: `0x${'11'.repeat(32)}`,
    args: {
      from: PEER, to: ACCOUNT, fromNonceAfter: 10n,
      transferCt: [pending.c.x, pending.c.y, 0n, 0n, pending.d.x, pending.d.y],
      hint: toHex(sealHint(k, keys.P, tctx, AMOUNT)),
      senderHint: toHex(sealSenderHint(peerKeys.kAe, tctx, AMOUNT)),
    },
  };
  const { c } = await client({
    pending, pendingCount: 1n, logs: { ConfidentialTransfer: [log], PendingApplied: [] },
  });
  const b = await c.getBalances();
  assert.equal(b.pending, AMOUNT);
  assert.equal(b.pendingCount, 1);
  assert.equal(b.balancePublic, false, 'a received private transfer is not a public balance');

  // A lying sender: the hint decrypts but disagrees with the ciphertext, so BSGS recovers it.
  const lying = { ...log, args: { ...log.args, hint: toHex(sealHint(k, keys.P, tctx, AMOUNT + 1n)) } };
  const { c: c2 } = await client({
    pending, pendingCount: 1n, logs: { ConfidentialTransfer: [lying], PendingApplied: [] },
  });
  assert.equal((await c2.getBalances()).pending, AMOUNT);
});

// --- §7 step 6 history -------------------------------------------------------------------

test('getLogs halves its range on the 10,000-log cap instead of giving up', async () => {
  const { c, calls } = await client({ maxSpan: 1_000n, logs: {} });
  await c.history();
  // 5 topic filters over a 5,000-block span, each halved until every chunk is <= 1,000 blocks.
  assert.ok(calls.getLogs > 5, `only ${calls.getLogs} getLogs calls: no halving happened`);
  assert.ok(calls.getLogs < 200, `${calls.getLogs} getLogs calls: halving did not converge`);
});

test('a range error that is not about the range is not retried forever', async () => {
  const { pub, wallet } = fakeChain();
  pub.getLogs = async () => {
    throw new Error('connection refused');
  };
  const c = await LiveDarkClient.create({
    chainId: CHAIN_ID, account: ACCOUNT, privateKey: SK, prover: new FixtureDarkProver(),
    publicClient: pub as never, walletClient: wallet as never,
  });
  await assert.rejects(c.history(), /connection refused/);
});

test('history merges by (block, logIndex), reads sent amounts from senderHint, and fills applies', async () => {
  const SENT = 7_000000n;
  const tctx = { chainId: CHAIN_ID, vault: D.vault, from: ACCOUNT, to: PEER, fromNonce: 2n };
  const inCtx = { chainId: CHAIN_ID, vault: D.vault, from: PEER, to: ACCOUNT, fromNonce: 5n };
  const inR = hedgedScalar(TAG_TRANSFER_R, peerKeys.s, contextBytes(inCtx));
  const inK = hedgedScalar(TAG_HINT_K, peerKeys.s, contextBytes(inCtx));
  const RECEIVED = 3_000000n;
  const inE = encrypt(RECEIVED, [peerKeys.P, keys.P], inR);
  const [inC, inDr] = [encode(inE.C), encode(inE.D[1])];

  const { c } = await client({
    logs: {
      Deposited: [{ blockNumber: D.deployBlock + 1n, logIndex: 0, transactionHash: `0x${'01'.repeat(32)}`, args: { account: ACCOUNT, amount: 100_000000n } }],
      ConfidentialTransfer: [
        {
          blockNumber: D.deployBlock + 2n, logIndex: 1, transactionHash: `0x${'02'.repeat(32)}`,
          args: { from: ACCOUNT, to: PEER, fromNonceAfter: 3n, senderHint: toHex(sealSenderHint(keys.kAe, tctx, SENT)), transferCt: [0n, 0n, 0n, 0n, 0n, 0n], hint: '0x' },
        },
        {
          blockNumber: D.deployBlock + 3n, logIndex: 0, transactionHash: `0x${'03'.repeat(32)}`,
          args: {
            from: PEER, to: ACCOUNT, fromNonceAfter: 6n,
            transferCt: [inC.x, inC.y, 0n, 0n, inDr.x, inDr.y],
            hint: toHex(sealHint(inK, keys.P, inCtx, RECEIVED)), senderHint: '0x',
          },
        },
      ],
      PendingApplied: [{ blockNumber: D.deployBlock + 4n, logIndex: 0, transactionHash: `0x${'04'.repeat(32)}`, args: { account: ACCOUNT } }],
      Withdrawn: [{ blockNumber: D.deployBlock + 5n, logIndex: 0, transactionHash: `0x${'05'.repeat(32)}`, args: { account: ACCOUNT, amount: 9_000000n, to: PEER } }],
    },
  });
  const h = await c.history();
  assert.deepEqual(h.map((e) => e.kind), ['deposit', 'transfer_out', 'transfer_in', 'apply_pending', 'withdraw']);
  assert.equal(h[0].amount, 100_000000n);
  assert.equal(h[0].amountPublic, true);
  assert.equal(h[1].amount, SENT, 'sent amount must come from senderHint');
  assert.equal(h[1].amountPublic, false);
  assert.equal(h[2].amount, RECEIVED);
  assert.equal(h[3].amount, RECEIVED, 'apply_pending moves exactly what arrived since the last one');
  assert.equal(h[4].amount, 9_000000n);
  assert.equal(h[4].counterparty, PEER);
});

// --- §13 owner actions -------------------------------------------------------------------

test('withdraw walks building -> proving -> simulating -> submitted -> final', async () => {
  const events: { kind: string; state: string }[] = [];
  const { c, calls } = await client({}, new FixtureDarkProver(), events);
  const tx = await c.withdraw(10_000000n, PEER);
  assert.equal(calls.write, 1);
  assert.match(tx, /^0x[0-9a-f]{64}$/);
  const states = events.filter((e) => e.kind === 'withdraw').map((e) => e.state);
  assert.deepEqual(
    states.filter((s, i) => states.indexOf(s) === i),
    ['building', 'proving', 'simulating', 'submitted', 'soft_confirmed', 'final'],
  );
  // The proof and the aeBalance actually reach the vault call.
  const args = (lastWrite as { args: unknown[] }).args;
  assert.equal(args[0], 10_000000n);
  assert.equal(args[1], PEER);
  assert.equal((args[3] as string).length, 2 + 56 * 2, 'aeBalance must be 56 bytes');
});

test('a prover that returns different public inputs is rejected, proof unused', async () => {
  const liar: DarkProver = {
    isAvailable: async () => true,
    async prove(): Promise<ProofResult> {
      return { proof: new Uint8Array(8), publicInputs: [`0x${'00'.repeat(32)}`], ms: 1 };
    },
  };
  const { c, calls } = await client({}, liar);
  await assert.rejects(
    c.withdraw(1_000000n, PEER),
    (e: unknown) => isDarkError(e) && e.code === 'PUBLIC_INPUT_MISMATCH',
  );
  assert.equal(calls.write, 0, 'a rejected proof must never be sent');
});

test('the caps, balance and recipient checks all fire before any proving', async () => {
  const { c, calls } = await client();
  await assert.rejects(c.deposit(1n), (e: unknown) => isDarkError(e) && e.code === 'CAP_EXCEEDED');
  await assert.rejects(c.deposit(3_000_000000n), (e: unknown) => isDarkError(e) && e.code === 'CAP_EXCEEDED');
  await assert.rejects(c.withdraw(BALANCE + 1n), (e: unknown) => isDarkError(e) && e.code === 'INSUFFICIENT_BALANCE');
  await assert.rejects(c.withdraw(0n), (e: unknown) => isDarkError(e) && e.code === 'AMOUNT_OUT_OF_RANGE');
  await assert.rejects(c.withdraw(1n, D.vault), (e: unknown) => isDarkError(e) && e.code === 'AMOUNT_OUT_OF_RANGE');
  await assert.rejects(c.transfer(ACCOUNT, 1_000000n), (e: unknown) => isDarkError(e) && /self-transfer/.test(e.message));
  await assert.rejects(c.applyPending(), (e: unknown) => isDarkError(e) && e.code === 'STALE_STATE');
  assert.equal(calls.write, 0);
});

test('a transfer to an unregistered address never silently falls back to a public one', async () => {
  const { c, calls } = await client({ peerRegistered: false });
  await assert.rejects(
    c.transfer(PEER, 1_000000n),
    (e: unknown) => isDarkError(e) && e.code === 'RECIPIENT_NOT_REGISTERED',
  );
  assert.equal(calls.write, 0);
});

test('a private transfer sends the ciphertext, both hints and the new aeBalance', async () => {
  const { c } = await client();
  await c.transfer(PEER, 1_000000n, 'lunch');
  const args = (lastWrite as { args: unknown[] }).args;
  assert.equal(args[0], PEER);
  const ct = args[1] as { c: { x: bigint }; dSender: { x: bigint }; dRecipient: { x: bigint } };
  for (const p of [ct.c, ct.dSender, ct.dRecipient]) assert.notEqual(p.x, 0n);
  assert.equal((args[3] as string).length, 2 + 240 * 2, 'hint must be 240 bytes');
  assert.equal((args[4] as string).length, 2 + 176 * 2, 'senderHint must be 176 bytes');
  assert.equal((args[5] as string).length, 2 + 56 * 2, 'aeBalance must be 56 bytes');
});

test('deposit approves the exact amount before depositing', async () => {
  const seen: unknown[][] = [];
  const f = fakeChain();
  f.wallet.writeContract = async (req: unknown) => {
    seen.push([(req as { functionName: string }).functionName, (req as { args: unknown[] }).args]);
    return `0x${'cd'.repeat(32)}` as const;
  };
  const c = await LiveDarkClient.create({
    chainId: CHAIN_ID, account: ACCOUNT, privateKey: SK, prover: new FixtureDarkProver(),
    publicClient: f.pub as never, walletClient: f.wallet as never,
  });
  await c.deposit(50_000000n);
  assert.deepEqual(seen[0], ['approve', [D.vault, 50_000000n]]);
  assert.equal(seen[1][0], 'deposit');
  assert.equal((seen[1][1] as unknown[])[0], 50_000000n);
});

test('registering proves dark_register and passes the derived key to the registry', async () => {
  const { c } = await client({ registryKey: null });
  await c.register();
  const w = lastWrite as { functionName: string; args: unknown[] };
  assert.equal(w.functionName, 'register');
  assert.deepEqual(w.args[0], keys.publicKey);
  assert.ok(mul(keys.P, keys.s).equals(H));
});

test('the constants the fallbacks lean on are the §5 ceilings', () => {
  assert.equal(HARD_MAX_TRANSFER, 2_500_000_000n);
  assert.ok(mul(G, 0n).equals(Point.ZERO));
});
