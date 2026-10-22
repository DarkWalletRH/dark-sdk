import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DarkClient, LiveDarkClient, DarkError, isRangeError, isRateLimited, type ActionEvent, type Hex } from '../src/index.ts';

const ALICE = `0x${'aa'.repeat(20)}` as Hex;
const BOB = `0x${'bb'.repeat(20)}` as Hex;

function newClient(events: ActionEvent[] = [], initialAvailable = 0n) {
  return new DarkClient({
    mode: 'fixture',
    chainId: 46630,
    account: ALICE,
    privateKey: `0x${'05'.repeat(32)}` as Hex,
    initialAvailable,
    onAction: (e) => events.push(e),
  });
}

test('register walks the 7.3 states and flips status to ready', async () => {
  const events: ActionEvent[] = [];
  const c = newClient(events);
  assert.equal(c.isRegistered(), false);
  await c.register();
  assert.equal(c.isRegistered(), true);
  assert.equal(c.getStatus(), 'ready');
  const states = events.filter((e) => e.state !== 'proving').map((e) => e.state);
  assert.deepEqual(states, ['building', 'simulating', 'submitted', 'soft_confirmed', 'final']);
  assert.ok(events.some((e) => e.state === 'proving' && e.progress === 1));
});

test('deposit then getBalances decrypts through the verified aeBalance hint', async () => {
  const c = newClient();
  await c.register();
  await c.deposit(25_000_000n);
  const b = await c.getBalances();
  assert.equal(b.available, 25_000_000n);
  assert.equal(b.nonce, 1n);
  assert.equal(b.balancePublic, true);
});

test('deposit enforces the caps', async () => {
  const c = newClient();
  await c.register();
  await assert.rejects(c.deposit(1n), (e: Error & { code?: string }) => e.code === 'CAP_EXCEEDED');
  await assert.rejects(c.deposit(3_000_000_000n), (e: Error & { code?: string }) => e.code === 'CAP_EXCEEDED');
});

test('actions before register throw NOT_REGISTERED', async () => {
  const c = newClient();
  await assert.rejects(c.deposit(2_000_000n), (e: Error & { code?: string }) => e.code === 'NOT_REGISTERED');
});

test('transfer needs a registered recipient and enough balance', async () => {
  const c = newClient([], 0n);
  await c.register();
  await c.deposit(50_000_000n);
  // An unknown recipient is still unregistered: the fixture keeps its own registry so this state,
  // which real screens must handle, stays testable without a chain.
  await assert.rejects(
    c.transfer(BOB, 1_000_000n),
    (e: Error & { code?: string }) => e.code === 'RECIPIENT_NOT_REGISTERED',
  );
  c.registerFixtureAccount(BOB);
  await assert.rejects(
    c.transfer(BOB, 999_000_000n),
    (e: Error & { code?: string }) => e.code === 'INSUFFICIENT_BALANCE',
  );
  await assert.rejects(
    c.transfer(ALICE, 1_000_000n),
    (e: Error & { code?: string }) => e.code === 'AMOUNT_OUT_OF_RANGE',
  );

  await c.transfer(BOB, 1_000_000n, 'lunch');
  assert.equal((await c.getBalances()).available, 49_000_000n);
  const h = await c.history();
  assert.equal(h.at(-1)?.kind, 'transfer_out');
  assert.equal(h.at(-1)?.amountPublic, false);
});

test('a private send OUT clears balancePublic in fixture mode too', async () => {
  const c = newClient();
  await c.register();
  await c.deposit(50_000_000n);
  await c.withdraw(20_000_000n);
  assert.equal((await c.getBalances()).balancePublic, true, 'deposit + withdraw only: still public');
  c.registerFixtureAccount('0x00000000000000000000000000000000000000b0');
  await c.transfer('0x00000000000000000000000000000000000000b0', 10_000_000n);
  assert.equal((await c.getBalances()).balancePublic, false, 'a private send out is not public');
});

test('an inbound transfer lands in pending, clears balancePublic, and applies', async () => {
  const bob = newClient();
  await bob.register();
  await bob.deposit(10_000_000n);
  bob.receiveFixtureTransfer(ALICE, 3_000_000n);

  let b = await bob.getBalances();
  assert.equal(b.pending, 3_000_000n);
  assert.equal(b.pendingCount, 1);
  assert.equal(b.balancePublic, false);

  await bob.applyPending();
  b = await bob.getBalances();
  assert.equal(b.available, 13_000_000n);
  assert.equal(b.pending, 0n);
  await assert.rejects(bob.applyPending(), (e: Error & { code?: string }) => e.code === 'STALE_STATE');
});

test('withdraw reduces the balance and is labelled public', async () => {
  const c = newClient();
  await c.register();
  await c.deposit(20_000_000n);
  await c.withdraw(5_000_000n, BOB);
  assert.equal((await c.getBalances()).available, 15_000_000n);
  assert.equal((await c.history()).at(-1)?.amountPublic, true);
  await assert.rejects(c.withdraw(99_000_000n), (e: Error & { code?: string }) => e.code === 'INSUFFICIENT_BALANCE');
});

test('disclosures are created, listed and revoked; testnet ids are t_-prefixed', async () => {
  const c = newClient();
  const d = await c.createDisclosure('balance_exact', 'payroll proof');
  assert.ok(d.id.startsWith('t_'));
  assert.ok(d.url.includes('#k='));
  await c.revokeDisclosure(d.id);
  assert.equal((await c.listDisclosures())[0].revoked, true);
  await assert.rejects(c.revokeDisclosure('nope'), (e: Error & { code?: string }) => e.code === 'STALE_STATE');
  await assert.rejects(c.createDisclosure('balance_exact', 'x'.repeat(65)));
  await assert.rejects(c.createDisclosure('balance_exact', 'ok', 400));
});

test('live mode is NOT_IMPLEMENTED', async () => {
  const c = new DarkClient({ mode: 'live', chainId: 46630, account: ALICE });
  await assert.rejects(c.getBalances(), (e: Error & { code?: string }) => e.code === 'NOT_IMPLEMENTED');
});

test('betaNotice comes from deployments', () => {
  assert.equal(newClient().betaNotice, 'pre_audit');
});

test('a live client without an account secret refuses to exist', async () => {
  // Omitting `privateKey` used to derive s and k_ae from a constant, so every such account shared one
  // publicly derivable key: anyone could open their hints and aeBalance and read their balances, and
  // register() would publish the shared key on chain. A walletClient replaces signing, never this.
  const opts = {
    chainId: 46630,
    account: `0x${'ab'.repeat(20)}`,
    prover: { isAvailable: () => false, prove: async () => ({ proof: '0x', publicInputs: [], ms: 0 }) },
  } as never;

  assert.throws(
    () => new LiveDarkClient(opts),
    (e: DarkError) => e.code === 'MISSING_ACCOUNT_SECRET',
    'a live client with no secret must fail loudly rather than share a public key',
  );

  // The fixture client keeps its deterministic fallback — that is what fixtures are for.
  const fixture = new DarkClient({ chainId: 46630, account: `0x${'ab'.repeat(20)}` } as never);
  assert.ok(fixture.publicKey.x !== 0n);
});

// --- Log paging must not attack an endpoint that is already refusing -------------------

/** A LiveDarkClient with its RPC replaced, so the paging logic can be driven without a network. */
function clientWithFakeRpc(getLogs: (p: { fromBlock: bigint; toBlock: bigint }) => Promise<unknown[]>) {
  const c = new LiveDarkClient({
    chainId: 46630,
    account: `0x${'ab'.repeat(20)}`,
    privateKey: `0x${'11'.repeat(32)}`,
    prover: { isAvailable: () => false, prove: async () => ({ proof: '0x', publicInputs: [], ms: 0 }) },
  } as never);
  (c as unknown as { pub: unknown }).pub = { getLogs };
  return c as unknown as { getLogsChunked(p: object, from: bigint, to: bigint): Promise<unknown[]> };
}

test('a size refusal splits the range one request at a time', async () => {
  let inFlight = 0;
  let peak = 0;
  const seen: Array<[bigint, bigint]> = [];

  const c = clientWithFakeRpc(async ({ fromBlock, toBlock }) => {
    inFlight++;
    peak = Math.max(peak, inFlight);
    try {
      await new Promise((r) => setTimeout(r, 1));
      seen.push([fromBlock, toBlock]);
      // Anything wider than 100 blocks is refused for size, as a capped endpoint would.
      if (toBlock - fromBlock > 100n) throw new Error('query returned more than 10000 results');
      return [{ blockNumber: fromBlock }];
    } finally {
      inFlight--;
    }
  });

  const logs = await c.getLogsChunked({}, 0n, 1_000n);
  assert.equal(peak, 1, 'the halves must be walked sequentially, never fanned out concurrently');
  assert.ok(logs.length > 0, 'the split ranges still return their logs');

  // Every range that actually succeeded is within the endpoint's limit, and together they cover the
  // whole span with no gap — a split that dropped blocks would lose transfers from history.
  const ok = seen.filter(([f, t]) => t - f <= 100n).sort((a, b) => Number(a[0] - b[0]));
  assert.equal(ok[0]![0], 0n);
  assert.equal(ok.at(-1)![1], 1_000n);
  for (let i = 1; i < ok.length; i++) assert.equal(ok[i]![0], ok[i - 1]![1] + 1n, 'ranges must be contiguous');
});

test('a rate limit waits instead of splitting, then gives up honestly', async () => {
  const ranges: Array<[bigint, bigint]> = [];
  const c = clientWithFakeRpc(async ({ fromBlock, toBlock }) => {
    ranges.push([fromBlock, toBlock]);
    throw new Error('HTTP 429 Too Many Requests');
  });

  await assert.rejects(
    () => c.getLogsChunked({}, 0n, 1_000n),
    (e: DarkError) => e.code === 'STALE_STATE' && /rate limiting/.test(e.message),
  );
  // Crucially: every attempt asked for the SAME range. Halving cannot fix a rate limit, and the old
  // code both halved and doubled its concurrency because a 429 body matches the size pattern.
  assert.ok(ranges.length >= 2, 'it retries');
  for (const [f, t] of ranges) {
    assert.equal(f, 0n);
    assert.equal(t, 1_000n);
  }
});

test('the two refusal kinds are told apart', () => {
  assert.equal(isRateLimited(new Error('HTTP 429 Too Many Requests')), true);
  assert.equal(isRateLimited(new Error('rate limit exceeded')), true);
  assert.equal(isRateLimited(new Error('query returned more than 10000 results')), false);
  // "too many results" is a size refusal even though it contains "too many".
  assert.equal(isRangeError(new Error('query returned more than 10000 results')), true);
  assert.equal(isRangeError(new Error('execution reverted')), false);
});

test('both clients satisfy the surface useDark depends on', async () => {
  // A screen is written against DarkSurface. If the fixture grows a method the live client lacks,
  // every screen built against the fixture breaks the first time it meets the chain — which is
  // exactly the failure a fixture is supposed to prevent. This asserts the two stay interchangeable.
  const SURFACE = [
    'getStatus', 'caps', 'getBalances', 'history', 'isRegistered', 'listDisclosures',
    'register', 'deposit', 'applyPending', 'transfer', 'withdraw',
    'createDisclosure', 'revokeDisclosure',
  ] as const;

  for (const name of SURFACE) {
    assert.equal(typeof (DarkClient.prototype as never as Record<string, unknown>)[name], 'function', `fixture is missing ${name}`);
    assert.equal(typeof (LiveDarkClient.prototype as never as Record<string, unknown>)[name], 'function', `live client is missing ${name}`);
  }

  // `betaNotice` and `prover` are properties rather than methods, so they are checked on an instance.
  const fixture = new DarkClient({ chainId: 46630, account: `0x${'ab'.repeat(20)}` } as never);
  assert.equal(typeof fixture.betaNotice, 'string');
  assert.equal(typeof fixture.prover.isAvailable, 'function');
});

test('the live client refuses disclosures it has nowhere to store', async () => {
  const c = new LiveDarkClient({
    chainId: 46630,
    account: `0x${'ab'.repeat(20)}`,
    privateKey: `0x${'22'.repeat(32)}`,
    prover: { isAvailable: () => false, prove: async () => ({ proof: new Uint8Array(), publicInputs: [], ms: 0 }) },
  } as never);

  // No `api`: storing a blob somewhere undefined would be worse than saying so.
  await assert.rejects(() => c.listDisclosures(), (e: DarkError) => e.code === 'NOT_IMPLEMENTED');

  // With an api but no session, the failure names the real cause rather than surfacing a 401.
  const withApi = new LiveDarkClient({
    chainId: 46630,
    account: `0x${'ab'.repeat(20)}`,
    privateKey: `0x${'22'.repeat(32)}`,
    prover: { isAvailable: () => false, prove: async () => ({ proof: new Uint8Array(), publicInputs: [], ms: 0 }) },
    api: { baseUrl: 'https://example.invalid', token: () => null },
  } as never);
  await assert.rejects(
    () => withApi.listDisclosures(),
    (e: DarkError) => e.code === 'NOT_IMPLEMENTED' && /sign in/.test(e.message),
  );
});

// revoke tokens lived only in memory, so an app restart lost them and the
// user could never revoke a link they had shared. export/import lets the app keep them in its vault.
function liveForRevoke() {
  return new LiveDarkClient({
    chainId: 46630,
    account: `0x${'ab'.repeat(20)}`,
    privateKey: `0x${'22'.repeat(32)}`,
    prover: { isAvailable: () => false, prove: async () => ({ proof: new Uint8Array(), publicInputs: [], ms: 0 }) },
    api: { baseUrl: 'https://example.invalid', token: () => null },
  } as never);
}
const RT_ID = 't_AAAAAAAAAAAAAAAA';
const RT_TOKEN = `0x${'cd'.repeat(32)}`;

test('a revoke token restored after a restart still revokes the link', async () => {
  const before = liveForRevoke();
  before.importRevokeTokens({ [RT_ID]: RT_TOKEN });
  const saved = before.exportRevokeTokens();
  assert.deepEqual(saved, { [RT_ID]: RT_TOKEN });

  // A fresh client — as after the app restarts — restored from what was saved.
  const after = liveForRevoke();
  after.importRevokeTokens(saved);
  const seen: { url: string; headers: Record<string, string> }[] = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (url: string, init: { headers: Record<string, string> }) => {
    seen.push({ url, headers: init.headers });
    return new Response(null, { status: 204 });
  }) as never;
  try {
    // No session token: the revoke has to work on the restored token alone, which is the point.
    await after.revokeDisclosure(RT_ID);
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(seen.length, 1);
  assert.match(seen[0]!.url, new RegExp(`/v1/disclosures/${RT_ID}$`));
  assert.equal(seen[0]!.headers['x-revoke-token'], RT_TOKEN);
  assert.equal(seen[0]!.headers.authorization, undefined, 'revoking by token needs no session');
  assert.deepEqual(after.exportRevokeTokens(), {}, 'a revoked link drops its token');
});

test('importRevokeTokens is all-or-nothing and never echoes a token', () => {
  const c = liveForRevoke();
  assert.throws(() => c.importRevokeTokens({ [RT_ID]: RT_TOKEN, 'not-an-id': RT_TOKEN }), TypeError);
  assert.deepEqual(c.exportRevokeTokens(), {}, 'the valid entry must not have been applied');

  const secret = `0x${'ef'.repeat(31)}`; // 31 bytes: wrong length
  assert.throws(
    () => c.importRevokeTokens({ [RT_ID]: secret }),
    (e: Error) => e instanceof TypeError && !e.message.includes('efef'),
    'the error names the id, never the token',
  );
  // Tokens are normalised to lowercase, which is what the API hashes.
  c.importRevokeTokens({ [RT_ID]: RT_TOKEN.toUpperCase().replace('0X', '0x') });
  assert.equal(c.exportRevokeTokens()[RT_ID], RT_TOKEN);
});

test('the revoke-token hash matches what the API stores', async () => {
  // The token is hashed as hex TEXT, as the API stores it, not as the decoded bytes: a digest that
  // disagrees with the server's leaves a link live with no way to take it down.
  const { createHash } = await import('node:crypto');
  const token = 'ab'.repeat(32);

  const server = createHash('sha256').update(token).digest('hex');
  const { sha256 } = await import('@noble/hashes/sha2');
  const { bytesToHex, utf8ToBytes } = await import('@noble/hashes/utils');
  const sdk = bytesToHex(sha256(utf8ToBytes(token)));

  assert.equal(sdk, server, 'the SDK and the API must hash the same bytes');
  // And explicitly NOT the decoded form, which is what the bug did.
  const decoded = bytesToHex(sha256(Uint8Array.from({ length: 32 }, () => 0xab)));
  assert.notEqual(sdk, decoded);
});

test('a live client refuses a secret that belongs to another account', async () => {
  // `account` and `privateKey` can be updated in separate renders, so a client could be built with
  // A's key for B's address. That surfaces later as the terminal key-mismatch stop, after the user
  // has already acted.
  await assert.rejects(
    () => LiveDarkClient.create({
      chainId: 46630,
      account: `0x${'ab'.repeat(20)}`,
      privateKey: `0x${'33'.repeat(32)}`,
      prover: { isAvailable: () => false, prove: async () => ({ proof: new Uint8Array(), publicInputs: [], ms: 0 }) },
    } as never),
    (e: DarkError) => e.code === 'KEY_DERIVATION_MISMATCH',
  );

  // The all-zero key is not "absent", so the required-secret check alone would let it through.
  await assert.rejects(
    () => LiveDarkClient.create({
      chainId: 46630,
      account: `0x${'ab'.repeat(20)}`,
      privateKey: `0x${'00'.repeat(32)}`,
      prover: { isAvailable: () => false, prove: async () => ({ proof: new Uint8Array(), publicInputs: [], ms: 0 }) },
    } as never),
    (e: Error) => e instanceof Error,
  );
});

// --- flow disclosures: the total of a set of payments, proved once ---------------------------------

const flow = await import('./flow-world.ts');
const dsc = await import('../src/disclosure.ts');
const { buildPublicInputs } = await import('../src/publicInputs.ts');
const { ALICE: A, BOB: B, CAROL: C, B0, payment, flowClient } = flow;

const toBob = [payment(A, B, 1_250_000n, B0 + 10n), payment(A, B, 3_000_000n, B0 + 20n), payment(A, B, 750_000n, B0 + 30n)];
const world = [...toBob, payment(A, C, 9_000_000n, B0 + 25n), payment(B, A, 2_000_000n, B0 + 40n)];
const B_TOTAL = 5_000_000n;
const corrupt = (l: flow.PaymentLog) => ({ ...l, args: { ...l.args, senderHint: `0x${'ee'.repeat(176)}` as Hex } });
const range = { fromBlock: 0n, toBlock: B0 + 100n };

test('flowTotal sums one direction and counterparty, clamps to the deployment, and reads caps once', async () => {
  // One hint that will not open: BSGS under the hard cap recovers it, without another caps scan.
  const { client, seen } = flowClient(A, [corrupt(world[0]!), ...world.slice(1)]);
  const f = await client.flowTotal({ direction: 'out', counterparty: B.address, ...range });
  assert.equal(f.count, 3);
  assert.equal(f.total, B_TOTAL);
  assert.equal(f.fromBlock, B0);
  assert.equal(seen.transfers[0]!.fromBlock, B0, 'the relay refuses a fromBlock before the deployment');
  assert.equal(seen.caps, 1);
  assert.deepEqual({ c: f.c, d: f.d }, dsc.sumFlow(toBob.map((l) => l.args.transferCt), 'out'));

  assert.equal((await client.flowTotal({ direction: 'out', ...range })).total, B_TOTAL + 9_000_000n, 'anyone');
  assert.equal((await client.flowTotal({ direction: 'in', ...range })).total, 2_000_000n);
  assert.equal((await client.flowTotal({ direction: 'in', counterparty: C.address, ...range })).count, 0);
  await assert.rejects(client.flowTotal({ direction: 'out', fromBlock: B0, toBlock: flow.HEAD + 1n }), (e: DarkError) => e.code === 'AMOUNT_OUT_OF_RANGE');
  await assert.rejects(client.flowTotal({ direction: 'out', fromBlock: B0 + 5n, toBlock: B0 + 4n }), (e: DarkError) => e.code === 'AMOUNT_OUT_OF_RANGE');
});

test('flowTotal fails closed when an amount will not open', async () => {
  // A cap of 1 makes the BSGS fallback fail, as it would for a garbage hint above the real cap.
  const caps = [{ blockNumber: B0, args: { newCaps: { maxTransfer: 1n } } }];
  const { client, seen } = flowClient(A, [corrupt(toBob[0]!), corrupt(toBob[1]!), toBob[2]!], { caps });
  await assert.rejects(client.flowTotal({ direction: 'out', ...range }), (e: DarkError) => e.code === 'DECRYPTION_FAILED');
  assert.equal(seen.caps, 1, 'CapsUpdated is read once for the whole set, not once per bad hint');
});

const openPosted = (seen: { posted: { id: string; blob: string }[] }, url: string) => {
  const { id, key } = dsc.parseDisclosureLink(url);
  return dsc.openDisclosure(dsc.fromBase64url(seen.posted[0]!.blob), key, id)!;
};

test('createFlowDisclosure: an exact total, stored only after it verifies here', async () => {
  const { client, seen } = flowClient(A, world);
  const made = await client.createFlowDisclosure({
    direction: 'out', counterparty: B.address, ...range, claim: { exact: true }, label: 'Sent to @bob', ttlDays: 7,
  });
  assert.equal(made.kind, 'flow_total_exact');
  assert.equal(seen.posted.length, 1);
  const doc = openPosted(seen, made.url);
  assert.deepEqual(doc.claim, { value: String(B_TOTAL) });
  assert.deepEqual(doc.blockRange, [String(B0), String(B0 + 100n)]);
  assert.equal(doc.direction, 'out');
  assert.equal(doc.counterparty, B.address);
  // The viewer's check, from the logs alone.
  const onChain = dsc.sumFlow(toBob.map((l) => l.args.transferCt), 'out');
  assert.equal((await dsc.verifyDisclosure({ doc, onChain, registryKey: A.keys.publicKey })).verdict, 'verified');
  assert.equal((await dsc.verifyDisclosure({ doc, onChain: dsc.sumFlow(toBob.slice(1).map((l) => l.args.transferCt), 'out'), registryKey: A.keys.publicKey })).verdict, 'invalid');
});

test('createFlowDisclosure: "at least" goes through the range prover with the context-bound inputs', async () => {
  const progress: number[] = [];
  const prover = {
    isAvailable: async () => true,
    prove: async (circuit: 'dark_disclose_range', w: never, on?: (f: number) => void) => {
      on?.(0.5);
      return { proof: new Uint8Array([1, 2, 3]), publicInputs: buildPublicInputs(circuit, w), ms: 1 };
    },
  };
  const { client, seen } = flowClient(B, world, { prover: prover as never });
  const made = await client.createFlowDisclosure(
    { direction: 'in', counterparty: A.address, ...range, claim: { lo: 4_000_000n }, label: 'from alice', ttlDays: 1 },
    (f) => progress.push(f),
  );
  assert.equal(made.kind, 'flow_total_range');
  assert.deepEqual(progress, [0.5]);
  const doc = openPosted(seen, made.url);
  assert.deepEqual(doc.claim, { lo: '4000000', hi: String(dsc.RANGE_MAX) });
  assert.equal(doc.proof, '0x010203');
});

test('createFlowDisclosure refuses an empty set, a floor above the total, and a document that does not check out', async () => {
  let proved = 0;
  const prover = { isAvailable: async () => true, prove: async () => { proved++; throw new Error('unreachable'); } };
  const w = flowClient(A, world, { prover: prover as never });
  await assert.rejects(
    w.client.createFlowDisclosure({ direction: 'in', counterparty: C.address, ...range, claim: { exact: true }, label: '', ttlDays: 1 }),
    (e: DarkError) => e.code === 'AMOUNT_OUT_OF_RANGE' && /no payments match/.test(e.message),
  );
  await assert.rejects(
    w.client.createFlowDisclosure({ direction: 'out', counterparty: B.address, ...range, claim: { lo: B_TOTAL + 1n }, label: '', ttlDays: 1 }),
    (e: DarkError) => e.code === 'INSUFFICIENT_BALANCE',
  );
  assert.equal(proved, 0);

  // A zero counterparty (an RPC that ignores the topic filter serves logs anyway): the document breaks
  // the flow rules, and the self-check stops it before anything is stored.
  const lying = flowClient(A, toBob, { ignoreFilter: true });
  await assert.rejects(
    lying.client.createFlowDisclosure({
      direction: 'out', counterparty: '0x0000000000000000000000000000000000000000', ...range, claim: { exact: true }, label: '', ttlDays: 1,
    }),
    (e: DarkError) => e.code === 'DECRYPTION_FAILED' && /nothing was stored/.test(e.message),
  );
  assert.equal(w.seen.posted.length + lying.seen.posted.length, 0, 'nothing reaches the API');
});
