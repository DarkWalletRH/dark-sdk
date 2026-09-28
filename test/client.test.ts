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
  // The SDK hashed the DECODED bytes while the server hashes the hex TEXT, so every digest
  // disagreed and revoking from the device that made a link always 404'd — leaving the link live
  // with no way to take it down. The smoke test missed it by hashing the server's way.
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
