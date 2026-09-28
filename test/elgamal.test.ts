import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hexToBytes } from '@noble/hashes/utils';
import { deriveDarkKeys } from '../src/keys.ts';
import { G, H, mul, add, sub, Point } from '../src/grumpkin.ts';
import {
  encrypt, decryptToPoint, decryptAmount, discreteLog, addCiphertexts, subCiphertexts,
  publicCiphertext, hedgedScalar, contextBytes, assertHintPrivacy,
  TAG_TRANSFER_R, TAG_HINT_K, TAG_DLEQ_NONCE, MAX_AMOUNT,
} from '../src/elgamal.ts';

const alice = deriveDarkKeys(hexToBytes('01'.repeat(32)), 4663);
const bob = deriveDarkKeys(hexToBytes('02'.repeat(32)), 4663);
const ctx = contextBytes({
  chainId: 4663,
  vault: `0x${'11'.repeat(20)}`,
  from: `0x${'aa'.repeat(20)}`,
  to: `0x${'bb'.repeat(20)}`,
  fromNonce: 7n,
});

test('encrypt/decrypt round-trips for both handles', () => {
  const rho = hedgedScalar(TAG_TRANSFER_R, alice.s, ctx);
  const { C, D } = encrypt(1_234_567n, [alice.P, bob.P], rho);
  assert.equal(decryptAmount(C, D[0], alice.s, 2n ** 21n), 1_234_567n);
  assert.equal(decryptAmount(C, D[1], bob.s, 2n ** 21n), 1_234_567n);
});

test('decryptToPoint is C - s*D', () => {
  const rho = hedgedScalar(TAG_TRANSFER_R, alice.s, ctx);
  const { C, D } = encrypt(9n, [alice.P], rho);
  assert.ok(decryptToPoint(C, D[0], alice.s).equals(mul(G, 9n)));
});

test('encrypt rejects out-of-range amounts and zero rho', () => {
  assert.throws(() => encrypt(MAX_AMOUNT, [alice.P], 5n));
  assert.throws(() => encrypt(-1n, [alice.P], 5n));
  assert.throws(() => encrypt(1n, [alice.P], 0n));
  assert.throws(() => encrypt(1n, [], 5n));
});

test('homomorphic add/sub under one key', () => {
  const r1 = hedgedScalar(TAG_TRANSFER_R, alice.s, ctx);
  const r2 = hedgedScalar(TAG_TRANSFER_R, alice.s, ctx);
  const a = encrypt(500n, [alice.P], r1);
  const b = encrypt(120n, [alice.P], r2);
  const sum = addCiphertexts({ c: a.C, d: a.D[0] }, { c: b.C, d: b.D[0] });
  const diff = subCiphertexts({ c: a.C, d: a.D[0] }, { c: b.C, d: b.D[0] });
  assert.equal(decryptAmount(sum.c, sum.d, alice.s, 1024n), 620n);
  assert.equal(decryptAmount(diff.c, diff.d, alice.s, 1024n), 380n);
});

test('a public amount is (x*G, identity)', () => {
  const p = publicCiphertext(42n);
  assert.ok(p.d.is0());
  assert.equal(decryptAmount(p.c, p.d, alice.s, 64n), 42n);
});

test('bounded BSGS finds values up to 2^20 and refuses beyond the bound', () => {
  for (const v of [0n, 1n, 255n, 1_048_575n]) {
    assert.equal(discreteLog(mul(G, v), 1n << 20n), v);
  }
  assert.equal(discreteLog(mul(G, 1n << 20n), (1n << 20n) - 1n), null);
});

test('a small value under a huge bound returns fast, without building the full table', () => {
  // the $250k-ceiling tvl bound used to cost 12.9 s and ~190 MB for v = 1,
  // because the whole baby-step table was built before the first giant step. 1 s leaves 13x
  // headroom over the measured 13 ms and still fails hard against the old code.
  const TVL_CEILING = 250_000_000000n;
  const t0 = performance.now();
  assert.equal(discreteLog(mul(G, 1n), TVL_CEILING), 1n);
  assert.equal(discreteLog(mul(G, 1_000n), TVL_CEILING), 1_000n);
  const ms = performance.now() - t0;
  assert.ok(ms < 1_000, `two small BSGS lookups under the tvl bound took ${ms.toFixed(0)} ms`);
  // The bound itself must not have moved: a value above it is still refused.
  assert.equal(discreteLog(mul(G, 1n << 20n), (1n << 20n) - 1n), null);
});

test('the hedged-randomness tags are pinned strings and separate the domains', () => {
  // the `notEqual(r, k)` below passes even with both tags equal, because each
  // call draws fresh randomness. Pin the tag bytes and compare at one fixed draw instead, so
  // swapping or merging the two constants fails here.
  const d = new TextDecoder();
  assert.equal(d.decode(TAG_TRANSFER_R), 'DARK-CB-1/transfer-r/v1');
  assert.equal(d.decode(TAG_HINT_K), 'DARK-CB-1/hint-k/v1');
  assert.equal(d.decode(TAG_DLEQ_NONCE), 'DARK-CB-1/dleq-nonce/v1');
  const rand = new Uint8Array(32).fill(5);
  assert.notEqual(
    hedgedScalar(TAG_TRANSFER_R, alice.s, ctx, rand),
    hedgedScalar(TAG_HINT_K, alice.s, ctx, rand),
  );
});

test('hedged r and k differ; hint privacy assertions hold', () => {
  const r = hedgedScalar(TAG_TRANSFER_R, alice.s, ctx);
  const k = hedgedScalar(TAG_HINT_K, alice.s, ctx);
  assert.notEqual(r, k);

  const amount = 1000n;
  const { C, D } = encrypt(amount, [alice.P, bob.P], r);
  assertHintPrivacy({ C, amount, Re: mul(H, k), K: mul(bob.P, k), Dr: D[1] });

  // property: with k == r both assertions fire
  assert.throws(() =>
    assertHintPrivacy({ C, amount, Re: mul(H, r), K: mul(bob.P, r), Dr: D[1] }),
  );
});

test('hedged scalars are deterministic in their inputs and vary with the draw', () => {
  const rand = new Uint8Array(32).fill(3);
  assert.equal(
    hedgedScalar(TAG_TRANSFER_R, alice.s, ctx, rand),
    hedgedScalar(TAG_TRANSFER_R, alice.s, ctx, rand),
  );
  assert.notEqual(
    hedgedScalar(TAG_TRANSFER_R, alice.s, ctx, rand),
    hedgedScalar(TAG_TRANSFER_R, alice.s, ctx, new Uint8Array(32).fill(4)),
  );
  assert.throws(() => hedgedScalar(TAG_TRANSFER_R, alice.s, ctx, new Uint8Array(16)));
});

test('identity decrypts to zero', () => {
  assert.equal(discreteLog(Point.ZERO, 1024n), 0n);
  assert.ok(sub(add(G, H), H).equals(G));
});
