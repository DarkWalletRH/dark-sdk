import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  G, H, Fr, FIELD_R, GROUP_N, Point, add, sub, mul, encode, decode, isValidPoint,
} from '../src/grumpkin.ts';

test('generator is on curve and has prime order n', () => {
  G.assertValidity();
  assert.ok(mul(G, GROUP_N).is0());
  assert.ok(!mul(G, GROUP_N - 1n).is0());
});

test('H is on curve, even-LSB y, and distinct from G', () => {
  H.assertValidity();
  assert.equal(H.toAffine().y & 1n, 0n);
  assert.ok(!H.equals(G));
  assert.ok(mul(H, GROUP_N).is0());
});

test('H is deterministic', async () => {
  const { deriveH } = await import('../src/grumpkin.ts');
  assert.ok(deriveH().equals(H));
});

test('add/sub/mul are consistent', () => {
  const a = mul(G, 7n);
  const b = mul(H, 11n);
  assert.ok(sub(add(a, b), b).equals(a));
  assert.ok(mul(G, 0n).is0());
  assert.ok(mul(G, -1n).equals(mul(G, GROUP_N - 1n)));
});

test('encode identity is the (0,0) sentinel', () => {
  assert.deepEqual(encode(Point.ZERO), { x: 0n, y: 0n });
});

test('decode rejects non-canonical, off-curve and identity', () => {
  const p = encode(mul(G, 3n));
  assert.ok(decode(p).equals(mul(G, 3n)));
  // x + r must never pass
  assert.throws(() => decode({ x: p.x + FIELD_R, y: p.y }));
  assert.throws(() => decode({ x: p.x, y: p.y + FIELD_R }));
  assert.throws(() => decode({ x: 0n, y: 0n }));
  assert.throws(() => decode({ x: p.x, y: Fr.add(p.y, 1n) }));
  assert.equal(isValidPoint({ x: 2n, y: 3n }), false);
});
