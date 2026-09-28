// the BSGS bound is clamped to the protocol ceiling before it reaches discreteLog.
//
// discreteLog's memory is capped by bsgsTableBits, but its time is linear in the bound — the final
// pass runs bound / 2^tableBits giant steps. Both bounds the live client passes it (`tvl()` and the
// `maxTransfer` from a CapsUpdated log) come over the RPC, which §2's threat table says may serve
// wrong data. Unclamped, a hostile or buggy RPC hangs balance decryption forever, which is exactly
// the self-rescue path §18.10 promises keeps working when Dark is hostile or down.
import test from 'node:test';
import assert from 'node:assert/strict';

import { capBsgsBound, HARD_MAX_TVL, HARD_MAX_TRANSFER } from '../src/client.js';
import { discreteLog } from '../src/elgamal.js';
import { G, mul } from '../src/grumpkin.js';

test('the ceilings match the contract immutables', () => {
  // DarkVault.sol: HARD_MAX_TVL = 250_000e6, HARD_MAX_TRANSFER = 2_500e6.
  assert.equal(HARD_MAX_TVL, 250_000_000_000n);
  assert.equal(HARD_MAX_TRANSFER, 2_500_000_000n);
});

test('an absurd bound is clamped, a legitimate one is untouched', () => {
  const absurd = (1n << 256n) - 1n;
  assert.equal(capBsgsBound(absurd, HARD_MAX_TVL), HARD_MAX_TVL);
  assert.equal(capBsgsBound(HARD_MAX_TVL + 1n, HARD_MAX_TVL), HARD_MAX_TVL);
  // Anything at or under the ceiling must pass through exactly, or we would break real decryption.
  assert.equal(capBsgsBound(HARD_MAX_TVL, HARD_MAX_TVL), HARD_MAX_TVL);
  assert.equal(capBsgsBound(1_234_567n, HARD_MAX_TVL), 1_234_567n);
  assert.equal(capBsgsBound(0n, HARD_MAX_TVL), 0n);
});

test('a clamped bound still decrypts a real balance', () => {
  // The clamp must not cost correctness: a value inside the ceiling still resolves.
  const v = 4_242_424n;
  const found = discreteLog(mul(G, v), capBsgsBound((1n << 256n) - 1n, HARD_MAX_TVL), 20);
  assert.equal(found, v);
});

test('the clamped bound is small enough to terminate', () => {
  // The point of the fix: bound/2^20 giant steps must be a number of steps a phone can finish.
  // Unclamped at 2^256 this is ~2^236 and never returns.
  const giantSteps = capBsgsBound((1n << 256n) - 1n, HARD_MAX_TVL) / (1n << 20n);
  assert.ok(giantSteps < 1_000_000n, `clamped bound still needs ${giantSteps} giant steps`);
});
