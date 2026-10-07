import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hexToBytes } from '@noble/hashes/utils';
import { deriveDarkKeys } from '../src/keys.ts';
import { sealBalance, openBalance, AE_BALANCE_BYTES, type AeContext } from '../src/hint.ts';

const k = deriveDarkKeys(hexToBytes('07'.repeat(32)), 4663);
const ctx: AeContext = { chainId: 4663, vault: `0x${'11'.repeat(20)}`, account: `0x${'aa'.repeat(20)}` };

test('aeBalance round-trips and is exactly 56 bytes', () => {
  const blob = sealBalance(k.kAe, { value: 250_000_000_000n, nonceAfter: 42n }, ctx);
  assert.equal(blob.length, AE_BALANCE_BYTES);
  assert.deepEqual(openBalance(k.kAe, blob, ctx), { value: 250_000_000_000n, nonceAfter: 42n });
});

test('a wrong key, wrong context or tampered blob opens to null, not a throw', () => {
  const blob = sealBalance(k.kAe, { value: 1n, nonceAfter: 0n }, ctx);
  const other = deriveDarkKeys(hexToBytes('08'.repeat(32)), 4663);
  assert.equal(openBalance(other.kAe, blob, ctx), null);
  assert.equal(openBalance(k.kAe, blob, { ...ctx, chainId: 46630 }), null);
  assert.equal(openBalance(k.kAe, blob, { ...ctx, account: `0x${'bb'.repeat(20)}` }), null);
  const bad = Uint8Array.from(blob);
  bad[30] ^= 1;
  assert.equal(openBalance(k.kAe, bad, ctx), null);
  assert.equal(openBalance(k.kAe, new Uint8Array(0), ctx), null);
});

test('seal rejects out-of-range values', () => {
  assert.throws(() => sealBalance(k.kAe, { value: 1n << 64n, nonceAfter: 0n }, ctx));
  assert.throws(() => sealBalance(k.kAe, { value: -1n, nonceAfter: 0n }, ctx));
  assert.throws(() => sealBalance(new Uint8Array(16), { value: 0n, nonceAfter: 0n }, ctx));
});

// --- the 240 B / 176 B transfer hints ------------------------------------------------------
import { G, H, mul, sub } from '../src/grumpkin.ts';
import { deriveDarkKeys } from '../src/keys.ts';
import {
  encrypt, hedgedScalar, contextBytes, assertHintPrivacy, decryptAmount,
  TAG_TRANSFER_R, TAG_HINT_K,
} from '../src/elgamal.ts';
import {
  sealHint, openHint, sealSenderHint, openSenderHint, HINT_BYTES, SENDER_HINT_BYTES,
} from '../src/hint.ts';

const CHAIN = 46630;
// Not a deployment: any address works here, and a real one reads as live config.
const VAULT = '0x00000000000000000000000000000000000000fa';
const FROM = '0x000000000000000000000000000000000000beef';
const TO = '0x000000000000000000000000000000000000cafe';
const sender = deriveDarkKeys(new Uint8Array(32).fill(0x11), CHAIN);
const recipient = deriveDarkKeys(new Uint8Array(32).fill(0x22), CHAIN);
const tctx = { chainId: CHAIN, vault: VAULT, from: FROM, to: TO, fromNonce: 7n };
const ctxBytes = contextBytes(tctx);
const rT = hedgedScalar(TAG_TRANSFER_R, sender.s, ctxBytes);
const kT = hedgedScalar(TAG_HINT_K, sender.s, ctxBytes);
const AMOUNT = 12_345678n;

test('the recipient hint is 240 B and opens only with the recipient s', () => {
  const blob = sealHint(kT, recipient.P, tctx, AMOUNT, 'coffee');
  assert.equal(blob.length, HINT_BYTES);
  assert.deepEqual(openHint(blob, recipient.s, tctx), { amount: AMOUNT, note: 'coffee' });
  assert.equal(openHint(blob, sender.s, tctx), null);
  assert.equal(openHint(blob, recipient.s, { ...tctx, fromNonce: 8n }), null, 'the context is the AAD');
  const flipped = Uint8Array.from(blob);
  flipped[239] ^= 1;
  assert.equal(openHint(flipped, recipient.s, tctx), null);
  assert.equal(openHint(blob.subarray(0, 100), recipient.s, tctx), null);
});

test('the sender hint is 176 B and opens under k_ae', () => {
  const blob = sealSenderHint(sender.kAe, tctx, AMOUNT, 'coffee');
  assert.equal(blob.length, SENDER_HINT_BYTES);
  assert.deepEqual(openSenderHint(sender.kAe, blob, tctx), { amount: AMOUNT, note: 'coffee' });
  assert.equal(openSenderHint(recipient.kAe, blob, tctx), null);
});

test('a note longer than 127 bytes is refused, and an empty note round-trips', () => {
  assert.throws(() => sealHint(kT, recipient.P, tctx, AMOUNT, 'x'.repeat(128)));
  assert.equal(openHint(sealHint(kT, recipient.P, tctx, AMOUNT), recipient.s, tctx)?.note, '');
  // UTF-8 length, not code points.
  assert.throws(() => sealHint(kT, recipient.P, tctx, AMOUNT, 'é'.repeat(64)));
});

test('a verified hint agrees with the ciphertext, and a lying one loses to BSGS', () => {
  const { C, D } = encrypt(AMOUNT, [sender.P, recipient.P], rT);
  // §3: k must never equal r, or R_e and K leak.
  assertHintPrivacy({ C, amount: AMOUNT, Re: mul(H, kT), K: mul(recipient.P, kT), Dr: D[1] });
  const opened = openHint(sealHint(kT, recipient.P, tctx, AMOUNT), recipient.s, tctx);
  assert.ok(opened);
  assert.ok(mul(G, opened.amount).equals(sub(C, mul(D[1], recipient.s))), 'hint check a*G == C - s_r*D_r');

  // A sender that lies about the amount fails that check; BSGS bounded by maxTransfer recovers it.
  const lie = openHint(sealHint(kT, recipient.P, tctx, AMOUNT + 1n), recipient.s, tctx);
  assert.ok(lie && !mul(G, lie.amount).equals(sub(C, mul(D[1], recipient.s))));
  assert.equal(decryptAmount(C, D[1], recipient.s, 25_000_000n), AMOUNT);
});
