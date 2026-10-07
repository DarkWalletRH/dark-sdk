// SPDX-License-Identifier: MIT OR Apache-2.0
// aeBalance, the owner-only balance hint (§6.3).
// 56 B = nonce(24) || XChaCha20-Poly1305(k_ae, u64be(value) || u64be(nonceAfter), AAD).
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha2';
import { addressBytes, concatBytes } from './elgamal.ts';
import { u64be } from './keys.ts';

const AE_AAD_TAG = new TextEncoder().encode('DARK-CB-1/ae/v1');

export const AE_BALANCE_BYTES = 56;
const NONCE_BYTES = 24;
const NONCE_TAG = new TextEncoder().encode('DARK-CB-1/aead-nonce/v1');

/**
 * Hedged AEAD nonce, like r and k (§3 "Randomness"): HMAC-SHA256(key, tag || 32 fresh CSPRNG bytes
 * || AAD || plaintext), truncated to 24 B. With a dead or replayed CSPRNG a raw draw repeats under
 * the long-lived k_ae across every aeBalance and senderHint, which is keystream reuse; this one
 * still differs whenever the message does. Not a wire change: the nonce travels in the blob and
 * openers never recompute it.
 */
function hedgedNonce(key: Uint8Array, aad: Uint8Array, pt: Uint8Array): Uint8Array {
  const rand = crypto.getRandomValues(new Uint8Array(32));
  return hmac(sha256, key, concatBytes(NONCE_TAG, rand, aad, pt)).subarray(0, NONCE_BYTES);
}

/** The account whose balance this hint describes. */
export interface AeContext {
  chainId: number;
  vault: string;
  account: string;
}

/** AE AAD = tag || u64be(chainId) || vault(20) || account(20) (§6.3). */
export function aeAad(ctx: AeContext): Uint8Array {
  return concatBytes(AE_AAD_TAG, u64be(ctx.chainId), addressBytes(ctx.vault), addressBytes(ctx.account));
}

export interface BalanceHint {
  value: bigint;
  nonceAfter: bigint;
}

/**
 * Seal the post-state balance. `nonce` is exposed only so tests and vectors can
 * pin a value; production always takes the hedged default.
 */
export function sealBalance(
  kAe: Uint8Array,
  hint: BalanceHint,
  ctx: AeContext,
  nonce?: Uint8Array,
): Uint8Array {
  if (kAe.length !== 32) throw new Error('sealBalance: k_ae must be 32 bytes');
  if (nonce && nonce.length !== NONCE_BYTES) throw new Error('sealBalance: nonce must be 24 bytes');
  if (hint.value < 0n || hint.value >= 1n << 64n) throw new Error('sealBalance: value out of u64');
  if (hint.nonceAfter < 0n || hint.nonceAfter >= 1n << 64n) throw new Error('sealBalance: nonceAfter out of u64');
  const pt = concatBytes(u64be(hint.value), u64be(hint.nonceAfter));
  nonce ??= hedgedNonce(kAe, aeAad(ctx), pt);
  const ct = xchacha20poly1305(kAe, nonce, aeAad(ctx)).encrypt(pt);
  return concatBytes(nonce, ct);
}

/**
 * Open an aeBalance blob. Returns null for an empty/wrong-length blob or a failed
 * tag check, so callers fall back to history replay or BSGS (§6.7 step 5) instead
 * of crashing on a blob a hostile chain state could have written.
 */
export function openBalance(kAe: Uint8Array, blob: Uint8Array, ctx: AeContext): BalanceHint | null {
  if (kAe.length !== 32 || blob.length !== AE_BALANCE_BYTES) return null;
  try {
    const pt = xchacha20poly1305(kAe, blob.subarray(0, NONCE_BYTES), aeAad(ctx)).decrypt(
      blob.subarray(NONCE_BYTES),
    );
    const dv = new DataView(pt.buffer, pt.byteOffset, pt.byteLength);
    return { value: dv.getBigUint64(0, false), nonceAfter: dv.getBigUint64(8, false) };
  } catch {
    return null;
  }
}

// --- the transfer hints (§3 "Fixed-size blobs") -------------------------------------------
// Neither hint is proven in-circuit: the recipient verifies a*G == C_t - s_r*D_r and, on a
// mismatch, falls back to a bounded BSGS (§7 step 5). A lying sender costs a sub-second search.

import { hkdf } from '@noble/hashes/hkdf';
import { H, mul, pointBytes, decode, encode, type Pt } from './grumpkin.ts';
import { invModN } from './keys.ts';
import { contextBytes, type TransferContext } from './elgamal.ts';

/** R_e.x(32) || R_e.y(32) || nonce(24) || ct(152). */
export const HINT_BYTES = 240;
/** nonce(24) || ct(152). */
export const SENDER_HINT_BYTES = 176;
/** u64be(a) || u8(noteLen) || note[127]. */
const NOTE_MAX = 127;
const PLAINTEXT_BYTES = 8 + 1 + NOTE_MAX;

const HINT_SALT = new TextEncoder().encode('DARK-CB-1/hint/v1');

export interface TransferNote {
  amount: bigint;
  note: string;
}

/** k_h = HKDF-SHA256(K.x || K.y, salt, info) -- an ECDH independent of r (§3). */
const hintKey = (K: Pt, info: Uint8Array): Uint8Array => hkdf(sha256, pointBytes(K), HINT_SALT, info, 32);

function notePlaintext(amount: bigint, note: string): Uint8Array {
  if (amount < 0n || amount >= 1n << 64n) throw new Error('hint: amount out of u64');
  const bytes = new TextEncoder().encode(note);
  if (bytes.length > NOTE_MAX) throw new Error(`hint: note is ${bytes.length} bytes, max ${NOTE_MAX}`);
  const pt = new Uint8Array(PLAINTEXT_BYTES);
  pt.set(u64be(amount), 0);
  pt[8] = bytes.length;
  pt.set(bytes, 9);
  return pt;
}

function readNote(pt: Uint8Array): TransferNote | null {
  if (pt.length !== PLAINTEXT_BYTES) return null;
  const len = pt[8];
  if (len > NOTE_MAX) return null;
  const dv = new DataView(pt.buffer, pt.byteOffset, pt.byteLength);
  return { amount: dv.getBigUint64(0, false), note: new TextDecoder().decode(pt.subarray(9, 9 + len)) };
}

/** The 240 B recipient hint. `k` is the hedged ephemeral scalar; R_e = k*H, K = k*P_r. */
export function sealHint(
  k: bigint,
  recipientKey: Pt,
  ctx: TransferContext,
  amount: bigint,
  note = '',
  nonce?: Uint8Array,
): Uint8Array {
  const info = contextBytes(ctx);
  const Re = mul(H, k);
  const kh = hintKey(mul(recipientKey, k), info);
  const pt = notePlaintext(amount, note);
  nonce ??= hedgedNonce(kh, info, pt);
  const ct = xchacha20poly1305(kh, nonce, info).encrypt(pt);
  const { x, y } = encode(Re);
  return concatBytes(toBytes32BE(x), toBytes32BE(y), nonce, ct);
}

/** The recipient recomputes K = (s_r^-1 mod n) * R_e. Returns null on any failure (§19). */
export function openHint(blob: Uint8Array, s: bigint, ctx: TransferContext): TransferNote | null {
  if (blob.length !== HINT_BYTES) return null;
  try {
    const Re = decode({ x: beToBig(blob.subarray(0, 32)), y: beToBig(blob.subarray(32, 64)) });
    const info = contextBytes(ctx);
    const kh = hintKey(mul(Re, invModN(s)), info);
    return readNote(xchacha20poly1305(kh, blob.subarray(64, 64 + NONCE_BYTES), info).decrypt(blob.subarray(64 + NONCE_BYTES)));
  } catch {
    return null;
  }
}

/** The 176 B sender copy, under k_ae, so the 12 words rebuild the sender's own history. */
export function sealSenderHint(
  kAe: Uint8Array,
  ctx: TransferContext,
  amount: bigint,
  note = '',
  nonce?: Uint8Array,
): Uint8Array {
  const info = contextBytes(ctx);
  const pt = notePlaintext(amount, note);
  nonce ??= hedgedNonce(kAe, info, pt);
  return concatBytes(nonce, xchacha20poly1305(kAe, nonce, info).encrypt(pt));
}

export function openSenderHint(kAe: Uint8Array, blob: Uint8Array, ctx: TransferContext): TransferNote | null {
  if (kAe.length !== 32 || blob.length !== SENDER_HINT_BYTES) return null;
  try {
    const info = contextBytes(ctx);
    return readNote(xchacha20poly1305(kAe, blob.subarray(0, NONCE_BYTES), info).decrypt(blob.subarray(NONCE_BYTES)));
  } catch {
    return null;
  }
}

function toBytes32BE(v: bigint): Uint8Array {
  const b = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    b[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return b;
}

const beToBig = (b: Uint8Array): bigint => b.reduce((v, x) => (v << 8n) | BigInt(x), 0n);
