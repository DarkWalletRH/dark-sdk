// SPDX-License-Identifier: MIT OR Apache-2.0
// Twisted ElGamal with decrypt handles (§6.3).
// C = v*G + rho*H, D_i = rho*P_i. Decrypt: C - s*D = v*G.
import { sha512 } from '@noble/hashes/sha2';
import { G, H, GROUP_N, Point, mul, add, sub, encode, type AffinePoint, type Pt } from './grumpkin.ts';
import { u64be } from './keys.ts';

const enc = new TextEncoder();

/** Hedged-randomness tags, §6.3 table. */
export const TAG_TRANSFER_R = enc.encode('DARK-CB-1/transfer-r/v1');
export const TAG_HINT_K = enc.encode('DARK-CB-1/hint-k/v1');
export const TAG_DLEQ_NONCE = enc.encode('DARK-CB-1/dleq-nonce/v1');

/** The circuit range for amounts. */
export const MAX_AMOUNT = 1n << 48n;

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function beToBigint(b: Uint8Array): bigint {
  let v = 0n;
  for (const byte of b) v = (v << 8n) | BigInt(byte);
  return v;
}

function scalarBytes(s: bigint): Uint8Array {
  const b = new Uint8Array(32);
  let v = s;
  for (let i = 31; i >= 0; i--) {
    b[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return b;
}

/** 20-byte address from a 0x-hex string. */
export function addressBytes(a: string): Uint8Array {
  const hex = a.startsWith('0x') ? a.slice(2) : a;
  if (hex.length !== 40) throw new Error(`addressBytes: not a 20-byte address: ${a}`);
  const out = new Uint8Array(20);
  for (let i = 0; i < 20; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** The (chainId, vault, from, to, fromNonce) context for r, k and the hint KDF (§6.3). */
export interface TransferContext {
  chainId: number;
  vault: string;
  from: string;
  to: string;
  fromNonce: bigint | number;
}

export function contextBytes(c: TransferContext): Uint8Array {
  return concatBytes(
    u64be(c.chainId),
    addressBytes(c.vault),
    addressBytes(c.from),
    addressBytes(c.to),
    u64be(c.fromNonce),
  );
}

/** HashToScalar = SHA-512 mod n, rejecting 0 (§6.3). */
export function hashToScalar(...parts: Uint8Array[]): bigint {
  let msg = concatBytes(...parts);
  for (let i = 0; i < 256; i++) {
    const v = beToBigint(sha512(msg)) % GROUP_N;
    if (v !== 0n) return v;
    msg = concatBytes(msg, Uint8Array.of(i));
  }
  /* c8 ignore next */
  throw new Error('hashToScalar: exhausted');
}

/** 32 fresh CSPRNG bytes. expo-crypto polyfills this on native. */
function freshBytes(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

/**
 * Hedged scalar (§6.3): HashToScalar(tag || 32 fresh CSPRNG bytes || s || context).
 * r and k must use different tags AND separate draws; see assertHintPrivacy.
 */
export function hedgedScalar(
  tag: Uint8Array,
  s: bigint,
  context: Uint8Array,
  rand: Uint8Array = freshBytes(),
): bigint {
  if (rand.length !== 32) throw new Error('hedgedScalar: rand must be 32 bytes');
  return hashToScalar(tag, rand, scalarBytes(s), context);
}

/** C = v*G + rho*H with one decrypt handle per recipient key. */
export interface Ciphertext {
  c: Pt;
  d: Pt;
}

export interface Encryption {
  C: Pt;
  /** D_i = rho*P_i, in the order the recipient keys were given. */
  D: Pt[];
  rho: bigint;
}

export function encrypt(v: bigint, recipients: Pt[], rho: bigint): Encryption {
  if (v < 0n || v >= MAX_AMOUNT) throw new Error('encrypt: amount out of [0, 2^48)');
  if (rho % GROUP_N === 0n) throw new Error('encrypt: rho must be non-zero');
  if (recipients.length === 0) throw new Error('encrypt: no recipients');
  return {
    C: add(mul(G, v), mul(H, rho)),
    D: recipients.map((P) => mul(P, rho)),
    rho,
  };
}

/** A public amount x is the ciphertext (x*G, identity). */
export const publicCiphertext = (x: bigint): Ciphertext => ({ c: mul(G, x), d: Point.ZERO });

/** C - s*D = v*G. */
export const decryptToPoint = (c: Pt, d: Pt, s: bigint): Pt => sub(c, mul(d, s));

/** Componentwise point addition; only valid under the same P. */
export const addCiphertexts = (a: Ciphertext, b: Ciphertext): Ciphertext => ({
  c: add(a.c, b.c),
  d: add(a.d, b.d),
});

export const subCiphertexts = (a: Ciphertext, b: Ciphertext): Ciphertext => ({
  c: sub(a.c, b.c),
  d: sub(a.d, b.d),
});

/**
 * Bounded baby-step giant-step: find v in [0, maxV] with v*G == target, else null.
 *
 * The search restarts at a 256x-growing bound, so a small v pays about sqrt(v) work and sqrt(v)
 * memory instead of always building the full maxV-sized table first. Before this, a v of 1 under
 * the tvl bound cost 12.5 s and ~190 MB. A restarted pass costs ~sqrt(bound),
 * so the discarded passes are a geometric series of ratio 1/16: the worst case grows by at most
 * 1/(1 - 1/16) = 1.07x and the bound itself is unchanged.
 */
export function discreteLog(target: Pt, maxV: bigint, maxTableBits = 20): bigint | null {
  if (maxV < 0n) throw new Error('discreteLog: negative bound');
  if (target.is0()) return 0n;
  for (let bound = 1n << 16n; bound < maxV; bound <<= 8n) {
    const found = bsgs(target, bound, maxTableBits);
    if (found !== null) return found;
  }
  return bsgs(target, maxV, maxTableBits);
}

/**
 * One BSGS pass: v = i*m + j, a table of m baby steps and ceil(maxV/m) giant steps.
 * `maxTableBits` caps memory, so a huge maxV costs steps rather than RAM.
 */
function bsgs(target: Pt, maxV: bigint, maxTableBits: number): bigint | null {
  let m = 1n;
  while (m * m <= maxV) m <<= 1n;
  const cap = 1n << BigInt(maxTableBits);
  if (m > cap) m = cap;

  const table = new Map<bigint, bigint>();
  let cur = Point.ZERO;
  for (let j = 0n; j < m; j++) {
    table.set(cur.is0() ? 0n : cur.toAffine().x, j);
    cur = add(cur, G);
  }
  const stride = mul(G, m); // = m*G, the giant step

  let gamma = target;
  const giants = maxV / m;
  for (let i = 0n; i <= giants; i++) {
    const key = gamma.is0() ? 0n : gamma.toAffine().x;
    const j = table.get(key);
    if (j !== undefined) {
      const v = i * m + j;
      // The x-only table cannot tell P from -P, so confirm.
      if (v <= maxV && mul(G, v).equals(target)) return v;
    }
    gamma = sub(gamma, stride);
  }
  return null;
}

/** Full decrypt: C - s*D, then a bounded BSGS. */
export function decryptAmount(c: Pt, d: Pt, s: bigint, maxV: bigint): bigint | null {
  return discreteLog(decryptToPoint(c, d, s), maxV);
}

/**
 * §6.3: the hint key must come from an independent ECDH, so k must never equal r.
 * Asserted before every send; a violation would leak amounts and the hint key.
 */
export function assertHintPrivacy(args: { C: Pt; amount: bigint; Re: Pt; K: Pt; Dr: Pt }): void {
  if (args.Re.equals(sub(args.C, mul(G, args.amount)))) {
    throw new Error('hint privacy: R_e == C - a*G (k reused as r)');
  }
  if (args.K.equals(args.Dr)) {
    throw new Error('hint privacy: K == D_r (k reused as r)');
  }
}

export const toAffine = (p: Pt): AffinePoint => encode(p);
