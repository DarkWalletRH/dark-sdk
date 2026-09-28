// SPDX-License-Identifier: MIT OR Apache-2.0
// Key hierarchy (§6.4). Frozen: changing any tag or length strands balances.
import { sha512 } from '@noble/hashes/sha2';
import { extract, expand } from '@noble/hashes/hkdf';
import { invert } from '@noble/curves/abstract/modular';
import { GROUP_N, H, mul, encode, type AffinePoint, type Pt } from './grumpkin.ts';

const enc = new TextEncoder();

/** HKDF salt, §6.3 table. */
export const HKDF_SALT = enc.encode('darkwallet.cash/conf-bal/v1');
const INFO_S = enc.encode('DARK-CB-1/elgamal-s');
const INFO_AE = enc.encode('DARK-CB-1/ae-key');

export function u64be(v: bigint | number): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(v), false);
  return b;
}

function concat(...parts: Uint8Array[]): Uint8Array {
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

export interface DarkKeys {
  /** ElGamal secret, in [1, n). Never persisted, never exported. */
  s: bigint;
  /** Public key P = s^-1 * H, so s*P = H. */
  P: Pt;
  /** P in on-chain (x, y) form. */
  publicKey: AffinePoint;
  /** XChaCha20-Poly1305 key for aeBalance and senderHint. */
  kAe: Uint8Array;
  /** The counter that produced a non-zero s (normally 0). */
  ctr: number;
  chainId: number;
}

/**
 * sk -> PRK -> (s, P, k_ae), exactly per §6.4.
 * `sk` is the secp256k1 private key (32 bytes) behind the EOA that *is* the Dark account.
 */
export function deriveDarkKeys(sk: Uint8Array, chainId: number): DarkKeys {
  if (sk.length !== 32) throw new Error('deriveDarkKeys: sk must be 32 bytes');
  const prk = extract(sha512, sk, HKDF_SALT);
  const chain = u64be(chainId);

  let s = 0n;
  let ctr = 0;
  for (; ctr < 256; ctr++) {
    const info = concat(INFO_S, chain, Uint8Array.of(ctr));
    s = beToBigint(expand(sha512, prk, info, 64)) % GROUP_N;
    if (s !== 0n) break;
  }
  /* c8 ignore next */
  if (s === 0n) throw new Error('deriveDarkKeys: no valid s');

  const kAe = expand(sha512, prk, concat(INFO_AE, chain), 32);
  const P = mul(H, invModN(s));
  return { s, P, publicKey: encode(P), kAe, ctr, chainId };
}

/** Modular inverse in the scalar field (group order n). */
export const invModN = (v: bigint): bigint => invert(v, GROUP_N);

/** §6.4: the client hard-stops when the derived P differs from the registry's. */
export function checkRegistryKey(derived: AffinePoint, onChain: AffinePoint): void {
  if (derived.x !== onChain.x || derived.y !== onChain.y) {
    const e = new Error('Derived public key does not match the registry') as Error & { code: string };
    e.code = 'KEY_DERIVATION_MISMATCH';
    throw e;
  }
}

/** Sanity check the §6.3 invariant s*P == H. */
export function keysAreConsistent(k: DarkKeys): boolean {
  return mul(k.P, k.s).equals(H);
}
