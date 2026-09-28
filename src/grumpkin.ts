// SPDX-License-Identifier: MIT OR Apache-2.0
// Grumpkin (§6.3): y^2 = x^3 - 17 over F_r, r = BN254 scalar field.
// Group order n = BN254 base field, prime, cofactor 1.
import { weierstrass } from '@noble/curves/abstract/weierstrass';
import { Field } from '@noble/curves/abstract/modular';
import { sha256 } from '@noble/hashes/sha2';
import { keccak_256 } from '@noble/hashes/sha3';

/** Grumpkin base field = BN254 scalar field. Coordinates live here. */
export const FIELD_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
/** Grumpkin group order = BN254 base field. Prime, so no cofactor. */
export const GROUP_N = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

export const Fr = Field(FIELD_R);

// `hash` is only there because @noble's legacy weierstrass() builds an ECDSA
// bundle around the point class. Dark never signs on Grumpkin.
export const grumpkin = weierstrass({
  a: 0n,
  b: FIELD_R - 17n,
  Fp: Fr,
  n: GROUP_N,
  Gx: 1n,
  Gy: 17631683881184975370165255887551781615748388533673675138860n,
  h: 1n,
  hash: sha256,
});

export const Point = grumpkin.Point;
export type Pt = InstanceType<typeof Point>;

/** Affine point as the contracts see it. (0,0) is the identity sentinel. */
export interface AffinePoint {
  x: bigint;
  y: bigint;
}

/** Noir's embedded-curve generator. */
export const G: Pt = Point.BASE;

function u32be(i: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, i, false);
  return b;
}

function beToBigint(b: Uint8Array): bigint {
  let v = 0n;
  for (const byte of b) v = (v << 8n) | BigInt(byte);
  return v;
}

const H_TAG = new TextEncoder().encode('DARK-CB-1/generator/H');

/**
 * Nothing-up-my-sleeve H (§6.3): for i = 0,1,...  x = keccak256(tag || u32be(i)) mod r;
 * the first x with x^3 - 17 a square gives H = (x, sqrt with even LSB).
 */
export function deriveH(): Pt {
  for (let i = 0; i < 1000; i++) {
    const msg = new Uint8Array(H_TAG.length + 4);
    msg.set(H_TAG, 0);
    msg.set(u32be(i), H_TAG.length);
    const x = beToBigint(keccak_256(msg)) % FIELD_R;
    const rhs = Fr.sub(Fr.mul(Fr.sqr(x), x), 17n);
    let y: bigint;
    try {
      y = Fr.sqrt(rhs);
    } catch {
      continue; // not a square
    }
    if (Fr.sqr(y) !== rhs) continue;
    if ((y & 1n) === 1n) y = Fr.neg(y);
    return Point.fromAffine({ x, y });
  }
  /* c8 ignore next */
  throw new Error('deriveH: no candidate found');
}

/** The second generator. log_G(H) is unknown. */
export const H: Pt = deriveH();

export const IDENTITY: AffinePoint = { x: 0n, y: 0n };

export const add = (a: Pt, b: Pt): Pt => a.add(b);
export const sub = (a: Pt, b: Pt): Pt => a.subtract(b);

/** Scalar multiplication, accepting 0 and scalars outside [1, n). */
export function mul(p: Pt, k: bigint): Pt {
  const s = ((k % GROUP_N) + GROUP_N) % GROUP_N;
  return s === 0n ? Point.ZERO : p.multiply(s);
}

/** Encode to the on-chain (x, y) pair; identity is the (0,0) sentinel. */
export function encode(p: Pt): AffinePoint {
  if (p.is0()) return { ...IDENTITY };
  const a = p.toAffine();
  return { x: a.x, y: a.y };
}

/**
 * Decode an untrusted (x, y). Enforces all four §6.3 checks: x < r, y < r,
 * on-curve, and not the identity sentinel. Non-canonical x + r never passes.
 */
export function decode(a: AffinePoint): Pt {
  if (a.x < 0n || a.x >= FIELD_R || a.y < 0n || a.y >= FIELD_R) {
    throw new Error('InvalidPoint: non-canonical coordinate');
  }
  if (a.x === 0n && a.y === 0n) throw new Error('InvalidPoint: identity sentinel');
  const p = Point.fromAffine({ x: a.x, y: a.y });
  p.assertValidity();
  return p;
}

/** True when (x, y) would pass `decode`. */
export function isValidPoint(a: AffinePoint): boolean {
  try {
    decode(a);
    return true;
  } catch {
    return false;
  }
}

/** 32-byte big-endian encoding of a field element or scalar. */
export function toBytes32(v: bigint): Uint8Array {
  const b = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    b[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return b;
}

/** x(32) || y(32), the form hashed into KDFs. */
export function pointBytes(p: Pt): Uint8Array {
  const { x, y } = encode(p);
  const out = new Uint8Array(64);
  out.set(toBytes32(x), 0);
  out.set(toBytes32(y), 32);
  return out;
}
