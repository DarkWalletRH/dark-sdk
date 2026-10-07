// SPDX-License-Identifier: MIT OR Apache-2.0
// Disclosure links (§7.7, §7.8, §14): DLEQ for exact claims, RFC 8785 canonical JSON for the
// document, and an XChaCha20-Poly1305 blob whose key lives only in the URL fragment.
//
// This module is reached as `@darkwalletrh/dark-sdk/disclosure`, not from the package index, so the
// core SDK keeps working without viem installed.
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { keccak256, encodeAbiParameters, recoverTypedDataAddress, type Address } from 'viem';
import {
  FIELD_R, GROUP_N, G, H, Point, add, sub, mul, encode, decode, pointBytes, toBytes32,
  type AffinePoint, type Pt,
} from './grumpkin.ts';
import { u64be } from './keys.ts';
import { concatBytes, hashToScalar, hedgedScalar, MAX_AMOUNT, TAG_DLEQ_NONCE } from './elgamal.ts';
import { DarkError } from './errors.ts';
import { deployments, isDeployed } from './deployments.ts';
import type { Hex } from './prover.ts';

const enc = new TextEncoder();

// --- RFC 8785 (JCS) ---------------------------------------------------------------------------

/**
 * Canonical JSON per RFC 8785: keys sorted by UTF-16 code unit (JS default sort), no
 * whitespace, JSON string escaping, ES6 number serialization. `undefined` members are dropped,
 * which is how the optional document fields stay out of the signed form.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new DarkError('DECRYPTION_FAILED', 'canonicalJson: non-finite number');
    return JSON.stringify(value);
  }
  if (typeof value === 'bigint') {
    throw new DarkError('DECRYPTION_FAILED', 'canonicalJson: bigint has no JSON form; use a decimal string');
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    const o = value as Record<string, unknown>;
    const keys = Object.keys(o).filter((k) => o[k] !== undefined).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`).join(',')}}`;
  }
  throw new DarkError('DECRYPTION_FAILED', `canonicalJson: cannot serialize ${typeof value}`);
}

// --- DLEQ (Chaum-Pedersen, §6 "Exact disclosure uses DLEQ, not a circuit") ---------------------

const TAG_DLEQ = enc.encode('DARK-CB-1/dleq/v1');

/** (c, z), 64 bytes. */
export interface DleqProof {
  c: bigint;
  z: bigint;
}

/** The public half of the statement: exists s with s*P = H and s*D = C - v*G. */
export interface DleqStatement {
  P: Pt;
  C: Pt;
  D: Pt;
  /** The claimed plaintext. */
  v: bigint;
  /** Disclosure context bytes, bound into the challenge. */
  context: Uint8Array;
}

/**
 * Every statement element and every prover message goes into the challenge -- the Solana
 * "phantom challenge" lesson. Dropping any one of them is exploitable, so this is the only
 * place the hash input is written.
 */
function dleqChallenge(st: DleqStatement, T: Pt, A1: Pt, A2: Pt): bigint {
  return hashToScalar(
    TAG_DLEQ,
    pointBytes(G), pointBytes(H), pointBytes(st.P), pointBytes(st.C), pointBytes(st.D),
    u64be(st.v), st.context,
    pointBytes(T), pointBytes(A1), pointBytes(A2),
  );
}

/** The hedged-nonce preimage: the disclosure context plus every element of the statement. */
function dleqNonceContext(st: DleqStatement): Uint8Array {
  return concatBytes(st.context, pointBytes(st.P), pointBytes(st.C), pointBytes(st.D), u64be(st.v));
}

export function dleqProve(st: DleqStatement, s: bigint, rand?: Uint8Array): DleqProof {
  if (!mul(st.P, s).equals(H)) throw new DarkError('KEY_DERIVATION_MISMATCH', 'dleqProve: s*P != H');
  const T = sub(st.C, mul(G, st.v));
  if (!mul(st.D, s).equals(T)) {
    throw new DarkError('DECRYPTION_FAILED', 'dleqProve: C - v*G != s*D (v is not the plaintext)');
  }
  // The hedge must cover the statement, not just the context: two disclosures over different
  // ciphertexts in the same context would otherwise share k if the RNG died, and k1 == k2 with
  // c1 != c2 solves for s.
  const k = hedgedScalar(TAG_DLEQ_NONCE, s, dleqNonceContext(st), rand);
  const c = dleqChallenge(st, T, mul(st.P, k), mul(st.D, k));
  return { c, z: ((k - ((c * s) % GROUP_N)) % GROUP_N + GROUP_N) % GROUP_N };
}

export function dleqVerify(st: DleqStatement, proof: DleqProof): boolean {
  // The range check comes first: an out-of-range (c, z) is a malformed proof whatever the
  // statement looks like, and letting the D = identity branch skip it accepted junk.
  if (proof.c <= 0n || proof.c >= GROUP_N || proof.z < 0n || proof.z >= GROUP_N) return false;
  // §6: a public amount has D = identity, and then there is nothing to prove about s. Callers
  // must not read this as knowledge of the secret: `verifyDisclosure` returns `public_balance`.
  if (st.D.is0()) return st.C.equals(mul(G, st.v));
  const T = sub(st.C, mul(G, st.v));
  const A1 = add(mul(st.P, proof.z), mul(H, proof.c));
  const A2 = add(mul(st.D, proof.z), mul(T, proof.c));
  return dleqChallenge(st, T, A1, A2) === proof.c;
}

/** c(32) || z(32), big-endian. */
export function dleqToBytes(p: DleqProof): Uint8Array {
  return concatBytes(toBytes32(p.c), toBytes32(p.z));
}

export function dleqFromBytes(b: Uint8Array): DleqProof {
  if (b.length !== 64) throw new DarkError('DECRYPTION_FAILED', `dleq proof is ${b.length} bytes, not 64`);
  const be = (o: number) => b.subarray(o, o + 32).reduce((v, x) => (v << 8n) | BigInt(x), 0n);
  return { c: be(0), z: be(32) };
}

// --- context hash (§7.7 step 4) ----------------------------------------------------------------

export type DisclosureKind =
  | 'balance_exact' | 'balance_range' | 'transfer_exact' | 'flow_total_exact' | 'flow_total_range';

/** §7.7: `available`, or the homomorphic sum available + pending the viewer recomputes. */
export type DisclosureComponent = 'available' | 'total';

/**
 * The single source of truth for "is this claim a range?". Everything that used to ask the CLAIM
 * this question has to ask the KIND instead — when those two can disagree, a proof of one statement
 * gets rendered as another.
 */
export const isRangeKind = (kind: DisclosureKind): boolean => kind.endsWith('_range');

/**
 * The context-hash preimage members (§18b). Every one of them is also a `DarkDisclosureV2` field,
 * which is what lets the viewer rebuild this from the document alone and catch a tampered
 * `contextHash`.
 */
export interface DisclosureContext {
  chainId: number;
  vault: Address;
  registry: Address;
  account: Address;
  kind: DisclosureKind;
  component?: DisclosureComponent | undefined;
  /** Single-block kinds. Flow kinds use `blockRange` instead; exactly one is set. */
  block?: bigint | undefined;
  blockRange?: [bigint, bigint] | undefined;
  txHash?: Hex | undefined;
  role?: 'sender' | 'recipient' | undefined;
  direction?: 'in' | 'out' | undefined;
  counterparty?: Address | undefined;
  /** Exact claims set lo = hi = the value. */
  lo: bigint;
  hi: bigint;
  /** Unix seconds. */
  createdAt: number;
  expiresAt: number;
  id: string;
  /** <= 64 chars. Bound here so the label the viewer renders is not forgeable either. */
  label: string;
}

const ZERO = '0x0000000000000000000000000000000000000000' as const;
const ZERO32 = `0x${'00'.repeat(32)}` as const;

const CONTEXT_ABI = [
  { type: 'string' }, { type: 'uint256' }, { type: 'address' }, { type: 'address' },
  { type: 'address' }, { type: 'string' }, { type: 'string' }, { type: 'uint256' },
  { type: 'uint256' }, { type: 'bytes32' }, { type: 'string' }, { type: 'string' },
  { type: 'address' }, { type: 'uint256' }, { type: 'uint256' }, { type: 'uint256' },
  { type: 'uint256' }, { type: 'string' }, { type: 'string' },
] as const;

/**
 * keccak256(abi.encode(...)) mod r, the `context_hash` public input of `dark_disclose_range`
 * and the field the DLEQ challenge commits to. §18b: one fixed tuple, always all 19 members,
 * absent optionals encoding as "" / 0 / the zero address / bytes32(0), and a single-block kind
 * repeating its block in both slots.
 */
export function disclosureContextHash(c: DisclosureContext): bigint {
  const [from, to] = c.blockRange ?? [c.block ?? 0n, c.block ?? 0n];
  const bytes = encodeAbiParameters(CONTEXT_ABI, [
    'DARK-CB-1/disclose/v2', BigInt(c.chainId), c.vault, c.registry, c.account,
    c.kind, c.component ?? '', from, to,
    c.txHash ?? ZERO32, c.role ?? '', c.direction ?? '', c.counterparty ?? ZERO,
    c.lo, c.hi, BigInt(c.createdAt), BigInt(c.expiresAt), c.id, c.label,
  ]);
  return BigInt(keccak256(bytes)) % FIELD_R;
}

// --- the document (§7.7 step 5) ----------------------------------------------------------------

export interface JsonPoint {
  x: Hex;
  y: Hex;
}

/**
 * §7.7 step 5. v2: the document carries every disclosure-context member (`id`, `role`, `direction`,
 * `counterparty` were missing in v1, so the viewer could not rebuild `contextHash` and had to
 * take the document's word for it).
 */
export interface DarkDisclosureV2 {
  v: 2;
  chainId: number;
  vault: Address;
  registry: Address;
  account: Address;
  kind: DisclosureKind;
  component?: DisclosureComponent | undefined;
  /** Decimal strings: JSON has no bigint, and JCS must round-trip exactly. */
  block?: string | undefined;
  blockRange?: [string, string] | undefined;
  txHash?: Hex | undefined;
  role?: 'sender' | 'recipient' | undefined;
  direction?: 'in' | 'out' | undefined;
  counterparty?: Address | undefined;
  pk: JsonPoint;
  c: JsonPoint;
  d: JsonPoint;
  claim: { value: string } | { lo: string; hi: string };
  /** DLEQ (64 B) for exact kinds, the Honk proof for range kinds. */
  proof: Hex;
  contextHash: Hex;
  label: string;
  createdAt: number;
  expiresAt: number;
  /** The disclosure id, also the blob's AAD and the last-but-one disclosure-context member. */
  id: string;
  ownerSig?: Hex | undefined;
}

/** The current document version. */
export const DISCLOSURE_VERSION = 2;

const hex32 = (v: bigint): Hex => `0x${v.toString(16).padStart(64, '0')}`;
const toHexBytes = (b: Uint8Array): Hex => `0x${[...b].map((x) => x.toString(16).padStart(2, '0')).join('')}`;
const fromHexBytes = (h: string): Uint8Array =>
  Uint8Array.from((h.startsWith('0x') ? h.slice(2) : h).match(/../g) ?? [], (b) => parseInt(b, 16));

export const jsonPoint = (p: Pt): JsonPoint => {
  const a = encode(p);
  return { x: hex32(a.x), y: hex32(a.y) };
};

export const pointFromJson = (p: JsonPoint): AffinePoint => ({ x: BigInt(p.x), y: BigInt(p.y) });

/** keccak256 of the RFC 8785 canonical JSON of the document *without* `ownerSig` (§8). */
export function disclosureDigest(doc: DarkDisclosureV2): Hex {
  const { ownerSig: _drop, ...rest } = doc;
  return keccak256(enc.encode(canonicalJson(rest)));
}

/**
 * §8, EIP-712. v1 signed the raw 32-byte JCS digest with `personal_sign`, which is indistinguishable
 * from any other dApp's "sign this hash" prompt: a signature collected elsewhere was a valid Dark
 * disclosure signature. The domain pins the signature to
 * DARK-CB-1 on one chain and one vault, and the five plain fields give the wallet something a
 * human can actually read before approving. `document` binds everything else via the JCS digest.
 */
export const DISCLOSURE_EIP712_TYPES = {
  Disclosure: [
    { name: 'account', type: 'address' },
    { name: 'kind', type: 'string' },
    { name: 'claim', type: 'string' },
    { name: 'label', type: 'string' },
    { name: 'expiresAt', type: 'uint64' },
    { name: 'document', type: 'bytes32' },
  ],
} as const;

// Kept consistent with the shape check above: a claim that carries both keys never reaches here.
const claimText = (claim: DarkDisclosureV2['claim']): string =>
  'value' in claim ? `value=${claim.value}` : `lo=${claim.lo},hi=${claim.hi}`;

/** The exact EIP-712 payload the owner signs and the viewer recovers against. */
export function disclosureTypedData(doc: DarkDisclosureV2) {
  return {
    domain: {
      name: 'DARK-CB-1',
      version: '1',
      chainId: doc.chainId,
      verifyingContract: doc.vault,
    },
    types: DISCLOSURE_EIP712_TYPES,
    primaryType: 'Disclosure',
    message: {
      account: doc.account,
      kind: doc.kind,
      claim: claimText(doc.claim),
      label: doc.label,
      expiresAt: BigInt(doc.expiresAt),
      document: disclosureDigest(doc),
    },
  } as const;
}

export type DisclosureTypedData = ReturnType<typeof disclosureTypedData>;

/** `sign` is a viem `signTypedData` (account or wallet client), never a raw-hash personal_sign. */
export async function signDisclosure(
  doc: DarkDisclosureV2,
  sign: (typedData: DisclosureTypedData) => Promise<Hex>,
): Promise<DarkDisclosureV2> {
  return { ...doc, ownerSig: await sign(disclosureTypedData(doc)) };
}

// --- blob (§7.7 step 6) ------------------------------------------------------------------------

const BLOB_AAD = enc.encode('DARK-CB-1/disclosure-blob/v1');
const NONCE_BYTES = 24;
/** The API enforces this after base64 decoding (§7.7 step 6). */
export const DISCLOSURE_BLOB_MAX = 65_536;

const blobAad = (id: string): Uint8Array => concatBytes(BLOB_AAD, enc.encode(id));

// btoa/atob, not Buffer: this module is vendored verbatim into the public web repo for the /d/<id>
// viewer, and Buffer does not exist in a browser. Both globals are present in Node 16+ too, so there
// is one implementation rather than a copy that has quietly diverged from its source.
export const base64url = (b: Uint8Array): string => {
  let s = '';
  for (const byte of b) s += String.fromCharCode(byte);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

export const fromBase64url = (s: string): Uint8Array => {
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};

/**
 * Plaintext frames (§18b). AEAD is length-preserving, so an unpadded blob's size tracks the
 * JCS length, which tracks the number of digits in the amount -- and the API, the CDN and anyone
 * watching the response store exactly that. Framing leaves one
 * of three sizes: every balance document fits the first, the larger two exist for Honk proofs.
 */
export const DISCLOSURE_FRAMES = [2_048, 16_384, 65_496] as const;

function frame(pt: Uint8Array): Uint8Array {
  const size = DISCLOSURE_FRAMES.find((f) => pt.length + 4 <= f);
  if (size === undefined) {
    const cap = DISCLOSURE_FRAMES[DISCLOSURE_FRAMES.length - 1]! - 4;
    throw new DarkError('AMOUNT_OUT_OF_RANGE', `disclosure document is ${pt.length} B, over the ${cap} B cap`);
  }
  const out = new Uint8Array(size);
  new DataView(out.buffer).setUint32(0, pt.length, false);
  out.set(pt, 4);
  return out;
}

function unframe(framed: Uint8Array): Uint8Array | null {
  if (!(DISCLOSURE_FRAMES as readonly number[]).includes(framed.length)) return null;
  const n = new DataView(framed.buffer, framed.byteOffset, framed.byteLength).getUint32(0, false);
  return n + 4 <= framed.length ? framed.subarray(4, 4 + n) : null;
}

/**
 * Encrypt the framed document under a fresh 32-byte K_link. The blob is nonce(24) || ciphertext,
 * mirroring `aeBalance`.
 */
export function sealDisclosure(
  doc: DarkDisclosureV2,
  id: string,
  key: Uint8Array = crypto.getRandomValues(new Uint8Array(32)),
  nonce: Uint8Array = crypto.getRandomValues(new Uint8Array(NONCE_BYTES)),
): { blob: Uint8Array; key: Uint8Array } {
  if (key.length !== 32) throw new DarkError('DECRYPTION_FAILED', 'K_link must be 32 bytes');
  const ct = xchacha20poly1305(key, nonce, blobAad(id)).encrypt(frame(enc.encode(canonicalJson(doc))));
  const blob = concatBytes(nonce, ct);
  if (blob.length > DISCLOSURE_BLOB_MAX) {
    throw new DarkError('AMOUNT_OUT_OF_RANGE', `disclosure blob is ${blob.length} B, over the ${DISCLOSURE_BLOB_MAX} B cap`);
  }
  return { blob, key };
}

/** Returns null on a bad tag, wrong key, wrong id or a bad frame, so the viewer renders "invalid". */
export function openDisclosure(blob: Uint8Array, key: Uint8Array, id: string): DarkDisclosureV2 | null {
  if (key.length !== 32 || blob.length <= NONCE_BYTES) return null;
  try {
    const framed = xchacha20poly1305(key, blob.subarray(0, NONCE_BYTES), blobAad(id)).decrypt(blob.subarray(NONCE_BYTES));
    const pt = unframe(framed);
    if (!pt) return null;
    const doc = JSON.parse(new TextDecoder().decode(pt)) as DarkDisclosureV2;
    // The AAD binds the id the blob was *stored* under; `doc.id` is the one that goes into the
    // context-hash preimage. They have to be the same id or the rebuild checks the wrong context.
    return doc?.id === id ? doc : null;
  } catch {
    return null;
  }
}

/** §7.7 step 8. The fragment never reaches a server. */
export function disclosureLink(id: string, key: Uint8Array, origin = 'https://darkwallet.cash'): string {
  return `${origin}/d/${id}#k=${base64url(key)}`;
}

/** Parses `/d/<id>#k=<base64url>` back into (id, key). */
export function parseDisclosureLink(url: string): { id: string; key: Uint8Array } {
  const u = new URL(url);
  const id = u.pathname.split('/').filter(Boolean).pop();
  const k = new URLSearchParams(u.hash.replace(/^#/, '')).get('k');
  if (!id || !k) throw new DarkError('DECRYPTION_FAILED', 'not a disclosure link');
  return { id, key: fromBase64url(k) };
}

// --- build + verify ----------------------------------------------------------------------------

export interface BuildDisclosureArgs {
  /** Carries the registry and the label too: every disclosure-context member lives here (§18b). */
  context: DisclosureContext;
  /** The account's registered key and the ciphertext the claim is about. */
  pk: Pt;
  ciphertext: { c: Pt; d: Pt };
  /** The plaintext for exact kinds. */
  value: bigint;
  s: bigint;
  /** Test-only: pins the DLEQ nonce. */
  rand?: Uint8Array;
}

/** An unsigned `DarkDisclosureV2` for an exact kind, with its DLEQ proof (§7.7 steps 3-5). */
export function buildExactDisclosure(a: BuildDisclosureArgs): DarkDisclosureV2 {
  const c = a.context;
  if (c.label.length > 64) throw new DarkError('AMOUNT_OUT_OF_RANGE', 'label longer than 64 chars');
  if (c.lo !== a.value || c.hi !== a.value) {
    throw new DarkError('AMOUNT_OUT_OF_RANGE', 'an exact claim must set context lo = hi = value');
  }
  const contextHash = disclosureContextHash(c);
  const st: DleqStatement = {
    P: a.pk, C: a.ciphertext.c, D: a.ciphertext.d, v: a.value, context: toBytes32(contextHash),
  };
  return {
    v: 2,
    chainId: c.chainId,
    vault: c.vault,
    registry: c.registry,
    account: c.account,
    kind: c.kind,
    component: c.component,
    block: c.block?.toString(10),
    blockRange: c.blockRange?.map((b) => b.toString(10)) as [string, string] | undefined,
    txHash: c.txHash,
    role: c.role,
    direction: c.direction,
    counterparty: c.counterparty,
    pk: jsonPoint(a.pk),
    c: jsonPoint(a.ciphertext.c),
    d: jsonPoint(a.ciphertext.d),
    claim: { value: a.value.toString(10) },
    proof: toHexBytes(dleqToBytes(dleqProve(st, a.s, a.rand))),
    contextHash: hex32(contextHash),
    label: c.label,
    createdAt: c.createdAt,
    expiresAt: c.expiresAt,
    id: c.id,
  };
}

const KINDS: DisclosureKind[] =
  ['balance_exact', 'balance_range', 'transfer_exact', 'flow_total_exact', 'flow_total_range'];
const MAX_BLOCK = 1n << 64n;

/**
 * The disclosure context rebuilt from the document alone (§7.8 step 4). This is the whole point of
 * v2: the viewer holds nothing but the link, so unless every preimage member is a document field it
 * cannot recompute `contextHash` and has to trust it -- which made `expiresAt`, `kind`,
 * `component`, the block range and `label` forgeable by anyone holding the link.
 *
 * Throws on a malformed document; `verifyDisclosure` turns that into `invalid`.
 */
export function contextFromDocument(doc: DarkDisclosureV2): DisclosureContext {
  if (!KINDS.includes(doc.kind)) throw new Error(`unknown kind ${JSON.stringify(doc.kind)}`);
  // The enum members encode as `string` in the disclosure-context tuple, so an unknown value would
  // rebuild consistently and reach the viewer as text to render. Pin them to their sets.
  const oneOf = (v: unknown, name: string, set: readonly string[]) => {
    if (v !== undefined && !set.includes(v as string)) throw new Error(`unknown ${name} ${JSON.stringify(v)}`);
  };
  oneOf(doc.component, 'component', ['available', 'total']);
  oneOf(doc.role, 'role', ['sender', 'recipient']);
  oneOf(doc.direction, 'direction', ['in', 'out']);
  if (typeof doc.label !== 'string' || doc.label.length > 64) throw new Error('label is missing or over 64 chars');
  if (typeof doc.id !== 'string' || doc.id.length === 0 || doc.id.length > 64) throw new Error('id is missing');
  if (!Number.isSafeInteger(doc.createdAt) || doc.createdAt < 0) throw new Error('createdAt is not a unix second');
  if (!Number.isSafeInteger(doc.expiresAt) || doc.expiresAt < 0) throw new Error('expiresAt is not a unix second');

  // Exactly one of block / blockRange, so the "single-block kinds repeat B" rule cannot be used
  // to make two documents hash to the same context.
  const isFlow = doc.kind.startsWith('flow_');
  if (isFlow === (doc.block !== undefined) || isFlow !== Array.isArray(doc.blockRange)) {
    throw new Error('a flow kind needs blockRange and every other kind needs block, never both');
  }
  const blockRange = doc.blockRange
    ? ([numeral(doc.blockRange[0], 'blockRange[0]', MAX_BLOCK),
        numeral(doc.blockRange[1], 'blockRange[1]', MAX_BLOCK)] as [bigint, bigint])
    : undefined;
  if (blockRange && blockRange[0] > blockRange[1]) throw new Error('blockRange is inverted');

  // The claim's SHAPE must match the kind exactly: { value } for exact kinds, { lo, hi } for range
  // kinds, never both. contextHash and the range proof must commit to the same fields.
  const hasValue = 'value' in doc.claim;
  const hasRange = 'lo' in doc.claim || 'hi' in doc.claim;
  const wantsRange = isRangeKind(doc.kind);
  if (hasValue && hasRange) throw new Error('claim must be { value } or { lo, hi }, never both');
  if (wantsRange && !hasRange) throw new Error(`${doc.kind} must claim { lo, hi }`);
  if (!wantsRange && !hasValue) throw new Error(`${doc.kind} must claim { value }`);
  if (wantsRange && hasValue) throw new Error(`${doc.kind} must not claim { value }`);
  if (!wantsRange && hasRange) throw new Error(`${doc.kind} must not claim { lo, hi }`);

  const [lo, hi] = hasValue
    ? [numeral((doc.claim as { value: string }).value, 'claim.value'), numeral((doc.claim as { value: string }).value, 'claim.value')]
    : [numeral((doc.claim as { lo: string }).lo, 'claim.lo'), numeral((doc.claim as { hi: string }).hi, 'claim.hi')];

  return {
    chainId: doc.chainId,
    vault: doc.vault,
    registry: doc.registry,
    account: doc.account,
    kind: doc.kind,
    component: doc.component,
    block: doc.block === undefined ? undefined : numeral(doc.block, 'block', MAX_BLOCK),
    blockRange,
    txHash: doc.txHash,
    role: doc.role,
    direction: doc.direction,
    counterparty: doc.counterparty,
    lo,
    hi,
    createdAt: doc.createdAt,
    expiresAt: doc.expiresAt,
    id: doc.id,
    label: doc.label,
  };
}

export type DisclosureVerdict =
  | 'verified'
  /**
   * The statement checks out, but `d` is the identity, so the ciphertext carries no randomness
   * and anyone can read the amount off the chain (§2, the deposit-only account). Nothing here
   * demonstrates knowledge of the privacy secret, so a link like this can be minted against a
   * victim's address by a stranger. **The viewer must render this differently from `verified`:**
   * "public balance, not proof of ownership".
   */
  | 'public_balance'
  | 'invalid'
  | 'expired'
  | 'unsupported_version';

export interface VerifyDisclosureArgs {
  doc: DarkDisclosureV2;
  /**
   * The (c, d) the viewer read from chain at the document's block (§7.8 step 3). **Required**:
   * without it the document is a self-signed claim about nothing.
   */
  onChain: { c: AffinePoint; d: AffinePoint };
  /** `registry.keyOf(account)`, read from the pinned registry for the chain. **Required**. */
  registryKey: AffinePoint;
  /** Unix seconds; defaults to now. */
  now?: number;
  /** Range kinds need bb.js, which is the viewer's job, not the SDK's. */
  verifyRangeProof?: (proof: Hex, publicInputs: Hex[]) => Promise<boolean>;
}

export interface VerifyDisclosureResult {
  verdict: DisclosureVerdict;
  reason?: string;
}

/**
 * §7.8 step 4, minus the network: the caller supplies the on-chain ciphertext and registry key.
 * Every check is independent of the server that served the blob.
 *
 * The document is attacker-controlled JSON, so **every** exit is a verdict. Anything malformed
 * enough to throw -- a bad hex field, a proof of the wrong length, a claim that is not a numeral --
 * comes back as `invalid` rather than as an exception the viewer has to catch.
 */
export async function verifyDisclosure(a: VerifyDisclosureArgs): Promise<VerifyDisclosureResult> {
  try {
    return await verify(a);
  } catch (e) {
    return { verdict: 'invalid', reason: `malformed document: ${(e as Error).message}` };
  }
}

const DECIMAL = /^(0|[1-9][0-9]*)$/;

/**
 * A claim numeral: a canonical decimal string (no sign, no leading zero, no exponent, no hex)
 * below the circuit's 2^48 amount range. These reach the range proof's public inputs, so they
 * are validated before anything else touches them.
 */
function numeral(v: unknown, what: string, max = MAX_AMOUNT): bigint {
  if (typeof v !== 'string' || !DECIMAL.test(v)) {
    throw new Error(`${what} is not a canonical decimal numeral: ${JSON.stringify(v)}`);
  }
  const n = BigInt(v);
  if (n >= max) throw new Error(`${what} ${v} is out of range`);
  return n;
}

async function verify(a: VerifyDisclosureArgs): Promise<VerifyDisclosureResult> {
  const { doc } = a;
  const no = (reason: string): VerifyDisclosureResult => ({ verdict: 'invalid', reason });
  if (doc.v !== DISCLOSURE_VERSION) {
    return { verdict: 'unsupported_version', reason: `document version ${doc.v}` };
  }
  const now = a.now ?? Math.floor(Date.now() / 1000);
  if (doc.expiresAt <= now) return { verdict: 'expired' };

  // A JS caller can omit what TypeScript marks required; without the chain reads there is nothing
  // to verify against, so this is invalid.
  if (!a.onChain || !a.registryKey) {
    return no('the viewer must supply the on-chain ciphertext and the registry key');
  }
  // Both of those are read at addresses, so the addresses have to be the pinned ones for the
  // chain -- otherwise a forger points the viewer at a vault and registry it controls.
  const dep = deployments[doc.chainId];
  if (!dep || !isDeployed(doc.chainId)) return no(`chain ${doc.chainId} has no pinned Dark deployment`);
  if (doc.vault.toLowerCase() !== dep.vault.toLowerCase() ||
      doc.registry.toLowerCase() !== dep.registry.toLowerCase()) {
    return no('vault or registry is not the pinned deployment for that chain');
  }

  const pk = decode(pointFromJson(doc.pk));
  const C = pointOrIdentity(doc.c);
  const D = pointOrIdentity(doc.d);

  if (a.registryKey.x !== BigInt(doc.pk.x) || a.registryKey.y !== BigInt(doc.pk.y)) {
    return no('pk is not the account\'s registered key');
  }
  const want = { c: encode(C), d: encode(D) };
  if (a.onChain.c.x !== want.c.x || a.onChain.c.y !== want.c.y ||
      a.onChain.d.x !== want.d.x || a.onChain.d.y !== want.d.y) {
    return no('the document\'s ciphertext is not the one on chain at that block');
  }
  // rebuild the context-hash preimage from the document; never trust the field.
  // Everything the viewer renders -- the kind, the component, the block, the expiry, the label --
  // is only as trustworthy as this comparison, because the DLEQ binds nothing but contextHash.
  const rebuilt = hex32(disclosureContextHash(contextFromDocument(doc)));
  if (rebuilt.toLowerCase() !== doc.contextHash.toLowerCase()) {
    return no('contextHash does not rebuild from the document fields');
  }

  // Required: while this was `if (doc.ownerSig)`, dropping the field skipped the only check that
  // ties the document to the account at all.
  if (!doc.ownerSig) return no('the document carries no ownerSig');
  const signer = await recoverTypedDataAddress({ ...disclosureTypedData(doc), signature: doc.ownerSig });
  if (signer.toLowerCase() !== doc.account.toLowerCase()) return no('ownerSig was not made by the account');

  // A ciphertext whose d is the identity has no randomness, so its plaintext is public and the
  // "proof" over it is not a statement of knowledge -- whichever kind carries it.
  const ok = (): VerifyDisclosureResult => (D.is0()
    ? {
      verdict: 'public_balance',
      reason: 'd is the identity, so the amount is already public on chain; this is not proof of ownership',
    }
    : { verdict: 'verified' });

  const isRange = isRangeKind(doc.kind);
  if (isRange) {
    if (!('lo' in doc.claim) || 'value' in doc.claim) return no('a range kind must claim { lo, hi } and nothing else');
    if (!a.verifyRangeProof) return no('range proofs need a bb.js verifier');
    const lo = numeral(doc.claim.lo, 'claim.lo');
    const hi = numeral(doc.claim.hi, 'claim.hi');
    if (lo > hi) return no('claim.lo is above claim.hi');
    const pi: Hex[] = [
      doc.contextHash, doc.pk.x, doc.pk.y, doc.c.x, doc.c.y, doc.d.x, doc.d.y, hex32(lo), hex32(hi),
    ];
    return (await a.verifyRangeProof(doc.proof, pi)) ? ok() : no('range proof did not verify');
  }

  if (!('value' in doc.claim) || 'lo' in doc.claim) return no('an exact kind must claim { value } and nothing else');
  const dleqOk = dleqVerify(
    { P: pk, C, D, v: numeral(doc.claim.value, 'claim.value'), context: fromHexBytes(doc.contextHash) },
    dleqFromBytes(fromHexBytes(doc.proof)),
  );
  return dleqOk ? ok() : no('DLEQ did not verify');
}

/** A stored ciphertext component may legitimately be the identity (an empty account). */
function pointOrIdentity(p: JsonPoint): Pt {
  const a = pointFromJson(p);
  if (a.x === 0n && a.y === 0n) return Point.ZERO;
  if (a.x >= FIELD_R || a.y >= FIELD_R) throw new Error('non-canonical coordinate');
  return decode(a);
}

/**
 * §7.7 step 8: testnet ids start with `t_`. A mainnet id is redrawn until it does not, so the viewer
 * (which routes `t_…` links to the testnet API) can never send a mainnet link to the wrong network.
 */
export function newDisclosureId(chainId: number, rand: Uint8Array = crypto.getRandomValues(new Uint8Array(12))): string {
  if (chainId !== 4663) return `t_${base64url(rand)}`;
  let body = base64url(rand);
  while (body.startsWith('t_')) body = base64url(crypto.getRandomValues(new Uint8Array(12)));
  return body;
}
