import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { privateKeyToAccount } from 'viem/accounts';
import { G, H, Point, GROUP_N, mul, encode, decode } from '../src/grumpkin.ts';
import { deriveDarkKeys } from '../src/keys.ts';
import { encrypt, publicCiphertext } from '../src/elgamal.ts';
import {
  buildExactDisclosure, canonicalJson, contextFromDocument, disclosureContextHash, disclosureDigest, disclosureLink,
  dleqFromBytes, dleqProve, dleqToBytes, dleqVerify, jsonPoint, openDisclosure, parseDisclosureLink,
  sealDisclosure, signDisclosure, verifyDisclosure, newDisclosureId, disclosureTypedData,
  DISCLOSURE_BLOB_MAX,
  type DarkDisclosureV2, type DisclosureContext,
} from '../src/disclosure.ts';
import { isDarkError } from '../src/errors.ts';

const VECTORS = JSON.parse(
  readFileSync(fileURLToPath(new URL('./vectors/disclosure.v2.json', import.meta.url)), 'utf8'),
);

const CHAIN_ID = 46630;
const keys = deriveDarkKeys(Uint8Array.from(Buffer.from(VECTORS.sk.slice(2), 'hex')), CHAIN_ID);
const account = privateKeyToAccount(VECTORS.sk);
const bytes = (h: string) => Uint8Array.from(Buffer.from(h.slice(2), 'hex'));

const LABEL = 'Payroll proof of funds';

const ctx = (over: Partial<DisclosureContext> = {}): DisclosureContext => ({
  chainId: CHAIN_ID,
  vault: VECTORS.vault,
  registry: VECTORS.registry,
  account: account.address,
  kind: 'balance_exact',
  component: 'available',
  block: BigInt(VECTORS.context.block),
  lo: BigInt(VECTORS.value),
  hi: BigInt(VECTORS.value),
  createdAt: VECTORS.context.createdAt,
  expiresAt: VECTORS.context.expiresAt,
  id: VECTORS.context.id,
  label: LABEL,
  ...over,
});

const stored = (() => {
  const e = encrypt(BigInt(VECTORS.value), [keys.P], BigInt(VECTORS.availRho));
  return { c: e.C, d: e.D[0] };
})();

// --- RFC 8785 --------------------------------------------------------------------------------

test('canonicalJson follows RFC 8785: sorted keys, no space, dropped undefined', () => {
  assert.equal(canonicalJson({ b: 1, a: 2 }), '{"a":2,"b":1}');
  // §3.2.3 of RFC 8785: keys sort by UTF-16 code unit, so uppercase sorts before lowercase.
  assert.equal(canonicalJson({ a: 1, A: 2, 'ä': 3, '\u000b': 4 }), '{"\\u000b":4,"A":2,"a":1,"ä":3}');
  assert.equal(canonicalJson({ a: undefined, b: null }), '{"b":null}');
  assert.equal(canonicalJson([1, 'x', true, null]), '[1,"x",true,null]');
  assert.equal(canonicalJson({ n: 1e21 }), '{"n":1e+21}');
  assert.throws(() => canonicalJson({ n: 1n }), (e: unknown) => isDarkError(e));
  assert.throws(() => canonicalJson({ n: Number.NaN }), (e: unknown) => isDarkError(e));
});

// --- DLEQ ------------------------------------------------------------------------------------

test('DLEQ proves and verifies the exact plaintext, and nothing else', () => {
  const v = BigInt(VECTORS.value);
  const st = { P: keys.P, C: stored.c, D: stored.d, v, context: new Uint8Array(32).fill(7) };
  const proof = dleqProve(st, keys.s);
  assert.ok(dleqVerify(st, proof));
  // A different claimed value, a different context, or a tampered proof must all fail.
  assert.equal(dleqVerify({ ...st, v: v + 1n }, proof), false);
  assert.equal(dleqVerify({ ...st, context: new Uint8Array(32).fill(8) }, proof), false);
  assert.equal(dleqVerify(st, { ...proof, z: proof.z + 1n }), false);
  assert.equal(dleqVerify(st, { ...proof, c: proof.c + 1n }), false);
  // Swapping in someone else's key breaks s*P = H.
  const other = deriveDarkKeys(new Uint8Array(32).fill(0x22), CHAIN_ID);
  assert.equal(dleqVerify({ ...st, P: other.P }, proof), false);
  assert.equal(dleqToBytes(proof).length, 64);
  assert.deepEqual(dleqFromBytes(dleqToBytes(proof)), proof);
});

test('DLEQ refuses to prove a statement that is not true', () => {
  const st = { P: keys.P, C: stored.c, D: stored.d, v: 1n, context: new Uint8Array(32) };
  assert.throws(() => dleqProve(st, keys.s), (e: unknown) => isDarkError(e) && /not the plaintext/.test(e.message));
  assert.throws(
    () => dleqProve({ ...st, v: BigInt(VECTORS.value) }, keys.s + 1n),
    (e: unknown) => isDarkError(e) && e.code === 'KEY_DERIVATION_MISMATCH',
  );
});

test('a public amount has D = identity, and then the verifier just checks C == v*G', () => {
  const pub = publicCiphertext(42n);
  const st = { P: keys.P, C: pub.c, D: pub.d, v: 42n, context: new Uint8Array(32) };
  assert.ok(st.D.is0());
  assert.ok(dleqVerify(st, { c: 1n, z: 1n }));
  assert.equal(dleqVerify({ ...st, v: 43n }, { c: 1n, z: 1n }), false);
  // the (c, z) range check must run before the identity short-circuit, or a
  // structurally impossible proof is accepted whenever D happens to be the identity.
  assert.equal(dleqVerify(st, { c: 0n, z: 0n }), false);
  assert.equal(dleqVerify(st, { c: GROUP_N, z: 1n }), false);
  assert.equal(dleqVerify(st, { c: 1n, z: GROUP_N }), false);
});

test('the DLEQ hedge folds the statement, so a dead RNG cannot reuse k across two disclosures', () => {
  // with the nonce hedged over (tag, rand, s, context) only, two disclosures in
  // the same context over different ciphertexts share k when the RNG repeats, and k1 == k2 with
  // c1 != c2 gives s = (z1 - z2)/(c2 - c1). k is recoverable here as z + c*s because we hold s.
  const dead = new Uint8Array(32).fill(0x11);
  const context = new Uint8Array(32).fill(9);
  const a = encrypt(7n, [keys.P], 1234n);
  const b = encrypt(9n, [keys.P], 5678n);
  const p1 = dleqProve({ P: keys.P, C: a.C, D: a.D[0], v: 7n, context }, keys.s, dead);
  const p2 = dleqProve({ P: keys.P, C: b.C, D: b.D[0], v: 9n, context }, keys.s, dead);
  const k = (p: { c: bigint; z: bigint }) => (p.z + p.c * keys.s) % GROUP_N;
  assert.notEqual(k(p1), k(p2), 'the DLEQ nonce must depend on P, C, D and v, not just the context');
});

test('the challenge commits to every statement element and both prover messages', () => {
  // Swapping C and D (both real points) must change the challenge, which is the phantom-challenge
  // class of bug: a challenge over a subset would accept the swap.
  const v = BigInt(VECTORS.value);
  const st = { P: keys.P, C: stored.c, D: stored.d, v, context: new Uint8Array(32) };
  const proof = dleqProve(st, keys.s);
  assert.equal(dleqVerify({ ...st, C: stored.d, D: stored.c }, proof), false);
  assert.equal(dleqVerify({ ...st, P: Point.ZERO }, proof), false);
});

// --- vectors ---------------------------------------------------------------------------------

test('the committed vectors are what the SDK produces today', () => {
  const out = execFileSync(process.execPath, [
    '--import', 'tsx', fileURLToPath(new URL('../scripts/gen-disclosure-vectors.mjs', import.meta.url)),
  ], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  assert.match(out, /wrote /);
  const fresh = JSON.parse(readFileSync(fileURLToPath(new URL('./vectors/disclosure.v2.json', import.meta.url)), 'utf8'));
  assert.deepEqual(fresh, VECTORS, 'disclosure vectors are stale: regenerate and commit');
});

test('every vector field reproduces from sk alone (the cross-implementation contract)', async () => {
  assert.equal(account.address, VECTORS.account);
  assert.equal(`0x${keys.s.toString(16).padStart(64, '0')}`, VECTORS.s);
  assert.deepEqual(jsonPoint(keys.P), VECTORS.pk);
  assert.deepEqual({ c: jsonPoint(stored.c), d: jsonPoint(stored.d) }, VECTORS.ciphertext);

  const contextHash = disclosureContextHash(ctx());
  assert.equal(`0x${contextHash.toString(16).padStart(64, '0')}`, VECTORS.contextHash);

  const unsigned = buildExactDisclosure({
    context: ctx(),
    pk: keys.P,
    ciphertext: stored,
    value: BigInt(VECTORS.value),
    s: keys.s,
    rand: bytes(VECTORS.dleqRand),
  });
  assert.equal(unsigned.proof, VECTORS.proof);
  assert.equal(canonicalJson(unsigned), VECTORS.jcsUnsigned);
  assert.equal(disclosureDigest(unsigned), VECTORS.digest);

  const doc = await signDisclosure(unsigned, (td) => account.signTypedData(td));
  assert.equal(doc.ownerSig, VECTORS.ownerSig);
  assert.equal(canonicalJson(doc), VECTORS.jcsSigned);

  const { blob } = sealDisclosure(doc, VECTORS.context.id, bytes(VECTORS.blobKey), bytes(VECTORS.blobNonce));
  assert.equal(Buffer.from(blob).toString('base64'), VECTORS.blob);
  assert.equal(disclosureLink(VECTORS.context.id, bytes(VECTORS.blobKey)), VECTORS.link);
});

// --- blob ------------------------------------------------------------------------------------

test('the blob round-trips only under the right key and id, and the key rides the fragment', () => {
  const doc = JSON.parse(VECTORS.jcsSigned) as DarkDisclosureV2;
  const { blob, key } = sealDisclosure(doc, VECTORS.context.id);
  assert.deepEqual(openDisclosure(blob, key, VECTORS.context.id), doc);
  assert.equal(openDisclosure(blob, key, 'another-id'), null);
  assert.equal(openDisclosure(blob, new Uint8Array(32), VECTORS.context.id), null);
  assert.equal(openDisclosure(blob.slice(0, 40), key, VECTORS.context.id), null);
  assert.ok(blob.length < DISCLOSURE_BLOB_MAX);

  const link = disclosureLink(VECTORS.context.id, key);
  assert.ok(!link.includes('?'), 'the key must not be a query parameter');
  assert.equal(link.split('#')[0], `https://darkwallet.cash/d/${VECTORS.context.id}`);
  const parsed = parseDisclosureLink(link);
  assert.equal(parsed.id, VECTORS.context.id);
  assert.deepEqual(parsed.key, key);
});

test('the blob is a fixed frame, so its length does not leak the amount', () => {
  // AEAD is length-preserving, so an unpadded blob's size
  // tracked the JCS length, which tracks the digit count of the amount. Whoever stores the blob
  // (the API, the CDN, anyone watching the response) reads that for free.
  const doc = JSON.parse(VECTORS.jcsSigned) as DarkDisclosureV2;
  const sizes = new Set<number>();
  for (const value of ['0', '7', '123456', '281474976710655']) {
    for (const label of ['', 'x'.repeat(64)]) {
      const { blob } = sealDisclosure({ ...doc, claim: { value }, label }, VECTORS.context.id);
      sizes.add(blob.length);
    }
  }
  assert.equal(sizes.size, 1, `blob length varies with the document: ${[...sizes].join(', ')}`);
  assert.equal([...sizes][0], 24 + 2_048 + 16, 'nonce + the 2 KiB frame + the Poly1305 tag');

  // And the frame round-trips: a document that is not a whole frame is refused.
  const { blob, key } = sealDisclosure(doc, VECTORS.context.id);
  assert.deepEqual(openDisclosure(blob, key, VECTORS.context.id), doc);
  assert.equal(openDisclosure(blob.subarray(0, blob.length - 1), key, VECTORS.context.id), null);
});

test('an oversized document is refused rather than silently truncated', () => {
  const doc = { ...JSON.parse(VECTORS.jcsSigned), label: 'x'.repeat(DISCLOSURE_BLOB_MAX) } as DarkDisclosureV2;
  assert.throws(() => sealDisclosure(doc, 't_x'), (e: unknown) => isDarkError(e) && e.code === 'AMOUNT_OUT_OF_RANGE');
});

test('testnet ids are prefixed, mainnet ids are not', () => {
  assert.match(newDisclosureId(46630), /^t_/);
  assert.doesNotMatch(newDisclosureId(4663), /^t_/);
});

// --- verify ----------------------------------------------------------------------------------

async function signedDoc(): Promise<DarkDisclosureV2> {
  const unsigned = buildExactDisclosure({
    context: ctx(),
    pk: keys.P, ciphertext: stored, value: BigInt(VECTORS.value), s: keys.s,
  });
  return signDisclosure(unsigned, (td) => account.signTypedData(td));
}

const onChain = () => ({ c: encode(stored.c), d: encode(stored.d) });
const chainRead = () => ({ onChain: onChain(), registryKey: keys.publicKey });

test('verifyDisclosure checks the document against the ciphertext read from chain', async () => {
  const doc = await signedDoc();
  const now = VECTORS.context.createdAt;
  assert.deepEqual(
    await verifyDisclosure({ doc, ...chainRead(), now }),
    { verdict: 'verified' },
  );

  // A different ciphertext at that block -- the server or the document is lying.
  const other = encrypt(BigInt(VECTORS.value), [keys.P], 12345n);
  assert.equal(
    (await verifyDisclosure({
      doc, onChain: { c: encode(other.C), d: encode(other.D[0]) }, registryKey: keys.publicKey, now,
    })).verdict,
    'invalid',
  );
  // A registry key that is not the document's pk.
  assert.equal(
    (await verifyDisclosure({ doc, onChain: onChain(), registryKey: { x: 1n, y: 2n }, now })).verdict,
    'invalid',
  );
  // A claim edited after signing.
  assert.equal(
    (await verifyDisclosure({ doc: { ...doc, claim: { value: '1' } }, ...chainRead(), now })).verdict,
    'invalid',
  );
  // A contextHash that is not the one the document's own fields hash to.
  assert.equal(
    (await verifyDisclosure({
      doc: { ...doc, contextHash: `0x${disclosureContextHash(ctx({ component: 'total' })).toString(16).padStart(64, '0')}` },
      ...chainRead(), now,
    })).verdict,
    'invalid',
  );
  // Someone else's signature.
  const forged = await signDisclosure(
    { ...doc, ownerSig: undefined },
    (td) => privateKeyToAccount(`0x${'22'.repeat(32)}`).signTypedData(td),
  );
  assert.equal((await verifyDisclosure({ doc: forged, ...chainRead(), now })).verdict, 'invalid');
});

test('a disclosure with no chain read, or over an unpinned vault, is never "verified"', async () => {
  // both reads used to be optional, so a document invented from nothing came
  // back `verified`. They are required now, and the addresses they are read at must be the
  // deployment this SDK pins for the chain.
  const doc = await signedDoc();
  const now = VECTORS.context.createdAt;
  const bare = { doc, now } as unknown as Parameters<typeof verifyDisclosure>[0];
  assert.equal((await verifyDisclosure(bare)).verdict, 'invalid');
  assert.equal(
    (await verifyDisclosure({ doc, onChain: onChain(), now } as unknown as Parameters<typeof verifyDisclosure>[0])).verdict,
    'invalid',
  );
  assert.equal(
    (await verifyDisclosure({ doc, registryKey: keys.publicKey, now } as unknown as Parameters<typeof verifyDisclosure>[0])).verdict,
    'invalid',
  );
  assert.equal(
    (await verifyDisclosure({ doc: { ...doc, vault: `0x${'ab'.repeat(20)}` }, ...chainRead(), now })).verdict,
    'invalid',
  );
  assert.equal(
    (await verifyDisclosure({ doc: { ...doc, registry: `0x${'ab'.repeat(20)}` }, ...chainRead(), now })).verdict,
    'invalid',
  );
  assert.equal((await verifyDisclosure({ doc: { ...doc, chainId: 1 }, ...chainRead(), now })).verdict, 'invalid');
});

test('every rendered field is bound: the verifier rebuilds contextHash from the document', async () => {
  // the DLEQ binds only contextHash, and contextHash used to be taken from the
  // document. Anyone holding the link could then restate the claim -- a later expiry, a different
  // component, another block, another label -- and still read "Verified". ownerSig is dropped on
  // each forgery so it is the rebuild, not the signature, that has to catch it.
  const signed = await signedDoc();
  const now = VECTORS.context.createdAt;
  // Each forgery is re-signed by the real account, so the signature check cannot be what rejects
  // it -- only the rebuild can.
  const verdict = async (over: Partial<DarkDisclosureV2>) => {
    const doc = await signDisclosure({ ...signed, ...over, ownerSig: undefined } as DarkDisclosureV2,
      (td) => account.signTypedData(td));
    return (await verifyDisclosure({ doc, ...chainRead(), now })).verdict;
  };

  assert.equal(await verdict({}), 'verified', 'the untouched document still verifies');
  assert.equal(await verdict({ expiresAt: signed.expiresAt + 86_400 }), 'invalid');
  assert.equal(await verdict({ kind: 'transfer_exact' }), 'invalid');
  assert.equal(await verdict({ component: 'total' }), 'invalid');
  assert.equal(await verdict({ block: '1' }), 'invalid');
  assert.equal(await verdict({ label: 'Proof of $50,000,000' }), 'invalid');
  assert.equal(await verdict({ createdAt: signed.createdAt - 1 }), 'invalid');
  assert.equal(await verdict({ id: 't_other' }), 'invalid');
  assert.equal(await verdict({ account: `0x${'cd'.repeat(20)}` }), 'invalid');
  // A single-block kind must not also carry a block range, or two documents share one context.
  assert.equal(await verdict({ blockRange: ['1', '2'] }), 'invalid');
  assert.equal(await verdict({ block: undefined }), 'invalid');
});

test('a malformed document is a verdict, never a thrown exception', async () => {
  // these used to escape verifyDisclosure as exceptions, so the viewer's
  // "Verified / Invalid" switch never saw them.
  const doc = await signedDoc();
  const now = VECTORS.context.createdAt;
  const verdict = async (over: Record<string, unknown>) =>
    (await verifyDisclosure({ doc: { ...doc, ...over } as DarkDisclosureV2, ...chainRead(), now })).verdict;

  assert.equal(await verdict({ pk: { x: 'nope', y: '0x1' } }), 'invalid');
  assert.equal(await verdict({ proof: '0xzz' }), 'invalid');
  assert.equal(await verdict({ proof: '0x00' }), 'invalid');
  assert.equal(await verdict({ contextHash: 'not-hex' }), 'invalid');
  assert.equal(await verdict({ ownerSig: '0x1234' }), 'invalid');
  assert.equal(await verdict({ claim: {} }), 'invalid');
  // The enum members encode as `string` in W1, so an unknown value would rebuild consistently
  // and land in the viewer as text to render.
  assert.equal(await verdict({ component: 'whatever' as 'total' }), 'invalid');
  assert.equal(await verdict({ role: 'auditor' as 'sender' }), 'invalid');
  assert.equal(await verdict({ direction: 'sideways' as 'in' }), 'invalid');
  assert.equal(await verdict({ kind: 'balance_available' as 'balance_exact' }), 'invalid');
  assert.equal(await verdict({ label: 'x'.repeat(65) }), 'invalid');

  // Claim numerals feed the range proof's public inputs, so they are validated first.
  for (const v of ['', ' 1', '01', '1e3', '-1', '0x10', '1.0', String(1n << 48n), 42, null]) {
    assert.equal(await verdict({ claim: { value: v } }), 'invalid', `claim value ${JSON.stringify(v)}`);
  }
  const range = { kind: 'balance_range' as const, claim: { lo: '-1', hi: '2' } };
  assert.equal(
    (await verifyDisclosure({
      doc: { ...doc, ...range }, ...chainRead(), now, verifyRangeProof: async () => true,
    })).verdict,
    'invalid',
    'a negative lo must never reach the range verifier as a public input',
  );
  assert.equal(
    (await verifyDisclosure({
      doc: { ...doc, kind: 'balance_range' as const, claim: { lo: '5', hi: '4' } },
      ...chainRead(), now, verifyRangeProof: async () => true,
    })).verdict,
    'invalid',
    'an inverted range is not a statement',
  );
});

test('expiry and version are their own verdicts, not "invalid"', async () => {
  const doc = await signedDoc();
  assert.equal((await verifyDisclosure({ doc, ...chainRead(), now: doc.expiresAt })).verdict, 'expired');
  assert.equal(
    (await verifyDisclosure({
      doc: { ...doc, v: 99 as 1 }, ...chainRead(), now: VECTORS.context.createdAt,
    })).verdict,
    'unsupported_version',
  );
});

/** A well-formed range document: same ciphertext, a real contextHash, a stand-in Honk proof. */
async function rangeDoc(lo: bigint, hi: bigint): Promise<DarkDisclosureV2> {
  const context = ctx({ kind: 'balance_range', lo, hi });
  const base = await signedDoc();
  const edited: DarkDisclosureV2 = {
    ...base,
    ownerSig: undefined,
    kind: 'balance_range',
    claim: { lo: lo.toString(10), hi: hi.toString(10) },
    contextHash: `0x${disclosureContextHash(context).toString(16).padStart(64, '0')}`,
    proof: `0x${'ab'.repeat(64)}`,
  };
  return signDisclosure(edited, (td) => account.signTypedData(td));
}

test('a range kind needs a bb.js verifier and gets the §6 C4 public inputs in order', async () => {
  const doc = await rangeDoc(1n, 2n);
  const now = VECTORS.context.createdAt;
  assert.equal((await verifyDisclosure({ doc, ...chainRead(), now })).verdict, 'invalid');
  let seen: string[] = [];
  const r = await verifyDisclosure({
    doc, ...chainRead(), now,
    verifyRangeProof: async (_p, pi) => {
      seen = pi;
      return true;
    },
  });
  assert.equal(r.verdict, 'verified');
  assert.deepEqual(seen, [
    doc.contextHash, doc.pk.x, doc.pk.y, doc.c.x, doc.c.y, doc.d.x, doc.d.y,
    `0x${(1n).toString(16).padStart(64, '0')}`, `0x${(2n).toString(16).padStart(64, '0')}`,
  ]);
});

test('a d = identity claim is "public_balance", never "verified"', async () => {
  // a deposit-only balance stores (x*G, identity), so its value
  // is public (§2) and the DLEQ over it demonstrates no knowledge of s. Rendering that as
  // "Verified" would let a stranger mint a proof-looking link attributed to a victim.
  const empty = { c: Point.ZERO, d: Point.ZERO };
  const context = ctx({ lo: 0n, hi: 0n, label: 'empty' });
  const unsigned = buildExactDisclosure({
    context, pk: keys.P, ciphertext: empty, value: 0n, s: keys.s,
  });
  assert.equal(unsigned.c.x, `0x${'0'.repeat(64)}`);
  const doc = await signDisclosure(unsigned, (td) => account.signTypedData(td));
  const r = await verifyDisclosure({
    doc, onChain: { c: { x: 0n, y: 0n }, d: { x: 0n, y: 0n } },
    registryKey: keys.publicKey, now: VECTORS.context.createdAt,
  });
  assert.equal(r.verdict, 'public_balance');
  assert.match(r.reason ?? '', /not proof of ownership/);

  // Same for a real deposit-only balance: (x*G, identity) with x != 0.
  const pub = publicCiphertext(1_000n);
  const c2 = ctx({ lo: 1_000n, hi: 1_000n, label: 'deposit only' });
  const d2 = await signDisclosure(
    buildExactDisclosure({ context: c2, pk: keys.P, ciphertext: { c: pub.c, d: pub.d }, value: 1_000n, s: keys.s }),
    (td) => account.signTypedData(td),
  );
  const r2 = await verifyDisclosure({
    doc: d2, onChain: { c: encode(pub.c), d: { x: 0n, y: 0n } },
    registryKey: keys.publicKey, now: VECTORS.context.createdAt,
  });
  assert.equal(r2.verdict, 'public_balance');
});

test('ownerSig is EIP-712 under the Dark domain, not a blind hash signature', async () => {
  // v1 signed the raw 32-byte JCS digest with personal_sign, so
  // any other dApp's "sign this hash" prompt produced a valid Dark disclosure signature.
  const doc = await signedDoc();
  const now = VECTORS.context.createdAt;
  const td = disclosureTypedData(doc);
  assert.equal(td.domain.name, 'DARK-CB-1');
  assert.equal(td.domain.version, '1');
  assert.equal(td.domain.chainId, CHAIN_ID);
  assert.equal(td.domain.verifyingContract, VECTORS.vault);
  assert.equal(td.message.document, disclosureDigest(doc));

  // The same account signing the same digest the v1 way must not produce a usable ownerSig.
  const blind = await account.signMessage({ message: { raw: disclosureDigest(doc) } });
  assert.notEqual(blind, doc.ownerSig);
  assert.equal(
    (await verifyDisclosure({ doc: { ...doc, ownerSig: blind }, ...chainRead(), now })).verdict,
    'invalid',
  );
  // And a signature made under another domain does not carry over either.
  const otherDomain = await account.signTypedData({
    ...td, domain: { ...td.domain, name: 'SomeOtherDapp' },
  });
  assert.equal(
    (await verifyDisclosure({ doc: { ...doc, ownerSig: otherDomain }, ...chainRead(), now })).verdict,
    'invalid',
  );
});

test('an unsigned document is never verified', async () => {
  // the ownerSig branch was `if (doc.ownerSig)`, so omitting the
  // field skipped the only check binding the document to the account.
  const { ownerSig: _drop, ...bare } = await signedDoc();
  const r = await verifyDisclosure({
    doc: bare as DarkDisclosureV2, ...chainRead(), now: VECTORS.context.createdAt,
  });
  assert.equal(r.verdict, 'invalid');
  assert.match(r.reason ?? '', /ownerSig/);
});

test('the SDK-side invariants the disclosure rests on still hold', () => {
  assert.ok(mul(keys.P, keys.s).equals(H));
  assert.ok(decode(encode(G)).equals(G));
});

test('a claim cannot carry both value and lo/hi (red-team: false exact balance shown as Verified)', () => {
  // The attack: kind `balance_range` with claim {value: 1_000_000 USDG, lo: 0, hi: 2^48-1}.
  // contextFromDocument preferred `value`, so contextHash was built from the huge figure; the range
  // path preferred `lo`/`hi`, so the PROOF only had to show 0 <= balance <= 2^48-1, which is true of
  // any balance. `context_hash` is a free public input, so that proof verified. The owner signs the
  // document themselves and pk/c/d are genuinely theirs, so every other check passed — and the
  // viewer, also branching on `value`, told a stranger the balance was 1,000,000 USDG.
  const base = {
    v: 2, chainId: 46630,
    vault: '0x00000000000000000000000000000000000000fa', // any address: contextFromDocument does not check pins
    registry: '0x00000000000000000000000000000000000000ce',
    account: `0x${'ab'.repeat(20)}`,
    kind: 'balance_range', component: 'available', block: '1000',
    pk: { x: '0x1', y: '0x2' }, c: { x: '0x3', y: '0x4' }, d: { x: '0x5', y: '0x6' },
    proof: '0x00', contextHash: '0x00', label: 'x', createdAt: 1, expiresAt: 2, id: 't_aaaaaaaaaaaaaaaa',
  } as never as DarkDisclosureV2;

  assert.throws(
    () => contextFromDocument({ ...base, claim: { value: '1000000000000', lo: '0', hi: '281474976710655' } } as never),
    /never both/,
    'a claim carrying both shapes must be rejected outright',
  );

  // A range kind must not smuggle an exact figure in, and vice versa.
  assert.throws(() => contextFromDocument({ ...base, claim: { value: '5' } } as never), /must claim \{ lo, hi \}/);
  assert.throws(
    () => contextFromDocument({ ...base, kind: 'balance_exact', claim: { lo: '0', hi: '9' } } as never),
    /must claim \{ value \}/,
  );

  // The honest shapes still work.
  assert.doesNotThrow(() => contextFromDocument({ ...base, claim: { lo: '0', hi: '9' } } as never));
  assert.doesNotThrow(() => contextFromDocument({ ...base, kind: 'balance_exact', claim: { value: '5' } } as never));
});
