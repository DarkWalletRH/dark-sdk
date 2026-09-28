// The witness builders against the committed circuits/*/Prover.toml, which
// circuits/tools/gen_prover.mjs produced from this same SDK. If the two ever disagree, the
// circuits are being proved with numbers the wallet does not produce.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { GROUP_N, G, H, mul } from '../src/grumpkin.ts';
import { encrypt } from '../src/elgamal.ts';
import {
  buildRegisterWitness, buildTransferWitness, buildWithdrawWitness,
  witnessToToml, scalarLimbs, type Witness,
} from '../src/witness.ts';
import { buildPublicInputs } from '../src/publicInputs.ts';
import { isDarkError } from '../src/errors.ts';
import {
  cases, CHAIN_ID, REGISTRY, VAULT, SENDER, RECIPIENT, WITHDRAW_TO, NONCE,
  MIN_TRANSFER, MAX_TRANSFER, BALANCE, AMOUNT, WITHDRAW_AMOUNT,
  senderKeys, recipientKeys, availRho, avail, r, ct,
} from './scenario.ts';

// --- the committed prover files ------------------------------------------------------------
/** Flatten a Prover.toml into name -> bigint, with points as `name.x` / `name.y`. */
function readProverToml(crate: string): Map<string, bigint> {
  const text = readFileSync(fileURLToPath(new URL(`../../../circuits/${crate}/Prover.toml`, import.meta.url)), 'utf8');
  const out = new Map<string, bigint>();
  let table = '';
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\s*#.*$/, '').trim();
    if (!line) continue;
    const t = line.match(/^\[(.+)\]$/);
    if (t) {
      table = `${t[1]}.`;
      continue;
    }
    const m = line.match(/^(\w+)\s*=\s*"(.*)"$/);
    if (m) out.set(`${table}${m[1]}`, BigInt(m[2]));
  }
  return out;
}

function flatten(w: Witness): Map<string, bigint> {
  const out = new Map<string, bigint>();
  for (const [k, v] of Object.entries(w)) {
    if (typeof v === 'string') out.set(k, BigInt(v));
    else {
      out.set(`${k}.x`, BigInt(v.x));
      out.set(`${k}.y`, BigInt(v.y));
    }
  }
  return out;
}


for (const [crate, witness] of Object.entries(cases)) {
  test(`${crate}: the witness equals the committed Prover.toml, value for value`, () => {
    const want = readProverToml(crate);
    const got = flatten(witness);
    assert.deepEqual([...got.keys()].sort(), [...want.keys()].sort());
    for (const [k, v] of want) assert.equal(got.get(k), v, `${crate}.${k}`);
  });
}

test('limbs reconstruct the scalar, and (0, 0) is never a legal scalar', () => {
  const { s_lo, s_hi } = scalarLimbs('s', senderKeys.s) as Record<string, string>;
  assert.equal((BigInt(s_hi) << 128n) | BigInt(s_lo), senderKeys.s);
  assert.throws(() => scalarLimbs('s', 0n), (e: unknown) => isDarkError(e));
  assert.throws(() => scalarLimbs('s', GROUP_N), (e: unknown) => isDarkError(e));
});

test('a witness feeds buildPublicInputs directly', () => {
  const pi = buildPublicInputs('dark_transfer', cases.transfer);
  assert.equal(pi.length, 21);
  assert.equal(BigInt(pi[0]), BigInt(CHAIN_ID));
  assert.equal(BigInt(pi[1]), BigInt(VAULT));
  assert.equal(BigInt(pi[13]), BigInt((cases.transfer.ct_c as { x: string }).x));
  assert.equal(BigInt(pi[20]), MAX_TRANSFER);
});

test('the builders refuse an inconsistent witness rather than proving it', () => {
  const wrong = { ...senderKeys, s: senderKeys.s + 1n };
  assert.throws(
    () => buildRegisterWitness({ chainId: CHAIN_ID, registry: REGISTRY, account: SENDER, s: wrong.s, pk: senderKeys.P }),
    (e: unknown) => isDarkError(e) && /s \* pk != H/.test(e.message),
  );
  assert.throws(
    () => buildWithdrawWitness({
      chainId: CHAIN_ID, vault: VAULT, account: SENDER, to: WITHDRAW_TO, nonce: NONCE,
      s: senderKeys.s, amount: BALANCE + 1n, balance: BALANCE, pk: senderKeys.P, avail,
    }),
    (e: unknown) => isDarkError(e) && /does not cover/.test(e.message),
  );
  // A stale `available` read: the ciphertext no longer decrypts to the balance we think we have.
  const stale = encrypt(BALANCE - 1n, [senderKeys.P], availRho);
  assert.throws(
    () => buildWithdrawWitness({
      chainId: CHAIN_ID, vault: VAULT, account: SENDER, to: WITHDRAW_TO, nonce: NONCE,
      s: senderKeys.s, amount: WITHDRAW_AMOUNT, balance: BALANCE, pk: senderKeys.P,
      avail: { c: stale.C, d: stale.D[0] },
    }),
    (e: unknown) => isDarkError(e) && /remainder is not w\*G/.test(e.message),
  );
  assert.throws(
    () => buildTransferWitness({
      chainId: CHAIN_ID, vault: VAULT, sender: SENDER, recipient: RECIPIENT, senderNonce: NONCE,
      s: senderKeys.s, r, amount: MIN_TRANSFER - 1n, balance: BALANCE,
      pkS: senderKeys.P, pkR: recipientKeys.P, avail, ct,
      minTransfer: MIN_TRANSFER, maxTransfer: MAX_TRANSFER,
    }),
    (e: unknown) => isDarkError(e) && /min_transfer/.test(e.message),
  );
});

test('witnessToToml keeps every scalar above the first [table] header', () => {
  const toml = witnessToToml(cases.withdraw);
  assert.ok(toml.indexOf('amount = ') < toml.indexOf('[pk]'), 'a scalar fell below a table header');
  assert.match(toml, /\n\[avail_d\]\nx = "0x[0-9a-f]{64}"\ny = "0x[0-9a-f]{64}"\n/);
});

test('a full-balance spend leaves w = 0, i.e. the identity remainder', () => {
  const full = encrypt(AMOUNT, [senderKeys.P, recipientKeys.P], r);
  const w = buildTransferWitness({
    chainId: CHAIN_ID, vault: VAULT, sender: SENDER, recipient: RECIPIENT, senderNonce: NONCE,
    s: senderKeys.s, r, amount: AMOUNT, balance: AMOUNT,
    pkS: senderKeys.P, pkR: recipientKeys.P,
    avail: { c: full.C, d: full.D[0] },
    ct: { c: full.C, ds: full.D[0], dr: full.D[1] },
    minTransfer: MIN_TRANSFER, maxTransfer: MAX_TRANSFER,
  });
  assert.equal(w.w, '0');
  assert.ok(mul(G, 0n).is0());
  assert.ok(mul(senderKeys.P, senderKeys.s).equals(H));
});
