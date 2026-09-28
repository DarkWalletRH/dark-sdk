import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { deriveDarkKeys, keysAreConsistent, checkRegistryKey, invModN } from '../src/keys.ts';
import { H, GROUP_N, mul, encode } from '../src/grumpkin.ts';

const FILE = fileURLToPath(new URL('./vectors/keys.v1.json', import.meta.url));

interface Vector {
  label: string;
  sk: string;
  chainId: number;
  s: string;
  px: string;
  py: string;
  kAe: string;
  ctr: number;
}

const INPUTS: Array<{ label: string; sk: string; chainId: number }> = [
  { label: 'sk=0x01 testnet', sk: `0x${'00'.repeat(31)}01`, chainId: 46630 },
  { label: 'sk=0x01 mainnet', sk: `0x${'00'.repeat(31)}01`, chainId: 4663 },
  { label: 'sk=0xff.. testnet', sk: `0x${'ff'.repeat(32)}`, chainId: 46630 },
  { label: 'sk=counting testnet', sk: '0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', chainId: 46630 },
  { label: 'sk=counting mainnet', sk: '0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', chainId: 4663 },
];

function compute(v: { label: string; sk: string; chainId: number }): Vector {
  const k = deriveDarkKeys(hexToBytes(v.sk.slice(2)), v.chainId);
  return {
    label: v.label,
    sk: v.sk,
    chainId: v.chainId,
    s: `0x${k.s.toString(16).padStart(64, '0')}`,
    px: `0x${k.publicKey.x.toString(16).padStart(64, '0')}`,
    py: `0x${k.publicKey.y.toString(16).padStart(64, '0')}`,
    kAe: `0x${bytesToHex(k.kAe)}`,
    ctr: k.ctr,
  };
}

// `node --import tsx test/keys.test.ts --write-vectors` regenerates the file.
if (process.argv.includes('--write-vectors')) {
  writeFileSync(FILE, `${JSON.stringify({ v: 1, vectors: INPUTS.map(compute) }, null, 2)}\n`);
}

test('replays keys.v1.json', () => {
  const { vectors } = JSON.parse(readFileSync(FILE, 'utf8')) as { vectors: Vector[] };
  assert.equal(vectors.length, 5);
  for (const v of vectors) {
    assert.deepEqual(compute(v), v, v.label);
  }
});

test('s*P == H and P is canonical', () => {
  const k = deriveDarkKeys(hexToBytes('42'.repeat(32)), 4663);
  assert.ok(keysAreConsistent(k));
  assert.ok(k.s > 0n && k.s < GROUP_N);
  assert.equal(k.kAe.length, 32);
  assert.deepEqual(k.publicKey, encode(mul(H, invModN(k.s))));
});

test('chainId separates keys', () => {
  const sk = hexToBytes('11'.repeat(32));
  assert.notEqual(deriveDarkKeys(sk, 4663).s, deriveDarkKeys(sk, 46630).s);
});

test('a wrong-length sk is rejected', () => {
  assert.throws(() => deriveDarkKeys(new Uint8Array(31), 4663));
});

test('checkRegistryKey throws KEY_DERIVATION_MISMATCH', () => {
  const k = deriveDarkKeys(hexToBytes('22'.repeat(32)), 4663);
  checkRegistryKey(k.publicKey, k.publicKey);
  assert.throws(
    () => checkRegistryKey(k.publicKey, { x: 1n, y: 2n }),
    (e: Error & { code?: string }) => e.code === 'KEY_DERIVATION_MISMATCH',
  );
});
