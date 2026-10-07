import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  publicInputOrder,
  publicInputCount,
  publicInputOnchain,
  buildPublicInputs,
  assertPublicInputsEqual,
} from '../src/publicInputs.ts';
import { isDarkError } from '../src/errors.ts';
import { CIRCUITS, noCircuits } from './scenario.ts';

const PKG = fileURLToPath(new URL('..', import.meta.url));

test('the committed publicInputs.ts is what the generator produces today', { skip: noCircuits }, () => {
  // Regenerate into a throwaway copy of the package so the working tree is untouched.
  const dir = mkdtempSync(join(tmpdir(), 'dark-pi-'));
  try {
    cpSync(join(PKG, 'scripts'), join(dir, 'scripts'), { recursive: true });
    cpSync(join(PKG, 'src'), join(dir, 'src'), { recursive: true });
    execFileSync(process.execPath, [join(dir, 'scripts/gen-public-inputs.mjs')], {
      stdio: 'ignore',
      env: { ...process.env, DARK_CIRCUITS_DIR: CIRCUITS },
    });
    assert.equal(
      readFileSync(join(dir, 'src/publicInputs.ts'), 'utf8'),
      readFileSync(join(PKG, 'src/publicInputs.ts'), 'utf8'),
      'src/publicInputs.ts is stale: run `node scripts/gen-public-inputs.mjs` and commit',
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('counts match §6 and circuits/manifest.json', { skip: noCircuits }, () => {
  assert.deepEqual(publicInputCount, {
    dark_register: 5,
    dark_transfer: 21,
    dark_withdraw: 12,
    dark_disclose_range: 9,
  });
  const manifest = JSON.parse(readFileSync(join(CIRCUITS, 'manifest.json'), 'utf8'));
  for (const [pkg, m] of Object.entries<{ public_input_count: number; onchain: boolean }>(manifest.circuits)) {
    assert.equal(m.public_input_count, publicInputCount[pkg as keyof typeof publicInputCount], pkg);
    assert.equal(m.onchain, publicInputOnchain[pkg as keyof typeof publicInputOnchain], pkg);
  }
});

test('buildPublicInputs pads addresses and points into bytes32, in order', () => {
  const words = buildPublicInputs('dark_register', {
    chain_id: 46630,
    registry: '0x00000000000000000000000000000000000000CE', // a placeholder, not a deployment
    account: '0x000000000000000000000000000000000000beef',
    pk: { x: 1n, y: 2n },
  });
  assert.deepEqual(words, [
    '0x000000000000000000000000000000000000000000000000000000000000b626',
    '0x00000000000000000000000000000000000000000000000000000000000000ce',
    '0x000000000000000000000000000000000000000000000000000000000000beef',
    '0x0000000000000000000000000000000000000000000000000000000000000001',
    '0x0000000000000000000000000000000000000000000000000000000000000002',
  ]);
  // The identity is the (0,0) sentinel, not a missing input.
  assert.deepEqual(buildPublicInputs('dark_register', {
    chain_id: 1, registry: 0, account: 0, 'pk.x': 0n, 'pk.y': 0n,
  }).slice(3), [`0x${'0'.repeat(64)}`, `0x${'0'.repeat(64)}`]);
});

test('a missing or oversized input is a PUBLIC_INPUT_MISMATCH', () => {
  assert.throws(
    () => buildPublicInputs('dark_register', { chain_id: 1, registry: 0, account: 0 }),
    (e: unknown) => isDarkError(e) && e.code === 'PUBLIC_INPUT_MISMATCH' && /missing public input pk\.x/.test(e.message),
  );
  assert.throws(
    () => buildPublicInputs('dark_register', { chain_id: 1n << 256n, registry: 0, account: 0, pk: { x: 0n, y: 0n } }),
    (e: unknown) => isDarkError(e) && e.code === 'PUBLIC_INPUT_MISMATCH',
  );
});

test('assertPublicInputsEqual is case-insensitive but order-sensitive', () => {
  const a = ['0xAB', '0xcd'];
  assertPublicInputsEqual('dark_register', a, ['0xab', '0xCD'] as never);
  assert.throws(
    () => assertPublicInputsEqual('dark_register', a, ['0xcd', '0xab'] as never),
    (e: unknown) => isDarkError(e) && e.code === 'PUBLIC_INPUT_MISMATCH',
  );
});

test('every circuit main() parameter list is mirrored here', { skip: noCircuits }, () => {
  // The Noir sources are the other half of the contract; a rename there must show up as a
  // public_inputs.toml change, which regenerates this file.
  const crates = { dark_register: 'register', dark_transfer: 'transfer', dark_withdraw: 'withdraw', dark_disclose_range: 'disclose_range' };
  for (const [pkg, crate] of Object.entries(crates)) {
    const src = readFileSync(join(CIRCUITS, crate, 'src/main.nr'), 'utf8');
    const sig = src.slice(src.indexOf('fn main('), src.indexOf(') {', src.indexOf('fn main(')));
    const names = [...sig.matchAll(/(\w+):\s*pub\s+(\w+)/g)].flatMap(([, name, ty]) =>
      ty === 'EmbeddedCurvePoint' ? [`${name}.x`, `${name}.y`] : [name],
    );
    assert.deepEqual(names, [...publicInputOrder[pkg as keyof typeof publicInputOrder]], pkg);
  }
});
