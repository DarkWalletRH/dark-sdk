// the witness file NodeDarkProver hands to nargo contains the account's spending key,
// so it must never be world-readable and must not survive as recoverable plaintext.
//
// This is the `dark-exit` path — it runs when someone is rescuing their funds with Dark's servers
// gone or untrusted, which is the worst possible moment to leave a key on disk.
//
// These tests exercise the file discipline directly rather than driving a full proof, which would
// need nargo and bb installed. What they pin is the thing that regressed: the mode on the write,
// and that the bytes are overwritten before the unlink.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const source = fs.readFileSync(new URL('../src/prover.ts', import.meta.url), 'utf8');

test('the prover file is written 0600', () => {
  const write = source.match(/fs\.writeFileSync\(proverFile,[^;]*;/s);
  assert.ok(write, 'could not find the prover-file write');
  assert.match(write[0], /mode:\s*0o600/, 'the witness holds the spending key and must not be world-readable');
});

test('the prover and witness files are overwritten before being unlinked', () => {
  const cleanup = source.slice(source.indexOf('} finally {'));
  assert.match(cleanup, /writeFileSync\(f,\s*Buffer\.alloc/, 'rmSync alone leaves the plaintext bytes on disk');
  // The overwrite has to come first, or it is pointless.
  assert.ok(
    cleanup.indexOf('Buffer.alloc') < cleanup.indexOf('fs.rmSync(f'),
    'the overwrite must precede the unlink',
  );
});

test('0600 actually denies group and other on this platform', () => {
  // Guards the assumption the fix rests on, rather than trusting the constant to mean what we think.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dark-mode-'));
  const f = path.join(dir, 'w.toml');
  try {
    fs.writeFileSync(f, 'secret', { mode: 0o600 });
    const mode = fs.statSync(f).mode & 0o777;
    assert.equal(mode & 0o077, 0, `group/other bits set: ${mode.toString(8)}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the secret scalar really does reach the file on disk', async () => {
  // The premise of every test above. Proven by running the serialiser rather than grepping for a
  // field name, because the limb keys are built at runtime by scalarLimbs('s', …) and a grep for
  // "s_lo" finds nothing in the source even though it is exactly what gets written.
  const { witnessToToml, scalarLimbs } = await import('../src/witness.ts');
  const secret = 0xdeadbeefcafef00d1234567890abcdefn;
  const toml = witnessToToml(scalarLimbs('s', secret) as never);

  assert.match(toml, /s_lo = "/, 'the secret is serialised as s_lo/s_hi limbs');
  assert.match(toml, /s_hi = "/);
  // And the low limb really carries the secret's bits, so this is the key, not a placeholder.
  const lo = (secret & ((1n << 128n) - 1n)).toString(16);
  assert.ok(toml.toLowerCase().includes(lo), 'the low limb should carry the secret bits');
});
