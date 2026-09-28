import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync } from 'node:fs';
import { NodeDarkProver, FixtureDarkProver } from '../src/prover.ts';
import { buildPublicInputs } from '../src/publicInputs.ts';
import { buildRegisterWitness } from '../src/witness.ts';
import { deriveDarkKeys } from '../src/keys.ts';
import { cases } from './scenario.ts';
import { deployments, isDeployed, darkVaultAbi, darkKeyRegistryAbi, ZERO_ADDRESS } from '../src/deployments.ts';

const CHAIN_ID = 46630;
const keys = deriveDarkKeys(new Uint8Array(32).fill(0x11), CHAIN_ID);
const registerWitness = buildRegisterWitness({
  chainId: CHAIN_ID,
  registry: '0x00000000000000000000000000000000000000ce',
  account: '0x000000000000000000000000000000000000beef',
  s: keys.s,
  pk: keys.P,
});

const prover = new NodeDarkProver();
const toolchain = await prover.isAvailable();

// nargo + bb are a ~1 GB toolchain; CI has them, a laptop checkout may not.
test('NodeDarkProver proves dark_register and re-derives its public inputs', { skip: toolchain ? false : 'nargo/bb not on this machine', timeout: 600_000 }, async () => {
  const seen: number[] = [];
  const r = await prover.prove('dark_register', registerWitness, (f) => seen.push(f));
  assert.ok(r.proof.length > 1000, `proof is ${r.proof.length} B`);
  assert.deepEqual(r.publicInputs, buildPublicInputs('dark_register', registerWitness));
  assert.equal(r.publicInputs.length, 5);
  assert.equal(BigInt(r.publicInputs[0]), BigInt(CHAIN_ID));
  assert.ok(seen.length >= 3 && seen.at(-1) === 1);
  assert.ok(r.ms > 0);
});

test('a witness whose public inputs the SDK cannot derive never reaches bb', async () => {
  await assert.rejects(
    prover.prove('dark_register', { s_lo: '0x1', s_hi: '0x0', chain_id: '1' }),
    (e: Error & { code?: string }) => e.code === 'PUBLIC_INPUT_MISMATCH',
  );
});

test('a missing toolchain or workspace is PROVER_UNAVAILABLE, never a silent pass', async () => {
  const broken = new NodeDarkProver({ circuitsDir: '/nonexistent/circuits' });
  assert.equal(await broken.isAvailable(), false);
  await assert.rejects(
    broken.prove('dark_register', registerWitness),
    (e: Error & { code?: string }) => e.code === 'PROVER_UNAVAILABLE',
  );
});

test('every circuit proves, with the wire public-input count §6 measured', { skip: toolchain ? false : 'nargo/bb not on this machine', timeout: 600_000 }, async () => {
  const want = { register: 5, transfer: 21, withdraw: 12, disclose_range: 9 };
  for (const [crate, witness] of Object.entries(cases)) {
    const circuit = `dark_${crate}` as 'dark_register';
    const r = await prover.prove(circuit, witness);
    assert.equal(r.publicInputs.length, want[crate as keyof typeof want], crate);
    assert.ok(r.proof.length > 7000, `${crate} proof is ${r.proof.length} B`);
  }
});

test('the prove run leaves no files behind in the circuits workspace', { skip: toolchain ? false : 'nargo/bb not on this machine', timeout: 600_000 }, async () => {
  const dir = new URL('../../../circuits/register/', import.meta.url);
  const before = readdirSync(dir);
  await prover.prove('dark_register', registerWitness);
  assert.deepEqual(readdirSync(dir).sort(), before.sort());
});

test('FixtureDarkProver reports progress and returns a proof', async () => {
  const seen: number[] = [];
  const r = await new FixtureDarkProver().prove('dark_register', registerWitness, (f) => seen.push(f));
  assert.deepEqual(seen, [0.1, 0.6, 1]);
  assert.equal(r.proof.length, 32);
  assert.deepEqual(r.publicInputs, buildPublicInputs('dark_register', registerWitness));
  assert.ok(r.ms >= 0);
});

test('testnet and mainnet (launch, 2026-09-28) are deployed; nothing else is', () => {
  assert.equal(isDeployed(46630), true);
  assert.equal(isDeployed(4663), true);
  assert.equal(isDeployed(1), false);
  // Every address on both chains is set, distinct and non-zero, and the deploy block is pinned.
  for (const id of [46630, 4663]) {
    const t = deployments[id];
    const addrs = [t.vault, t.registry, t.usdg, t.timelock, t.guardian, t.verifiers.register, t.verifiers.transfer, t.verifiers.withdraw];
    for (const a of addrs) assert.notEqual(a, ZERO_ADDRESS, `chain ${id}`);
    assert.equal(new Set(addrs).size, addrs.length, `chain ${id}`);
    assert.ok(t.deployBlock > 0n, `chain ${id}`);
  }
  // MockUSDG on testnet must never be the mainnet USDG.
  const t = deployments[46630];
  assert.notEqual(t.usdg, '0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168');
  assert.equal(deployments[4663].usdg, '0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168');
  assert.equal(deployments[4663].vault, '0xeD7a0c6899a6AC94Aea7A5b2F8f24a948042DA9C');
  assert.equal(deployments[4663].betaNoticeState, 'pre_audit');
});

test('draft ABIs carry the §6.5 owner functions and post-state events', () => {
  const names = new Set(darkVaultAbi.map((e) => e.name));
  for (const n of ['deposit', 'applyPending', 'transfer', 'withdraw', 'getAccount', 'caps', 'tvl']) {
    assert.ok(names.has(n), n);
  }
  for (const n of ['Deposited', 'PendingApplied', 'ConfidentialTransfer', 'Withdrawn']) {
    assert.ok(names.has(n), n);
  }
  assert.ok(darkKeyRegistryAbi.some((e) => e.name === 'keyOf'));
});

test('every deployment address is EIP-55 checksummed, so viem accepts it', async () => {
  const { getAddress } = await import('viem');
  for (const d of Object.values(deployments)) {
    for (const a of [d.vault, d.registry, d.usdg, d.timelock, d.guardian, d.darkToken, d.staking,
      d.verifiers.register, d.verifiers.transfer, d.verifiers.withdraw]) {
      assert.equal(getAddress(a), a, a);
    }
  }
});
