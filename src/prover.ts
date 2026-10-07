// SPDX-License-Identifier: MIT OR Apache-2.0
import { DarkError } from './errors.ts';
import { assertPublicInputsEqual, buildPublicInputs } from './publicInputs.ts';
import { circuitCrate, witnessToToml, type Witness } from './witness.ts';

export type Hex = `0x${string}`;

export type CircuitId = 'dark_register' | 'dark_transfer' | 'dark_withdraw' | 'dark_disclose_range';

export interface ProofResult {
  proof: Uint8Array;
  publicInputs: Hex[];
  ms: number;
}

/** Proving progress in [0, 1], with an optional stage label for the UI. */
export type ProgressFn = (fraction: number, stage?: string) => void;

export interface DarkProver {
  isAvailable(): Promise<boolean>;
  prove(circuitId: CircuitId, witness: Record<string, unknown>, onProgress?: ProgressFn): Promise<ProofResult>;
}

export interface NodeDarkProverOptions {
  /** The Noir workspace. Default: $DARK_CIRCUITS_DIR, else the nearest `circuits/` above cwd. */
  circuitsDir?: string;
  /** Default: $DARK_NARGO, else ~/.nargo/bin/nargo, else `nargo` on PATH. */
  nargo?: string;
  /** Default: $DARK_BB, else ~/.bb/bb, else `bb` on PATH. */
  bb?: string;
  /** bb's target verification environment. `evm` is what the deployed verifiers were built for. */
  verifierTarget?: string;
}

// node: imports are dynamic so a browser bundle that pulls in the SDK index never loads them.
type NodeApi = {
  execFile: (cmd: string, args: string[], opts: { cwd?: string; maxBuffer: number }) => Promise<{ stdout: string }>;
  fs: typeof import('node:fs');
  os: typeof import('node:os');
  path: typeof import('node:path');
};

let nodeApi: Promise<NodeApi> | null = null;
async function node(): Promise<NodeApi> {
  nodeApi ??= (async () => {
    const [{ execFile }, { promisify }, fs, os, path] = await Promise.all([
      import('node:child_process'), import('node:util'),
      import('node:fs'), import('node:os'), import('node:path'),
    ]);
    return { execFile: promisify(execFile) as NodeApi['execFile'], fs, os, path };
  })().catch(() => {
    throw new DarkError('PROVER_UNAVAILABLE', 'NodeDarkProver needs a Node runtime');
  });
  return nodeApi;
}

let tmpCounter = 0;

/**
 * Native prover (§7): `nargo execute` for the witness, `bb prove` for the proof, with the
 * flags circuits/tools/build.mjs proves work against the deployed verifiers.
 *
 * It never trusts the proof's own public inputs: it re-derives all of them from the witness via
 * `buildPublicInputs` and throws `PUBLIC_INPUT_MISMATCH` if bb's `public_inputs` file disagrees.
 */
export class NodeDarkProver implements DarkProver {
  private readonly opts: NodeDarkProverOptions;
  private resolved: Promise<{ circuitsDir: string; nargo: string; bb: string }> | null = null;
  private compiled: Promise<void> | null = null;

  constructor(opts: NodeDarkProverOptions = {}) {
    this.opts = opts;
  }

  async isAvailable(): Promise<boolean> {
    try {
      const { nargo, bb } = await this.tools();
      const { execFile } = await node();
      await Promise.all([
        execFile(nargo, ['--version'], { maxBuffer: 1 << 20 }),
        execFile(bb, ['--version'], { maxBuffer: 1 << 20 }),
      ]);
      return true;
    } catch {
      return false;
    }
  }

  async prove(circuitId: CircuitId, witness: Record<string, unknown>, onProgress?: ProgressFn): Promise<ProofResult> {
    const started = Date.now();
    const { execFile, fs, os, path } = await node();
    const { circuitsDir, nargo, bb } = await this.tools();
    const crate = circuitCrate[circuitId];
    if (!crate) throw new DarkError('PROVER_UNAVAILABLE', `unknown circuit ${circuitId}`, { circuitId });

    // Derive the public inputs from the witness BEFORE proving, so a witness the SDK cannot
    // account for never reaches bb.
    const expected = buildPublicInputs(circuitId, witness);

    await this.compile();
    onProgress?.(0.1, 'witness');

    const acir = path.join(circuitsDir, 'target', `${circuitId}.json`);
    const name = `.dark-prove-${process.pid}-${++tmpCounter}`;
    const proverFile = path.join(circuitsDir, crate, `${name}.toml`);
    const witnessFile = path.join(circuitsDir, 'target', `${name}.gz`);
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dark-prove-'));
    try {
      // 0600, because this file contains the account's spending key.
      //
      // `witnessToToml` serialises the whole witness, and that includes the ElGamal secret scalar
      // as s_lo/s_hi. nargo requires the prover file to sit in the crate directory, so it cannot be
      // moved into the private temp dir the proof output uses — but it can at least not be
      // world-readable. Without the mode it lands at the process umask, typically 0644.
      //
      // This is not a theoretical path: `dark-exit` uses NodeDarkProver by default, so it runs when
      // someone is rescuing their funds with Dark's servers gone or untrusted.
      fs.writeFileSync(proverFile, witnessToToml(witness as Witness, `# ${circuitId} witness from @darkwalletrh/dark-sdk.`), { mode: 0o600 });
      await this.run(execFile, nargo, ['execute', name, '-p', name, '--package', circuitId, '--silence-warnings'], path.join(circuitsDir, crate));
      onProgress?.(0.3, 'proving');

      await this.run(execFile, bb, [
        'prove',
        '-b', acir,
        '-w', witnessFile,
        '-k', await this.vk(circuitId),
        '-o', outDir,
        '--verifier_target', this.opts.verifierTarget ?? 'evm',
      ]);
      onProgress?.(0.9, 'checking');

      const proof = new Uint8Array(fs.readFileSync(path.join(outDir, 'proof')));
      const got = words(new Uint8Array(fs.readFileSync(path.join(outDir, 'public_inputs'))));
      // §7: the SDK re-derives the public inputs and rejects the proof on any mismatch.
      assertPublicInputsEqual(circuitId, got, expected);
      onProgress?.(1, 'done');
      return { proof, publicInputs: expected, ms: Date.now() - started };
    } finally {
      // Overwrite before unlinking. `rmSync` drops the directory entry and leaves the bytes, so on a
      // hard kill between write and delete — or simply afterwards, via the journal, the page cache,
      // a backup or a cloud-sync folder watching the repo — the plaintext key is still recoverable.
      // Best-effort: on a copy-on-write or log-structured filesystem this does not guarantee the old
      // blocks are gone, which is why the mode above matters as much as this does.
      for (const f of [proverFile, witnessFile]) {
        try {
          const { size } = fs.statSync(f);
          fs.writeFileSync(f, Buffer.alloc(size, 0));
        } catch {
          // Never let cleanup mask the real error, and a missing file here is the normal case.
        }
        fs.rmSync(f, { force: true });
      }
      fs.rmSync(outDir, { recursive: true, force: true });
    }
  }

  /**
   * The circuit's verification key, cached beside its ACIR under `target/` (gitignored) and
   * rebuilt whenever the ACIR is newer. Computing it costs more than the proof itself.
   */
  private async vk(circuitId: CircuitId): Promise<string> {
    const { execFile, fs, path } = await node();
    const { circuitsDir, bb } = await this.tools();
    const acir = path.join(circuitsDir, 'target', `${circuitId}.json`);
    const dir = path.join(circuitsDir, 'target', `${circuitId}.vk`);
    const vk = path.join(dir, 'vk');
    const stale = !fs.existsSync(vk) || fs.statSync(vk).mtimeMs < fs.statSync(acir).mtimeMs;
    if (stale) {
      await this.run(execFile, bb, [
        'write_vk', '-b', acir, '-o', dir, '--verifier_target', this.opts.verifierTarget ?? 'evm',
      ]);
    }
    return vk;
  }

  /** `nargo compile` once per instance; the ACIR artifacts are the cache. */
  private compile(): Promise<void> {
    this.compiled ??= (async () => {
      const { execFile, fs, path } = await node();
      const { circuitsDir, nargo } = await this.tools();
      const fresh = Object.keys(circuitCrate).every((pkg) =>
        fs.existsSync(path.join(circuitsDir, 'target', `${pkg}.json`)));
      if (fresh) return;
      await this.run(execFile, nargo, ['compile', '--silence-warnings'], circuitsDir);
    })().catch((e) => {
      this.compiled = null;
      throw e;
    });
    return this.compiled;
  }

  private async run(
    execFile: NodeApi['execFile'], cmd: string, args: string[], cwd?: string,
  ): Promise<string> {
    try {
      return (await execFile(cmd, args, { cwd, maxBuffer: 1 << 28 })).stdout;
    } catch (e) {
      const err = e as { stderr?: string; stdout?: string; message?: string };
      throw new DarkError('PROVER_UNAVAILABLE', `${cmd.split('/').pop()} failed: ${(err.stderr || err.stdout || err.message || '').trim().split('\n').slice(-4).join(' ')}`, {
        cmd, args,
      });
    }
  }

  private tools(): Promise<{ circuitsDir: string; nargo: string; bb: string }> {
    this.resolved ??= (async () => {
      const { fs, os, path } = await node();
      const pick = (given: string | undefined, env: string | undefined, home: string, onPath: string) => {
        if (given) return given;
        if (env) return env;
        const h = path.join(os.homedir(), home);
        return fs.existsSync(h) ? h : onPath;
      };
      const circuitsDir = this.opts.circuitsDir ?? process.env.DARK_CIRCUITS_DIR ?? findCircuits(fs, path);
      if (!fs.existsSync(path.join(circuitsDir, 'Nargo.toml'))) {
        throw new DarkError('PROVER_UNAVAILABLE', `no Noir workspace at ${circuitsDir}; set DARK_CIRCUITS_DIR`, { circuitsDir });
      }
      return {
        circuitsDir,
        nargo: pick(this.opts.nargo, process.env.DARK_NARGO, '.nargo/bin/nargo', 'nargo'),
        bb: pick(this.opts.bb, process.env.DARK_BB, '.bb/bb', 'bb'),
      };
    })();
    return this.resolved;
  }
}

/** The nearest `circuits/` (or `.`, when cwd already is it) at or above cwd. */
function findCircuits(fs: typeof import('node:fs'), path: typeof import('node:path')): string {
  let dir = process.cwd();
  for (;;) {
    if (fs.existsSync(path.join(dir, 'circuits', 'Nargo.toml'))) return path.join(dir, 'circuits');
    if (fs.existsSync(path.join(dir, 'Nargo.toml'))) return dir;
    const up = path.dirname(dir);
    if (up === dir) return path.join(process.cwd(), 'circuits');
    dir = up;
  }
}

/** bb writes the wire public inputs as 32-byte big-endian words (§19). */
function words(buf: Uint8Array): Hex[] {
  if (buf.length % 32 !== 0) {
    throw new DarkError('PUBLIC_INPUT_MISMATCH', `public_inputs is ${buf.length} bytes, not a multiple of 32`);
  }
  const out: Hex[] = [];
  for (let i = 0; i < buf.length; i += 32) {
    out.push(`0x${[...buf.subarray(i, i + 32)].map((b) => b.toString(16).padStart(2, '0')).join('')}`);
  }
  return out;
}

/** Deterministic stand-in so the app can build proving UI without a toolchain. */
export class FixtureDarkProver implements DarkProver {
  constructor(private readonly delayMs = 0) {}

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async prove(circuitId: CircuitId, witness: Record<string, unknown>, onProgress?: ProgressFn): Promise<ProofResult> {
    const started = Date.now();
    for (const [f, stage] of [[0.1, 'witness'], [0.6, 'proving'], [1, 'done']] as const) {
      onProgress?.(f, stage);
      if (this.delayMs) await new Promise((r) => setTimeout(r, this.delayMs));
    }
    // A real-shaped public-input array when the witness supports one, so callers that check
    // the prover's output against their own derivation exercise that path in fixture mode too.
    let publicInputs: Hex[];
    try {
      publicInputs = buildPublicInputs(circuitId, witness);
    } catch {
      publicInputs = [`0x${'00'.repeat(32)}`];
    }
    return { proof: new Uint8Array(32).fill(circuitId.length), publicInputs, ms: Date.now() - started };
  }
}
