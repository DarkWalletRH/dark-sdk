// SPDX-License-Identifier: MIT OR Apache-2.0
// WebDarkProver: proving in the browser, and in the app's WebView (the
// only prover — there is no native one, so this single file is what proves on web, on iOS and on
// Android, and what the offline exit page uses).
//
// The property that matters most here is not speed. It is that generating a proof must not tell
// anyone that you are generating a proof.
//
// bb.js, left to itself, downloads the structured reference string from Aztec's CDN the first time
// it proves. That hands a third party the user's IP address at the exact moment they are making a
// private payment — the precise metadata this product exists to remove. So the SRS is REQUIRED as a
// constructor argument, bundled by the app and pinned by hash (circuits/tools/extract-srs.mjs), and
// bb is started with `skipSrsInit` so it never has the chance. There is deliberately no fallback
// that fetches it: a privacy tool that quietly degrades to leaking is worse than one that stops.
import { DarkError } from '../errors.ts';
import { buildPublicInputs, assertPublicInputsEqual } from '../publicInputs.ts';
import type { CircuitId, DarkProver, ProgressFn, ProofResult, Hex } from '../prover.ts';

/** A compiled Noir circuit: the `.json` nargo emits. Supply it directly or lazily. */
export type CircuitSource = { bytecode: string } | (() => Promise<{ bytecode: string }>);

export interface PinnedSrs {
  /** G1 points, compressed (32 B each) or uncompressed (64 B each) — bb detects which. */
  g1: Uint8Array;
  numPoints: number;
  /** The 128-byte G2 point. */
  g2: Uint8Array;
}

export interface WebDarkProverOptions {
  /** The circuits this prover can run. Anything absent is a clear error, never a silent failure. */
  circuits: Partial<Record<CircuitId, CircuitSource>>;
  /**
   * The bundled SRS. Required — see the note above. `circuits/tools/extract-srs.mjs` produces it
   * and pins its hashes; the app should verify those hashes at startup, not here, because a prover
   * that hashes 8 MB on every construction is a prover nobody keeps.
   */
  srs: PinnedSrs;
  /**
   * Worker threads. Multithreading needs cross-origin isolation (COOP/COEP); without it the browser
   * refuses SharedArrayBuffer and bb falls back to one thread. Default: a conservative reading of
   * hardwareConcurrency when isolated, 1 otherwise.
   */
  threads?: number;
  /** Escape hatch for tests. Never set this in an app. */
  loadBackend?: () => Promise<{ Barretenberg: unknown; UltraHonkBackend: unknown }>;
  loadNoir?: () => Promise<{ Noir: unknown }>;
}

/** True when the page can use SharedArrayBuffer, which is what bb needs for threads. */
export function crossOriginIsolated(): boolean {
  return typeof globalThis !== 'undefined' && (globalThis as { crossOriginIsolated?: boolean }).crossOriginIsolated === true;
}

function defaultThreads(): number {
  if (!crossOriginIsolated()) return 1;
  const cores = (globalThis as { navigator?: { hardwareConcurrency?: number } }).navigator?.hardwareConcurrency ?? 1;
  // Leave the main thread responsive; more than 8 buys little and costs memory on phones.
  return Math.max(1, Math.min(8, cores - 1));
}

export class WebDarkProver implements DarkProver {
  private api: unknown;
  private readonly threads: number;
  private starting?: Promise<void>;

  constructor(private readonly opts: WebDarkProverOptions) {
    if (!opts.srs?.g1?.length || !opts.srs?.g2?.length) {
      throw new DarkError(
        'PROVER_UNAVAILABLE',
        'WebDarkProver needs a bundled SRS: without one bb.js would fetch it and leak the user IP mid-payment',
      );
    }
    this.threads = opts.threads ?? defaultThreads();
  }

  /**
   * Whether this platform can prove at all. It does NOT start the prover — callers use it to decide
   * whether to offer a private action, and starting bb costs megabytes.
   */
  async isAvailable(): Promise<boolean> {
    try {
      const { Barretenberg } = await this.backend();
      return typeof Barretenberg !== 'undefined';
    } catch {
      return false;
    }
  }

  private backend(): Promise<{ Barretenberg: unknown; UltraHonkBackend: unknown }> {
    // A dynamic import so an app that never proves never pays for several megabytes of WebAssembly.
    return this.opts.loadBackend ? this.opts.loadBackend() : (import('@aztec/bb.js') as never);
  }

  /** One Barretenberg instance per prover, with the SRS loaded exactly once. */
  private async start(): Promise<void> {
    if (this.api) return;
    if (!this.starting) {
      this.starting = (async () => {
        const { Barretenberg } = (await this.backend()) as {
          Barretenberg: { new: (o: object) => Promise<Record<string, (a: object) => Promise<unknown>>> };
        };
        const api = await Barretenberg.new({ threads: this.threads, skipSrsInit: true });
        await api.srsInitSrs({
          pointsBuf: this.opts.srs.g1,
          numPoints: this.opts.srs.numPoints,
          g2Point: this.opts.srs.g2,
        });
        this.api = api;
      })().catch((e: unknown) => {
        this.starting = undefined;
        throw new DarkError('PROVER_UNAVAILABLE', `the prover could not start: ${(e as Error)?.message ?? e}`);
      });
    }
    return this.starting;
  }

  private async circuit(circuitId: CircuitId): Promise<{ bytecode: string }> {
    const source = this.opts.circuits[circuitId];
    if (!source) {
      throw new DarkError('PROVER_UNAVAILABLE', `this prover was not given the ${circuitId} circuit`, { circuitId });
    }
    return typeof source === 'function' ? source() : source;
  }

  async prove(circuitId: CircuitId, witness: Record<string, unknown>, onProgress?: ProgressFn): Promise<ProofResult> {
    const started = Date.now();

    // Derive the public inputs from the witness BEFORE proving, exactly as NodeDarkProver does, so
    // a witness the SDK cannot account for never reaches bb.
    const expected = buildPublicInputs(circuitId, witness);

    onProgress?.(0.05, 'starting');
    await this.start();

    const acir = await this.circuit(circuitId);
    onProgress?.(0.2, 'witness');

    const { Noir } = (await (this.opts.loadNoir ? this.opts.loadNoir() : (import('@noir-lang/noir_js') as never))) as {
      Noir: new (c: object) => { execute: (i: object) => Promise<{ witness: Uint8Array }> };
    };
    const { witness: solved } = await new Noir(acir).execute(witness);

    onProgress?.(0.35, 'proving');
    // The second argument IS the Barretenberg instance — the one whose SRS we loaded ourselves at
    // start(), with skipSrsInit and the bundled bytes. Handing it over here is what stops the
    // backend building its own, which would fetch the reference string from the network and defeat
    // the entire arrangement this class exists for.
    //
    // this used to be called with three arguments — `{ threads }` where the api belongs,
    // plus a `{ srsInit: false }` option this version does not have — and then repaired on the next
    // line with `backend.api = this.api`. It worked only because the constructor does nothing with
    // its second argument except assign it. The shim is now the library's real two-argument shape,
    // so a mismatch is a type error rather than something a tidy-up of the "redundant" reassignment
    // would silently turn into a network fetch. `threads` was never needed here; it is already set
    // on the instance at Barretenberg.new().
    const { UltraHonkBackend } = (await this.backend()) as {
      UltraHonkBackend: new (bytecode: string, api: unknown) => {
        generateProof: (w: Uint8Array, o: object) => Promise<{ proof: Uint8Array; publicInputs: string[] }>;
      };
    };
    const backend = new UltraHonkBackend(acir.bytecode, this.api);

    // `verifierTarget: 'evm'` must match how the deployed verifiers were built (§18b). bb.js's
    // older `keccak: true` means keccak AND ZK disabled, which is a different setting and silently
    // produces proofs the on-chain verifier rejects.
    const { proof, publicInputs } = await backend.generateProof(solved, { verifierTarget: 'evm' });

    onProgress?.(0.9, 'checking');
    // §7: the SDK re-derives the public inputs and rejects the proof on any mismatch. A prover that
    // returns a valid proof of the wrong statement is the failure this catches.
    assertPublicInputsEqual(circuitId, publicInputs, expected);

    onProgress?.(1, 'done');
    return { proof, publicInputs: expected as Hex[], ms: Date.now() - started };
  }

  /** Release the WebAssembly instance and its threads. */
  async destroy(): Promise<void> {
    const api = this.api as { destroy?: () => Promise<void> } | undefined;
    this.api = undefined;
    this.starting = undefined;
    await api?.destroy?.();
  }
}
