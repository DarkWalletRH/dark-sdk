// SPDX-License-Identifier: MIT OR Apache-2.0
// useDark(). One hook, two clients: the fixture DarkClient for building screens with no
// chain, and the real LiveDarkClient against the deployed contracts. The screens cannot tell them
// apart, which is the point — a screen that only works against a fixture has not been tested.
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  DarkClient, LiveDarkClient,
  type ActionEvent, type Balances, type Caps, type DarkClientOptions, type DarkStatus,
  type Disclosure, type HistoryEntry, type LiveDarkClientOptions,
} from './client.ts';
import { DarkError } from './errors.ts';

/**
 * Preserve a thrown error's own code. `checkRegistryKey` throws a plain Error carrying
 * `code: 'KEY_DERIVATION_MISMATCH'` — the §11 terminal hard stop — and rewrapping everything as
 * DECRYPTION_FAILED told the user the wrong thing about the one error they must not ignore
 *.
 */
function asDarkError(e: unknown): DarkError {
  if (e instanceof DarkError) return e;
  const code = (e as { code?: string })?.code;
  const message = (e as Error)?.message ?? String(e);
  return code === 'KEY_DERIVATION_MISMATCH'
    ? new DarkError('KEY_DERIVATION_MISMATCH', message)
    : new DarkError('DECRYPTION_FAILED', message);
}
import type { BetaNoticeState } from './deployments.ts';
import type { Hex } from './prover.ts';

export interface UseDark {
  status: DarkStatus;
  /** Whether a prover is available on this platform. */
  available: boolean;
  registered: boolean;
  balance: bigint | null;
  pending: bigint;
  pendingCount: number;
  balancePublic: boolean;
  caps: Caps | null;
  betaNotice: BetaNoticeState;
  /** Proving progress in [0, 1] while an action is in flight. */
  progress: number;
  action: ActionEvent | null;
  error: DarkError | null;
  history: HistoryEntry[];
  disclosures: Disclosure[];
  /**
   * These two reads fail independently of the balance, and a failure is NOT emptiness. Showing "no
   * transactions" when the truth is "we could not read them" is the quiet lie this pair exists to
   * prevent — and an expired session showing "no live links" would hide exactly the link a user
   * wants to revoke.
   */
  historyError: DarkError | null;
  disclosuresError: DarkError | null;
  refresh: () => Promise<void>;
  register: () => Promise<void>;
  deposit: (amount: bigint) => Promise<void>;
  applyPending: () => Promise<void>;
  transfer: (to: Hex, amount: bigint, note?: string) => Promise<void>;
  withdraw: (amount: bigint, to?: Hex) => Promise<void>;
  createDisclosure: (kind: Disclosure['kind'], label: string, ttlDays?: number) => Promise<Disclosure>;
  revokeDisclosure: (id: string) => Promise<void>;
  client: DarkSurface | null;
}

/**
 * What a screen is allowed to depend on. Both clients satisfy it, so a screen written against the
 * fixture runs unchanged against the chain.
 *
 * `isRegistered` is the one place the two genuinely differ — the fixture answers from memory, the
 * live client has to ask the registry — so the shared shape is the async one and the hook awaits it.
 */
export interface DarkSurface {
  readonly prover: { isAvailable(): boolean | Promise<boolean> };
  readonly betaNotice: BetaNoticeState;
  getStatus(): DarkStatus;
  caps(): Promise<Caps>;
  getBalances(): Promise<Balances>;
  history(): Promise<HistoryEntry[]>;
  isRegistered(): boolean | Promise<boolean>;
  listDisclosures(): Promise<Disclosure[]>;
  register(): Promise<unknown>;
  deposit(amount: bigint): Promise<unknown>;
  applyPending(): Promise<unknown>;
  /** Third argument is a private NOTE for the recipient, not a key. */
  transfer(to: Hex, amount: bigint, note?: string): Promise<unknown>;
  withdraw(amount: bigint, to?: Hex): Promise<unknown>;
  createDisclosure(kind: Disclosure['kind'], label: string, ttlDays?: number): Promise<Disclosure>;
  revokeDisclosure(id: string): Promise<void>;
}

/**
 * A stable identity for the account secret, so the effect can depend on it without the secret itself
 * becoming a render-time value. Two different keys always differ here; the same key never does.
 */
function secretId(options: UseDarkOptions): string {
  const pk = (options as { privateKey?: Uint8Array | Hex }).privateKey;
  if (!pk) return '';
  return typeof pk === 'string' ? pk : Array.from(pk).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export type UseDarkOptions =
  | ({ mode?: 'fixture' } & DarkClientOptions)
  | ({ mode: 'live' } & LiveDarkClientOptions);

export function useDark(options: UseDarkOptions): UseDark {
  const [action, setAction] = useState<ActionEvent | null>(null);
  const [error, setError] = useState<DarkError | null>(null);
  const [balances, setBalances] = useState<Balances | null>(null);
  const [caps, setCaps] = useState<Caps | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [disclosures, setDisclosures] = useState<Disclosure[]>([]);
  const [historyError, setHistoryError] = useState<DarkError | null>(null);
  const [disclosuresError, setDisclosuresError] = useState<DarkError | null>(null);
  const [registered, setRegistered] = useState(false);
  const [available, setAvailable] = useState(false);

  // LiveDarkClient.create is async (it builds viem clients), so a live client is not available on
  // the first render. `client` is null until it is, and every action guards on that rather than
  // pretending a half-built client exists.
  // Built by the effect below, for both modes, so there is exactly one place that decides which
  // client is current.
  const [client, setClient] = useState<DarkSurface | null>(null);

  // A generation counter, because switching account is not a refresh — it is a different person.
  //
  // Previously the effect started building B's client and left A's in state. Until B resolved the
  // hook showed A's balances and every action ran with A's key; if B's create() rejected (secret
  // still locked, wrong chain) A's client stayed indefinitely. `createDisclosure` would then
  // publish A's balance while B was on screen.
  const generation = useRef(0);
  useEffect(() => {
    const mine = ++generation.current;
    const current = <T,>(set: (v: T) => void) => (v: T) => {
      if (generation.current === mine) set(v);
    };

    // Drop everything belonging to whoever was here before, immediately and synchronously. Stale
    // balances on screen are worse than none: they are another person's.
    setClient(null);
    setBalances(null);
    setCaps(null);
    setHistory([]);
    setDisclosures([]);
    setHistoryError(null);
    setDisclosuresError(null);
    setRegistered(false);
    setAction(null);
    setError(null);

    if (options.mode !== 'live') {
      setClient(new DarkClient({ ...(options as DarkClientOptions), onAction: current(setAction) }) as DarkSurface);
      return;
    }

    void LiveDarkClient.create({ ...(options as LiveDarkClientOptions), onAction: current(setAction) })
      .then(current<DarkSurface>((c) => setClient(c)))
      .catch(current<unknown>((e) => setError(asDarkError(e))));

    return () => {
      // Anything still in flight belongs to a previous generation and must not write state.
      generation.current++;
    };
    // Rebuilt whenever the identity changes — including the SECRET, because `account` and
    // `privateKey` can update in separate renders, and a client built with A's key for B's address
    // is the KEY_DERIVATION_MISMATCH hard stop.
  }, [options.mode, options.chainId, options.account, secretId(options)]);

  const refresh = useCallback(async () => {
    if (!client) return;
    try {
      setAvailable(await client.prover.isAvailable());
      setCaps(await client.caps());
      setBalances(await client.getBalances());
      setRegistered(await client.isRegistered());
      // History and the disclosure list are the expensive, failure-prone reads (log paging, a
      // network call to the API). A screen must still show a balance when they fail — but the
      // PREVIOUS values are kept and the failure is surfaced, because an empty list is a claim.
      try {
        setHistory(await client.history());
        setHistoryError(null);
      } catch (e) {
        setHistoryError(asDarkError(e));
      }
      try {
        setDisclosures(await client.listDisclosures());
        setDisclosuresError(null);
      } catch (e) {
        setDisclosuresError(asDarkError(e));
      }
      setError(null);
    } catch (e) {
      setError(asDarkError(e));
    }
  }, [client]);

  // First load, and again whenever the live client finishes being built.
  useEffect(() => {
    void refresh();
  }, [refresh]);

  /** Every action clears the previous error, runs, then re-reads state. */
  const wrap = useCallback(
    <A extends unknown[], R>(fn: (...a: A) => Promise<R>) =>
      async (...a: A): Promise<R> => {
        if (!client) throw new DarkError('STALE_STATE', 'the wallet is still starting up');
        setError(null);
        try {
          const r = await fn(...a);
          await refresh();
          return r;
        } catch (e) {
          setError(asDarkError(e));
          throw e;
        }
      },
    [refresh, client],
  );

  return useMemo<UseDark>(
    () => ({
      status: client ? client.getStatus() : 'idle',
      available,
      registered,
      balance: balances?.available ?? null,
      pending: balances?.pending ?? 0n,
      pendingCount: balances?.pendingCount ?? 0,
      balancePublic: balances?.balancePublic ?? true,
      caps,
      betaNotice: client?.betaNotice ?? 'pre_audit',
      progress: action?.state === 'proving' ? (action.progress ?? 0) : 0,
      action,
      error,
      history,
      disclosures,
      historyError,
      disclosuresError,
      refresh,
      register: wrap(() => client!.register().then(() => undefined)),
      deposit: wrap((amount: bigint) => client!.deposit(amount).then(() => undefined)),
      applyPending: wrap(() => client!.applyPending().then(() => undefined)),
      transfer: wrap((to: Hex, amount: bigint, note?: string) =>
        client!.transfer(to, amount, note).then(() => undefined)),
      withdraw: wrap((amount: bigint, to?: Hex) => client!.withdraw(amount, to).then(() => undefined)),
      createDisclosure: wrap((kind: Disclosure['kind'], label: string, ttlDays?: number) =>
        client!.createDisclosure(kind, label, ttlDays)),
      revokeDisclosure: wrap((id: string) => client!.revokeDisclosure(id)),
      client,
    }),
    [client, available, registered, balances, caps, action, error, history, disclosures, historyError, disclosuresError, refresh, wrap],
  );
}
