// A fake chain for flow disclosures: real ConfidentialTransfer logs (real ElGamal, real hints) between
// test accounts, served to a LiveDarkClient through its getLogs, with the API's POSTs captured.
// Shared by the SDK's client tests, the API's real-proof test and qa/gen-range-fixture-v2.ts.
import { privateKeyToAccount } from 'viem/accounts';
import { LiveDarkClient } from '../src/client.ts';
import { deployments } from '../src/deployments.ts';
import { deriveDarkKeys } from '../src/keys.ts';
import { encrypt, hedgedScalar, contextBytes, TAG_TRANSFER_R, TAG_HINT_K } from '../src/elgamal.ts';
import { sealHint, sealSenderHint } from '../src/hint.ts';
import { encode } from '../src/grumpkin.ts';
import type { DarkProver, Hex } from '../src/prover.ts';

export const CHAIN = 46630;
export const DEP = deployments[CHAIN]!;
export const B0 = DEP.deployBlock;
export const HEAD = B0 + 10_000n;

const hex = (b: Uint8Array): Hex => `0x${Buffer.from(b).toString('hex')}`;
const party = (sk: Hex) => ({
  sk, account: privateKeyToAccount(sk), address: privateKeyToAccount(sk).address,
  keys: deriveDarkKeys(Uint8Array.from(Buffer.from(sk.slice(2), 'hex')), CHAIN),
});
export type Party = ReturnType<typeof party>;
export const ALICE = party(`0x${'44'.repeat(32)}`);
export const BOB = party(`0x${'55'.repeat(32)}`);
export const CAROL = party(`0x${'66'.repeat(32)}`);

let nonce = 0n;
/** One ConfidentialTransfer log, as viem decodes it. */
export function payment(from: Party, to: Party, amount: bigint, blockNumber: bigint, logIndex = 0) {
  const tctx = { chainId: CHAIN, vault: DEP.vault, from: from.address, to: to.address, fromNonce: nonce++ };
  const ctx = contextBytes(tctx);
  const k = hedgedScalar(TAG_HINT_K, from.keys.s, ctx);
  const { C, D } = encrypt(amount, [from.keys.P, to.keys.P], hedgedScalar(TAG_TRANSFER_R, from.keys.s, ctx));
  return {
    blockNumber, logIndex, transactionHash: hex(new Uint8Array(32).fill(logIndex + 1)),
    args: {
      from: from.address, to: to.address, fromNonceAfter: tctx.fromNonce + 1n,
      transferCt: [C, D[0]!, D[1]!].flatMap((p) => { const q = encode(p); return [q.x, q.y]; }),
      hint: hex(sealHint(k, to.keys.P, tctx, amount)),
      senderHint: hex(sealSenderHint(from.keys.kAe, tctx, amount)),
    },
  };
}
export type PaymentLog = ReturnType<typeof payment>;

const noProver: DarkProver = {
  isAvailable: async () => false,
  prove: async () => { throw new Error('no prover in this test'); },
} as never;

/**
 * `me`'s live client over `logs`. `ignoreFilter` serves every log whatever the topics asked for, as a
 * lying RPC would; `caps` are the CapsUpdated logs.
 */
export function flowClient(me: Party, logs: PaymentLog[], o: { prover?: DarkProver; caps?: unknown[]; ignoreFilter?: boolean } = {}) {
  const seen = { transfers: [] as { fromBlock: bigint; toBlock: bigint }[], caps: 0, posted: [] as { id: string; blob: string }[] };
  const client = new (LiveDarkClient as unknown as new (o: unknown) => LiveDarkClient)({
    chainId: CHAIN, account: me.address, privateKey: me.sk, prover: o.prover ?? noProver,
    api: { baseUrl: 'https://api.test', token: () => 'tok' },
  });
  const lc = (v: unknown) => String(v).toLowerCase();
  Object.assign(client, {
    pub: {
      getBlockNumber: async () => HEAD,
      getLogs: async (p: { event: { name: string }; args: Record<string, string>; fromBlock: bigint; toBlock: bigint }) => {
        if (p.event.name === 'CapsUpdated') { seen.caps++; return o.caps ?? []; }
        seen.transfers.push({ fromBlock: p.fromBlock, toBlock: p.toBlock });
        return logs.filter((l) => l.blockNumber >= p.fromBlock && l.blockNumber <= p.toBlock &&
          (o.ignoreFilter || Object.entries(p.args).every(([k, v]) => lc(l.args[k as 'from']) === lc(v))));
      },
    },
    wallet: { account: me.account, signTypedData: (td: never) => me.account.signTypedData(td) },
  });
  globalThis.fetch = (async (_url: string, init: { body: string }) => {
    seen.posted.push(JSON.parse(init.body));
    return new Response('{}', { status: 201 });
  }) as never;
  return { client, seen };
}
