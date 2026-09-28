// The scenario circuits/tools/gen_prover.mjs pins, shared by the witness and prover tests.
import { keccak_256 } from '@noble/hashes/sha3';
import { GROUP_N } from '../src/grumpkin.ts';
import { deriveDarkKeys } from '../src/keys.ts';
import { encrypt, hedgedScalar, contextBytes, TAG_TRANSFER_R } from '../src/elgamal.ts';
import {
  buildRegisterWitness, buildTransferWitness, buildWithdrawWitness, buildDiscloseRangeWitness,
} from '../src/witness.ts';

// --- gen_prover.mjs's scenario, reproduced ------------------------------------------------
const CHAIN_ID = 46630;
const REGISTRY = '0x00000000000000000000000000000000000000ce' as const;
const VAULT = '0x00000000000000000000000000000000000000fa' as const;
const SENDER = '0x000000000000000000000000000000000000beef' as const;
const RECIPIENT = '0x000000000000000000000000000000000000cafe' as const;
const WITHDRAW_TO = '0x0000000000000000000000000000000000001234' as const;
const NONCE = 3n;
const MIN_TRANSFER = 1_000000n;
const MAX_TRANSFER = 25_000_000000n;
const BALANCE = 500_000000n;
const AMOUNT = 120_000000n;
const WITHDRAW_AMOUNT = 200_000000n;
const DISCLOSE_LO = 100_000000n;
const DISCLOSE_HI = 500_000000n;

const senderKeys = deriveDarkKeys(new Uint8Array(32).fill(0x11), CHAIN_ID);
const recipientKeys = deriveDarkKeys(new Uint8Array(32).fill(0x22), CHAIN_ID);

const availRho = hedgedScalar(TAG_TRANSFER_R, senderKeys.s, new Uint8Array(8).fill(1), new Uint8Array(32).fill(0xa1));
const availE = encrypt(BALANCE, [senderKeys.P], availRho);
const avail = { c: availE.C, d: availE.D[0] };

const r = hedgedScalar(
  TAG_TRANSFER_R,
  senderKeys.s,
  contextBytes({ chainId: CHAIN_ID, vault: VAULT, from: SENDER, to: RECIPIENT, fromNonce: NONCE }),
  new Uint8Array(32).fill(0x5a),
);
const ctE = encrypt(AMOUNT, [senderKeys.P, recipientKeys.P], r);
const ct = { c: ctE.C, ds: ctE.D[0], dr: ctE.D[1] };

const beToBigint = (b: Uint8Array) => b.reduce((v, x) => (v << 8n) | BigInt(x), 0n);
const contextHash = beToBigint(keccak_256(new TextEncoder().encode('DARK-CB-1/disclose/v1'))) % GROUP_N;


export const cases = {
  register: buildRegisterWitness({ chainId: CHAIN_ID, registry: REGISTRY, account: SENDER, s: senderKeys.s, pk: senderKeys.P }),
  transfer: buildTransferWitness({
    chainId: CHAIN_ID, vault: VAULT, sender: SENDER, recipient: RECIPIENT, senderNonce: NONCE,
    s: senderKeys.s, r, amount: AMOUNT, balance: BALANCE,
    pkS: senderKeys.P, pkR: recipientKeys.P, avail, ct,
    minTransfer: MIN_TRANSFER, maxTransfer: MAX_TRANSFER,
  }),
  withdraw: buildWithdrawWitness({
    chainId: CHAIN_ID, vault: VAULT, account: SENDER, to: WITHDRAW_TO, nonce: NONCE,
    s: senderKeys.s, amount: WITHDRAW_AMOUNT, balance: BALANCE, pk: senderKeys.P, avail,
  }),
  disclose_range: buildDiscloseRangeWitness({
    contextHash, s: senderKeys.s, value: BALANCE, pk: senderKeys.P, ciphertext: avail,
    lo: DISCLOSE_LO, hi: DISCLOSE_HI,
  }),
};

export {
  CHAIN_ID, REGISTRY, VAULT, SENDER, RECIPIENT, WITHDRAW_TO, NONCE,
  MIN_TRANSFER, MAX_TRANSFER, BALANCE, AMOUNT, WITHDRAW_AMOUNT, DISCLOSE_LO, DISCLOSE_HI,
  senderKeys, recipientKeys, availRho, avail, r, ct, contextHash,
};
