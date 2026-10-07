// SPDX-License-Identifier: MIT OR Apache-2.0
import type { Hex } from './prover.ts';

export const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000' as const;

/** §13: the notice state is one constant per chain. */
export type BetaNoticeState = 'pre_audit' | 'in_audit' | 'audited';

export interface Deployment {
  vault: Hex;
  registry: Hex;
  verifiers: { register: Hex; transfer: Hex; withdraw: Hex };
  timelock: Hex;
  guardian: Hex;
  usdg: Hex;
  darkToken: Hex;
  staking: Hex;
  deployBlock: bigint;
  /** Public fallback RPC. $DARK_RPC_URL wins when set; never commit a keyed URL. */
  rpcUrl: string;
  explorer: string;
  betaNoticeState: BetaNoticeState;
}

const UNDEPLOYED = {
  vault: ZERO_ADDRESS,
  registry: ZERO_ADDRESS,
  verifiers: { register: ZERO_ADDRESS, transfer: ZERO_ADDRESS, withdraw: ZERO_ADDRESS },
  timelock: ZERO_ADDRESS,
  guardian: ZERO_ADDRESS,
  usdg: ZERO_ADDRESS,
  darkToken: ZERO_ADDRESS,
  staking: ZERO_ADDRESS,
  deployBlock: 0n,
} as const;

export const CHAIN_ID_MAINNET = 4663;
export const CHAIN_ID_TESTNET = 46630;

/** Addresses are zero until a deployment lands; `isDeployed` gates every flow. */
export const deployments: Record<number, Deployment> = {
  [CHAIN_ID_TESTNET]: {
    ...UNDEPLOYED,
    // Hardened deployment of 2026-09-20: carries the pending-count lower bound and the MIT OR
    // Apache-2.0 headers; verifiers unchanged since v0. MockUSDG is the testnet asset (§14.14);
    // owner is the timelock, guardian is the deployer EOA (§14.36).
    vault: '0x14fa77C25357C1Dc7de0DD7F36e0EbE807110aB7',
    registry: '0x850907E912c5F89B233252E3633BEfaBe66232B2',
    verifiers: {
      register: '0x97dB97Eec8d722a5C48F0Fb1612D1DC160A7c085',
      transfer: '0xAf2332Ef3910A9328418b4963BA0E50b9d5846Fe',
      withdraw: '0x0905e66f00Bd3261A8E32Dc4b6Cb060a6B8A8f74',
    },
    timelock: '0x4522d92128219FE0F3DcFf17324617881C3f7D05',
    guardian: '0x8FFB462Ae98Bb8975BD3FCE03df244637Dba9547',
    usdg: '0x77FfdE2D07f08f847944B6951dDd9243ae5EE950',
    deployBlock: 122104964n,
    rpcUrl: 'https://rpc.testnet.chain.robinhood.com',
    explorer: 'https://explorer.testnet.chain.robinhood.com', // testnet.explorer.… serves no TLS; this host answers the Blockscout v2 API
    betaNoticeState: 'pre_audit',
  },
  [CHAIN_ID_MAINNET]: {
    ...UNDEPLOYED,
    vault: '0xeD7a0c6899a6AC94Aea7A5b2F8f24a948042DA9C',
    registry: '0x2E245135FD561965CC546c14C23C9162f36d9C87',
    verifiers: {
      register: '0xAf2332Ef3910A9328418b4963BA0E50b9d5846Fe',
      transfer: '0x0905e66f00Bd3261A8E32Dc4b6Cb060a6B8A8f74',
      withdraw: '0xaa921526C05b2F11204525D28A81391d91C4258a',
    },
    timelock: '0xADbF7E3cf5418BeAC10BcDD3BBD9a51dc19EBC54',
    guardian: '0x87879CbAfC1E92528b950444E693D3b2F07CB1d7',
    deployBlock: 75151289n,
    // Launch deploy 2026-09-28: real USDG, beta caps, owner = timelock (owner Safe
    // 0xD1A9…2305, 2-of-3), guardian = the guardian Safe (1-of-2).
    usdg: '0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168',
    rpcUrl: 'https://rpc.mainnet.chain.robinhood.com',
    explorer: 'https://robinhoodchain.blockscout.com', // explorer.mainnet.chain.robinhood.com 301s here; explorer.chain.robinhood.com serves no TLS
    betaNoticeState: 'pre_audit',
  },
};

/** True once the vault and registry for `chainId` are non-zero. */
export function isDeployed(chainId: number): boolean {
  const d = deployments[chainId];
  return !!d && d.vault !== ZERO_ADDRESS && d.registry !== ZERO_ADDRESS;
}

// --- Vault and registry ABIs (§6.5): functions and events only. ---

export const darkKeyRegistryAbi = [
  {
    type: 'function',
    name: 'register',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'publicKey', type: 'tuple', components: [{ name: 'x', type: 'uint256' }, { name: 'y', type: 'uint256' }] },
      { name: 'proof', type: 'bytes' },
    ],
    outputs: [],
  },
  {
    type: 'function',
    name: 'keyOf',
    stateMutability: 'view',
    inputs: [{ name: 'account', type: 'address' }],
    outputs: [
      { name: '', type: 'tuple', components: [{ name: 'x', type: 'uint256' }, { name: 'y', type: 'uint256' }] },
    ],
  },
  {
    type: 'function',
    name: 'isRegistered',
    stateMutability: 'view',
    inputs: [{ name: 'account', type: 'address' }],
    outputs: [{ name: '', type: 'bool' }],
  },
  {
    type: 'function',
    name: 'registerVerifier',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'address' }],
  },
  {
    type: 'event',
    name: 'KeyRegistered',
    inputs: [
      { name: 'account', type: 'address', indexed: true },
      { name: 'px', type: 'uint256', indexed: false },
      { name: 'py', type: 'uint256', indexed: false },
    ],
  },
] as const;

const POINT = { type: 'tuple', components: [{ name: 'x', type: 'uint256' }, { name: 'y', type: 'uint256' }] } as const;
const CIPHERTEXT = {
  type: 'tuple',
  components: [{ name: 'c', ...POINT }, { name: 'd', ...POINT }],
} as const;
const CAPS = {
  type: 'tuple',
  components: [
    { name: 'minDeposit', type: 'uint64' },
    { name: 'maxDeposit', type: 'uint64' },
    { name: 'maxAccountInflow', type: 'uint64' },
    { name: 'minTransfer', type: 'uint64' },
    { name: 'maxTransfer', type: 'uint64' },
    { name: 'tvlCap', type: 'uint64' },
  ],
} as const;

export const darkVaultAbi = [
  {
    type: 'function',
    name: 'deposit',
    stateMutability: 'nonpayable',
    inputs: [{ name: 'amount', type: 'uint256' }, { name: 'aeBalance', type: 'bytes' }],
    outputs: [],
  },
  {
    type: 'function',
    name: 'applyPending',
    stateMutability: 'nonpayable',
    inputs: [{ name: 'expectedPendingCount', type: 'uint64' }, { name: 'aeBalance', type: 'bytes' }],
    outputs: [],
  },
  {
    type: 'function',
    name: 'transfer',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'to', type: 'address' },
      {
        name: 'ct',
        type: 'tuple',
        components: [{ name: 'c', ...POINT }, { name: 'dSender', ...POINT }, { name: 'dRecipient', ...POINT }],
      },
      { name: 'proof', type: 'bytes' },
      { name: 'hint', type: 'bytes' },
      { name: 'senderHint', type: 'bytes' },
      { name: 'aeBalance', type: 'bytes' },
    ],
    outputs: [],
  },
  {
    type: 'function',
    name: 'withdraw',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'amount', type: 'uint256' },
      { name: 'to', type: 'address' },
      { name: 'proof', type: 'bytes' },
      { name: 'aeBalance', type: 'bytes' },
    ],
    outputs: [],
  },
  {
    type: 'function',
    name: 'getAccount',
    stateMutability: 'view',
    inputs: [{ name: 'account', type: 'address' }],
    outputs: [
      {
        name: '',
        type: 'tuple',
        components: [
          { name: 'available', ...CIPHERTEXT },
          { name: 'pending', ...CIPHERTEXT },
          { name: 'nonce', type: 'uint64' },
          { name: 'pendingCount', type: 'uint64' },
          { name: 'netInflow', type: 'uint128' },
          { name: 'aeBalance', type: 'bytes' },
        ],
      },
    ],
  },
  { type: 'function', name: 'caps', stateMutability: 'view', inputs: [], outputs: [{ name: '', ...CAPS }] },
  { type: 'function', name: 'tvl', stateMutability: 'view', inputs: [], outputs: [{ name: '', type: 'uint256' }] },
  { type: 'function', name: 'usdg', stateMutability: 'view', inputs: [], outputs: [{ name: '', type: 'address' }] },
  { type: 'function', name: 'registry', stateMutability: 'view', inputs: [], outputs: [{ name: '', type: 'address' }] },
  { type: 'function', name: 'guardian', stateMutability: 'view', inputs: [], outputs: [{ name: '', type: 'address' }] },
  { type: 'function', name: 'paused', stateMutability: 'view', inputs: [], outputs: [{ name: '', type: 'bool' }] },
  {
    type: 'event',
    name: 'Deposited',
    inputs: [
      { name: 'account', type: 'address', indexed: true },
      { name: 'nonceAfter', type: 'uint64', indexed: false },
      { name: 'amount', type: 'uint256', indexed: false },
      { name: 'availableAfter', type: 'uint256[4]', indexed: false },
      { name: 'netInflowAfter', type: 'uint128', indexed: false },
      { name: 'tvlAfter', type: 'uint256', indexed: false },
    ],
  },
  {
    type: 'event',
    name: 'PendingApplied',
    inputs: [
      { name: 'account', type: 'address', indexed: true },
      { name: 'nonceAfter', type: 'uint64', indexed: false },
      { name: 'appliedCount', type: 'uint64', indexed: false },
      { name: 'availableAfter', type: 'uint256[4]', indexed: false },
    ],
  },
  {
    type: 'event',
    name: 'ConfidentialTransfer',
    inputs: [
      { name: 'from', type: 'address', indexed: true },
      { name: 'to', type: 'address', indexed: true },
      { name: 'fromNonceAfter', type: 'uint64', indexed: false },
      { name: 'transferCt', type: 'uint256[6]', indexed: false },
      { name: 'fromAvailableAfter', type: 'uint256[4]', indexed: false },
      { name: 'toPendingAfter', type: 'uint256[4]', indexed: false },
      { name: 'toPendingCountAfter', type: 'uint64', indexed: false },
      { name: 'hint', type: 'bytes', indexed: false },
      { name: 'senderHint', type: 'bytes', indexed: false },
    ],
  },
  {
    type: 'event',
    name: 'Withdrawn',
    inputs: [
      { name: 'account', type: 'address', indexed: true },
      { name: 'to', type: 'address', indexed: true },
      { name: 'nonceAfter', type: 'uint64', indexed: false },
      { name: 'amount', type: 'uint256', indexed: false },
      { name: 'availableAfter', type: 'uint256[4]', indexed: false },
      { name: 'netInflowAfter', type: 'uint128', indexed: false },
      { name: 'tvlAfter', type: 'uint256', indexed: false },
    ],
  },
  {
    type: 'event',
    name: 'CapsUpdated',
    inputs: [
      { name: 'oldCaps', ...CAPS, indexed: false },
      { name: 'newCaps', ...CAPS, indexed: false },
      { name: 'by', type: 'address', indexed: true },
    ],
  },
  {
    type: 'event',
    name: 'GuardianUpdated',
    inputs: [
      { name: 'oldGuardian', type: 'address', indexed: true },
      { name: 'newGuardian', type: 'address', indexed: true },
    ],
  },
] as const;
