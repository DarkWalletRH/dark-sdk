// SPDX-License-Identifier: MIT OR Apache-2.0
/** Every SDK failure carries one of these codes. */
export type DarkErrorCode =
  | 'NOT_IMPLEMENTED'
  | 'NOT_DEPLOYED'
  | 'KEY_DERIVATION_MISMATCH'
  | 'MISSING_ACCOUNT_SECRET'
  | 'NOT_REGISTERED'
  | 'RECIPIENT_NOT_REGISTERED'
  | 'INSUFFICIENT_BALANCE'
  | 'AMOUNT_OUT_OF_RANGE'
  | 'CAP_EXCEEDED'
  | 'STALE_STATE'
  | 'RPC_DISAGREEMENT'
  | 'PROVER_UNAVAILABLE'
  | 'PUBLIC_INPUT_MISMATCH'
  | 'DECRYPTION_FAILED';

export class DarkError extends Error {
  readonly code: DarkErrorCode;
  readonly detail?: unknown;
  constructor(code: DarkErrorCode, message: string, detail?: unknown) {
    super(message);
    this.name = 'DarkError';
    this.code = code;
    this.detail = detail;
  }
}

export const isDarkError = (e: unknown): e is DarkError => e instanceof DarkError;
