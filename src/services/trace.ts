/**
 * Authentication outcome counts, read through identity's own /health body.
 *
 * NO TELEMETRY TRACE PER AUTH RESOLVE (2026-10-22). Every resolve used to POST an `auth_resolve_v1` execution trace to
 * activity-api, steered by env switches (a sample rate, an always-trace-failures flag, an endpoint and a key fallback
 * chain) that no trace or walk could see. A credential check is not a gradable execution: it has no target shapes and
 * no reach verdict, so the traces taught the learner nothing, and since failures were traced unsampled, every bad key
 * presented to identity became a trace-store write. What an operator or a self-observer needs from it is how
 * authentications are going, and that is a handful of integers.
 *
 * So each resolve now bumps one in-memory count by reason class, since process start (or the last reset), and /health
 * carries the counts. They hold integers and a timestamp only: no key ids, org ids, tokens or reason strings (a reason
 * can quote upstream text).
 *
 * Reason classes:
 *   success: the credential authenticated;
 *   revoked: a valid key that has been revoked;
 *   expired: a JWT past its expiry;
 *   invalid: any other refusal (bad format or signature, unknown key, missing credential, wrong audience);
 *   unknown: the resolve threw instead of answering.
 */

export type AuthOutcomeClass = 'success' | 'invalid' | 'revoked' | 'expired' | 'unknown';

export interface AuthOutcomeCounts {
  success: number;
  invalid: number;
  revoked: number;
  expired: number;
  unknown: number;
  /** When counting started: process start, or the last reset. */
  since: string;
}

function zeroCounts(): AuthOutcomeCounts {
  return { success: 0, invalid: 0, revoked: 0, expired: 0, unknown: 0, since: new Date().toISOString() };
}

let counts: AuthOutcomeCounts = zeroCounts();

/** A copy of the current counts. */
export function authOutcomeCounts(): AuthOutcomeCounts {
  return { ...counts };
}

/** Zero the counts and restamp `since`. */
export function resetAuthOutcomeCounts(): void {
  counts = zeroCounts();
}

function classify(result: { authenticated?: boolean; reason?: string }): AuthOutcomeClass {
  if (result?.authenticated === true) return 'success';
  const reason = typeof result?.reason === 'string' ? result.reason : '';
  if (/revoked/i.test(reason)) return 'revoked';
  if (/expired/i.test(reason)) return 'expired';
  return 'invalid';
}

/**
 * Run an authentication and count its outcome. The result, or the error, passes through unchanged.
 */
export function traceAuthentication<T>(operation: () => Promise<T>): Promise<T> {
  return operation().then(
    (result: any) => {
      counts[classify(result)] += 1;
      return result;
    },
    (error) => {
      counts.unknown += 1;
      throw error;
    },
  );
}
