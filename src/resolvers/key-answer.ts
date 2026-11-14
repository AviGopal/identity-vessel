/**
 * keyAnswer resolver: the last answer this identity gave for each of the caller org's keys (services/answer-log.ts), so
 * a reader (the walk, a detector's gap evidence) can see how a key was answered: which branch, how its row was found,
 * the row, what it stored and the class answered. Served on identity's resolve door (POST /v1/auth/resolve,
 * pointer.type 'keyAnswer', optional pointer.key_mask: the first characters of a key id), advertised to discovery like
 * apiKeyClass and authorized the same way: a service ApiKey of the org (serviceCallerOrg).
 *
 * The answer always names this identity's node and when it started holding answers. Answers live in memory, in the
 * identity that gave them: another node's identity, or this one after a restart, holds none for a key it did not
 * answer since it started. So an empty answer says so in words ("no answer held here since <started>"), never as an
 * empty list a reader could take for "no mismatch".
 */
import { serviceCallerOrg, nodeName, type KeyClassFailureCode } from './key-class';
import { heldAnswers, heldSince, type HeldAnswer } from '../services/answer-log';

export const KEY_ANSWER_SHAPE = 'keyAnswer';

export type KeyAnswerResult =
  | { ok: true; node: string | null; held_since: string; answers: HeldAnswer[]; none?: string }
  | { ok: false; status: number; code: KeyClassFailureCode; message: string };

/** A key mask a reader may ask for: a prefix of a key id, no longer than the 12 characters an answer holds. */
const MASK_SHAPE = /^key_[A-Za-z0-9_]{0,8}$/;

export async function readKeyAnswer(authHeader: string | undefined, pointer: Record<string, unknown> | undefined): Promise<KeyAnswerResult> {
  const caller = await serviceCallerOrg(authHeader, KEY_ANSWER_SHAPE);
  if (!caller.ok) return caller;
  const raw = pointer?.key_mask;
  if (raw !== undefined && (typeof raw !== 'string' || !MASK_SHAPE.test(raw))) {
    return { ok: false, status: 400, code: 'INVALID_INPUT', message: 'key_mask is the first 4 to 12 characters of a key id (key_ and up to 8 more)' };
  }
  const answers = heldAnswers(caller.orgId, raw as string | undefined);
  const since = heldSince();
  const node = nodeName();
  // Counts only: no key id or mask.
  console.log(`[keyAnswer] served ${answers.length} answer(s) held since ${since}`);
  return answers.length > 0
    ? { ok: true, node, held_since: since, answers }
    : { ok: true, node, held_since: since, answers, none: `no answer held here${raw ? ` for ${raw}` : ''} since ${since}` };
}
