/**
 * Exhibit 6 — the state-compromise experiment.
 *
 * Exhibits 1 and 2 make a strong claim in prose: "the old state is destroyed by
 * a one-way function; this is why the past can't be recovered". This module
 * turns that sentence into a measurement, and — crucially — measures it against
 * a positive control, so the result is evidence rather than a restatement.
 *
 * The experiment:
 *   1. Seed two generators from the SAME entropy. One is the approved
 *      HMAC_DRBG (SP 800-90A §10.1.2). The other is CTR-no-update: the approved
 *      CTR_DRBG with its post-Generate Update step deleted, and nothing else.
 *   2. Both emit three rounds of output. The learner records all three.
 *   3. The attacker steals the internal state AFTER round 2.
 *   4. From that stolen state alone, the attacker tries four things, and every
 *      attempt is compared byte-for-byte against what really happened.
 *
 * Neither verdict is written from which generator it is. Both come from the
 * same match counter over the same four attacks, so the defective generator is
 * what proves the experiment can detect a failure at all: if backtracking
 * resistance were being asserted rather than measured, CTR-no-update would come
 * out looking safe too.
 *
 * On the backward attacks: CTR-no-update exposes an exact `rewind`, so its
 * recovery is a real inversion. HMAC_DRBG exposes no such operation — its state
 * transition is K = HMAC(K, V‖0x00), and reversing it is the SHA-256 preimage
 * problem. So the attacker's move against HMAC_DRBG is the only one the stolen
 * state permits: emit the stream that state generates, and see whether it
 * happens to agree with the past. It agrees at the chance rate, which is what
 * the numbers below report and what the verdict is derived from.
 */

import {
  hmacDrbgInstantiate,
  hmacDrbgGenerate,
  hmacDrbgReseed,
  type HmacDrbgState,
} from './hmac-drbg';
import {
  noUpdateInstantiate,
  noUpdateGenerate,
  noUpdateReseed,
  blocksFor,
  rewind,
  type NoUpdateState,
} from './ctr-no-update';
import { fromHex } from './utils';

export type AttackVerdict = 'recovered' | 'failed' | 'partial';

export interface AttackResult {
  /** What the generator really emitted (or will emit). */
  truth: Uint8Array;
  /** What the attacker produced from the stolen state alone. */
  attempt: Uint8Array;
  matchedBytes: number;
  totalBytes: number;
  verdict: AttackVerdict;
}

export interface AttackRow {
  id: string;
  label: string;
  /** Direction of the attack, for the page's framing. */
  direction: 'backward' | 'forward';
  hmac: AttackResult;
  noUpdate: AttackResult;
}

export interface CompromiseRun {
  entropyHex: string;
  roundBytes: number;
  /** Truncated hex of each generator's stolen state, for display. */
  stolenHmac: string;
  stolenNoUpdate: string;
  rows: AttackRow[];
  /** Bytes a chance agreement is expected to reach, and the failure ceiling. */
  expectedByChance: number;
  chanceCeiling: number;
}

/** Count positions where two byte strings agree. */
export function countMatches(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  let m = 0;
  for (let i = 0; i < n; i++) if (a[i] === b[i]) m++;
  return m;
}

/**
 * Largest number of agreeing bytes still consistent with pure chance.
 * One byte in 256 agrees by accident, so the expectation for n bytes is n/256;
 * the ceiling is deliberately generous (at least 3) so a "failed" verdict is
 * never a knife-edge call on a lucky run.
 */
export function chanceCeilingFor(totalBytes: number): number {
  return Math.max(3, Math.ceil((totalBytes / 256) * 8));
}

/**
 * The verdict is a pure function of the match count. It never sees which
 * generator produced the attempt — that is the point.
 */
export function classify(matched: number, total: number): AttackVerdict {
  if (total > 0 && matched === total) return 'recovered';
  if (matched <= chanceCeilingFor(total)) return 'failed';
  return 'partial';
}

function score(truth: Uint8Array, attempt: Uint8Array): AttackResult {
  const matchedBytes = countMatches(truth, attempt);
  const totalBytes = truth.length;
  return { truth, attempt, matchedBytes, totalBytes, verdict: classify(matchedBytes, totalBytes) };
}

/** Hex, for display. Kept local so this module has no UI dependency. */
function hex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');
}

export interface CompromiseInputs {
  entropy: Uint8Array;
  /** Fresh entropy used by the reseed row. */
  reseedEntropy: Uint8Array;
  roundBytes?: number;
}

/**
 * Run the whole experiment. Deterministic in its inputs, so the browser suite
 * can pin a seed and assert exact numbers.
 */
export async function runCompromise(inputs: CompromiseInputs): Promise<CompromiseRun> {
  const roundBytes = inputs.roundBytes ?? 32;
  const { entropy, reseedEntropy } = inputs;

  // ── the victim generators, seeded identically ────────────────────────────
  const h0: HmacDrbgState = await hmacDrbgInstantiate(entropy);
  const n0: NoUpdateState = await noUpdateInstantiate(entropy);

  const h1 = await hmacDrbgGenerate(h0, roundBytes); // round 1
  const n1 = await noUpdateGenerate(n0, roundBytes);
  const h2 = await hmacDrbgGenerate(h1.state, roundBytes); // round 2
  const n2 = await noUpdateGenerate(n1.state, roundBytes);

  // ── the theft: the state as it stands immediately after round 2 ──────────
  // The attacker exfiltrates the state as bytes and rebuilds it on their own
  // machine. Reconstructing through hex rather than sharing the victim's object
  // matters: it makes the forward rows a real test that the leaked bytes ALONE
  // reproduce the victim's stream, instead of two calls that agree because they
  // were handed the same reference.
  const stolenH = h2.state;
  const stolenN = n2.state;
  const attackerH: HmacDrbgState = {
    K: fromHex(hex(stolenH.K)),
    V: fromHex(hex(stolenH.V)),
    reseedCounter: stolenH.reseedCounter,
  };
  const attackerN: NoUpdateState = {
    Key: fromHex(hex(stolenN.Key)),
    V: fromHex(hex(stolenN.V)),
  };

  // ── what really happens next ─────────────────────────────────────────────
  const h3 = await hmacDrbgGenerate(stolenH, roundBytes); // round 3, no reseed
  const n3 = await noUpdateGenerate(stolenN, roundBytes);

  // ── and what happens if the victim reseeds first ─────────────────────────
  const hReseeded = await hmacDrbgReseed(stolenH, reseedEntropy);
  const nReseeded = await noUpdateReseed(stolenN, reseedEntropy);
  const h3r = await hmacDrbgGenerate(hReseeded, roundBytes);
  const n3r = await noUpdateGenerate(nReseeded, roundBytes);

  // ── the attacker, holding only the stolen state ──────────────────────────
  // Forward: run the stolen state onwards. Available to both.
  const hForward = (await hmacDrbgGenerate(attackerH, roundBytes)).output;
  const nForward = (await noUpdateGenerate(attackerN, roundBytes)).output;

  // Backward, CTR-no-update: an exact inverse exists, so use it.
  const blocks = blocksFor(roundBytes);
  const nBack1 = (await noUpdateGenerate(rewind(attackerN, blocks), roundBytes)).output;
  const nBack2 = (await noUpdateGenerate(rewind(attackerN, blocks * 2), roundBytes)).output;

  // Backward, HMAC_DRBG: no inverse exists to call. The stolen state generates
  // exactly one stream, so that stream is the attacker's entire repertoire; it
  // is scored against the past on the same footing as the exact recovery above.
  const hBack = hForward;

  const rows: AttackRow[] = [
    {
      id: 'past-1',
      label: 'Recover round 1 output (two rounds before the theft)',
      direction: 'backward',
      hmac: score(h1.output, hBack),
      noUpdate: score(n1.output, nBack2),
    },
    {
      id: 'past-2',
      label: 'Recover round 2 output (the round just before the theft)',
      direction: 'backward',
      hmac: score(h2.output, hBack),
      noUpdate: score(n2.output, nBack1),
    },
    {
      id: 'future-3',
      label: 'Predict round 3 output (no reseed in between)',
      direction: 'forward',
      hmac: score(h3.output, hForward),
      noUpdate: score(n3.output, nForward),
    },
    {
      id: 'future-3-reseeded',
      label: 'Predict round 3 output after the victim reseeds with fresh entropy',
      direction: 'forward',
      hmac: score(h3r.output, hForward),
      noUpdate: score(n3r.output, nForward),
    },
  ];

  return {
    entropyHex: hex(entropy),
    roundBytes,
    stolenHmac: `K=${hex(stolenH.K).slice(0, 16)}… V=${hex(stolenH.V).slice(0, 16)}…`,
    stolenNoUpdate: `Key=${hex(stolenN.Key).slice(0, 16)}… V=${hex(stolenN.V).slice(0, 16)}…`,
    rows,
    expectedByChance: roundBytes / 256,
    chanceCeiling: chanceCeilingFor(roundBytes),
  };
}

/**
 * The page-level conclusion, written from the row verdicts only. If the
 * measurements ever stopped supporting the sentence Exhibit 2 prints, this
 * would say so rather than printing the sentence anyway.
 */
export interface CompromiseSummary {
  hmacBacktrackingHolds: boolean;
  noUpdateBacktrackingHolds: boolean;
  bothPredictableForward: boolean;
  reseedRestoresBoth: boolean;
  headline: string;
}

export function summarize(run: CompromiseRun): CompromiseSummary {
  const back = run.rows.filter((r) => r.direction === 'backward');
  const forward = run.rows.find((r) => r.id === 'future-3')!;
  const reseeded = run.rows.find((r) => r.id === 'future-3-reseeded')!;

  const hmacBacktrackingHolds = back.every((r) => r.hmac.verdict === 'failed');
  const noUpdateBacktrackingHolds = back.every((r) => r.noUpdate.verdict === 'failed');
  const bothPredictableForward =
    forward.hmac.verdict === 'recovered' && forward.noUpdate.verdict === 'recovered';
  const reseedRestoresBoth =
    reseeded.hmac.verdict === 'failed' && reseeded.noUpdate.verdict === 'failed';

  let headline: string;
  if (hmacBacktrackingHolds && !noUpdateBacktrackingHolds) {
    headline =
      'Backtracking resistance measured, not assumed: the same theft rewinds CTR-no-update completely and gets nothing from HMAC_DRBG.';
  } else if (hmacBacktrackingHolds && noUpdateBacktrackingHolds) {
    headline =
      'Neither generator gave up its past — but the defective control was supposed to, so this run proves nothing about HMAC_DRBG. Treat it as an inconclusive experiment, not a pass.';
  } else {
    headline =
      'HMAC_DRBG gave up past output in this run. That contradicts SP 800-90A and this page; trust the byte counts above, not the prose.';
  }
  return {
    hmacBacktrackingHolds,
    noUpdateBacktrackingHolds,
    bothPredictableForward,
    reseedRestoresBoth,
    headline,
  };
}
