/**
 * Exhibit 6 measures exact recovery, prediction, and confirmation after state theft.
 * CTR-no-update is the positive control for recovery. The HMAC_DRBG confirmation
 * row tests the post-Generate relation described by Woodage and Shumow, §7.1.
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
import { fromHex, hmacSha256 } from './utils';

export type AttackVerdict = 'recovered' | 'failed' | 'partial' | 'confirmed';

export interface AttackResult {
  /** The reference bytes: generator output or the stolen V for confirmation. */
  truth: Uint8Array;
  /** The attacker’s computed bytes, using a candidate block for confirmation. */
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
  noUpdate: AttackResult | null;
}

export interface CompromiseRun {
  entropyHex: string;
  roundBytes: number;
  usesAdditionalInput: boolean;
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
  /** Public additional input used for each HMAC_DRBG Generate request. */
  additionalInput?: Uint8Array;
}

/**
 * Run the whole experiment. Deterministic in its inputs, so the browser suite
 * can pin a seed and assert exact numbers.
 */
export async function runCompromise(inputs: CompromiseInputs): Promise<CompromiseRun> {
  const roundBytes = inputs.roundBytes ?? 32;
  const { entropy, reseedEntropy, additionalInput } = inputs;

  // ── the victim generators, seeded identically ────────────────────────────
  const h0: HmacDrbgState = await hmacDrbgInstantiate(entropy);
  const n0: NoUpdateState = await noUpdateInstantiate(entropy);

  const h1 = await hmacDrbgGenerate(h0, roundBytes, additionalInput); // round 1
  const n1 = await noUpdateGenerate(n0, roundBytes);
  const h2 = await hmacDrbgGenerate(h1.state, roundBytes, additionalInput); // round 2
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
  const h3 = await hmacDrbgGenerate(stolenH, roundBytes, additionalInput); // round 3, no reseed
  const n3 = await noUpdateGenerate(stolenN, roundBytes);

  // ── and what happens if the victim reseeds first ─────────────────────────
  const hReseeded = await hmacDrbgReseed(stolenH, reseedEntropy);
  const nReseeded = await noUpdateReseed(stolenN, reseedEntropy);
  const h3r = await hmacDrbgGenerate(hReseeded, roundBytes, additionalInput);
  const n3r = await noUpdateGenerate(nReseeded, roundBytes);

  // ── the attacker, holding only the stolen state ──────────────────────────
  // Forward: run the stolen state onwards. Available to both.
  const hForward = (await hmacDrbgGenerate(attackerH, roundBytes, additionalInput)).output;
  const nForward = (await noUpdateGenerate(attackerN, roundBytes)).output;

  // Backward, CTR-no-update: an exact inverse exists, so use it.
  const blocks = blocksFor(roundBytes);
  const nBack1 = (await noUpdateGenerate(rewind(attackerN, blocks), roundBytes)).output;
  const nBack2 = (await noUpdateGenerate(rewind(attackerN, blocks * 2), roundBytes)).output;

  // Try replaying the stolen state's stream as a recovery attempt.
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

  // Truncated requests do not expose the final full internal block as a candidate.
  if (roundBytes >= 32 && roundBytes % 32 === 0) {
    const attempt = await hmacSha256(attackerH.K, h2.output.slice(-32));
    const truth = attackerH.V;
    const matchedBytes = countMatches(truth, attempt);
    rows.splice(2, 0, {
      id: 'confirm-last-block',
      label: 'Confirm the last block of round 2 from the stolen state',
      direction: 'backward',
      hmac: {
        truth,
        attempt,
        matchedBytes,
        totalBytes: truth.length,
        verdict: matchedBytes === truth.length ? 'confirmed' : 'failed',
      },
      noUpdate: null,
    });
  }

  return {
    entropyHex: hex(entropy),
    roundBytes,
    usesAdditionalInput: Boolean(additionalInput?.length),
    stolenHmac: `K=${hex(stolenH.K).slice(0, 16)}… V=${hex(stolenH.V).slice(0, 16)}…`,
    stolenNoUpdate: `Key=${hex(stolenN.Key).slice(0, 16)}… V=${hex(stolenN.V).slice(0, 16)}…`,
    rows,
    expectedByChance: roundBytes / 256,
    chanceCeiling: chanceCeilingFor(roundBytes),
  };
}

/**
 * The page-level conclusion follows the recovery and confirmation verdicts.
 */
export interface CompromiseSummary {
  /** The two recovery attempts failed, independently of the confirmation check. */
  hmacBacktrackingHolds: boolean;
  noUpdateBacktrackingHolds: boolean;
  bothPredictableForward: boolean;
  reseedRestoresBoth: boolean;
  headline: string;
}

export function summarize(run: CompromiseRun): CompromiseSummary {
  const back = run.rows.filter((r) => r.id === 'past-1' || r.id === 'past-2');
  const confirm = run.rows.find((r) => r.id === 'confirm-last-block');
  const forward = run.rows.find((r) => r.id === 'future-3')!;
  const reseeded = run.rows.find((r) => r.id === 'future-3-reseeded')!;

  const hmacBacktrackingHolds = back.every((r) => r.hmac.verdict === 'failed');
  const noUpdateBacktrackingHolds = back.every((r) => r.noUpdate?.verdict === 'failed');
  const bothPredictableForward =
    forward.hmac.verdict === 'recovered' && forward.noUpdate?.verdict === 'recovered';
  const reseedRestoresBoth =
    reseeded.hmac.verdict === 'failed' && reseeded.noUpdate?.verdict === 'failed';

  let headline: string;
  if (!hmacBacktrackingHolds) {
    headline =
      'The HMAC_DRBG recovery attempt matched more bytes than expected. That contradicts SP 800-90A and this page; trust the byte counts above.';
  } else if (!back.every((r) => r.noUpdate?.verdict === 'recovered')) {
    headline =
      'The defective control was supposed to give up its past. Treat this run as an inconclusive experiment.';
  } else if (!confirm) {
    headline = 'Confirmation requires a full final output block.';
  } else if (!run.usesAdditionalInput && confirm.hmac.verdict !== 'confirmed') {
    headline =
      'Confirmation failed without additional input. This should never happen; trust the byte counts above.';
  } else if (run.usesAdditionalInput && confirm.hmac.verdict !== 'failed') {
    headline =
      'Confirmation unexpectedly succeeded with additional input; trust the byte counts above.';
  } else {
    const recovery = 'Recovery measured, not assumed: the stolen state rewinds CTR-no-update completely, while the HMAC_DRBG recovery attempts fail.';
    const confirmation = run.usesAdditionalInput
      ? ' With additional input, the check does not confirm the final block.'
      : ' Without additional input, the stolen state confirms the last block of the most recent request (Woodage & Shumow, §7.1).';
    headline = recovery + confirmation;
  }
  return {
    hmacBacktrackingHolds,
    noUpdateBacktrackingHolds,
    bothPredictableForward,
    reseedRestoresBoth,
    headline,
  };
}
