import { describe, it, expect } from 'vitest';
import {
  runCompromise,
  summarize,
  classify,
  countMatches,
  chanceCeilingFor,
} from './compromise';
import {
  noUpdateInstantiate,
  noUpdateGenerate,
  rewind,
  decrementCounter,
  blocksFor,
} from './ctr-no-update';
import { incrementCounter, toHex, fromHex } from './utils';
import { hmacDrbgInstantiate, hmacDrbgGenerate } from './hmac-drbg';

const SEED = fromHex(
  '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f'
);
const RESEED = fromHex(
  'f0e0d0c0b0a0908070605040302010000f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0'
);

describe('decrementCounter', () => {
  it('inverts incrementCounter on every borrow pattern that matters', () => {
    const cases = [
      new Uint8Array(16),
      new Uint8Array(16).fill(0xff),
      fromHex('000000000000000000000000000000ff'),
      fromHex('00000000000000000000000000000100'),
      fromHex('0102030405060708090a0b0c0d0e0f10'),
    ];
    for (const c of cases) {
      expect(toHex(decrementCounter(incrementCounter(c)))).toBe(toHex(c));
      expect(toHex(incrementCounter(decrementCounter(c)))).toBe(toHex(c));
    }
  });

  it('wraps 0 back to all-ones, matching increment wrapping', () => {
    expect(toHex(decrementCounter(new Uint8Array(16)))).toBe('ff'.repeat(16));
  });
});

describe('CTR-no-update: rewind is an exact inverse of the state transition', () => {
  it('replays an earlier round byte-for-byte from a later state', async () => {
    const s0 = await noUpdateInstantiate(SEED);
    const r1 = await noUpdateGenerate(s0, 32);
    const r2 = await noUpdateGenerate(r1.state, 32);

    const back = rewind(r2.state, blocksFor(32) * 2);
    const replay = await noUpdateGenerate(back, 32);
    expect(toHex(replay.output)).toBe(toHex(r1.output));
  });

  it('never changes its key — the deleted Update step is the whole defect', async () => {
    const s0 = await noUpdateInstantiate(SEED);
    const r1 = await noUpdateGenerate(s0, 32);
    const r2 = await noUpdateGenerate(r1.state, 32);
    expect(toHex(r2.state.Key)).toBe(toHex(s0.Key));
  });
});

describe('HMAC_DRBG: the state really does move on every Generate', () => {
  it('changes both K and V, so no rewind is even definable', async () => {
    const s0 = await hmacDrbgInstantiate(SEED);
    const r1 = await hmacDrbgGenerate(s0, 32);
    expect(r1.newK).not.toBe(r1.prevK);
    expect(r1.newV).not.toBe(r1.prevV);
  });
});

describe('classify / countMatches', () => {
  it('counts agreeing positions only', () => {
    expect(countMatches(fromHex('00112233'), fromHex('00ff2233'))).toBe(3);
    expect(countMatches(fromHex('00112233'), fromHex('ffffffff'))).toBe(0);
  });

  it('calls a full match RECOVERED', () => {
    expect(classify(32, 32)).toBe('recovered');
  });

  it('calls a chance-level match failed', () => {
    expect(classify(0, 32)).toBe('failed');
    expect(classify(chanceCeilingFor(32), 32)).toBe('failed');
  });

  it('calls anything in between PARTIAL rather than rounding it to a pass', () => {
    expect(classify(chanceCeilingFor(32) + 1, 32)).toBe('partial');
    expect(classify(31, 32)).toBe('partial');
  });

  it('is a function of the counts alone — it cannot see which generator ran', () => {
    expect(classify(32, 32)).toBe(classify(32, 32));
    expect(classify(0, 32)).not.toBe(classify(32, 32));
  });
});

describe('runCompromise — the experiment itself', () => {
  it('recovers CTR-no-update’s entire past exactly and HMAC_DRBG’s not at all', async () => {
    const run = await runCompromise({ entropy: SEED, reseedEntropy: RESEED, roundBytes: 32 });

    const past1 = run.rows.find((r) => r.id === 'past-1')!;
    const past2 = run.rows.find((r) => r.id === 'past-2')!;

    // Positive control: the defective generator hands back both earlier rounds.
    expect(past1.noUpdate.matchedBytes).toBe(32);
    expect(past1.noUpdate.verdict).toBe('recovered');
    expect(past2.noUpdate.matchedBytes).toBe(32);
    expect(past2.noUpdate.verdict).toBe('recovered');

    // The approved construction gives up nothing beyond chance.
    expect(past1.hmac.verdict).toBe('failed');
    expect(past2.hmac.verdict).toBe('failed');
    expect(past1.hmac.matchedBytes).toBeLessThanOrEqual(run.chanceCeiling);
    expect(past2.hmac.matchedBytes).toBeLessThanOrEqual(run.chanceCeiling);
  });

  it('shows BOTH generators handing over the next round — prediction resistance is a separate property', async () => {
    const run = await runCompromise({ entropy: SEED, reseedEntropy: RESEED, roundBytes: 32 });
    const forward = run.rows.find((r) => r.id === 'future-3')!;
    expect(forward.hmac.verdict).toBe('recovered');
    expect(forward.noUpdate.verdict).toBe('recovered');
    expect(forward.hmac.matchedBytes).toBe(32);
    expect(forward.noUpdate.matchedBytes).toBe(32);
  });

  it('locks both attackers out once the victim reseeds from fresh entropy', async () => {
    const run = await runCompromise({ entropy: SEED, reseedEntropy: RESEED, roundBytes: 32 });
    const reseeded = run.rows.find((r) => r.id === 'future-3-reseeded')!;
    expect(reseeded.hmac.verdict).toBe('failed');
    expect(reseeded.noUpdate.verdict).toBe('failed');
  });

  it('is deterministic in its inputs, so the browser suite can pin exact numbers', async () => {
    const a = await runCompromise({ entropy: SEED, reseedEntropy: RESEED, roundBytes: 32 });
    const b = await runCompromise({ entropy: SEED, reseedEntropy: RESEED, roundBytes: 32 });
    expect(a.rows.map((r) => [r.hmac.matchedBytes, r.noUpdate.matchedBytes])).toEqual(
      b.rows.map((r) => [r.hmac.matchedBytes, r.noUpdate.matchedBytes])
    );
    expect(a.stolenHmac).toBe(b.stolenHmac);
  });

  it('scores the attacker against real output: changing the seed changes the truth', async () => {
    const other = new Uint8Array(SEED);
    other[0] ^= 0x01;
    const a = await runCompromise({ entropy: SEED, reseedEntropy: RESEED, roundBytes: 32 });
    const b = await runCompromise({ entropy: other, reseedEntropy: RESEED, roundBytes: 32 });
    const pa = a.rows.find((r) => r.id === 'past-2')!;
    const pb = b.rows.find((r) => r.id === 'past-2')!;
    expect(toHex(pa.noUpdate.truth)).not.toBe(toHex(pb.noUpdate.truth));
    // …and the recovery still lands, because it is an inversion, not a lookup.
    expect(pb.noUpdate.matchedBytes).toBe(32);
  });
});

describe('summarize — the page-level conclusion', () => {
  it('reports a measured pass on the real run', async () => {
    const run = await runCompromise({ entropy: SEED, reseedEntropy: RESEED, roundBytes: 32 });
    const s = summarize(run);
    expect(s.hmacBacktrackingHolds).toBe(true);
    expect(s.noUpdateBacktrackingHolds).toBe(false);
    expect(s.bothPredictableForward).toBe(true);
    expect(s.reseedRestoresBoth).toBe(true);
    expect(s.headline).toContain('measured, not assumed');
  });

  it('refuses to call an inconclusive run a pass when the control also holds', async () => {
    const run = await runCompromise({ entropy: SEED, reseedEntropy: RESEED, roundBytes: 32 });
    // Force the control to look safe, as it would if the experiment were blind.
    for (const row of run.rows) {
      if (row.direction === 'backward') {
        row.noUpdate.matchedBytes = 0;
        row.noUpdate.verdict = 'failed';
      }
    }
    const s = summarize(run);
    expect(s.hmacBacktrackingHolds).toBe(true);
    expect(s.headline).toContain('inconclusive');
    expect(s.headline).not.toContain('measured, not assumed');
  });

  it('says so loudly if HMAC_DRBG ever gave up its past', async () => {
    const run = await runCompromise({ entropy: SEED, reseedEntropy: RESEED, roundBytes: 32 });
    const past2 = run.rows.find((r) => r.id === 'past-2')!;
    past2.hmac.matchedBytes = 32;
    past2.hmac.verdict = 'recovered';
    const s = summarize(run);
    expect(s.hmacBacktrackingHolds).toBe(false);
    expect(s.headline).toContain('contradicts SP 800-90A');
  });
});
