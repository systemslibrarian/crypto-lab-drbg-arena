import { describe, it, expect } from 'vitest';
import { runAllTests, shannonEntropyTest } from './nist-tests';

/**
 * The low byte of a power-of-two-modulus LCG — the stream Exhibit 5 paints as
 * its "broken generator" grid. Kept byte-identical to `lcgBytes` in
 * `src/ui/exhibit5.ts`, because these tests exist to hold that stream to the
 * claims the exhibit makes about it.
 */
function lcgLowByte(n: number): Uint8Array {
  const out = new Uint8Array(n);
  let s = 1234567 >>> 0;
  for (let i = 0; i < n; i++) {
    s = (Math.imul(s, 16807) + 12345) >>> 0;
    out[i] = s & 0xff;
  }
  return out;
}

/** The HIGH byte of the same generator — what the exhibit used to paint. */
function lcgHighByte(n: number): Uint8Array {
  const out = new Uint8Array(n);
  let s = 1234567 >>> 0;
  for (let i = 0; i < n; i++) {
    s = (Math.imul(s, 16807) + 12345) >>> 0;
    out[i] = (s >>> 24) & 0xff;
  }
  return out;
}

function rowCorrelation(bytes: Uint8Array, rowWidth: number): number {
  const n = bytes.length - rowWidth;
  let sx = 0, sy = 0, sxy = 0, sxx = 0, syy = 0;
  for (let i = 0; i < n; i++) {
    const x = bytes[i]!;
    const y = bytes[i + rowWidth]!;
    sx += x; sy += y; sxy += x * y; sxx += x * x; syy += y * y;
  }
  const denom = Math.sqrt((n * sxx - sx * sx) * (n * syy - sy * sy));
  return denom === 0 ? 1 : (n * sxy - sx * sy) / denom;
}

describe('statistical test results carry the right kind of number', () => {
  it('Shannon Entropy reports bits/byte and no p-value', () => {
    const bytes = new Uint8Array(1024);
    crypto.getRandomValues(bytes);
    const entropy = shannonEntropyTest(bytes);
    // Its normalized entropy used to be written into `pValue` and printed in
    // the same table column as three genuine probabilities.
    expect(entropy.pValue).toBeNull();
    expect(entropy.statistic.unit).toBe('bits/byte');
    expect(entropy.statistic.value).toBeGreaterThan(7);
    expect(entropy.statistic.value).toBeLessThanOrEqual(8);
  });

  it('the three hypothesis tests report a p-value in [0,1]', () => {
    const bytes = new Uint8Array(1024);
    crypto.getRandomValues(bytes);
    for (const r of runAllTests(bytes).slice(0, 3)) {
      expect(r.pValue, r.name).not.toBeNull();
      expect(r.pValue!, r.name).toBeGreaterThanOrEqual(0);
      expect(r.pValue!, r.name).toBeLessThanOrEqual(1);
    }
  });
});

describe("Exhibit 5's broken-generator grid", () => {
  const GRID = 64 * 64;
  const ROW = 64;

  it('is genuinely structured: every row of the grid is identical', () => {
    // The page says the LCG grid shows visible banding. The low byte of a
    // 2^32-modulus LCG has period at most 2^8, and here it is exactly 64 — the
    // grid width — so row N and row N+1 are the same 64 bytes.
    const stream = lcgLowByte(GRID);
    expect(rowCorrelation(stream, ROW)).toBeCloseTo(1, 6);
    expect(new Set(stream).size).toBe(64); // only 64 of 256 byte values ever appear
  });

  it('fails all four of the demo\'s own tests', () => {
    const results = runAllTests(lcgLowByte(GRID));
    expect(results.filter((r) => r.passed)).toHaveLength(0);
    // Only 64 distinct values, uniformly hit → exactly log2(64) = 6 bits/byte.
    expect(results[3]!.statistic.value).toBeCloseTo(6, 6);
  });

  it('the high byte it used to paint is indistinguishable from noise', () => {
    // This is why the claim was false: `(s >>> 24) & 0xff` takes the LCG's GOOD
    // bits. It renders as snow and passes every test the demo runs, while the
    // caption beside it read "visible diagonal banding … your eye catches the
    // LCG instantly". Asserted here so the regression cannot come back quietly.
    const stream = lcgHighByte(GRID);
    expect(Math.abs(rowCorrelation(stream, ROW))).toBeLessThan(0.05);
    expect(runAllTests(stream).filter((r) => r.passed)).toHaveLength(4);
  });

  it('a real DRBG stream shows no row structure', () => {
    const bytes = new Uint8Array(GRID);
    crypto.getRandomValues(bytes);
    expect(Math.abs(rowCorrelation(bytes, ROW))).toBeLessThan(0.1);
  });
});

describe('the entropy shortfall the exhibit explains', () => {
  it('a perfect 1024-byte sample averages ~7.81 bits/byte, not 8.00', () => {
    // The panel used to assert "all three bars sit at essentially 8.00
    // bits/byte" while the labels beside it printed ~7.8. The shortfall is a
    // property of the sample size — 1024 draws cannot cover 256 values evenly —
    // which is what the panel now says, so pin the number it says.
    let total = 0;
    const runs = 60;
    for (let i = 0; i < runs; i++) {
      const s = new Uint8Array(1024);
      crypto.getRandomValues(s);
      total += shannonEntropyTest(s).statistic.value;
    }
    const mean = total / runs;
    expect(mean).toBeGreaterThan(7.75);
    expect(mean).toBeLessThan(7.86);
  });
});
