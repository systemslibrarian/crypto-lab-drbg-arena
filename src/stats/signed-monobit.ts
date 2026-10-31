import { erfc } from './nist-tests';

export type Calibration = 'normal' | 'exact';
export interface Monobit { ones: number; signed: number; absolute: number; p: number; q: number }

function validateSize(n: number): void {
  if (!Number.isInteger(n) || n < 2 || n > 64 || n % 2) throw new Error('Use an even block length from 2 to 64 bits.');
}

/** Exact finite null: X ~ Binomial(n, 1/2). No fitted parameters. */
export function binomialMasses(n: number): number[] {
  validateSize(n);
  const masses = [2 ** -n];
  for (let k = 0; k < n; k++) masses.push(masses[k] * (n - k) / (k + 1));
  return masses;
}

/** Q is a signed survival transform, not a multiple-testing/FDR q-value.
 * Exact tails include equality; discrete tail values are not uniform. */
export function monobit(ones: number, n: number, calibration: Calibration = 'normal'): Monobit {
  validateSize(n);
  if (!Number.isInteger(ones) || ones < 0 || ones > n) throw new Error('Invalid one count.');
  const signed = (2 * ones - n) / Math.sqrt(n);
  const absolute = Math.abs(signed);
  let p = signed === 0 ? 1 : erfc(absolute / Math.SQRT2);
  let q = signed === 0 ? 0.5 : 0.5 * erfc(signed / Math.SQRT2);
  if (calibration === 'exact') {
    const masses = binomialMasses(n);
    p = masses.reduce((s, mass, k) => s + (Math.abs(2 * k - n) >= Math.abs(2 * ones - n) ? mass : 0), 0);
    q = masses.slice(ones).reduce((s, mass) => s + mass, 0);
  }
  return { ones, signed, absolute, p: Math.min(1, Math.max(0, p)), q: Math.min(1, Math.max(0, q)) };
}

/** Bins [i/b,(i+1)/b), with 1 included in the final bin. Use raw values. */
export function binIndex(value: number, bins = 10): number {
  if (!Number.isFinite(value) || value < 0 || value > 1 || !Number.isInteger(bins) || bins < 1) throw new Error('Invalid bin input.');
  return Math.min(bins - 1, Math.floor(value * bins));
}

export function expectedBins(n: number, field: 'p' | 'q', calibration: Calibration = 'normal', folded = false): number[] {
  const expected = Array<number>(10).fill(0);
  binomialMasses(n).forEach((mass, k) => {
    const ones = folded && k < n / 2 ? n - k : k;
    expected[binIndex(monobit(ones, n, calibration)[field])] += mass;
  });
  return expected;
}

export function analyzeBlocks(bits: Uint8Array, n: number, calibration: Calibration, folded = false) {
  validateSize(n);
  if (!bits.length || bits.length % n || bits.some(b => b !== 0 && b !== 1)) throw new Error('Supply complete binary blocks.');
  const rows: Monobit[] = [], p = Array<number>(10).fill(0), q = Array<number>(10).fill(0);
  for (let i = 0; i < bits.length; i += n) {
    let ones = bits.slice(i, i + n).reduce((s, b) => s + b, 0);
    if (folded && ones < n / 2) ones = n - ones;
    const row = monobit(ones, n, calibration);
    rows.push(row); p[binIndex(row.p)]++; q[binIndex(row.q)]++;
  }
  return { rows, p, q };
}
