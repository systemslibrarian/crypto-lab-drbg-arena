/**
 * Simplified NIST SP 800-22 statistical tests for browser use.
 * Tests output quality of DRBG byte sequences.
 */

export interface StatTestResult {
  name: string;
  passed: boolean;
  pValue: number;
  description: string;
}

function bytesToBits(bytes: Uint8Array): number[] {
  const bits: number[] = [];
  for (const b of bytes) {
    for (let i = 7; i >= 0; i--) {
      bits.push((b >> i) & 1);
    }
  }
  return bits;
}

/**
 * Complementary error function approximation (needed for p-value computation).
 */
function erfc(x: number): number {
  const a1 = 0.254829592;
  const a2 = -0.284496736;
  const a3 = 1.421413741;
  const a4 = -1.453152027;
  const a5 = 1.061405429;
  const p = 0.3275911;

  const sign = x < 0 ? -1 : 1;
  x = Math.abs(x);
  const t = 1.0 / (1.0 + p * x);
  const y = 1.0 - ((((a5 * t + a4) * t + a3) * t + a2) * t + a1) * t * Math.exp(-x * x);
  return 1.0 - sign * y;
}

/**
 * Test 1: Frequency (Monobit) Test — SP 800-22 Section 2.1
 * Checks whether the proportion of 0s and 1s is approximately 50/50.
 */
export function frequencyTest(bytes: Uint8Array): StatTestResult {
  const bits = bytesToBits(bytes);
  const n = bits.length;
  let sum = 0;
  for (const bit of bits) {
    sum += bit === 1 ? 1 : -1;
  }
  const sObs = Math.abs(sum) / Math.sqrt(n);
  const pValue = erfc(sObs / Math.sqrt(2));

  return {
    name: 'Frequency (Monobit)',
    passed: pValue >= 0.01,
    pValue: Math.round(pValue * 10000) / 10000,
    description: `Proportion of 1s vs 0s. Sum=${sum}, n=${n}. ${pValue >= 0.01 ? 'Bits are balanced.' : 'Significant imbalance detected.'}`,
  };
}

/**
 * Test 2: Runs Test — SP 800-22 Section 2.3
 * Checks the number of uninterrupted sequences of identical bits.
 */
export function runsTest(bytes: Uint8Array): StatTestResult {
  const bits = bytesToBits(bytes);
  const n = bits.length;
  const ones = bits.filter(b => b === 1).length;
  const pi = ones / n;

  // Pre-test: frequency check
  if (Math.abs(pi - 0.5) > 2 / Math.sqrt(n)) {
    return {
      name: 'Runs',
      passed: false,
      pValue: 0,
      description: 'Failed prerequisite: bit frequency too imbalanced for runs test.',
    };
  }

  let runs = 1;
  for (let i = 1; i < n; i++) {
    if (bits[i] !== bits[i - 1]) runs++;
  }

  const pValue = erfc(
    Math.abs(runs - 2 * n * pi * (1 - pi)) /
    (2 * Math.sqrt(2 * n) * pi * (1 - pi))
  );

  return {
    name: 'Runs',
    passed: pValue >= 0.01,
    pValue: Math.round(pValue * 10000) / 10000,
    description: `Runs of consecutive bits: ${runs}. ${pValue >= 0.01 ? 'Run lengths are normal.' : 'Abnormal run pattern.'}`,
  };
}

/**
 * Test 3: Longest Run of Ones — SP 800-22 Section 2.4 (simplified)
 * Checks the longest consecutive run of 1s within fixed-size blocks.
 */
export function longestRunTest(bytes: Uint8Array): StatTestResult {
  const bits = bytesToBits(bytes);
  const n = bits.length;
  const blockSize = 8; // simplified: 8-bit blocks
  const numBlocks = Math.floor(n / blockSize);

  let maxRun = 0;
  const runLengths: number[] = [];

  for (let block = 0; block < numBlocks; block++) {
    let currentRun = 0;
    let blockMaxRun = 0;
    for (let i = 0; i < blockSize; i++) {
      if (bits[block * blockSize + i] === 1) {
        currentRun++;
        blockMaxRun = Math.max(blockMaxRun, currentRun);
      } else {
        currentRun = 0;
      }
    }
    runLengths.push(blockMaxRun);
    maxRun = Math.max(maxRun, blockMaxRun);
  }

  // For 8-bit blocks, expected longest run ~ 2-3
  // Simplified p-value using chi-squared approximation
  const expected = [0.2148, 0.3672, 0.2305, 0.1875]; // P(max <= 1,2,3,>=4) for M=8
  const counts = [0, 0, 0, 0];
  for (const r of runLengths) {
    if (r <= 1) counts[0]++;
    else if (r === 2) counts[1]++;
    else if (r === 3) counts[2]++;
    else counts[3]++;
  }

  let chiSq = 0;
  for (let i = 0; i < 4; i++) {
    const exp = expected[i]! * numBlocks;
    if (exp > 0) {
      chiSq += ((counts[i]! - exp) ** 2) / exp;
    }
  }

  // Approximate p-value from chi-squared with 3 df
  const pValue = Math.exp(-chiSq / 2);

  return {
    name: 'Longest Run of Ones',
    passed: pValue >= 0.01,
    pValue: Math.round(pValue * 10000) / 10000,
    description: `Longest run of 1s: ${maxRun} bits. Blocks: ${numBlocks}. ${pValue >= 0.01 ? 'Run lengths are within expected range.' : 'Unusually long or short runs.'}`,
  };
}

/**
 * Test 4: Shannon Entropy Estimate
 * Computes the Shannon entropy of the byte distribution.
 * For true random 8-bit output, entropy should be close to 8.0 bits.
 */
export function shannonEntropyTest(bytes: Uint8Array): StatTestResult {
  const freq = new Array<number>(256).fill(0);
  for (const b of bytes) {
    freq[b]++;
  }

  let entropy = 0;
  const n = bytes.length;
  for (let i = 0; i < 256; i++) {
    if (freq[i]! > 0) {
      const p = freq[i]! / n;
      entropy -= p * Math.log2(p);
    }
  }

  // For 1024 bytes of true random data, expected entropy ~ 7.81+
  const passed = entropy >= 7.0;
  const normalized = entropy / 8.0;

  return {
    name: 'Shannon Entropy',
    passed,
    pValue: Math.round(normalized * 10000) / 10000,
    description: `Entropy: ${entropy.toFixed(4)} bits/byte (max 8.0). ${passed ? 'Good randomness quality.' : 'Low entropy — poor randomness.'}`,
  };
}

/**
 * Run all four tests on a byte sequence.
 */
export function runAllTests(bytes: Uint8Array): StatTestResult[] {
  return [
    frequencyTest(bytes),
    runsTest(bytes),
    longestRunTest(bytes),
    shannonEntropyTest(bytes),
  ];
}
