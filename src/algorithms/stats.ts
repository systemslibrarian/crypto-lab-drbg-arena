// Simplified NIST SP 800-22 statistical tests

export interface StatTestResult {
  name: string;
  passed: boolean;
  pValue: number;
  description: string;
  detail: string;
}

// Convert bytes to bit array
function toBits(bytes: Uint8Array): number[] {
  const bits: number[] = [];
  for (const byte of bytes) {
    for (let i = 7; i >= 0; i--) {
      bits.push((byte >> i) & 1);
    }
  }
  return bits;
}

// Error function approximation (erfc)
function erfc(x: number): number {
  // Approximation of erfc using numerical method
  const t = 1 / (1 + 0.3275911 * Math.abs(x));
  const poly = t * (0.254829592 + t * (-0.284496736 + t * (1.421413741 + t * (-1.453152027 + t * 1.061405429))));
  const result = poly * Math.exp(-(x * x));
  return x >= 0 ? result : 2 - result;
}

// Test 1: Frequency (Monobit) Test per NIST SP 800-22 §2.1
export function frequencyTest(bytes: Uint8Array): StatTestResult {
  const bits = toBits(bytes);
  const n = bits.length;
  let sum = 0;
  for (const b of bits) sum += b === 1 ? 1 : -1;
  const sObs = Math.abs(sum) / Math.sqrt(n);
  const pValue = erfc(sObs / Math.sqrt(2));
  return {
    name: 'Frequency (Monobit) Test',
    passed: pValue >= 0.01,
    pValue,
    description: 'Tests that the proportion of 0s and 1s is approximately equal (~50/50)',
    detail: `n=${n}, S_obs=${sObs.toFixed(4)}, p-value=${pValue.toFixed(4)} (pass if ≥0.01)`
  };
}

// Test 2: Runs Test per NIST SP 800-22 §2.3
export function runsTest(bytes: Uint8Array): StatTestResult {
  const bits = toBits(bytes);
  const n = bits.length;
  const oneCount = bits.filter(b => b === 1).length;
  const pi = oneCount / n;

  // Pre-test: |pi - 0.5| must be < 2/sqrt(n)
  if (Math.abs(pi - 0.5) >= 2 / Math.sqrt(n)) {
    return {
      name: 'Runs Test',
      passed: false,
      pValue: 0,
      description: 'Tests uninterrupted sequences of identical bits (runs)',
      detail: `Pre-test failed: pi=${pi.toFixed(4)}, threshold=${(2/Math.sqrt(n)).toFixed(4)}`
    };
  }

  let vObs = 1;
  for (let i = 1; i < n; i++) {
    if (bits[i] !== bits[i - 1]) vObs++;
  }

  const numerator = Math.abs(vObs - 2 * n * pi * (1 - pi));
  const denominator = 2 * Math.sqrt(2 * n) * pi * (1 - pi);
  const pValue = erfc(numerator / denominator);

  return {
    name: 'Runs Test',
    passed: pValue >= 0.01,
    pValue,
    description: 'Tests uninterrupted sequences of identical bits (runs)',
    detail: `V_obs=${vObs}, p-value=${pValue.toFixed(4)} (pass if ≥0.01)`
  };
}

// Test 3: Longest Run of Ones in a Block per NIST SP 800-22 §2.4
export function longestRunTest(bytes: Uint8Array): StatTestResult {
  const bits = toBits(bytes);
  const n = bits.length;

  // For n >= 6272, use M=10, K=6, N=968
  // For simplicity with smaller inputs, use M=8, K=3, N=16 (n=128 case)
  let M: number, K: number, V: number[], pi: number[];

  if (n < 128) {
    return {
      name: 'Longest Run of Ones Test',
      passed: true,
      pValue: 1,
      description: 'Tests the longest run of consecutive 1s',
      detail: 'Insufficient data (need ≥128 bits); skipped'
    };
  } else if (n < 6272) {
    M = 8; K = 3; V = [1, 2, 3, 4]; pi = [0.2148, 0.3672, 0.2305, 0.1875];
  } else {
    M = 10; K = 6; V = [10, 11, 12, 13, 14, 15, 16];
    pi = [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727];
  }

  const N = Math.floor(n / M);

  // Find longest run in each block
  const counts = new Array(K + 1).fill(0) as number[];
  for (let i = 0; i < N; i++) {
    const block = bits.slice(i * M, (i + 1) * M);
    let maxRun = 0, run = 0;
    for (const b of block) {
      if (b === 1) { run++; maxRun = Math.max(maxRun, run); }
      else run = 0;
    }
    // Categorize
    const idx = Math.min(maxRun, V.length - 1);
    counts[Math.max(0, idx)]++;
  }

  // Chi-squared statistic
  let chiSquared = 0;
  for (let i = 0; i <= K; i++) {
    const expected = (pi[i] ?? 0) * N;
    if (expected > 0) {
      const diff = (counts[i] ?? 0) - expected;
      chiSquared += diff * diff / expected;
    }
  }

  // p-value via incomplete gamma function approximation (K degrees of freedom)
  const pValue = Math.exp(-chiSquared / 2); // simplified approximation
  const clampedP = Math.min(1, Math.max(0, pValue));

  return {
    name: 'Longest Run of Ones Test',
    passed: clampedP >= 0.01,
    pValue: clampedP,
    description: 'Tests the longest run of consecutive 1s in blocks',
    detail: `χ²=${chiSquared.toFixed(4)}, p-value=${clampedP.toFixed(4)} (pass if ≥0.01)`
  };
}

// Test 4: Shannon Entropy Estimate
export function shannonEntropyTest(bytes: Uint8Array): StatTestResult {
  const freq = new Array(256).fill(0) as number[];
  for (const b of bytes) freq[b]++;
  const n = bytes.length;
  let entropy = 0;
  for (const f of freq) {
    if (f > 0) {
      const p = f / n;
      entropy -= p * Math.log2(p);
    }
  }
  // Max entropy for bytes is 8 bits
  const ratio = entropy / 8;
  const passed = entropy >= 7.0; // expect close to 8 for good RNG

  return {
    name: 'Shannon Entropy Estimate',
    passed,
    pValue: ratio,
    description: 'Estimates information entropy of the byte distribution (expect ~8 bits/byte)',
    detail: `H=${entropy.toFixed(4)} bits/byte, ratio=${(ratio * 100).toFixed(1)}% of max (pass if ≥7.0)`
  };
}

export function runAllTests(bytes: Uint8Array): StatTestResult[] {
  return [
    frequencyTest(bytes),
    runsTest(bytes),
    longestRunTest(bytes),
    shannonEntropyTest(bytes),
  ];
}
