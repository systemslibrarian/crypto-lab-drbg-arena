/**
 * Live conformance self-check.
 *
 * Runs the three NIST SP 800-90A DRBGs against official CAVP known-answer
 * vectors *in the browser, on page load*, and reports whether each produced
 * the exact bytes NIST published. This is what makes the demo trustworthy:
 * the learner doesn't have to take "these are correct" on faith — the page
 * proves it against the reference vectors every time it loads.
 *
 * These same vectors are the single source of truth for `drbg-kat.test.ts`,
 * so the values shown in the UI are exactly the values verified in CI.
 *
 * Vectors reproduced from NIST's DRBG Validation System (DRBGVS), the
 * "no prediction resistance / no reseed" category:
 *   https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/random-number-generators
 */

import { hmacDrbgInstantiate, hmacDrbgGenerate } from './hmac-drbg';
import { ctrDrbgInstantiate, ctrDrbgGenerate } from './ctr-drbg';
import { hashDrbgInstantiate, hashDrbgGenerate } from './hash-drbg';
import { fromHex, toHex } from './utils';

export interface KatVector {
  algorithm: string;
  detail: string;
  entropy: string;
  nonce?: string;
  /** Bytes per Generate call. */
  outLen: number;
  /** Expected output of the Generate call we assert on, full hex. */
  expected: string;
  /**
   * CAVP protocol: number of Generate calls; we assert on the LAST one.
   * (For the no-PR vectors the first Generate output is discarded.)
   */
  generates: number;
  run: (entropy: Uint8Array, nonce: Uint8Array | undefined, outLen: number, generates: number) => Promise<string>;
}

export const NIST_VECTORS: KatVector[] = [
  {
    algorithm: 'HMAC_DRBG',
    detail: 'SHA-256 · no prediction resistance',
    entropy: 'ca851911349384bffe89de1cbdc46e6831e44d34a4fb935ee285dd14b71a7488',
    nonce: '659ba96c601dc69fc902940805ec0ca8',
    outLen: 128,
    generates: 2,
    expected:
      'e528e9abf2dece54d47c7e75e5fe302149f817ea9fb4bee6f4199697d04d5b89' +
      'd54fbb978a15b5c443c9ec21036d2460b6f73ebad0dc2aba6e624abf07745bc1' +
      '07694bb7547bb0995f70de25d6b29e2d3011bb19d27676c07162c8b5ccde0668' +
      '961df86803482cb37ed6d5c0bb8d50cf1f50d476aa0458bdaba806f48be9dcb8',
    run: async (entropy, nonce, outLen, generates) => {
      let st = await hmacDrbgInstantiate(entropy, nonce);
      let r = await hmacDrbgGenerate(st, outLen);
      for (let i = 1; i < generates; i++) {
        st = r.state;
        r = await hmacDrbgGenerate(st, outLen);
      }
      return toHex(r.output);
    },
  },
  {
    algorithm: 'CTR_DRBG',
    detail: 'AES-256, no df · no prediction resistance',
    entropy:
      'df5d73faa468649edda33b5cca79b0b05600419ccb7a879ddfec9db32ee494e5' +
      '531b51de16a30f769262474c73bec010',
    outLen: 64,
    generates: 2,
    expected:
      'd1c07cd95af8a7f11012c84ce48bb8cb87189e99d40fccb1771c619bdf82ab22' +
      '80b1dc2f2581f39164f7ac0c510494b3a43c41b7db17514c87b107ae793e01c5',
    run: async (entropy, _nonce, outLen, generates) => {
      let st = await ctrDrbgInstantiate(entropy);
      let r = await ctrDrbgGenerate(st, outLen);
      for (let i = 1; i < generates; i++) {
        st = r.state;
        r = await ctrDrbgGenerate(st, outLen);
      }
      return toHex(r.output);
    },
  },
  {
    algorithm: 'Hash_DRBG',
    detail: 'SHA-256 · no prediction resistance',
    entropy:
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' +
      '202122232425262728292a2b2c2d2e2f30313233343536',
    nonce: '2021222324252627',
    outLen: 64,
    generates: 1, // this CAVP vector publishes the FIRST Generate output
    expected:
      '77e05a0e7dc78ab5d8934d5e93e82c06a07c04cee6c9c53045eeb485872777cf' +
      '3b3e35c474f976b894bf301a86fa651f463970e89d4a0534b2ecad29ec044e7e',
    run: async (entropy, nonce, outLen, generates) => {
      let st = await hashDrbgInstantiate(entropy, nonce, undefined, 'SHA-256');
      let r = await hashDrbgGenerate(st, outLen);
      for (let i = 1; i < generates; i++) {
        st = r.state;
        r = await hashDrbgGenerate(st, outLen);
      }
      return toHex(r.output);
    },
  },
];

export interface KatResult {
  algorithm: string;
  detail: string;
  expected: string;
  actual: string;
  pass: boolean;
}

export async function runSelfCheck(): Promise<KatResult[]> {
  const results: KatResult[] = [];
  for (const v of NIST_VECTORS) {
    const entropy = fromHex(v.entropy);
    const nonce = v.nonce ? fromHex(v.nonce) : undefined;
    const actual = await v.run(entropy, nonce, v.outLen, v.generates);
    results.push({
      algorithm: v.algorithm,
      detail: v.detail,
      expected: v.expected,
      actual,
      pass: actual === v.expected,
    });
  }
  return results;
}
