/**
 * Known-Answer Tests (KAT) for the three NIST SP 800-90A DRBGs.
 *
 * These are the heart of the project's credibility: a DRBG demo is only
 * trustworthy if its output is *bit-for-bit identical* to the reference
 * values published by NIST's Cryptographic Algorithm Validation Program
 * (CAVP). Each vector below is reproduced from the official NIST DRBG
 * Validation System (DRBGVS) test data:
 *
 *   https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/random-number-generators
 *
 * CAVP protocol for the "no prediction resistance / no reseed" vectors used
 * here: Instantiate(entropy, nonce, personalization), then call Generate
 * twice with the requested length. The FIRST Generate output is discarded;
 * the SECOND Generate output is the value NIST publishes as ReturnedBits.
 * (Where a vector publishes both Generate outputs we assert on both.)
 *
 * If any assertion in this file fails, the implementation is NOT conformant
 * to SP 800-90A — do not ship it.
 */

import { describe, it, expect } from 'vitest';
import { hmacDrbgInstantiate, hmacDrbgGenerate } from './hmac-drbg';
import { ctrDrbgInstantiate, ctrDrbgGenerate } from './ctr-drbg';
import { hashDrbgInstantiate, hashDrbgGenerate } from './hash-drbg';
import { fromHex, toHex } from './utils';
import { NIST_VECTORS, runSelfCheck } from './self-check';

describe('NIST CAVP known-answer tests', () => {
  // The vectors live in self-check.ts so the UI badge and CI assert the exact
  // same reference values — one source of truth, no drift.
  for (const v of NIST_VECTORS) {
    it(`${v.algorithm} (${v.detail}) matches the published vector`, async () => {
      const actual = await v.run(
        fromHex(v.entropy),
        v.nonce ? fromHex(v.nonce) : undefined,
        v.outLen,
        v.generates,
      );
      expect(actual).toBe(v.expected);
    });
  }

  it('runSelfCheck() reports every algorithm as conformant', async () => {
    const results = await runSelfCheck();
    expect(results.every((r) => r.pass)).toBe(true);
    expect(results).toHaveLength(3);
  });

  // A second Hash_DRBG vector that exercises the *second* Generate call, proving
  // the V += H + C + reseed_counter state update between calls is correct.
  it('Hash_DRBG SHA-256 second Generate matches', async () => {
    const entropy = fromHex(
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' +
      '202122232425262728292a2b2c2d2e2f30313233343536'
    );
    const nonce = fromHex('2021222324252627');
    const gen2 =
      '5ff4ba493c40cfff3b01e472c575668cce3880b9290b05bfede5ec96ed5e9b28' +
      '98508b09bc800eee099a3c90602abd4b1d4f343d497c6055c87bb956d53bf351';
    let st = await hashDrbgInstantiate(entropy, nonce, undefined, 'SHA-256');
    let r = await hashDrbgGenerate(st, 64);
    st = r.state;
    r = await hashDrbgGenerate(st, 64);
    expect(toHex(r.output)).toBe(gen2);
  });
});

describe('DRBG security & correctness properties', () => {
  const seed = fromHex('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff');
  const nonce = fromHex('0123456789abcdef0123456789abcdef');

  it('HMAC_DRBG is deterministic: same seed → same stream', async () => {
    const a = await hmacDrbgGenerate(await hmacDrbgInstantiate(seed, nonce), 64);
    const b = await hmacDrbgGenerate(await hmacDrbgInstantiate(seed, nonce), 64);
    expect(toHex(a.output)).toBe(toHex(b.output));
  });

  it('HMAC_DRBG advances state: both K and V change on Generate (backtracking resistance)', async () => {
    const r = await hmacDrbgGenerate(await hmacDrbgInstantiate(seed, nonce), 32);
    expect(r.newK).not.toBe(r.prevK);
    expect(r.newV).not.toBe(r.prevV);
  });

  it('HMAC_DRBG: consecutive Generate calls produce different output', async () => {
    let st = await hmacDrbgInstantiate(seed, nonce);
    const r1 = await hmacDrbgGenerate(st, 32);
    const r2 = await hmacDrbgGenerate(r1.state, 32);
    expect(toHex(r1.output)).not.toBe(toHex(r2.output));
  });

  it('CTR_DRBG advances state: both Key and V change on Generate', async () => {
    const ent = fromHex(
      '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677'
    );
    const r = await ctrDrbgGenerate(await ctrDrbgInstantiate(ent), 32);
    expect(r.newKey).not.toBe(r.prevKey);
    expect(r.newV).not.toBe(r.prevV);
  });

  it('Hash_DRBG: C stays constant across Generate, V advances', async () => {
    const r = await hashDrbgGenerate(await hashDrbgInstantiate(seed, nonce), 32);
    expect(r.newC).toBe(r.prevC); // C is fixed at seed time
    expect(r.newV).not.toBe(r.prevV);
  });

  it('Hash_DRBG SHA-512 uses an 888-bit (111-byte) seedlen state', async () => {
    const ent = fromHex('00'.repeat(111));
    const st = await hashDrbgInstantiate(ent, nonce, undefined, 'SHA-512');
    expect(st.seedLen).toBe(111);
    expect(st.V.length).toBe(111);
    expect(st.C.length).toBe(111);
  });

  it('requested length is honored exactly, including non-block-multiples', async () => {
    for (const n of [1, 7, 16, 17, 31, 33, 200]) {
      const r = await hmacDrbgGenerate(await hmacDrbgInstantiate(seed, nonce), n);
      expect(r.output.length).toBe(n);
    }
  });
});
