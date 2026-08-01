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

  // A second Hash_DRBG vector (CAVP no_reseed, SHA-256, COUNT = 1). Like every
  // no-PR vector its ReturnedBits is the *second* Generate output, so this also
  // proves the V += H + C + reseed_counter state update between calls is correct.
  it('Hash_DRBG SHA-256 second CAVP vector matches', async () => {
    const entropy = fromHex('72da39d053c6e052bde22d10ace144cc74a65fa22610140168c6e01a5a987918');
    const nonce = fromHex('c015f7a717b530cd6b3db49fdf62c494');
    const returnedBits =
      '2daae5267ee22d8488ec158086bca87f1abffa5fe76dc532516e0f93dea5ad30' +
      'f6d179e977e2bba496868e535c0489227af41ae73d61909b2dba2d94f80530dd' +
      '87a9292080f6bef224d1292d70a5d35c5b5b94f7bf7c0f70f4cf1475c27de210' +
      'c5173875f7bbe59f9adf07a721a914afe3ad1c8729947d514d2bb33f6c298b4c';
    const st = await hashDrbgInstantiate(entropy, nonce, undefined, 'SHA-256');
    let r = await hashDrbgGenerate(st, 128);
    r = await hashDrbgGenerate(r.state, 128);
    expect(toHex(r.output)).toBe(returnedBits);
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
