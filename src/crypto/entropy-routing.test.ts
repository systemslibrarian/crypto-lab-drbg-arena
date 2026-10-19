import { expect, it } from 'vitest';
import { entropyRouting } from './entropy-routing';
import { hashDrbgInstantiate, hashDrbgReseed, hashDrbgGenerate } from './hash-drbg';
import { toHex } from './utils';

const good = {validated: true, healthy: true, fresh: true, includeExtra: true, route: 'additional' as const};
it('extra input cannot rescue a missing, unhealthy or replayed credited source', () => {
  for (const key of ['validated', 'healthy', 'fresh']) {
    expect(entropyRouting({...good, [key]: false})).toMatchObject({allowed: false, creditedBits: 0, extraBits: 0});
  }
  expect(entropyRouting(good)).toMatchObject({allowed: true, creditedBits: 256, extraBits: 0});
  expect(entropyRouting({...good, route: 'external'}).allowed).toBe(false);
  expect(entropyRouting({...good, route: 'external', includeExtra: false}).allowed).toBe(true);
});
it('optional additional input preserves the existing empty-input reseed and influences real output', async () => {
  const initial = await hashDrbgInstantiate(new Uint8Array(48).fill(0x11));
  const entropy = new Uint8Array(32).fill(0xa1);
  const absent = await hashDrbgReseed(initial, entropy);
  const empty = await hashDrbgReseed(initial, entropy, new Uint8Array());
  expect(empty).toEqual(absent);
  const a = await hashDrbgReseed(initial, entropy, new Uint8Array(32).fill(0xb2));
  const b = await hashDrbgReseed(initial, entropy, new Uint8Array(32).fill(0xb3));
  // Independent Python hashlib evaluation of §10.1.1.3 + Hashgen, using
  // 440-bit Hash_df and the public 0x11 / 0xa1 / 0xb2 inputs above.
  expect(toHex((await hashDrbgGenerate(a, 32)).output)).toBe('185a6bd5521ffe69579163c72278fe5b1a70daa67329f39d43c45909de79900f');
  expect((await hashDrbgGenerate(a, 32)).output).not.toEqual((await hashDrbgGenerate(b, 32)).output);
  expect(initial.reseedCounter).toBe(1);
});
