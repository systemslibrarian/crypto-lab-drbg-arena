import { createHmac } from 'node:crypto';
import { expect, it } from 'vitest';
import { hmacDrbgGenerate, hmacDrbgInstantiate } from './hmac-drbg';

it('preserves the recorded no-input output and state for omitted and empty input', async () => {
  const seed = Uint8Array.from({ length: 48 }, (_, i) => i);
  const state = await hmacDrbgInstantiate(seed);
  const omitted = await hmacDrbgGenerate(state, 65);
  expect(Buffer.from(omitted.output).toString('hex')).toBe(
    '0ffb80875a3e9022a4941a3fa1b0d3611df14e1cf651a73ce9229b9f3ad56887680428845710288ea4391ca6f21df8cd88b7b27a8dfc16559540739759480c16a4'
  );
  expect(omitted.newK).toBe('c4e2228998d39dc56b14d57790969f06f5bdc990585fd6f864d3fbb651ff4fa9');
  expect(omitted.newV).toBe('fd62994ae16aa4b7befeb1f33ceda1aea8c48f6da7a04e9bd8008e7c3bf1ab3c');
  expect(await hmacDrbgGenerate(state, 65, new Uint8Array())).toEqual(omitted);
});

it('matches the independent SP 800-90A reference with additional input', async () => {
  // Start at a synthetic working state to test Generate independently of Instantiate.
  const state = { K: new Uint8Array(32).fill(0x21), V: new Uint8Array(32).fill(0x43), reseedCounter: 4 };
  const additionalInput = Buffer.from([0x00, 0x23, 0xff, 0x01]);
  const hmac = (key, ...parts) => createHmac('sha256', key).update(Buffer.concat(parts)).digest();
  let key = Buffer.from(state.K);
  let value = Buffer.from(state.V);
  // Update with nonempty provided data, SP 800-90A §10.1.2.2.
  function update() {
    for (const separator of [0, 1]) {
      key = hmac(key, value, Buffer.of(separator), additionalInput);
      value = hmac(key, value);
    }
  }

  // Generate 65 bytes, including a truncated third block, §10.1.2.5.
  update();
  const blocks = [];
  for (let i = 0; i < 3; i++) {
    value = hmac(key, value);
    blocks.push(value);
  }
  const expected = Buffer.concat(blocks).subarray(0, 65);
  update();

  const actual = await hmacDrbgGenerate(state, 65, additionalInput);
  expect(Buffer.from(actual.output)).toEqual(expected);
  expect(Buffer.from(actual.state.K)).toEqual(key);
  expect(Buffer.from(actual.state.V)).toEqual(value);
  expect(actual.state.reseedCounter).toBe(5);
});
