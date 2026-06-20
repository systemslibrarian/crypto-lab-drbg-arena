/**
 * Tests for the byte-manipulation primitives the DRBGs are built on.
 * A bug in any of these silently corrupts every DRBG output, so they are
 * pinned here with their own unit tests.
 */

import { describe, it, expect } from 'vitest';
import { toHex, fromHex, concatBytes, addBytes, incrementCounter } from './utils';

describe('hex conversion', () => {
  it('round-trips bytes', () => {
    const bytes = new Uint8Array([0x00, 0x0f, 0xa1, 0xff]);
    expect(toHex(bytes)).toBe('000fa1ff');
    expect(Array.from(fromHex('000fa1ff'))).toEqual([0x00, 0x0f, 0xa1, 0xff]);
  });

  it('zero-pads odd-length hex with a leading zero', () => {
    expect(Array.from(fromHex('f'))).toEqual([0x0f]);
    expect(Array.from(fromHex('abc'))).toEqual([0x0a, 0xbc]);
  });

  it('ignores embedded whitespace', () => {
    expect(Array.from(fromHex('de ad be ef'))).toEqual([0xde, 0xad, 0xbe, 0xef]);
  });
});

describe('concatBytes', () => {
  it('concatenates in order', () => {
    const r = concatBytes(new Uint8Array([1, 2]), new Uint8Array([3]), new Uint8Array([4, 5]));
    expect(Array.from(r)).toEqual([1, 2, 3, 4, 5]);
  });
});

describe('addBytes — big-endian addition mod 2^(8·len)', () => {
  it('adds with carry propagation', () => {
    expect(Array.from(addBytes(new Uint8Array([0x00, 0xff]), new Uint8Array([0x00, 0x01]))))
      .toEqual([0x01, 0x00]);
  });

  it('right-aligns operands of different lengths (shorter is the low-order addend)', () => {
    // 0x0100 + 0x01 = 0x0101, NOT 0x0200
    expect(Array.from(addBytes(new Uint8Array([0x01, 0x00]), new Uint8Array([0x01]))))
      .toEqual([0x01, 0x01]);
  });

  it('wraps on overflow of the full width', () => {
    expect(Array.from(addBytes(new Uint8Array([0xff, 0xff]), new Uint8Array([0x00, 0x01]))))
      .toEqual([0x00, 0x00]);
  });
});

describe('incrementCounter — big-endian +1 mod 2^(8·len)', () => {
  it('increments the low-order byte', () => {
    expect(Array.from(incrementCounter(new Uint8Array([0x00, 0x00, 0x05])))).toEqual([0, 0, 6]);
  });

  it('carries across byte boundaries', () => {
    expect(Array.from(incrementCounter(new Uint8Array([0x00, 0x00, 0xff])))).toEqual([0, 1, 0]);
  });

  it('wraps all-ones to all-zeros', () => {
    expect(Array.from(incrementCounter(new Uint8Array([0xff, 0xff])))).toEqual([0, 0]);
  });
});
