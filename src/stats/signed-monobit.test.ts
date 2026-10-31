import { describe, expect, it } from 'vitest';
import { analyzeBlocks, binIndex, binomialMasses, expectedBins, monobit } from './signed-monobit';

describe('signed monobit finite reference', () => {
  it('preserves P and reverses direction for every complemented nonzero block', () => {
    for (const calibration of ['normal', 'exact'] as const) for (let k = 0; k <= 16; k++) {
      const a = monobit(k, 16, calibration), b = monobit(16-k, 16, calibration);
      expect(a.p).toBeCloseTo(b.p, 14);
      expect(a.signed + b.signed).toBe(0);
      expect(a.absolute).toBe(b.absolute);
      expect(a.q + b.q).toBeCloseTo(calibration === 'normal' ? 1 : 1 + binomialMasses(16)[k], 12);
    }
    expect(monobit(8,16).q).toBe(.5);
    expect(monobit(2,4,'exact').q).toBe(11/16);
    expect(monobit(2,4,'exact').p).toBe(1);
    expect(monobit(10,16).q).toBeCloseTo(0.1586552539,6);
    expect(monobit(6,16).q).toBeCloseTo(0.8413447461,6);
    expect(monobit(10,16,'exact').q).toBe(14893/65536);
  });
  it('matches an independent exhaustive bit-string census including tail boundaries', () => {
    for (const calibration of ['normal', 'exact'] as const) for (const field of ['p','q'] as const) {
      const bits = new Uint8Array(256 * 8);
      for (let x=0;x<256;x++) for (let j=0;j<8;j++) bits[x*8+j] = (x >> j) & 1;
      const actual = analyzeBlocks(bits,8,calibration);
      expectedBins(8,field,calibration).forEach((mass,i) => expect(mass*256).toBeCloseTo(actual[field][i],12));
      const folded = analyzeBlocks(bits,8,calibration,true);
      expect(folded.p).toEqual(actual.p);
      expect(folded.rows.every(r=>r.signed>=0)).toBe(true);
    }
    expect(binomialMasses(4)).toEqual([1/16,4/16,6/16,4/16,1/16]);
    expect(binIndex(0)).toBe(0); expect(binIndex(.5)).toBe(5); expect(binIndex(1)).toBe(9);
  });
  it('rejects partial blocks and invalid domains', () => {
    expect(()=>analyzeBlocks(new Uint8Array(7),8,'normal')).toThrow();
    expect(()=>monobit(1,3)).toThrow();
    expect(()=>monobit(9,8)).toThrow();
    expect(()=>binIndex(NaN)).toThrow();
  });
});
