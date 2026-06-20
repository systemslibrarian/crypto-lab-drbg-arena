/**
 * Hash_DRBG — NIST SP 800-90A Rev 1, Section 10.1.1
 *
 * Uses SHA-256 or SHA-512 as the underlying hash function.
 * Internal state: V (seed value) and C (constant derived from V at seed time).
 * C does not change between reseeds.
 */

import { sha256, sha512, concatBytes, addBytes, toHex, getRandomEntropy } from './utils';

export interface HashDrbgState {
  V: Uint8Array;
  C: Uint8Array;
  reseedCounter: number;
  hashFn: 'SHA-256' | 'SHA-512';
  seedLen: number;
}

type HashFunc = (data: Uint8Array) => Promise<Uint8Array>;

function getHashFn(name: 'SHA-256' | 'SHA-512'): HashFunc {
  return name === 'SHA-256' ? sha256 : sha512;
}

function getSeedLen(name: 'SHA-256' | 'SHA-512'): number {
  // SP 800-90A Table 2: seedlen for SHA-256 = 440 bits (55 bytes),
  // SHA-384/SHA-512 = 888 bits (111 bytes)
  return name === 'SHA-256' ? 55 : 111;
}

/**
 * Hash_df per SP 800-90A Section 10.3.1
 * Derives exactly `numBytes` bytes from input_string using hash.
 */
async function hashDf(
  hash: HashFunc,
  inputString: Uint8Array,
  numBytes: number
): Promise<Uint8Array> {
  // outlen of the chosen hash (32 for SHA-256, 64 for SHA-512), probed once.
  const hashLen = (await hash(new Uint8Array(1))).length;
  const iterations = Math.ceil(numBytes / hashLen);
  const temp: Uint8Array[] = [];

  for (let counter = 1; counter <= iterations; counter++) {
    const counterByte = new Uint8Array([counter]);
    // no_of_bits_to_return as 4-byte big-endian
    const noBitsReturn = new Uint8Array(4);
    const totalBits = numBytes * 8;
    noBitsReturn[0] = (totalBits >> 24) & 0xff;
    noBitsReturn[1] = (totalBits >> 16) & 0xff;
    noBitsReturn[2] = (totalBits >> 8) & 0xff;
    noBitsReturn[3] = totalBits & 0xff;

    const block = await hash(concatBytes(counterByte, noBitsReturn, inputString));
    temp.push(block);
  }

  return concatBytes(...temp).slice(0, numBytes);
}

/**
 * Instantiate Hash_DRBG per SP 800-90A Section 10.1.1.2
 */
export async function hashDrbgInstantiate(
  entropy: Uint8Array,
  nonce?: Uint8Array,
  personalization?: Uint8Array,
  hashName: 'SHA-256' | 'SHA-512' = 'SHA-256'
): Promise<HashDrbgState> {
  const hash = getHashFn(hashName);
  const seedLen = getSeedLen(hashName);

  // seed_material = entropy_input || nonce || personalization_string
  let seedMaterial = entropy;
  if (nonce && nonce.length > 0) {
    seedMaterial = concatBytes(seedMaterial, nonce);
  }
  if (personalization && personalization.length > 0) {
    seedMaterial = concatBytes(seedMaterial, personalization);
  }

  // V = Hash_df(seed_material, seedlen)
  const V = await hashDf(hash, seedMaterial, seedLen);

  // C = Hash_df(0x00 || V, seedlen)
  const C = await hashDf(hash, concatBytes(new Uint8Array([0x00]), V), seedLen);

  return { V, C, reseedCounter: 1, hashFn: hashName, seedLen };
}

/**
 * Generate bytes from Hash_DRBG per SP 800-90A Section 10.1.1.4
 */
export async function hashDrbgGenerate(
  state: HashDrbgState,
  requestedBytes: number
): Promise<{
  output: Uint8Array;
  state: HashDrbgState;
  prevV: string;
  prevC: string;
  newV: string;
  newC: string;
}> {
  const hash = getHashFn(state.hashFn);
  const prevV = toHex(state.V);
  const prevC = toHex(state.C);

  // Hashgen per Section 10.1.1.4, step 4
  const hashLen = (await hash(new Uint8Array(1))).length;
  const m = Math.ceil(requestedBytes / hashLen);
  let data = new Uint8Array(state.V);
  const W: Uint8Array[] = [];

  for (let i = 0; i < m; i++) {
    const wi = await hash(data);
    W.push(wi);
    data = new Uint8Array(addBytes(data, new Uint8Array([0x01])));
  }

  const output = concatBytes(...W).slice(0, requestedBytes);

  // Step 5: H = Hash(0x03 || V)
  const H = await hash(concatBytes(new Uint8Array([0x03]), state.V));

  // Step 6: V = V + H + C + reseed_counter
  const rcBytes = new Uint8Array(state.seedLen);
  let rc = state.reseedCounter;
  for (let i = rcBytes.length - 1; i >= 0 && rc > 0; i--) {
    rcBytes[i] = rc & 0xff;
    rc = rc >> 8;
  }

  let newV = addBytes(state.V, H);
  newV = addBytes(newV, state.C);
  newV = addBytes(newV, rcBytes);
  // Trim to seedLen
  if (newV.length > state.seedLen) {
    newV = newV.slice(newV.length - state.seedLen);
  }

  const newState: HashDrbgState = {
    V: newV,
    C: state.C, // C does not change between reseeds
    reseedCounter: state.reseedCounter + 1,
    hashFn: state.hashFn,
    seedLen: state.seedLen,
  };

  return {
    output,
    state: newState,
    prevV,
    prevC,
    newV: toHex(newV),
    newC: toHex(state.C), // C unchanged
  };
}

/**
 * Reseed Hash_DRBG per SP 800-90A Section 10.1.1.3
 */
export async function hashDrbgReseed(
  state: HashDrbgState,
  entropy?: Uint8Array
): Promise<HashDrbgState> {
  const hash = getHashFn(state.hashFn);
  const newEntropy = entropy ?? getRandomEntropy(state.seedLen);

  // seed_material = 0x01 || V || entropy_input
  const seedMaterial = concatBytes(new Uint8Array([0x01]), state.V, newEntropy);

  const V = await hashDf(hash, seedMaterial, state.seedLen);
  const C = await hashDf(hash, concatBytes(new Uint8Array([0x00]), V), state.seedLen);

  return { V, C, reseedCounter: 1, hashFn: state.hashFn, seedLen: state.seedLen };
}
