// Hash_DRBG per NIST SP 800-90A Rev 1 §10.1.1 using SHA-256 or SHA-512
// Internal state: V (seedlen bits) and C (constant, seedlen bits)
// seedlen for SHA-256: 440 bits = 55 bytes
// seedlen for SHA-512: 888 bits = 111 bytes

export type HashAlgorithm = 'SHA-256' | 'SHA-512';

export interface HashDrbgState {
  V: Uint8Array;
  C: Uint8Array;
  reseedCounter: number;
  algorithm: HashAlgorithm;
}

const SEEDLEN: Record<HashAlgorithm, number> = {
  'SHA-256': 55,
  'SHA-512': 111,
};

async function hash(algorithm: HashAlgorithm, data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest(algorithm, data.slice());
  return new Uint8Array(buf);
}

// Hash_df per §10.3.1
async function hashDf(
  algorithm: HashAlgorithm,
  inputString: Uint8Array,
  requestedBits: number
): Promise<Uint8Array> {
  const len = Math.ceil(requestedBits / 8);
  const outLen = algorithm === 'SHA-256' ? 32 : 64;
  const noOfBlocks = Math.ceil(len / outLen);

  const result = new Uint8Array(noOfBlocks * outLen);
  const requestedBitsBytes = new Uint8Array(4);
  new DataView(requestedBitsBytes.buffer).setUint32(0, requestedBits, false);

  for (let counter = 1; counter <= noOfBlocks; counter++) {
    // data = counter || no_of_bits_to_return || input_string
    const data = new Uint8Array(1 + 4 + inputString.length);
    data[0] = counter;
    data.set(requestedBitsBytes, 1);
    data.set(inputString, 5);
    const block = await hash(algorithm, data);
    result.set(block, (counter - 1) * outLen);
  }

  return result.subarray(0, len);
}

// Hash_DRBG_Instantiate per §10.1.1.2
export async function hashDrbgInstantiate(
  entropy: Uint8Array,
  nonce: Uint8Array,
  personalization: Uint8Array,
  algorithm: HashAlgorithm = 'SHA-256'
): Promise<HashDrbgState> {
  const seedLen = SEEDLEN[algorithm];
  const seedMaterial = new Uint8Array(entropy.length + nonce.length + personalization.length);
  seedMaterial.set(entropy, 0);
  seedMaterial.set(nonce, entropy.length);
  seedMaterial.set(personalization, entropy.length + nonce.length);

  const V = await hashDf(algorithm, seedMaterial, seedLen * 8);

  // C = Hash_df(0x00 || V, seedlen)
  const cInput = new Uint8Array(1 + V.length);
  cInput[0] = 0x00;
  cInput.set(V, 1);
  const C = await hashDf(algorithm, cInput, seedLen * 8);

  return { V, C, reseedCounter: 1, algorithm };
}

// Hash_DRBG_Reseed per §10.1.1.3
export async function hashDrbgReseed(
  state: HashDrbgState,
  entropy: Uint8Array
): Promise<HashDrbgState> {
  const seedLen = SEEDLEN[state.algorithm];
  // seed_material = 0x01 || V || entropy
  const seedMaterial = new Uint8Array(1 + state.V.length + entropy.length);
  seedMaterial[0] = 0x01;
  seedMaterial.set(state.V, 1);
  seedMaterial.set(entropy, 1 + state.V.length);

  const V = await hashDf(state.algorithm, seedMaterial, seedLen * 8);
  const cInput = new Uint8Array(1 + V.length);
  cInput[0] = 0x00;
  cInput.set(V, 1);
  const C = await hashDf(state.algorithm, cInput, seedLen * 8);

  return { V, C, reseedCounter: 1, algorithm: state.algorithm };
}

// Hashgen per §10.1.1.4
async function hashgen(
  algorithm: HashAlgorithm,
  requestedBytes: number,
  V: Uint8Array
): Promise<Uint8Array> {
  const outLen = algorithm === 'SHA-256' ? 32 : 64;
  const m = Math.ceil(requestedBytes / outLen);
  const W: Uint8Array[] = [];

  let data = new Uint8Array(V);
  for (let i = 0; i < m; i++) {
    const w = await hash(algorithm, data);
    W.push(w);
    // data = (data + 1) mod 2^seedlen*8
    data = addOne(data);
  }

  const output = new Uint8Array(requestedBytes);
  let offset = 0;
  for (const block of W) {
    const toCopy = Math.min(block.length, requestedBytes - offset);
    output.set(block.subarray(0, toCopy), offset);
    offset += toCopy;
    if (offset >= requestedBytes) break;
  }
  return output;
}

function addOne(V: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(V);
  for (let i = out.length - 1; i >= 0; i--) {
    out[i]++;
    if (out[i] !== 0) break;
  }
  return out;
}

function addBytes(a: Uint8Array, b: Uint8Array): Uint8Array<ArrayBuffer> {
  const len = Math.max(a.length, b.length);
  const out = new Uint8Array(len);
  let carry = 0;
  for (let i = 0; i < len; i++) {
    const ai = i < a.length ? (a[a.length - 1 - i] ?? 0) : 0;
    const bi = i < b.length ? (b[b.length - 1 - i] ?? 0) : 0;
    const sum = ai + bi + carry;
    out[len - 1 - i] = sum & 0xff;
    carry = sum >> 8;
  }
  return out;
}

// Hash_DRBG_Generate per §10.1.1.4
export async function hashDrbgGenerate(
  state: HashDrbgState,
  requestedBytes: number
): Promise<{ output: Uint8Array; newState: HashDrbgState }> {
  if (state.reseedCounter > 2 ** 48) {
    throw new Error('Reseed required');
  }

  const { V, C, algorithm } = state;

  const output = await hashgen(algorithm, requestedBytes, V);

  // H = Hash(0x03 || V)
  const hInput = new Uint8Array(1 + V.length);
  hInput[0] = 0x03;
  hInput.set(V, 1);
  const H = await hash(algorithm, hInput);

  // V = (V + H + C + reseed_counter) mod 2^seedlen
  const reseedBytes = new Uint8Array(8);
  new DataView(reseedBytes.buffer).setBigUint64(0, BigInt(state.reseedCounter), false);

  // Pad all to same length as V for addition
  const padH = new Uint8Array(V.length);
  padH.set(H.subarray(0, Math.min(H.length, V.length)), V.length - Math.min(H.length, V.length));

  const padReseed = new Uint8Array(V.length);
  padReseed.set(reseedBytes.subarray(0, Math.min(reseedBytes.length, V.length)), V.length - Math.min(reseedBytes.length, V.length));

  let newV = addBytes(V, padH);
  newV = addBytes(newV, C);
  newV = addBytes(newV, padReseed);
  // Truncate to seedlen
  newV = newV.subarray(newV.length - V.length);

  return {
    output,
    newState: { V: newV, C, reseedCounter: state.reseedCounter + 1, algorithm }
  };
}
