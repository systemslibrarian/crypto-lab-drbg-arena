/**
 * CTR_DRBG — NIST SP 800-90A Rev 1, Section 10.2
 *
 * Uses AES-256 in counter mode.
 * Internal state: Key (32 bytes) and V (16-byte counter block).
 * Both Key and V are updated after each Generate call.
 */

import { aesEncryptBlock, incrementCounter, concatBytes, toHex, getRandomEntropy } from './utils';

export interface CtrDrbgState {
  Key: Uint8Array;  // 32 bytes (AES-256)
  V: Uint8Array;    // 16 bytes (block size)
  reseedCounter: number;
}

const KEYLEN = 32;   // AES-256
const BLOCKLEN = 16;  // AES block size
const SEEDLEN = KEYLEN + BLOCKLEN; // 48 bytes

/**
 * CTR_DRBG_Update per SP 800-90A Section 10.2.1.2
 * Block_Cipher_df is not used here (use_df = false simplified variant).
 */
async function ctrDrbgUpdate(
  providedData: Uint8Array,
  Key: Uint8Array,
  V: Uint8Array
): Promise<{ Key: Uint8Array; V: Uint8Array }> {
  const temp: Uint8Array[] = [];
  let collected = 0;
  let currentV = V;

  while (collected < SEEDLEN) {
    currentV = incrementCounter(currentV);
    const block = await aesEncryptBlock(Key, currentV);
    temp.push(block);
    collected += BLOCKLEN;
  }

  const outputBlock = concatBytes(...temp).slice(0, SEEDLEN);

  // XOR with provided_data
  const xored = new Uint8Array(SEEDLEN);
  for (let i = 0; i < SEEDLEN; i++) {
    xored[i] = outputBlock[i]! ^ (providedData[i] ?? 0);
  }

  const newKey = xored.slice(0, KEYLEN);
  const newV = xored.slice(KEYLEN, SEEDLEN);

  return { Key: newKey, V: newV };
}

/**
 * Instantiate CTR_DRBG per SP 800-90A Section 10.2.1.3
 */
export async function ctrDrbgInstantiate(
  entropy: Uint8Array,
  personalization?: Uint8Array
): Promise<CtrDrbgState> {
  // seed_material = entropy_input XOR personalization_string (padded)
  const seedMaterial = new Uint8Array(SEEDLEN);
  for (let i = 0; i < SEEDLEN; i++) {
    seedMaterial[i] = (entropy[i] ?? 0) ^ (personalization?.[i] ?? 0);
  }

  // Initial Key = 0, V = 0
  const Key = new Uint8Array(KEYLEN);
  const V = new Uint8Array(BLOCKLEN);

  const updated = await ctrDrbgUpdate(seedMaterial, Key, V);
  return { Key: updated.Key, V: updated.V, reseedCounter: 1 };
}

/**
 * Generate bytes from CTR_DRBG per SP 800-90A Section 10.2.1.5
 */
export async function ctrDrbgGenerate(
  state: CtrDrbgState,
  requestedBytes: number
): Promise<{
  output: Uint8Array;
  state: CtrDrbgState;
  prevKey: string;
  prevV: string;
  newKey: string;
  newV: string;
}> {
  const prevKey = toHex(state.Key);
  const prevV = toHex(state.V);

  let { Key, V } = state;
  const temp: Uint8Array[] = [];
  let collected = 0;

  while (collected < requestedBytes) {
    V = incrementCounter(V);
    const block = await aesEncryptBlock(Key, V);
    temp.push(block);
    collected += BLOCKLEN;
  }

  const output = concatBytes(...temp).slice(0, requestedBytes);

  // Update Key and V (no additional input)
  const updated = await ctrDrbgUpdate(new Uint8Array(SEEDLEN), Key, V);

  const newState: CtrDrbgState = {
    Key: updated.Key,
    V: updated.V,
    reseedCounter: state.reseedCounter + 1,
  };

  return {
    output,
    state: newState,
    prevKey,
    prevV,
    newKey: toHex(updated.Key),
    newV: toHex(updated.V),
  };
}

/**
 * Reseed CTR_DRBG per SP 800-90A Section 10.2.1.4
 */
export async function ctrDrbgReseed(
  state: CtrDrbgState,
  entropy?: Uint8Array
): Promise<CtrDrbgState> {
  const newEntropy = entropy ?? getRandomEntropy(SEEDLEN);
  const seedMaterial = new Uint8Array(SEEDLEN);
  for (let i = 0; i < SEEDLEN; i++) {
    seedMaterial[i] = newEntropy[i] ?? 0;
  }
  const updated = await ctrDrbgUpdate(seedMaterial, state.Key, state.V);
  return { Key: updated.Key, V: updated.V, reseedCounter: 1 };
}
