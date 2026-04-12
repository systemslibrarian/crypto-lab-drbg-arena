/**
 * HMAC_DRBG — NIST SP 800-90A Rev 1, Section 10.1.2
 *
 * Uses HMAC-SHA-256 as the underlying primitive.
 * Internal state: K (key, 32 bytes) and V (value, 32 bytes).
 * Both K and V are updated on every Generate call.
 */

import { hmacSha256, concatBytes, getRandomEntropy, toHex } from './utils';

export interface HmacDrbgState {
  K: Uint8Array;
  V: Uint8Array;
  reseedCounter: number;
}

/**
 * HMAC_DRBG_Update per SP 800-90A Section 10.1.2.2
 */
async function hmacDrbgUpdate(
  K: Uint8Array, V: Uint8Array, providedData?: Uint8Array
): Promise<{ K: Uint8Array; V: Uint8Array }> {
  // Step 1: K = HMAC(K, V || 0x00 || provided_data)
  let input = concatBytes(V, new Uint8Array([0x00]));
  if (providedData && providedData.length > 0) {
    input = concatBytes(input, providedData);
  }
  K = await hmacSha256(K, input);

  // Step 2: V = HMAC(K, V)
  V = await hmacSha256(K, V);

  // Step 3-5: If provided_data is not null, repeat with 0x01
  if (providedData && providedData.length > 0) {
    input = concatBytes(V, new Uint8Array([0x01]), providedData);
    K = await hmacSha256(K, input);
    V = await hmacSha256(K, V);
  }

  return { K, V };
}

/**
 * Instantiate HMAC_DRBG per SP 800-90A Section 10.1.2.3
 */
export async function hmacDrbgInstantiate(
  entropy: Uint8Array,
  nonce?: Uint8Array,
  personalization?: Uint8Array
): Promise<HmacDrbgState> {
  // seed_material = entropy_input || nonce || personalization_string
  let seedMaterial = entropy;
  if (nonce && nonce.length > 0) {
    seedMaterial = concatBytes(seedMaterial, nonce);
  }
  if (personalization && personalization.length > 0) {
    seedMaterial = concatBytes(seedMaterial, personalization);
  }

  // Initial K = 0x00...00, V = 0x01...01 (32 bytes each)
  let K = new Uint8Array(32); // all zeros
  let V = new Uint8Array(32).fill(0x01); // all ones

  const updated = await hmacDrbgUpdate(K, V, seedMaterial);
  return { K: updated.K, V: updated.V, reseedCounter: 1 };
}

/**
 * Generate bytes from HMAC_DRBG per SP 800-90A Section 10.1.2.5
 * Returns the output bytes and the updated state (with K/V snapshots).
 */
export async function hmacDrbgGenerate(
  state: HmacDrbgState,
  requestedBytes: number
): Promise<{
  output: Uint8Array;
  state: HmacDrbgState;
  prevK: string;
  prevV: string;
  newK: string;
  newV: string;
}> {
  const prevK = toHex(state.K);
  const prevV = toHex(state.V);

  let { K, V } = state;
  const temp: Uint8Array[] = [];
  let collected = 0;

  // Generate output blocks
  while (collected < requestedBytes) {
    V = await hmacSha256(K, V);
    temp.push(V);
    collected += V.length;
  }

  // Concatenate and trim to requested length
  const output = concatBytes(...temp).slice(0, requestedBytes);

  // Update K and V (no additional input)
  const updated = await hmacDrbgUpdate(K, V);

  const newState: HmacDrbgState = {
    K: updated.K,
    V: updated.V,
    reseedCounter: state.reseedCounter + 1,
  };

  return {
    output,
    state: newState,
    prevK,
    prevV,
    newK: toHex(updated.K),
    newV: toHex(updated.V),
  };
}

/**
 * Reseed HMAC_DRBG per SP 800-90A Section 10.1.2.4
 */
export async function hmacDrbgReseed(
  state: HmacDrbgState,
  entropy?: Uint8Array
): Promise<HmacDrbgState> {
  const newEntropy = entropy ?? getRandomEntropy(32);
  const updated = await hmacDrbgUpdate(state.K, state.V, newEntropy);
  return { K: updated.K, V: updated.V, reseedCounter: 1 };
}
