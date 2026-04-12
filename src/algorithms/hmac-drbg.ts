// HMAC_DRBG per NIST SP 800-90A Rev 1 §10.1.2 using HMAC-SHA-256
// Internal state: V (256-bit) and K (256-bit AES key for HMAC)

export interface HmacDrbgState {
  V: Uint8Array;   // 32 bytes
  K: Uint8Array;   // 32 bytes
  reseedCounter: number;
}

// HMAC-SHA-256 helper using SubtleCrypto
async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw', key.slice(), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, data.slice());
  return new Uint8Array(sig);
}

// HMAC_DRBG_Update per §10.1.2.2
async function hmacDrbgUpdate(
  providedData: Uint8Array | null,
  K: Uint8Array,
  V: Uint8Array
): Promise<{ K: Uint8Array; V: Uint8Array }> {
  // K = HMAC(K, V || 0x00 || provided_data)
  const concat0 = new Uint8Array(V.length + 1 + (providedData?.length ?? 0));
  concat0.set(V, 0);
  concat0[V.length] = 0x00;
  if (providedData) concat0.set(providedData, V.length + 1);
  K = await hmacSha256(K, concat0);

  // V = HMAC(K, V)
  V = await hmacSha256(K, V);

  if (!providedData || providedData.length === 0) {
    return { K, V };
  }

  // K = HMAC(K, V || 0x01 || provided_data)
  const concat1 = new Uint8Array(V.length + 1 + providedData.length);
  concat1.set(V, 0);
  concat1[V.length] = 0x01;
  concat1.set(providedData, V.length + 1);
  K = await hmacSha256(K, concat1);

  // V = HMAC(K, V)
  V = await hmacSha256(K, V);

  return { K, V };
}

// HMAC_DRBG_Instantiate per §10.1.2.3
export async function hmacDrbgInstantiate(
  entropy: Uint8Array,
  nonce: Uint8Array,
  personalization: Uint8Array
): Promise<HmacDrbgState> {
  const seedMaterial = new Uint8Array(entropy.length + nonce.length + personalization.length);
  seedMaterial.set(entropy, 0);
  seedMaterial.set(nonce, entropy.length);
  seedMaterial.set(personalization, entropy.length + nonce.length);

  const K = new Uint8Array(32); // all zeros
  const V = new Uint8Array(32).fill(0x01); // all 0x01

  const state = await hmacDrbgUpdate(seedMaterial, K, V);
  return { K: state.K, V: state.V, reseedCounter: 1 };
}

// HMAC_DRBG_Reseed per §10.1.2.4
export async function hmacDrbgReseed(
  state: HmacDrbgState,
  entropy: Uint8Array
): Promise<HmacDrbgState> {
  const updated = await hmacDrbgUpdate(entropy, state.K, state.V);
  return { K: updated.K, V: updated.V, reseedCounter: 1 };
}

// HMAC_DRBG_Generate per §10.1.2.5
// Returns requested bytes and new state
export async function hmacDrbgGenerate(
  state: HmacDrbgState,
  requestedBytes: number
): Promise<{ output: Uint8Array; newState: HmacDrbgState }> {
  if (state.reseedCounter > 10000) {
    throw new Error('Reseed required');
  }

  let { K, V } = state;
  const temp: Uint8Array[] = [];
  let generated = 0;

  while (generated < requestedBytes) {
    V = await hmacSha256(K, V);
    temp.push(V);
    generated += V.length;
  }

  const output = new Uint8Array(requestedBytes);
  let offset = 0;
  for (const block of temp) {
    const toCopy = Math.min(block.length, requestedBytes - offset);
    output.set(block.subarray(0, toCopy), offset);
    offset += toCopy;
    if (offset >= requestedBytes) break;
  }

  const updated = await hmacDrbgUpdate(null, K, V);

  return {
    output,
    newState: { K: updated.K, V: updated.V, reseedCounter: state.reseedCounter + 1 }
  };
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
