// CTR_DRBG per NIST SP 800-90A Rev 1 §10.2.1 using AES-256 (keylen=256, outlen=128)
// Internal state: V (128-bit counter) and Key (256-bit AES key)

export interface CtrDrbgState {
  V: Uint8Array;    // 16 bytes (128-bit block)
  Key: Uint8Array;  // 32 bytes (256-bit key)
  reseedCounter: number;
}

// Increment V as a 128-bit big-endian counter
function incrementV(V: Uint8Array): Uint8Array {
  const out = new Uint8Array(V);
  for (let i = out.length - 1; i >= 0; i--) {
    out[i]++;
    if (out[i] !== 0) break;
  }
  return out;
}

// AES-256 block encrypt (single block)
async function aesEncryptBlock(key: Uint8Array, block: Uint8Array): Promise<Uint8Array> {
  // Use AES-CBC with zero IV to encrypt a single block
  // XOR with zero IV = just the block
  const cryptoKey = await crypto.subtle.importKey(
    'raw', key.slice(), { name: 'AES-CBC' }, false, ['encrypt']
  );
  const zeroIV = new Uint8Array(16);
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv: zeroIV },
    cryptoKey,
    block.slice()
  );
  // AES-CBC of 1 block produces 2 blocks (with PKCS7 padding block)
  // We only want the first 16 bytes
  return new Uint8Array(encrypted, 0, 16);
}

// CTR_DRBG_Update per §10.2.1.2
async function ctrDrbgUpdate(
  providedData: Uint8Array | null,
  Key: Uint8Array,
  V: Uint8Array
): Promise<{ Key: Uint8Array; V: Uint8Array }> {
  // seedlen = keylen + outlen = 256 + 128 = 384 bits = 48 bytes
  const seedLen = 48;
  const temp: Uint8Array[] = [];
  let generated = 0;

  let currentV = V;
  while (generated < seedLen) {
    currentV = incrementV(currentV);
    const block = await aesEncryptBlock(Key, currentV);
    temp.push(block);
    generated += block.length;
  }

  // Concatenate temp into seedLen bytes
  const tempBytes = new Uint8Array(seedLen);
  let offset = 0;
  for (const block of temp) {
    const toCopy = Math.min(block.length, seedLen - offset);
    tempBytes.set(block.subarray(0, toCopy), offset);
    offset += toCopy;
    if (offset >= seedLen) break;
  }

  // XOR with provided_data (or zeros if null)
  if (providedData && providedData.length > 0) {
    for (let i = 0; i < Math.min(tempBytes.length, providedData.length); i++) {
      tempBytes[i] ^= providedData[i];
    }
  }

  const newKey = tempBytes.subarray(0, 32);
  const newV = tempBytes.subarray(32, 48);
  return { Key: new Uint8Array(newKey), V: new Uint8Array(newV) };
}

// CTR_DRBG_Instantiate_algorithm per §10.2.1.3.2 (no derivation function for simplicity)
export async function ctrDrbgInstantiate(entropy: Uint8Array): Promise<CtrDrbgState> {
  // Pad/truncate entropy to seedLen (48 bytes) for no-df version
  const seedLen = 48;
  const seedMaterial = new Uint8Array(seedLen);
  const toCopy = Math.min(entropy.length, seedLen);
  seedMaterial.set(entropy.subarray(0, toCopy), 0);

  const Key = new Uint8Array(32); // all zeros
  const V = new Uint8Array(16);   // all zeros
  const state = await ctrDrbgUpdate(seedMaterial, Key, V);
  return { Key: state.Key, V: state.V, reseedCounter: 1 };
}

// CTR_DRBG_Reseed_algorithm per §10.2.1.4.2
export async function ctrDrbgReseed(
  state: CtrDrbgState,
  entropy: Uint8Array
): Promise<CtrDrbgState> {
  const seedLen = 48;
  const seedMaterial = new Uint8Array(seedLen);
  const toCopy = Math.min(entropy.length, seedLen);
  seedMaterial.set(entropy.subarray(0, toCopy), 0);

  const updated = await ctrDrbgUpdate(seedMaterial, state.Key, state.V);
  return { Key: updated.Key, V: updated.V, reseedCounter: 1 };
}

// CTR_DRBG_Generate_algorithm per §10.2.1.5.2
export async function ctrDrbgGenerate(
  state: CtrDrbgState,
  requestedBytes: number
): Promise<{ output: Uint8Array; newState: CtrDrbgState }> {
  if (state.reseedCounter > 2 ** 20) {
    throw new Error('Reseed required');
  }

  let { Key, V } = state;
  const temp: Uint8Array[] = [];
  let generated = 0;

  while (generated < requestedBytes) {
    V = incrementV(V);
    const block = await aesEncryptBlock(Key, V);
    temp.push(block);
    generated += block.length;
  }

  const output = new Uint8Array(requestedBytes);
  let offset = 0;
  for (const block of temp) {
    const toCopy = Math.min(block.length, requestedBytes - offset);
    output.set(block.subarray(0, toCopy), offset);
    offset += toCopy;
    if (offset >= requestedBytes) break;
  }

  const updated = await ctrDrbgUpdate(null, Key, V);

  return {
    output,
    newState: { Key: updated.Key, V: updated.V, reseedCounter: state.reseedCounter + 1 }
  };
}
