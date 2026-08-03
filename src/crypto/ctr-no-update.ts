/**
 * CTR-no-update — a DELIBERATELY DEFECTIVE generator, used as the positive
 * control in Exhibit 6.
 *
 * It is real AES-256 counter mode and it is byte-for-byte identical to the
 * approved CTR_DRBG in `ctr-drbg.ts` except for ONE deletion: after producing
 * output it does not run CTR_DRBG_Update, so the key never changes and the
 * counter simply keeps walking forward. Everything else — instantiation,
 * Block_Cipher_df-free seeding, the AES call — is the same code path.
 *
 * That single deletion is the whole subject of the exhibit. Because the state
 * (Key, V) is now an invertible position in a keystream rather than the image of
 * a one-way function, `rewind` below is an exact operation: anyone who learns
 * the state can step the counter backwards and reproduce every byte the
 * generator ever emitted. The approved construction has no such operation to
 * offer, and the exhibit measures the difference instead of asserting it.
 *
 * This construction is not a straw man. "Seed an AES-CTR keystream once and
 * keep drawing from it" is a recurring real-world implementation shortcut, and
 * the Update step in SP 800-90A §10.2.1.2 exists precisely to stop it.
 *
 * NOT FOR USE. Exported only so the exhibit can break it on camera.
 */

import { aesEncryptBlock, incrementCounter, concatBytes } from './utils';

const KEYLEN = 32; // AES-256
const BLOCKLEN = 16;
const SEEDLEN = KEYLEN + BLOCKLEN;

export interface NoUpdateState {
  Key: Uint8Array; // 32 bytes — never changes after instantiation (THE DEFECT)
  V: Uint8Array; // 16-byte counter block
}

/** Counter decrement — the inverse of `incrementCounter`. Exists only here. */
export function decrementCounter(block: Uint8Array): Uint8Array {
  const result = new Uint8Array(block);
  for (let i = result.length - 1; i >= 0; i--) {
    if (result[i] === 0) {
      result[i] = 0xff;
    } else {
      result[i]!--;
      break;
    }
  }
  return result;
}

/** The seeding half of CTR_DRBG_Update, kept because the defect is only in Generate. */
async function seedUpdate(
  providedData: Uint8Array,
  Key: Uint8Array,
  V: Uint8Array
): Promise<NoUpdateState> {
  const temp: Uint8Array[] = [];
  let collected = 0;
  let currentV = V;
  while (collected < SEEDLEN) {
    currentV = incrementCounter(currentV);
    temp.push(await aesEncryptBlock(Key, currentV));
    collected += BLOCKLEN;
  }
  const outputBlock = concatBytes(...temp).slice(0, SEEDLEN);
  const xored = new Uint8Array(SEEDLEN);
  for (let i = 0; i < SEEDLEN; i++) {
    xored[i] = outputBlock[i]! ^ (providedData[i] ?? 0);
  }
  return { Key: xored.slice(0, KEYLEN), V: xored.slice(KEYLEN, SEEDLEN) };
}

export async function noUpdateInstantiate(entropy: Uint8Array): Promise<NoUpdateState> {
  const seedMaterial = new Uint8Array(SEEDLEN);
  for (let i = 0; i < SEEDLEN; i++) seedMaterial[i] = entropy[i] ?? 0;
  return seedUpdate(seedMaterial, new Uint8Array(KEYLEN), new Uint8Array(BLOCKLEN));
}

/** Reseeding still mixes fresh entropy in, so this generator is not defenceless
 *  against a compromise — only against one that happened before the reseed. */
export async function noUpdateReseed(
  state: NoUpdateState,
  entropy: Uint8Array
): Promise<NoUpdateState> {
  const seedMaterial = new Uint8Array(SEEDLEN);
  for (let i = 0; i < SEEDLEN; i++) seedMaterial[i] = entropy[i] ?? 0;
  return seedUpdate(seedMaterial, state.Key, state.V);
}

/** How many AES blocks a request of `bytes` bytes consumes. */
export function blocksFor(bytes: number): number {
  return Math.ceil(bytes / BLOCKLEN);
}

/**
 * Generate — identical to CTR_DRBG_Generate with the trailing
 * `CTR_DRBG_Update(0, Key, V)` line removed. Key survives; V just advances.
 */
export async function noUpdateGenerate(
  state: NoUpdateState,
  requestedBytes: number
): Promise<{ output: Uint8Array; state: NoUpdateState }> {
  let V = state.V;
  const temp: Uint8Array[] = [];
  let collected = 0;
  while (collected < requestedBytes) {
    V = incrementCounter(V);
    temp.push(await aesEncryptBlock(state.Key, V));
    collected += BLOCKLEN;
  }
  return {
    output: concatBytes(...temp).slice(0, requestedBytes),
    // THE DEFECT: no CTR_DRBG_Update here. Key unchanged, V simply advanced.
    state: { Key: state.Key, V },
  };
}

/**
 * Step the state backwards by `blocks` AES blocks. This is what a compromised
 * CTR-no-update hands an attacker and what the approved constructions do not:
 * an exact inverse of the state transition.
 */
export function rewind(state: NoUpdateState, blocks: number): NoUpdateState {
  let V = state.V;
  for (let i = 0; i < blocks; i++) V = decrementCounter(V);
  return { Key: state.Key, V };
}
