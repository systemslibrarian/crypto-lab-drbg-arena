/**
 * Utility functions for DRBG implementations.
 * Uses the Web Crypto API (SubtleCrypto) for all primitives.
 */

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function fromHex(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const len = arrays.reduce((s, a) => s + a.length, 0);
  const result = new Uint8Array(len);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

export function textToBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest('SHA-256', data as Uint8Array<ArrayBuffer>);
  return new Uint8Array(buf);
}

export async function sha512(data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest('SHA-512', data as Uint8Array<ArrayBuffer>);
  return new Uint8Array(buf);
}

export async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw', key as Uint8Array<ArrayBuffer>, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, data as Uint8Array<ArrayBuffer>);
  return new Uint8Array(sig);
}

export async function aesEncryptBlock(key: Uint8Array, block: Uint8Array): Promise<Uint8Array> {
  // AES-256 ECB single block via AES-CBC with zero IV and no padding
  const cryptoKey = await crypto.subtle.importKey(
    'raw', key as Uint8Array<ArrayBuffer>, { name: 'AES-CBC' }, false, ['encrypt']
  );
  const iv = new Uint8Array(16); // zero IV
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv }, cryptoKey, block as Uint8Array<ArrayBuffer>
  );
  // AES-CBC returns block + padding block; take only first 16 bytes
  return new Uint8Array(ct).slice(0, 16);
}

export function incrementCounter(block: Uint8Array): Uint8Array {
  const result = new Uint8Array(block);
  for (let i = result.length - 1; i >= 0; i--) {
    result[i]++;
    if (result[i] !== 0) break;
  }
  return result;
}

export function addBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  // Adds two byte arrays as big-endian integers mod 2^(len*8)
  const len = Math.max(a.length, b.length);
  const result = new Uint8Array(len);
  let carry = 0;
  for (let i = len - 1; i >= 0; i--) {
    const ai = i < a.length ? a[i + (len - a.length)] ?? 0 : 0;
    const bi = i < b.length ? b[i + (len - b.length)] ?? 0 : 0;
    const sum = ai + bi + carry;
    result[i] = sum & 0xff;
    carry = sum >> 8;
  }
  return result;
}

export function getRandomEntropy(bytes: number): Uint8Array {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return buf;
}
