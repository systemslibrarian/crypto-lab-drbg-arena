# DRBG Arena

## What It Is

DRBG Arena demonstrates the three NIST SP 800-90A approved Deterministic Random Bit Generators: HMAC_DRBG, CTR_DRBG, and Hash_DRBG. Each construction takes entropy from a true random source and produces a cryptographically secure pseudorandom output stream. This demo is the correct-case companion to [Corrupted Oracle](https://systemslibrarian.github.io/crypto-lab-corrupted-oracle/), which shows what happens when a DRBG is intentionally backdoored (Dual_EC_DRBG). The security model is symmetric: all output is deterministically derived from the seed, computationally indistinguishable from true randomness, and resistant to backtracking and prediction attacks.

## When to Use It

- ✅ HMAC_DRBG: general-purpose secure random generation in most applications
- ✅ CTR_DRBG: FIPS 140-2/3 required environments, or when AES-NI is available
- ✅ Hash_DRBG: constrained environments needing the simplest correct implementation
- ❌ Never use Math.random() for cryptographic key or nonce generation
- ❌ Never use Dual_EC_DRBG under any circumstances (see Corrupted Oracle)
- ❌ Do not seed any DRBG with low-entropy sources (timestamps, PIDs, counters)

## Live Demo

**[https://systemslibrarian.github.io/crypto-lab-drbg-arena/](https://systemslibrarian.github.io/crypto-lab-drbg-arena/)**

Five exhibits: DRBG fundamentals and security properties, HMAC_DRBG with interactive state visualizer, CTR_DRBG with AES comparison and timing, Hash_DRBG with full three-way comparison table, and NIST SP 800-22 statistical tests run live on all three implementations with a Dual_EC_DRBG comparison showing why statistical tests alone are insufficient.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-drbg-arena
cd crypto-lab-drbg-arena
npm install
npm run dev
```

## Part of the Crypto-Lab Suite

Part of [crypto-lab](https://systemslibrarian.github.io/crypto-lab/) — browser-based cryptography demos spanning 2,500 years of cryptographic history to NIST FIPS 2024 post-quantum standards.

---

> So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31