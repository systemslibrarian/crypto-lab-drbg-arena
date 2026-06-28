# crypto-lab-drbg-arena

## What It Is

DRBG Arena demonstrates the three NIST SP 800-90A approved Deterministic Random Bit Generators: HMAC_DRBG, CTR_DRBG, and Hash_DRBG. Each construction takes entropy from a true random source and produces a cryptographically secure pseudorandom output stream. This demo is the correct-case companion to [Corrupted Oracle](https://systemslibrarian.github.io/crypto-lab-corrupted-oracle/), which shows what happens when a DRBG is intentionally backdoored (Dual_EC_DRBG). The security model is symmetric: all output is deterministically derived from the seed, computationally indistinguishable from true randomness, and resistant to backtracking and prediction attacks.

## When to Use It

- HMAC_DRBG — general-purpose secure random generation in most applications.
- CTR_DRBG — FIPS 140-2/3 required environments, or when AES-NI is available.
- Hash_DRBG — constrained environments needing the simplest correct implementation.
- Never use `Math.random()` for cryptographic key or nonce generation.
- Never use Dual_EC_DRBG under any circumstances (see Corrupted Oracle).
- Do not seed any DRBG with low-entropy sources (timestamps, PIDs, counters).
- Do NOT treat this as production code — it is a teaching demo, not a hardened RNG library.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-drbg-arena](https://systemslibrarian.github.io/crypto-lab-drbg-arena/)**

Five exhibits plus a live conformance check: DRBG fundamentals and security properties, HMAC_DRBG with interactive state visualizer, CTR_DRBG with AES comparison and timing, Hash_DRBG with full three-way comparison table, and NIST SP 800-22 statistical tests run live on all three implementations with a Dual_EC_DRBG comparison showing why statistical tests alone are insufficient.

## What Can Go Wrong

- **Insufficient entropy at seeding.** A DRBG is only as strong as its seed; seeding from a low-entropy or predictable source makes all output predictable regardless of the algorithm.
- **No reseeding or prediction resistance.** Generating indefinitely from one seed without reseeding means a future state compromise can expose subsequent output; SP 800-90A defines reseed limits for a reason.
- **State compromise and backtracking.** If the internal state leaks, an implementation without proper backtracking resistance can let an attacker reconstruct previously generated values.
- **Choosing a non-CSPRNG.** Using `Math.random()` or other statistical (non-cryptographic) generators for keys, nonces, or IVs defeats the entire scheme.
- **Trusting statistical tests for security.** Passing SP 800-22 randomness tests does not prove a generator is secure — Dual_EC_DRBG passed them while being backdoored.

## Real-World Usage

- **TLS and crypto libraries.** OpenSSL and many cryptographic libraries ship SP 800-90A DRBGs (commonly CTR_DRBG with AES) as their default secure random source.
- **Operating system RNGs.** OS entropy facilities feed CSPRNGs that follow the same seed-and-expand design these DRBGs formalize.
- **FIPS 140-2/3 modules.** Validated cryptographic modules are required to use SP 800-90A approved DRBGs, with CTR_DRBG common in FIPS-constrained environments.
- **HSMs and secure elements.** Hardware security modules combine a hardware entropy source with an approved DRBG to produce keys and nonces.
- **Protocol nonce/IV generation.** Secure generation of nonces, IVs, and ephemeral keys across TLS, IPsec, and similar protocols depends on a correctly seeded DRBG.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-drbg-arena
cd crypto-lab-drbg-arena
npm install
npm run dev
```

## Related Demos

- [crypto-lab-corrupted-oracle](https://systemslibrarian.github.io/crypto-lab-corrupted-oracle/) — the backdoored counterpart, showing Dual_EC_DRBG's hidden trapdoor.
- [crypto-lab-vrf-gate](https://systemslibrarian.github.io/crypto-lab-vrf-gate/) — verifiable random functions and VDFs for public, provable randomness.
- [crypto-lab-phantom-vault](https://systemslibrarian.github.io/crypto-lab-phantom-vault/) — PBKDF2 and HMAC-DRBG with rejection sampling in a key-derivation context.
- [crypto-lab-kdf-arena](https://systemslibrarian.github.io/crypto-lab-kdf-arena/) — HKDF, PBKDF2, scrypt, and Argon2id key-derivation comparison.

## Correctness Is Verified, Not Asserted

A DRBG demo is only worth learning from if its output is provably conformant. All three constructions are tested **byte-for-byte against the official NIST CAVP known-answer vectors** (DRBG Validation System):

| Algorithm | Vector | Status |
|-----------|--------|--------|
| HMAC_DRBG | SHA-256, no prediction resistance | exact match |
| CTR_DRBG  | AES-256 (no df), no prediction resistance | exact match |
| Hash_DRBG | SHA-256, no prediction resistance | exact match (both Generate calls) |

The same vectors run three ways: in CI on every commit (`npm test`), as a **live self-check in your browser** on page load (the "Live Conformance Check" panel), and as the values displayed in that panel — one source of truth in [`src/crypto/self-check.ts`](src/crypto/self-check.ts), no drift. The GitHub Pages deploy is gated on the test job: if a vector ever fails to match, the site does not ship.

```bash
npm test        # run the NIST CAVP known-answer tests + property tests
```

---

*One of 60+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
