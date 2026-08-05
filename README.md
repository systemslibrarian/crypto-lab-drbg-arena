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

Six exhibits plus a live conformance check:

1. **DRBG fundamentals and security properties** — what a DRBG is, the three constructions, backtracking vs prediction resistance, and the seed → state → output → reseed data flow.
2. **HMAC_DRBG** — an animated *state-update* visualizer that shows the old V flowing through the one-way `HMAC(K, V)` box to fork out both the output stream and a fresh (K, V), making backtracking resistance mechanical rather than asserted; a **determinism panel** that stacks and diff-highlights "Same Seed Again" (identical stream) against a one-click "Flip 1 Seed Digit" avalanche (the entire stream changes), with the reference row always naming what it is a baseline of; all three seed inputs — entropy, nonce, personalization — shown, because the output is a function of all of them and a hidden one makes "same seed, same stream" untestable from what is on screen; plus inline glossary terms for seed, entropy, nonce, and personalization string.
3. **CTR_DRBG** — AES-256 construction with a same-entropy side-by-side against HMAC_DRBG, an inline `seedlen` glossary explaining why AES-256 needs 48 bytes (256-bit key + 128-bit block), a **timed comparison** that runs 40 instantiate+generate rounds of each on your press and prints which one was faster here — with an explicit note that per-call browser overhead is not the same measurement as native AES-NI throughput — and an **under-seeding disclosure**: type two hex digits and the panel states that the instantiation carries 8 bits of entropy rather than 384, instead of zero-padding it silently.
4. **Hash_DRBG** — full three-way comparison table.
5. **Statistical output quality** — simplified NIST SP 800-22 tests run live on all three implementations, a Shannon-entropy chart whose caption quotes the run's own measured range and explains why 1,024 bytes cannot reach the 8.00 bits/byte ceiling, and a **randomness pixel grid** contrasting real DRBG output against the *low* byte of an LCG, whose period is exactly the grid width so every row comes out identical. Under each grid: the measured row-to-row correlation and how many of the four tests that exact stream passed. Then a Dual_EC_DRBG comparison — with an on-screen disclosure that the row uses OS randomness as a stand-in — showing that clean-looking output proves nothing about a hidden trapdoor. Every verdict on the page is the tally of what the run returned; nothing is announced in advance.

6. **Steal the state** — the page's strongest claim, made falsifiable. Exhibit 2 says in prose that an attacker who steals the internal state cannot reconstruct earlier output. Here you mount the theft. Two generators are seeded from the *same* entropy: the approved HMAC_DRBG, and **CTR-no-update** — the approved CTR_DRBG with exactly one line deleted, the `CTR_DRBG_Update` call after Generate. Both emit three 32-byte rounds; the state is stolen after round 2, exfiltrated as hex and rebuilt on the attacker's side; four attacks then run from those bytes alone, each scored byte-for-byte against what really happened. CTR-no-update's counter steps backwards and returns **32/32 bytes of both earlier rounds**; HMAC_DRBG returns nothing above the chance rate. The defective generator is the point: it is the positive control that proves the experiment can *see* a broken past, so "HMAC_DRBG gave up nothing" is a measurement rather than a restatement. The third row shows both generators handing over the *next* round exactly — prediction resistance is a separate property — and the fourth shows a reseed from fresh entropy locking both attackers out. Every verdict is a pure function of the match count and never sees which generator produced the attempt.

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
npm test        # NIST CAVP known-answer tests + property tests + exhibit-claim tests
npm run test:a11y   # axe WCAG A/AA gate + Playwright behaviour gates on the exhibits
```

The CAVP vectors gate the cryptography. A second class of gate covers what the *page* says
about it, because every defect found in the last review was a claim the primitives underneath
had no opinion on. `src/stats/nist-tests.test.ts` pins the broken-generator grid to its
measured properties (the low-byte LCG's row correlation is 1.0 and it fails all four tests;
the high byte it used to paint has correlation ~0.002 and passes all four), and pins the
~7.81 bits/byte a perfect 1,024-byte sample averages, which is the number the entropy caption
now explains rather than rounding to 8.00. `e2e/exhibits.spec.ts` drives the page: flip a seed
digit then press Same Seed Again and the determinism verdict must still read zero differences;
under-seed CTR_DRBG and the panel must say how many bits it really has; press Compare and the
speed row must contain a measured millisecond figure; and Exhibit 6's four attacks are pinned
from a fixed seed on **both** sides — the control must surrender 32/32 past bytes and
HMAC_DRBG must surrender no more than 3, because a blind experiment would pass the second
assertion while failing the first. `src/crypto/compromise.test.ts` additionally pins the
verdict function to the match counts alone and pins `summarize` to refuse a pass when the
control also looks safe ("inconclusive, not a pass").

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
