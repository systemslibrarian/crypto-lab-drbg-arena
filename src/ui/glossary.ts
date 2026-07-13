/**
 * Inline glossary terms — a code-literate but crypto-new learner hits words
 * like "seedlen" and "nonce" with no anchor. Each term renders as an
 * expandable <details class="gloss"> the learner can open in place, so the
 * vocabulary is introduced, not assumed, without cluttering the prose.
 *
 * Definitions are written to serve both audiences: the plain-language "what it
 * is" for the newcomer, plus the sizing rationale (why 48 bytes, why a nonce
 * must be unique) that a professional still wants stated correctly.
 */

const DEFS: Record<string, { term: string; html: string }> = {
  seed: {
    term: 'seed',
    html: `The one high-entropy input a DRBG starts from. Everything the generator
      ever outputs is a deterministic function of this seed — so the seed must be
      genuinely unpredictable (from a hardware entropy source), never a timestamp
      or counter. Its size is the <em>security strength</em> you get: 256 bits of
      seed entropy buys 256-bit security, no more.`,
  },
  entropy: {
    term: 'entropy',
    html: `A measure of true unpredictability, in bits. The <code>Entropy</code>
      input here comes from <code>crypto.getRandomValues</code> (the OS CSPRNG).
      A DRBG does not <em>create</em> entropy — it <em>stretches</em> a small amount
      of real entropy into a long pseudorandom stream.`,
  },
  nonce: {
    term: 'nonce',
    html: `A "number used once." SP 800-90A mixes a nonce into the seed material so
      that two instantiations from the same entropy pool still differ. It need not be
      secret, but it must not repeat for a given entropy value — reuse collapses two
      independent generators into one.`,
  },
  personalization: {
    term: 'personalization string',
    html: `Optional caller-supplied data folded into the seed (e.g. an app name,
      user ID, or device serial). It domain-separates DRBG instances: two apps drawing
      from the same OS entropy still get independent streams. It adds no entropy on its
      own — it only diversifies.`,
  },
  seedlen: {
    term: 'seedlen',
    html: `The exact number of bytes of seed material a construction consumes.
      For <strong>CTR_DRBG with AES-256</strong>, <code>seedlen = 48 bytes</code>,
      and that number is not arbitrary: the internal state is a
      <strong>256-bit AES key (32 bytes) + one 128-bit counter block (16 bytes)</strong>,
      so 32 + 16 = 48. Seeding with fewer bytes cannot fill the state to full strength.`,
  },
};

export function glossary(...keys: (keyof typeof DEFS | string)[]): string {
  return keys
    .map((k) => {
      const d = DEFS[k];
      if (!d) return '';
      return `<details class="gloss">
        <summary><span class="gloss-term">${d.term}</span></summary>
        <div class="gloss-body">${d.html}</div>
      </details>`;
    })
    .join('');
}
