/**
 * Exhibit 1 — What a DRBG Is
 * Static educational panel explaining DRBG fundamentals.
 */

export function buildExhibit1(): HTMLElement {
  const section = document.createElement('section');
  section.className = 'exhibit';
  section.setAttribute('aria-labelledby', 'exhibit1-title');

  section.innerHTML = `
    <h2 class="exhibit-title" id="exhibit1-title">Exhibit 1 — What a DRBG Is</h2>
    <div class="exhibit-body">
      <div class="panel">
        <div class="panel-header">
          <span aria-hidden="true">📐</span> Definition
        </div>
        <p style="font-size:0.9rem;line-height:1.8;color:var(--text-primary)">
          <strong>DRBG</strong> = <strong>Deterministic Random Bit Generator</strong> (defined in
          <a href="https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final"
             target="_blank" rel="noopener noreferrer"
             style="color:var(--blue-info);text-decoration:underline">
            NIST SP 800-90A Rev 1<span class="sr-only"> (opens in new tab)</span></a>.
          A DRBG takes a seed from a true entropy source and produces a stream of
          cryptographically secure pseudorandom bits.
        </p>
      </div>

      <div class="panel">
        <div class="panel-header">
          <span aria-hidden="true">🏗️</span> Three NIST-Approved Constructions
        </div>
        <ul style="list-style:none;padding:0;display:flex;flex-direction:column;gap:0.5rem" role="list">
          <li style="font-family:var(--font-mono);font-size:0.85rem;padding:0.5rem 0.75rem;border:1px solid var(--border-color);border-radius:4px;background:var(--bg-secondary)">
            <strong style="color:var(--green-clean)">Hash_DRBG</strong> — based on SHA-256 / SHA-512
          </li>
          <li style="font-family:var(--font-mono);font-size:0.85rem;padding:0.5rem 0.75rem;border:1px solid var(--border-color);border-radius:4px;background:var(--bg-secondary)">
            <strong style="color:var(--green-clean)">HMAC_DRBG</strong> — based on HMAC-SHA-256
          </li>
          <li style="font-family:var(--font-mono);font-size:0.85rem;padding:0.5rem 0.75rem;border:1px solid var(--border-color);border-radius:4px;background:var(--bg-secondary)">
            <strong style="color:var(--green-clean)">CTR_DRBG</strong> — based on AES-256 in counter mode
          </li>
        </ul>
      </div>

      <div class="panel">
        <div class="panel-header">
          <span aria-hidden="true">⚠️</span> Why Not Math.random()?
        </div>
        <p style="font-size:0.85rem;line-height:1.7;color:var(--text-secondary)">
          <code style="color:var(--red-corrupt);font-family:var(--font-mono)">Math.random()</code>
          is <strong style="color:var(--text-primary)">not cryptographically secure</strong>. Its
          output can be predicted from prior values because it uses a linear congruential
          generator or similar construction with no security guarantees. Never use it for
          key generation, nonces, or any security-critical purpose.
        </p>
      </div>

      <div class="panel">
        <div class="panel-header">
          <span aria-hidden="true">🛡️</span> Security Properties
        </div>
        <p style="font-size:0.8rem;line-height:1.6;color:var(--text-muted);margin:0">
          On top of the baseline requirement that output is computationally
          indistinguishable from true randomness, SP 800-90A defines
          <strong style="color:var(--text-primary)">two</strong> security properties
          around <em>state compromise</em>. They protect opposite directions in time:
        </p>
        <ol style="list-style:decimal;padding-left:1.5rem;display:flex;flex-direction:column;gap:0.75rem" role="list">
          <li style="font-size:0.85rem;line-height:1.7;color:var(--text-primary)">
            <strong>Backtracking resistance</strong> <span style="color:var(--text-muted)">(protects the past)</span>
            <span style="color:var(--text-secondary)"> — if the internal state is compromised at some
            moment, all outputs produced <em>before</em> it stay secure. The generator cannot be run
            backwards. All three constructions provide this by default, because each step replaces the
            state with a one-way function of itself.</span>
          </li>
          <li style="font-size:0.85rem;line-height:1.7;color:var(--text-primary)">
            <strong>Prediction resistance</strong> <span style="color:var(--text-muted)">(protects the future)</span>
            <span style="color:var(--text-secondary)"> — if the state is compromised, outputs produced
            <em>after</em> it become secure again only once the DRBG is <strong style="color:var(--text-primary)">reseeded</strong>
            with fresh entropy. It is <em>not</em> automatic: it is the caller's job to request a reseed
            (the <span style="font-family:var(--font-mono)">Reseed</span> control in the demos below).</span>
          </li>
        </ol>
        <p style="font-size:0.8rem;line-height:1.6;color:var(--text-muted);margin:0">
          "Forward secrecy" is just another name for backtracking resistance — the two are the same
          property, not separate guarantees.
        </p>
      </div>

      <div class="panel">
        <div class="panel-header">
          <span aria-hidden="true">🔄</span> DRBG Data Flow
        </div>
        <div class="flow-diagram" role="img" aria-label="Data flow: Entropy Source to Seed to DRBG Internal State to Output Stream, with a Reseed Trigger feeding back">
          <div class="flow-node">Entropy Source</div>
          <div class="flow-arrow" aria-hidden="true">→</div>
          <div class="flow-node">Seed</div>
          <div class="flow-arrow" aria-hidden="true">→</div>
          <div class="flow-node" style="border-color:var(--green-clean)">DRBG Internal State</div>
          <div class="flow-arrow" aria-hidden="true">→</div>
          <div class="flow-node">Output Stream</div>
          <div class="flow-arrow" aria-hidden="true">↩</div>
          <div class="flow-node" style="border-color:var(--amber-warn)">Reseed Trigger</div>
        </div>
      </div>

      <div class="callout" role="note">
        <strong>Why this matters:</strong> Every TLS session key, every keypair, every nonce in
        encrypted traffic depends on a DRBG. A weak or backdoored DRBG undermines every
        other cryptographic guarantee in the system. See
        <a href="https://systemslibrarian.github.io/crypto-lab-corrupted-oracle/"
           target="_blank" rel="noopener noreferrer"
           style="color:var(--blue-info);text-decoration:underline">
          Corrupted Oracle<span class="sr-only"> (opens in new tab)</span></a> for the failure case.
      </div>
    </div>
  `;

  return section;
}
