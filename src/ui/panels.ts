import { hmacDrbgInstantiate, hmacDrbgGenerate, hmacDrbgReseed, type HmacDrbgState } from '../algorithms/hmac-drbg.ts';
import { ctrDrbgInstantiate, ctrDrbgGenerate, ctrDrbgReseed, type CtrDrbgState } from '../algorithms/ctr-drbg.ts';
import { hashDrbgInstantiate, hashDrbgGenerate, hashDrbgReseed, type HashDrbgState, type HashAlgorithm } from '../algorithms/hash-drbg.ts';
import { runAllTests, type StatTestResult } from '../algorithms/stats.ts';
import { toHex } from '../algorithms/hmac-drbg.ts';

// ─── Utilities ───────────────────────────────────────────────────────────────

function getRandomBytes(n: number): Uint8Array {
  const bytes = new Uint8Array(n);
  crypto.getRandomValues(bytes);
  return bytes;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s/g, '').replace(/[^0-9a-fA-F]/g, '');
  if (clean.length % 2 !== 0) {
    const padded = clean.padEnd(clean.length + 1, '0');
    const bytes = new Uint8Array(padded.length / 2);
    for (let i = 0; i < padded.length; i += 2) {
      bytes[i / 2] = parseInt(padded.substring(i, i + 2), 16);
    }
    return bytes;
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
  }
  return bytes;
}

function textToBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function parseEntropy(input: string): Uint8Array {
  // Try hex first, then treat as text
  const trimmed = input.trim();
  if (/^[0-9a-fA-F\s]+$/.test(trimmed) && trimmed.replace(/\s/g, '').length >= 4) {
    return hexToBytes(trimmed);
  }
  return textToBytes(trimmed || 'default entropy');
}

function formatHexDisplay(bytes: Uint8Array, bytesPerLine = 16): string {
  const hex = toHex(bytes);
  const lines: string[] = [];
  for (let i = 0; i < hex.length; i += bytesPerLine * 2) {
    lines.push(hex.substring(i, i + bytesPerLine * 2));
  }
  return lines.join('\n');
}

// ─── Theme Toggle ─────────────────────────────────────────────────────────────

function initThemeToggle(): void {
  const btn = document.getElementById('theme-toggle');
  if (!btn) return;

  function updateButton(): void {
    const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
    btn!.textContent = isDark ? '🌙' : '☀️';
    btn!.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
  }

  btn.addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme');
    const next = current === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    updateButton();
  });

  updateButton();
}

// ─── Header ──────────────────────────────────────────────────────────────────

function buildHeader(): string {
  return `
    <header style="position: relative; padding: 1.5rem 2rem; background: var(--bg-secondary); border-bottom: 1px solid var(--border-color); margin-bottom: 1.5rem;">
      <a href="#main-content" class="skip-link">Skip to main content</a>
      <div>
        <h1 style="font-family: var(--font-mono); font-size: 1.4rem; font-weight: 700; letter-spacing: 0.05em; color: var(--green-clean); margin-bottom: 0.25rem;">
          ▶ DRBG Arena
        </h1>
        <p style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.1em;">
          NIST SP 800-90A Correct-Case Demo — HMAC_DRBG · CTR_DRBG · Hash_DRBG
        </p>
      </div>
      <button
        id="theme-toggle"
        class="theme-toggle"
        aria-label="Switch to light mode"
        title="Toggle theme"
      >🌙</button>
    </header>
  `;
}

// ─── Exhibit 1: What a DRBG is ───────────────────────────────────────────────

function buildExhibit1(): string {
  return `
    <section class="exhibit" id="exhibit-1" aria-labelledby="ex1-title">
      <div class="exhibit-header" id="ex1-title">
        <span style="color: var(--text-secondary); margin-right: 0.5rem;">01</span>
        What Is a DRBG?
      </div>

      <div style="font-size: 0.875rem; margin-bottom: 1rem; color: var(--text-secondary); font-style: italic; font-family: var(--font-mono);">
        NIST SP 800-90A Rev 1 — Recommendation for Random Number Generation Using Deterministic Random Bit Generators
      </div>

      <p style="margin-bottom: 0.75rem; font-size: 0.9rem; line-height: 1.6;">
        A <strong>Deterministic Random Bit Generator (DRBG)</strong> takes a seed from a true entropy source
        and produces a stream of cryptographically secure pseudorandom bits. The output is deterministic
        given the same seed — but computationally indistinguishable from true randomness to any adversary
        who does not know the seed.
      </p>

      <div class="section-title">Three NIST-Approved Constructions</div>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr)); gap: 0.75rem; margin-bottom: 1rem;">
        <div class="panel" style="border-color: var(--green-clean);">
          <div class="panel-header" style="color: var(--green-clean);">HMAC_DRBG</div>
          <div style="font-size: 0.8rem; color: var(--text-secondary);">Based on HMAC-SHA-256. State: V and K (both 256-bit). General-purpose recommended choice.</div>
        </div>
        <div class="panel" style="border-color: var(--blue-info);">
          <div class="panel-header" style="color: var(--blue-info);">CTR_DRBG</div>
          <div style="font-size: 0.8rem; color: var(--text-secondary);">Based on AES-256-CTR. State: V (128-bit) and Key (256-bit). Fast on AES-NI hardware. FIPS-required.</div>
        </div>
        <div class="panel" style="border-color: var(--amber-warn);">
          <div class="panel-header" style="color: var(--amber-warn);">Hash_DRBG</div>
          <div style="font-size: 0.8rem; color: var(--text-secondary);">Based on SHA-256/512. State: V and C (constant). Simplest approved construction. Good for constrained environments.</div>
        </div>
      </div>

      <div class="section-title">Why Not Math.random()?</div>
      <p style="font-size: 0.875rem; margin-bottom: 1rem; color: var(--red-corrupt); padding: 0.5rem; border: 1px solid var(--red-corrupt); background: var(--red-glow);">
        <strong>Math.random()</strong> is not cryptographically secure. Its output can be predicted from prior values.
        Never use it for cryptographic key or nonce generation.
      </p>

      <div class="section-title">Four Security Properties a Correct DRBG Must Have</div>
      <ul class="property-list" style="margin-bottom: 1rem;">
        <li>
          <span class="property-num">1</span>
          <strong>Backtracking Resistance</strong> — prior outputs cannot be recovered even if current state is compromised
        </li>
        <li>
          <span class="property-num">2</span>
          <strong>Prediction Resistance</strong> — future outputs cannot be predicted from past outputs without knowing the seed
        </li>
        <li>
          <span class="property-num">3</span>
          <strong>Forward Secrecy</strong> — state compromise does not expose prior outputs
        </li>
        <li>
          <span class="property-num">4</span>
          <strong>Statistical Indistinguishability</strong> — output is computationally indistinguishable from true randomness
        </li>
      </ul>

      <div class="section-title">Data Flow</div>
      <div class="diagram-box" style="margin-bottom: 1rem;">
        <span style="color: var(--amber-warn);">True Entropy Source</span>
        <span class="diagram-arrow">→</span>
        <span style="color: var(--text-primary);">Seed</span>
        <span class="diagram-arrow">→</span>
        <span style="color: var(--green-clean);">DRBG Internal State</span>
        <span class="diagram-arrow">→</span>
        <span style="color: var(--text-primary);">Output Stream</span>
        <span class="diagram-arrow">→</span>
        <span style="color: var(--blue-info);">↺ Reseed Trigger</span>
        <br/><br/>
        <span style="font-size: 0.7rem; color: var(--text-muted);">
          After 10,000 requests (HMAC_DRBG) or 2^48 requests (Hash_DRBG), a mandatory reseed is required.
        </span>
      </div>

      <div class="callout">
        <div class="callout-title">⚡ Why This Matters</div>
        Every TLS session key, every keypair, every nonce in encrypted traffic depends on a DRBG.
        A weak or backdoored DRBG undermines every other cryptographic guarantee in the system.
        <a href="https://systemslibrarian.github.io/crypto-lab-corrupted-oracle/"
           style="color: var(--green-clean); text-decoration: underline;"
           target="_blank" rel="noopener noreferrer">See Corrupted Oracle for the failure case →</a>
      </div>
    </section>
  `;
}

// ─── Exhibit 2: HMAC_DRBG ────────────────────────────────────────────────────

function buildExhibit2(): string {
  const defaultEntropy = toHex(getRandomBytes(32));
  return `
    <section class="exhibit" id="exhibit-2" aria-labelledby="ex2-title">
      <div class="exhibit-header" id="ex2-title">
        <span style="color: var(--text-secondary); margin-right: 0.5rem;">02</span>
        HMAC_DRBG
        <span style="font-weight: 400; color: var(--text-secondary); font-size: 0.75rem; margin-left: 0.5rem;">§10.1.2 — General-Purpose Recommended Choice</span>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem;">
        <div>
          <div class="section-title">How It Works</div>
          <ul style="font-size: 0.85rem; padding-left: 1.2rem; color: var(--text-secondary); line-height: 1.8;">
            <li>Internal state: <strong style="color: var(--text-primary);">V</strong> and <strong style="color: var(--text-primary);">K</strong> (both 256-bit)</li>
            <li>Update function: HMAC-SHA-256 updates both V and K on every Generate call</li>
            <li>Seed: entropy ‖ nonce ‖ personalization string</li>
            <li>Output: up to 7,500 bits per Generate call before mandatory reseed</li>
          </ul>
        </div>
        <div>
          <div class="section-title">Current State</div>
          <div class="state-viz" id="hmac-state-viz">
            <div class="state-row">
              <span class="state-label">K:</span>
              <span class="state-value" id="hmac-K-display">—</span>
            </div>
            <div class="state-row">
              <span class="state-label">V:</span>
              <span class="state-value" id="hmac-V-display">—</span>
            </div>
            <div style="font-size: 0.65rem; color: var(--text-muted); margin-top: 0.5rem;">
              ↑ K and V update on every Generate call (forward secrecy)
            </div>
          </div>
        </div>
      </div>

      <div class="input-group">
        <label class="input-label" for="hmac-entropy">Entropy Input (hex or text)</label>
        <div style="display: flex; gap: 0.5rem;">
          <input type="text" id="hmac-entropy" class="input-field" value="${defaultEntropy}" placeholder="hex or text entropy" />
          <button class="btn" id="hmac-entropy-random" style="white-space: nowrap; min-width: unset; padding: 0.4rem 0.75rem;">↺ Random</button>
        </div>
      </div>

      <div class="input-group">
        <label class="input-label" for="hmac-personalization">Personalization String (optional)</label>
        <input type="text" id="hmac-personalization" class="input-field" placeholder="optional — changes output" />
      </div>

      <div class="input-group">
        <label class="input-label" for="hmac-bytes-slider">Output Bytes: <span id="hmac-bytes-val">32</span></label>
        <input type="range" id="hmac-bytes-slider" class="slider" min="16" max="256" value="32" />
      </div>

      <div class="controls-row">
        <button class="btn" id="hmac-generate">▶ Generate</button>
        <button class="btn" id="hmac-generate-same">▶ Generate Again (same seed)</button>
        <button class="btn btn-danger" id="hmac-reseed">↺ Reseed</button>
        <button class="btn" id="hmac-copy" style="margin-left: auto;">⧉ Copy</button>
      </div>

      <div class="section-title">Output</div>
      <div class="hex-output" id="hmac-output" aria-live="polite" aria-label="HMAC_DRBG output">—</div>

      <div class="callout">
        <div class="callout-title">⚡ Why This Matters</div>
        HMAC_DRBG is used in OpenSSL, BoringSSL, and most TLS implementations worldwide.
        It is the direct, approved replacement for the backdoored Dual_EC_DRBG shown in Corrupted Oracle.
        If your system generates keys or nonces, it is almost certainly using HMAC_DRBG or CTR_DRBG.
      </div>
    </section>
  `;
}

// ─── Exhibit 3: CTR_DRBG ─────────────────────────────────────────────────────

function buildExhibit3(): string {
  const defaultEntropy = toHex(getRandomBytes(32));
  return `
    <section class="exhibit" id="exhibit-3" aria-labelledby="ex3-title">
      <div class="exhibit-header" id="ex3-title">
        <span style="color: var(--text-secondary); margin-right: 0.5rem;">03</span>
        CTR_DRBG
        <span style="font-weight: 400; color: var(--text-secondary); font-size: 0.75rem; margin-left: 0.5rem;">§10.2.1 — AES-Based, FIPS-Required Environments</span>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem;">
        <div>
          <div class="section-title">How It Works</div>
          <ul style="font-size: 0.85rem; padding-left: 1.2rem; color: var(--text-secondary); line-height: 1.8;">
            <li>Based on <strong style="color: var(--text-primary);">AES-256 in counter mode</strong></li>
            <li>Internal state: <strong style="color: var(--text-primary);">V</strong> (128-bit counter block) and <strong style="color: var(--text-primary);">Key</strong> (256-bit AES key)</li>
            <li>Both V and Key updated after each Generate call</li>
            <li>Faster than HMAC_DRBG on hardware with AES-NI instructions</li>
            <li>Required in U.S. government and DoD environments</li>
          </ul>
        </div>
        <div>
          <div class="section-title">Current State</div>
          <div class="state-viz" id="ctr-state-viz">
            <div class="state-row">
              <span class="state-label">Key:</span>
              <span class="state-value" id="ctr-Key-display">—</span>
            </div>
            <div class="state-row">
              <span class="state-label">V:</span>
              <span class="state-value" id="ctr-V-display">—</span>
            </div>
          </div>
        </div>
      </div>

      <div class="input-group">
        <label class="input-label" for="ctr-entropy">Entropy Input (hex or text)</label>
        <div style="display: flex; gap: 0.5rem;">
          <input type="text" id="ctr-entropy" class="input-field" value="${defaultEntropy}" placeholder="hex or text entropy" />
          <button class="btn" id="ctr-entropy-random" style="white-space: nowrap; min-width: unset; padding: 0.4rem 0.75rem;">↺ Random</button>
        </div>
      </div>

      <div class="input-group">
        <label class="input-label" for="ctr-bytes-slider">Output Bytes: <span id="ctr-bytes-val">32</span></label>
        <input type="range" id="ctr-bytes-slider" class="slider" min="16" max="256" value="32" />
      </div>

      <div class="controls-row">
        <button class="btn" id="ctr-generate">▶ Generate</button>
        <button class="btn" id="ctr-generate-same">▶ Generate (no reseed)</button>
        <button class="btn btn-danger" id="ctr-reseed">↺ Reseed</button>
        <button class="btn" id="ctr-copy" style="margin-left: auto;">⧉ Copy</button>
      </div>

      <div class="section-title">Output</div>
      <div class="hex-output" id="ctr-output" aria-live="polite" aria-label="CTR_DRBG output">—</div>

      <div class="section-title" style="margin-top: 1rem;">Side-by-Side Comparison (same entropy seed)</div>
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem;">
        <div>
          <div class="panel-header" style="margin-bottom: 0.5rem; color: var(--green-clean);">HMAC_DRBG output</div>
          <div class="hex-output" id="compare-hmac-output" aria-label="HMAC_DRBG comparison output">—</div>
        </div>
        <div>
          <div class="panel-header" style="margin-bottom: 0.5rem; color: var(--blue-info);">CTR_DRBG output</div>
          <div class="hex-output" id="compare-ctr-output" style="color: var(--blue-info);" aria-label="CTR_DRBG comparison output">—</div>
        </div>
      </div>
      <div style="font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 1rem;">
        ↑ Different construction, not a flaw — both are correct. Different output from the same seed is expected.
      </div>
      <button class="btn" id="ctr-compare">▶ Compare HMAC vs CTR (same seed)</button>

      <table class="comparison-table" style="margin-top: 1rem;">
        <thead>
          <tr>
            <th>Property</th>
            <th style="color: var(--green-clean);">HMAC_DRBG</th>
            <th style="color: var(--blue-info);">CTR_DRBG</th>
          </tr>
        </thead>
        <tbody>
          <tr><td>Primitive</td><td>HMAC-SHA-256</td><td>AES-256-CTR</td></tr>
          <tr><td>Speed</td><td>Medium</td><td>Fast (AES-NI)</td></tr>
          <tr><td>FIPS 140-2/3</td><td>✓</td><td>✓</td></tr>
          <tr><td>Use when</td><td>General use</td><td>AES-NI available</td></tr>
        </tbody>
      </table>

      <div class="callout">
        <div class="callout-title">⚡ Why This Matters</div>
        CTR_DRBG is mandated in U.S. government and DoD environments. Windows CNG (Cryptography Next
        Generation), many HSMs, and most FIPS 140-2 validated modules use CTR_DRBG with AES-256.
        If you are building for federal procurement, this is your DRBG.
      </div>
    </section>
  `;
}

// ─── Exhibit 4: Hash_DRBG ────────────────────────────────────────────────────

function buildExhibit4(): string {
  const defaultEntropy = toHex(getRandomBytes(32));
  return `
    <section class="exhibit" id="exhibit-4" aria-labelledby="ex4-title">
      <div class="exhibit-header" id="ex4-title">
        <span style="color: var(--text-secondary); margin-right: 0.5rem;">04</span>
        Hash_DRBG
        <span style="font-weight: 400; color: var(--text-secondary); font-size: 0.75rem; margin-left: 0.5rem;">§10.1.1 — Simplest Approved Construction</span>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem;">
        <div>
          <div class="section-title">How It Works</div>
          <ul style="font-size: 0.85rem; padding-left: 1.2rem; color: var(--text-secondary); line-height: 1.8;">
            <li>Based on <strong style="color: var(--text-primary);">SHA-256 or SHA-512</strong></li>
            <li>Internal state: <strong style="color: var(--text-primary);">V</strong> (seed value) and <strong style="color: var(--text-primary);">C</strong> (constant derived from V)</li>
            <li><strong style="color: var(--amber-warn);">C does not change between reseeds</strong> — simpler than HMAC_DRBG</li>
            <li>Reseed interval: up to 2^48 Generate requests</li>
            <li>Easier to implement correctly than HMAC_DRBG</li>
          </ul>
        </div>
        <div>
          <div class="section-title">Current State</div>
          <div class="state-viz" id="hash-state-viz">
            <div class="state-row">
              <span class="state-label">V:</span>
              <span class="state-value" id="hash-V-display">—</span>
            </div>
            <div class="state-row">
              <span class="state-label">C:</span>
              <span class="state-value" id="hash-C-display">—</span>
            </div>
            <div style="font-size: 0.65rem; color: var(--text-muted); margin-top: 0.5rem;">
              ↑ V updates on each Generate; C stays constant until reseed
            </div>
          </div>
        </div>
      </div>

      <div class="input-group">
        <label class="input-label" for="hash-entropy">Entropy Input (hex or text)</label>
        <div style="display: flex; gap: 0.5rem;">
          <input type="text" id="hash-entropy" class="input-field" value="${defaultEntropy}" placeholder="hex or text entropy" />
          <button class="btn" id="hash-entropy-random" style="white-space: nowrap; min-width: unset; padding: 0.4rem 0.75rem;">↺ Random</button>
        </div>
      </div>

      <div class="input-group">
        <label class="input-label" for="hash-algorithm">Hash Function</label>
        <select id="hash-algorithm" class="input-field">
          <option value="SHA-256" selected>SHA-256 (440-bit seedlen)</option>
          <option value="SHA-512">SHA-512 (888-bit seedlen)</option>
        </select>
      </div>

      <div class="input-group">
        <label class="input-label" for="hash-bytes-slider">Output Bytes: <span id="hash-bytes-val">32</span></label>
        <input type="range" id="hash-bytes-slider" class="slider" min="16" max="256" value="32" />
      </div>

      <div class="controls-row">
        <button class="btn" id="hash-generate">▶ Generate</button>
        <button class="btn btn-danger" id="hash-reseed">↺ Reseed</button>
        <button class="btn" id="hash-copy" style="margin-left: auto;">⧉ Copy</button>
      </div>

      <div class="section-title">Output</div>
      <div class="hex-output" id="hash-output" aria-live="polite" aria-label="Hash_DRBG output">—</div>

      <div class="section-title" style="margin-top: 1rem;">Three-Way DRBG Comparison</div>
      <table class="comparison-table">
        <thead>
          <tr>
            <th>Property</th>
            <th style="color: var(--amber-warn);">Hash_DRBG</th>
            <th style="color: var(--green-clean);">HMAC_DRBG</th>
            <th style="color: var(--blue-info);">CTR_DRBG</th>
          </tr>
        </thead>
        <tbody>
          <tr><td>Primitive</td><td>SHA-256/512</td><td>HMAC-SHA-256</td><td>AES-256-CTR</td></tr>
          <tr><td>State components</td><td>V, C</td><td>V, K</td><td>V, Key</td></tr>
          <tr><td>Speed</td><td>Medium</td><td>Medium</td><td>Fast (AES-NI)</td></tr>
          <tr><td>FIPS 140-2/3</td><td>✓</td><td>✓</td><td>✓</td></tr>
          <tr><td>Use when</td><td>Simplicity</td><td>General use</td><td>AES-NI hardware</td></tr>
          <tr><td>Avoid when</td><td>Perf needed</td><td>FIPS CTR req.</td><td>No AES-NI</td></tr>
        </tbody>
      </table>

      <div class="callout">
        <div class="callout-title">⚡ Why This Matters</div>
        Hash_DRBG is the easiest NIST DRBG to implement correctly from scratch, with no key schedule
        or HMAC overhead. It is used in embedded systems and constrained environments.
        Its simplicity makes it the best choice for learning DRBG internals.
      </div>
    </section>
  `;
}

// ─── Exhibit 5: Statistical Tests ────────────────────────────────────────────

function buildExhibit5(): string {
  return `
    <section class="exhibit" id="exhibit-5" aria-labelledby="ex5-title">
      <div class="exhibit-header" id="ex5-title">
        <span style="color: var(--text-secondary); margin-right: 0.5rem;">05</span>
        Statistical Output Quality Tests
        <span style="font-weight: 400; color: var(--text-secondary); font-size: 0.75rem; margin-left: 0.5rem;">Simplified NIST SP 800-22</span>
      </div>

      <p style="font-size: 0.875rem; color: var(--text-secondary); margin-bottom: 1rem; line-height: 1.6;">
        Run four simplified NIST SP 800-22 statistical tests on 1,024 bytes of output from each DRBG.
        All three approved DRBGs should pass all tests — demonstrating statistically indistinguishable output.
      </p>

      <div class="controls-row">
        <button class="btn" id="stats-run">▶ Test All Three DRBGs</button>
        <span id="stats-status" style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted); align-self: center;"></span>
      </div>

      <div id="stats-results" style="margin-top: 1rem;" aria-live="polite">
        <!-- Results rendered here -->
      </div>

      <div style="margin-top: 1.5rem; padding: 1rem; border: 1px solid var(--amber-warn); background: rgba(255,170,0,0.05);">
        <div style="font-family: var(--font-mono); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--amber-warn); margin-bottom: 0.5rem;">
          ⚠ Dual_EC_DRBG Warning
        </div>
        <p style="font-size: 0.875rem; line-height: 1.6;">
          The same four tests also <strong>pass on Dual_EC_DRBG output</strong> — despite its backdoor.
          The backdoor is undetectable by statistical analysis. It only helps the party who knows the
          discrete log relationship between curve points P and Q.
        </p>
        <p style="font-size: 0.875rem; margin-top: 0.5rem; line-height: 1.6;">
          This is exactly why algorithm choice and standard compliance matter — not just output quality checks.
          A backdoored DRBG passes every statistical test by design.
        </p>
        <a href="https://systemslibrarian.github.io/crypto-lab-corrupted-oracle/"
           style="display: inline-block; margin-top: 0.75rem; color: var(--green-clean); text-decoration: underline; font-family: var(--font-mono); font-size: 0.8rem;"
           target="_blank" rel="noopener noreferrer">
          See the attack demonstrated in Corrupted Oracle →
        </a>
      </div>

      <div class="callout">
        <div class="callout-title">⚡ Why This Matters</div>
        Statistical tests catch broken DRBGs (like a PRNG seeded with a constant) but cannot detect
        a mathematically sound backdoor. Algorithm choice and standard compliance matter —
        not just output quality checks.
      </div>
    </section>
  `;
}

// ─── Stats Results Renderer ───────────────────────────────────────────────────

function renderStatsResults(
  hmacResults: StatTestResult[],
  ctrResults: StatTestResult[],
  hashResults: StatTestResult[]
): string {
  const drbgs = [
    { name: 'HMAC_DRBG', results: hmacResults, color: 'var(--green-clean)' },
    { name: 'CTR_DRBG', results: ctrResults, color: 'var(--blue-info)' },
    { name: 'Hash_DRBG', results: hashResults, color: 'var(--amber-warn)' },
  ];

  let html = '';

  // Shannon entropy bar chart
  html += `<div class="section-title">Entropy Estimate (bits/byte, max 8)</div>`;
  html += `<div style="margin-bottom: 1rem;">`;
  for (const { name, results, color } of drbgs) {
    const entropyResult = results.find(r => r.name === 'Shannon Entropy Estimate');
    const entropyBits = entropyResult ? entropyResult.pValue * 8 : 0;
    const pct = (entropyBits / 8) * 100;
    html += `
      <div class="bar-container">
        <div class="bar-label" style="color: ${color};">${name}</div>
        <div class="bar-track">
          <div class="bar-fill" style="width: ${pct.toFixed(1)}%; background: ${color};"></div>
        </div>
        <span style="font-family: var(--font-mono); font-size: 0.7rem; color: ${color}; min-width: 5rem; text-align: right;">
          ${entropyBits.toFixed(3)} bits/byte
        </span>
      </div>
    `;
  }
  html += `</div>`;

  // Per-DRBG test results
  for (const { name, results, color } of drbgs) {
    html += `<div style="margin-bottom: 1rem;">`;
    html += `<div class="panel-header" style="color: ${color}; margin-bottom: 0.5rem;">${name}</div>`;
    for (const r of results) {
      html += `
        <div class="test-result ${r.passed ? 'test-pass' : 'test-fail'}">
          <span style="font-size: 1rem;">${r.passed ? '✓' : '✗'}</span>
          <div style="flex: 1;">
            <div style="font-weight: 600;">${r.name}</div>
            <div style="color: var(--text-secondary); font-size: 0.7rem;">${r.detail}</div>
          </div>
        </div>
      `;
    }
    html += `</div>`;
  }

  return html;
}

// ─── State Display Updater ────────────────────────────────────────────────────

function updateStateDisplay(prefix: string, state: HmacDrbgState | CtrDrbgState | HashDrbgState): void {
  function setVal(id: string, val: string): void {
    const el = document.getElementById(id);
    if (el) {
      el.textContent = val;
      el.className = 'state-value state-changed';
      setTimeout(() => {
        if (el) el.className = 'state-value';
      }, 600);
    }
  }

  if (prefix === 'hmac') {
    const s = state as HmacDrbgState;
    setVal('hmac-K-display', toHex(s.K).substring(0, 32) + '…');
    setVal('hmac-V-display', toHex(s.V).substring(0, 32) + '…');
  } else if (prefix === 'ctr') {
    const s = state as CtrDrbgState;
    setVal('ctr-Key-display', toHex(s.Key).substring(0, 32) + '…');
    setVal('ctr-V-display', toHex(s.V));
  } else if (prefix === 'hash') {
    const s = state as HashDrbgState;
    setVal('hash-V-display', toHex(s.V).substring(0, 32) + '…');
    setVal('hash-C-display', toHex(s.C).substring(0, 32) + '…');
  }
}

// ─── Main initUI ─────────────────────────────────────────────────────────────

export async function initUI(): Promise<void> {
  const app = document.getElementById('app');
  if (!app) return;

  app.innerHTML = `
    ${buildHeader()}
    <main id="main-content" style="max-width: 900px; margin: 0 auto; padding: 0 1.5rem 2rem;">
      ${buildExhibit1()}
      ${buildExhibit2()}
      ${buildExhibit3()}
      ${buildExhibit4()}
      ${buildExhibit5()}
    </main>
  `;

  initThemeToggle();

  // ── HMAC_DRBG state ──────────────────────────────────────────────────────
  let hmacState: HmacDrbgState | null = null;
  let hmacSeedEntropy = parseEntropy((document.getElementById('hmac-entropy') as HTMLInputElement | null)?.value ?? '');

  async function hmacInstantiate(): Promise<void> {
    const entropyInput = document.getElementById('hmac-entropy') as HTMLInputElement | null;
    const personInput = document.getElementById('hmac-personalization') as HTMLInputElement | null;
    const entropy = parseEntropy(entropyInput?.value ?? '');
    const nonce = getRandomBytes(16);
    const personalization = personInput?.value ? textToBytes(personInput.value) : new Uint8Array(0);
    hmacSeedEntropy = entropy;
    hmacState = await hmacDrbgInstantiate(entropy, nonce, personalization);
    updateStateDisplay('hmac', hmacState);
  }

  document.getElementById('hmac-entropy-random')?.addEventListener('click', () => {
    const el = document.getElementById('hmac-entropy') as HTMLInputElement | null;
    if (el) el.value = toHex(getRandomBytes(32));
  });

  document.getElementById('hmac-bytes-slider')?.addEventListener('input', (e) => {
    const val = document.getElementById('hmac-bytes-val');
    if (val) val.textContent = (e.target as HTMLInputElement).value;
  });

  document.getElementById('hmac-generate')?.addEventListener('click', async () => {
    if (!hmacState) await hmacInstantiate();
    const slider = document.getElementById('hmac-bytes-slider') as HTMLInputElement | null;
    const bytes = parseInt(slider?.value ?? '32');
    const { output, newState } = await hmacDrbgGenerate(hmacState!, bytes);
    hmacState = newState;
    updateStateDisplay('hmac', hmacState);
    const outEl = document.getElementById('hmac-output');
    if (outEl) outEl.textContent = formatHexDisplay(output);
  });

  document.getElementById('hmac-generate-same')?.addEventListener('click', async () => {
    // Re-instantiate with the same entropy to demonstrate determinism
    const personInput = document.getElementById('hmac-personalization') as HTMLInputElement | null;
    const personalization = personInput?.value ? textToBytes(personInput.value) : new Uint8Array(0);
    const slider = document.getElementById('hmac-bytes-slider') as HTMLInputElement | null;
    const bytes = parseInt(slider?.value ?? '32');
    const deterministicNonce = new Uint8Array(16); // fixed nonce for determinism demo
    const detState = await hmacDrbgInstantiate(hmacSeedEntropy, deterministicNonce, personalization);
    const { output } = await hmacDrbgGenerate(detState, bytes);
    const outEl = document.getElementById('hmac-output');
    if (outEl) {
      outEl.textContent = formatHexDisplay(output) + '\n[deterministic — same seed, same nonce → same output]';
    }
    // update hmacState so current state reflects this
    hmacState = detState;
    updateStateDisplay('hmac', hmacState);
  });

  document.getElementById('hmac-reseed')?.addEventListener('click', async () => {
    if (!hmacState) await hmacInstantiate();
    const newEntropy = getRandomBytes(32);
    const el = document.getElementById('hmac-entropy') as HTMLInputElement | null;
    if (el) el.value = toHex(newEntropy);
    hmacState = await hmacDrbgReseed(hmacState!, newEntropy);
    hmacSeedEntropy = newEntropy;
    updateStateDisplay('hmac', hmacState);
    const outEl = document.getElementById('hmac-output');
    if (outEl) outEl.textContent = '[Reseeded — generate new output]';
  });

  document.getElementById('hmac-copy')?.addEventListener('click', () => {
    const outEl = document.getElementById('hmac-output');
    if (outEl?.textContent) navigator.clipboard.writeText(outEl.textContent).catch(() => {});
  });

  // ── CTR_DRBG state ───────────────────────────────────────────────────────
  let ctrState: CtrDrbgState | null = null;

  async function ctrInstantiate(entropyOverride?: Uint8Array): Promise<CtrDrbgState> {
    const entropyInput = document.getElementById('ctr-entropy') as HTMLInputElement | null;
    const entropy = entropyOverride ?? parseEntropy(entropyInput?.value ?? '');
    const state = await ctrDrbgInstantiate(entropy);
    ctrState = state;
    updateStateDisplay('ctr', ctrState);
    return state;
  }

  document.getElementById('ctr-entropy-random')?.addEventListener('click', () => {
    const el = document.getElementById('ctr-entropy') as HTMLInputElement | null;
    if (el) el.value = toHex(getRandomBytes(32));
  });

  document.getElementById('ctr-bytes-slider')?.addEventListener('input', (e) => {
    const val = document.getElementById('ctr-bytes-val');
    if (val) val.textContent = (e.target as HTMLInputElement).value;
  });

  document.getElementById('ctr-generate')?.addEventListener('click', async () => {
    if (!ctrState) await ctrInstantiate();
    const slider = document.getElementById('ctr-bytes-slider') as HTMLInputElement | null;
    const bytes = parseInt(slider?.value ?? '32');
    const { output, newState } = await ctrDrbgGenerate(ctrState!, bytes);
    ctrState = newState;
    updateStateDisplay('ctr', ctrState);
    const outEl = document.getElementById('ctr-output');
    if (outEl) outEl.textContent = formatHexDisplay(output);
  });

  document.getElementById('ctr-generate-same')?.addEventListener('click', async () => {
    if (!ctrState) await ctrInstantiate();
    const slider = document.getElementById('ctr-bytes-slider') as HTMLInputElement | null;
    const bytes = parseInt(slider?.value ?? '32');
    // Generate without updating the seed state (re-use current state) - just show current output
    const { output } = await ctrDrbgGenerate(ctrState!, bytes);
    const outEl = document.getElementById('ctr-output');
    if (outEl) outEl.textContent = formatHexDisplay(output) + '\n[no reseed — state advances normally]';
  });

  document.getElementById('ctr-reseed')?.addEventListener('click', async () => {
    const newEntropy = getRandomBytes(32);
    const el = document.getElementById('ctr-entropy') as HTMLInputElement | null;
    if (el) el.value = toHex(newEntropy);
    if (!ctrState) { await ctrInstantiate(newEntropy); return; }
    ctrState = await ctrDrbgReseed(ctrState, newEntropy);
    updateStateDisplay('ctr', ctrState);
    const outEl = document.getElementById('ctr-output');
    if (outEl) outEl.textContent = '[Reseeded — generate new output]';
  });

  document.getElementById('ctr-copy')?.addEventListener('click', () => {
    const outEl = document.getElementById('ctr-output');
    if (outEl?.textContent) navigator.clipboard.writeText(outEl.textContent).catch(() => {});
  });

  document.getElementById('ctr-compare')?.addEventListener('click', async () => {
    // Same entropy seed → both HMAC and CTR
    const sharedEntropy = getRandomBytes(32);
    const slider = document.getElementById('ctr-bytes-slider') as HTMLInputElement | null;
    const bytes = parseInt(slider?.value ?? '32');

    const nonce = new Uint8Array(16);
    const hmacCompState = await hmacDrbgInstantiate(sharedEntropy, nonce, new Uint8Array(0));
    const { output: hmacOut } = await hmacDrbgGenerate(hmacCompState, bytes);

    const ctrCompState = await ctrDrbgInstantiate(sharedEntropy);
    const { output: ctrOut } = await ctrDrbgGenerate(ctrCompState, bytes);

    const hmacEl = document.getElementById('compare-hmac-output');
    const ctrEl = document.getElementById('compare-ctr-output');
    if (hmacEl) hmacEl.textContent = formatHexDisplay(hmacOut);
    if (ctrEl) ctrEl.textContent = formatHexDisplay(ctrOut);
  });

  // ── Hash_DRBG state ──────────────────────────────────────────────────────
  let hashState: HashDrbgState | null = null;

  async function hashInstantiate(): Promise<void> {
    const entropyInput = document.getElementById('hash-entropy') as HTMLInputElement | null;
    const algoSelect = document.getElementById('hash-algorithm') as HTMLSelectElement | null;
    const entropy = parseEntropy(entropyInput?.value ?? '');
    const algorithm = (algoSelect?.value ?? 'SHA-256') as HashAlgorithm;
    const nonce = getRandomBytes(16);
    hashState = await hashDrbgInstantiate(entropy, nonce, new Uint8Array(0), algorithm);
    updateStateDisplay('hash', hashState);
  }

  document.getElementById('hash-entropy-random')?.addEventListener('click', () => {
    const el = document.getElementById('hash-entropy') as HTMLInputElement | null;
    if (el) el.value = toHex(getRandomBytes(32));
  });

  document.getElementById('hash-bytes-slider')?.addEventListener('input', (e) => {
    const val = document.getElementById('hash-bytes-val');
    if (val) val.textContent = (e.target as HTMLInputElement).value;
  });

  document.getElementById('hash-generate')?.addEventListener('click', async () => {
    if (!hashState) await hashInstantiate();
    const slider = document.getElementById('hash-bytes-slider') as HTMLInputElement | null;
    const bytes = parseInt(slider?.value ?? '32');
    const { output, newState } = await hashDrbgGenerate(hashState!, bytes);
    hashState = newState;
    updateStateDisplay('hash', hashState);
    const outEl = document.getElementById('hash-output');
    if (outEl) outEl.textContent = formatHexDisplay(output);
  });

  document.getElementById('hash-reseed')?.addEventListener('click', async () => {
    if (!hashState) await hashInstantiate();
    const newEntropy = getRandomBytes(32);
    const el = document.getElementById('hash-entropy') as HTMLInputElement | null;
    if (el) el.value = toHex(newEntropy);
    hashState = await hashDrbgReseed(hashState!, newEntropy);
    updateStateDisplay('hash', hashState);
    const outEl = document.getElementById('hash-output');
    if (outEl) outEl.textContent = '[Reseeded — generate new output]';
  });

  document.getElementById('hash-copy')?.addEventListener('click', () => {
    const outEl = document.getElementById('hash-output');
    if (outEl?.textContent) navigator.clipboard.writeText(outEl.textContent).catch(() => {});
  });

  // ── Stats ────────────────────────────────────────────────────────────────
  document.getElementById('stats-run')?.addEventListener('click', async () => {
    const statusEl = document.getElementById('stats-status');
    const resultsEl = document.getElementById('stats-results');
    if (statusEl) statusEl.textContent = 'Running…';
    if (resultsEl) resultsEl.innerHTML = '';

    const testBytes = 1024;

    // HMAC_DRBG: fresh instantiation
    const hmacEntropy = getRandomBytes(32);
    const hmacNonce = getRandomBytes(16);
    const hmacTestState = await hmacDrbgInstantiate(hmacEntropy, hmacNonce, new Uint8Array(0));
    const { output: hmacTestOut } = await hmacDrbgGenerate(hmacTestState, testBytes);

    // CTR_DRBG: fresh instantiation
    const ctrEntropy = getRandomBytes(32);
    const ctrTestState = await ctrDrbgInstantiate(ctrEntropy);
    const { output: ctrTestOut } = await ctrDrbgGenerate(ctrTestState, testBytes);

    // Hash_DRBG: fresh instantiation
    const hashEntropy = getRandomBytes(32);
    const hashNonce = getRandomBytes(16);
    const hashTestState = await hashDrbgInstantiate(hashEntropy, hashNonce, new Uint8Array(0), 'SHA-256');
    const { output: hashTestOut } = await hashDrbgGenerate(hashTestState, testBytes);

    const hmacStatResults = runAllTests(hmacTestOut);
    const ctrStatResults = runAllTests(ctrTestOut);
    const hashStatResults = runAllTests(hashTestOut);

    if (resultsEl) {
      resultsEl.innerHTML = renderStatsResults(hmacStatResults, ctrStatResults, hashStatResults);
    }
    if (statusEl) statusEl.textContent = 'Done';
  });
}
