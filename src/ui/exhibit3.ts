/**
 * Exhibit 3 — CTR_DRBG (AES-based)
 * Interactive demo with side-by-side HMAC_DRBG comparison.
 */

import { ctrDrbgInstantiate, ctrDrbgGenerate } from '../crypto/ctr-drbg';
import { hmacDrbgInstantiate, hmacDrbgGenerate } from '../crypto/hmac-drbg';
import { toHex, fromHex, getRandomEntropy } from '../crypto/utils';
import { glossary } from './glossary';

export function buildExhibit3(announce: (msg: string) => void): HTMLElement {
  const section = document.createElement('section');
  section.className = 'exhibit';
  section.setAttribute('aria-labelledby', 'exhibit3-title');

  section.innerHTML = `
    <h2 class="exhibit-title" id="exhibit3-title">Exhibit 3 — CTR_DRBG</h2>
    <div class="exhibit-body">
      <div class="panel">
        <div class="panel-header"><span aria-hidden="true">🔒</span> AES-Based, FIPS-Required</div>
        <p style="font-size:0.85rem;line-height:1.7;color:var(--text-secondary)">
          Based on <strong style="color:var(--text-primary)">AES-256 in counter mode</strong>.
          Internal state: <strong style="color:var(--text-primary)">V</strong> (128-bit counter block) and
          <strong style="color:var(--text-primary)">Key</strong> (256-bit AES key). Both updated after
          each Generate call. Required in many U.S. government and DoD environments.
          It is usually the faster of the two on hardware with AES-NI instructions —
          <strong style="color:var(--text-primary)">Compare with HMAC_DRBG</strong> below times both in
          this browser and prints what it actually measured, which is not the same claim.
        </p>
      </div>

      <div class="panel">
        <div class="panel-header"><span aria-hidden="true">⚙️</span> Controls</div>
        <div class="field-group">
          <label for="ctr-entropy">Entropy (hex or leave blank for auto)</label>
          <input type="text" id="ctr-entropy" placeholder="e.g. a1b2c3... (96 hex chars = 48 bytes seedlen)" autocomplete="off" spellcheck="false" />
        </div>
        ${glossary('seedlen', 'entropy')}
        <div class="field-group">
          <label for="ctr-bytes">Output bytes: <span id="ctr-bytes-val">32</span></label>
          <div class="slider-group">
            <input type="range" id="ctr-bytes" min="16" max="256" value="32" aria-label="Output bytes" />
            <span class="slider-value" id="ctr-bytes-display">32</span>
          </div>
        </div>
        <div class="controls-row">
          <button class="btn btn-primary" id="ctr-generate" aria-label="Generate CTR DRBG output">Generate</button>
          <button class="btn" id="ctr-same-seed" disabled aria-label="Generate again with same seed">Same Seed Again</button>
          <button class="btn" id="ctr-compare" disabled aria-label="Compare CTR DRBG with HMAC DRBG using same entropy">Compare with HMAC_DRBG</button>
          <button class="copy-btn" id="ctr-copy" disabled aria-label="Copy output to clipboard">Copy</button>
        </div>
      </div>

      <div class="panel" id="ctr-output-panel" style="display:none">
        <div class="panel-header"><span aria-hidden="true">📤</span> CTR_DRBG Output</div>
        <div class="hex-output" tabindex="0" id="ctr-output" role="log" aria-live="polite" aria-label="CTR DRBG hex output"></div>
        <div id="ctr-seed-note" role="status"
             style="font-size:0.8rem;line-height:1.7;margin-top:0.6rem"></div>
        <div style="display:flex;flex-direction:column;gap:0.5rem;margin-top:0.5rem">
          <div class="state-row"><span class="state-label">Key:</span><span class="state-value" id="ctr-state-key"></span></div>
          <div class="state-row"><span class="state-label">V:</span><span class="state-value" id="ctr-state-v"></span></div>
        </div>
      </div>

      <div class="panel" id="ctr-comparison-panel" style="display:none">
        <div class="panel-header"><span aria-hidden="true">⚖️</span> Side-by-Side: Same Entropy, Different Construction</div>
        <p style="font-size:0.8rem;color:var(--text-muted);margin-bottom:0.75rem">
          Same entropy seed fed to both — different output is expected and correct.
          Different construction, not a flaw.
        </p>
        <div class="two-col">
          <div>
            <div style="font-family:var(--font-mono);font-size:0.75rem;color:var(--green-clean);margin-bottom:0.25rem">CTR_DRBG</div>
            <div class="hex-output" tabindex="0" id="ctr-cmp-output" role="log" aria-live="polite" aria-label="CTR DRBG comparison output"></div>
          </div>
          <div>
            <div style="font-family:var(--font-mono);font-size:0.75rem;color:var(--green-clean);margin-bottom:0.25rem">HMAC_DRBG</div>
            <div class="hex-output" tabindex="0" id="ctr-cmp-hmac" role="log" aria-live="polite" aria-label="HMAC DRBG comparison output"></div>
          </div>
        </div>
        <div id="ctr-timing" role="status"
             style="font-size:0.8rem;line-height:1.7;color:var(--text-secondary);margin-top:0.75rem"></div>
      </div>

      <div class="panel">
        <div class="panel-header"><span aria-hidden="true">📊</span> Comparison</div>
        <div style="overflow-x:auto">
          <table tabindex="0" class="cmp-table" aria-label="HMAC DRBG vs CTR DRBG comparison">
            <thead>
              <tr><th scope="col">Property</th><th scope="col">HMAC_DRBG</th><th scope="col">CTR_DRBG</th></tr>
            </thead>
            <tbody>
              <tr><td>Primitive</td><td>HMAC-SHA-256</td><td>AES-256-CTR</td></tr>
              <tr><td>Measured here</td><td id="cmp-speed-hmac">— press Compare</td><td id="cmp-speed-ctr">— press Compare</td></tr>
              <tr><td>FIPS 140-2/3</td><td>✓</td><td>✓</td></tr>
              <tr><td>Use when</td><td>General use</td><td>AES-NI available</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <div class="callout" role="note">
        <strong>Why this matters:</strong> CTR_DRBG is mandated in U.S. government and DoD
        environments. Windows CNG (Cryptography Next Generation), many HSMs, and most
        FIPS 140-2 validated modules use CTR_DRBG with AES-256. If you are building for
        federal procurement, this is your DRBG.
      </div>
    </div>
  `;

  requestAnimationFrame(() => wireExhibit3(section, announce));
  return section;
}

function wireExhibit3(section: HTMLElement, announce: (msg: string) => void): void {
  const entropyInput = section.querySelector<HTMLInputElement>('#ctr-entropy')!;
  const bytesSlider = section.querySelector<HTMLInputElement>('#ctr-bytes')!;
  const bytesDisplay = section.querySelector<HTMLSpanElement>('#ctr-bytes-display')!;
  const bytesVal = section.querySelector<HTMLSpanElement>('#ctr-bytes-val')!;
  const generateBtn = section.querySelector<HTMLButtonElement>('#ctr-generate')!;
  const sameSeedBtn = section.querySelector<HTMLButtonElement>('#ctr-same-seed')!;
  const compareBtn = section.querySelector<HTMLButtonElement>('#ctr-compare')!;
  const copyBtn = section.querySelector<HTMLButtonElement>('#ctr-copy')!;
  const outputPanel = section.querySelector<HTMLElement>('#ctr-output-panel')!;
  const outputEl = section.querySelector<HTMLElement>('#ctr-output')!;
  const comparisonPanel = section.querySelector<HTMLElement>('#ctr-comparison-panel')!;

  const seedNote = section.querySelector<HTMLElement>('#ctr-seed-note')!;
  const timingEl = section.querySelector<HTMLElement>('#ctr-timing')!;

  const SEEDLEN = 48; // AES-256 CTR_DRBG seedlen, in bytes

  let lastEntropy: Uint8Array | null = null;
  /** How many bytes the learner actually supplied, before padding. */
  let lastSuppliedBytes = SEEDLEN;

  bytesSlider.addEventListener('input', () => {
    bytesDisplay.textContent = bytesSlider.value;
    bytesVal.textContent = bytesSlider.value;
  });

  function getEntropy(): Uint8Array {
    const val = entropyInput.value.trim();
    if (val.length > 0 && /^[0-9a-fA-F]+$/.test(val)) {
      const raw = fromHex(val);
      // Pad or trim to seedlen. The padding used to be silent, so typing "ff"
      // produced a full-looking instantiation carrying 8 bits of entropy.
      lastSuppliedBytes = Math.min(raw.length, SEEDLEN);
      const ent = new Uint8Array(SEEDLEN);
      ent.set(raw.slice(0, SEEDLEN));
      return ent;
    }
    lastSuppliedBytes = SEEDLEN;
    return getRandomEntropy(SEEDLEN);
  }

  /** State what the seed the run actually used is worth, from the run's own numbers. */
  function renderSeedNote(): void {
    const supplied = lastSuppliedBytes;
    if (supplied >= SEEDLEN) {
      seedNote.style.color = 'var(--text-muted)';
      seedNote.textContent =
        `Seed: ${SEEDLEN} bytes (${SEEDLEN * 8} bits), the full AES-256 seedlen. Nothing was padded.`;
      return;
    }
    const padded = SEEDLEN - supplied;
    seedNote.style.color = 'var(--amber-warn)';
    seedNote.innerHTML =
      `<strong>Under-seeded:</strong> you supplied <strong>${supplied} byte${supplied === 1 ? '' : 's'}</strong> ` +
      `(${supplied * 8} bits). CTR_DRBG needs ${SEEDLEN} bytes, so the remaining ${padded} were zero-filled. ` +
      `The output below looks like ${SEEDLEN * 8}-bit-strength material and carries at most ` +
      `<strong>${supplied * 8} bits</strong> of entropy — an attacker searches 2<sup>${supplied * 8}</sup>, not ` +
      `2<sup>${SEEDLEN * 8}</sup>. SP 800-90A forbids this; the instantiate call would reject it.`;
  }

  async function doGenerate(reuse: boolean): Promise<void> {
    const numBytes = parseInt(bytesSlider.value, 10);

    if (!reuse || !lastEntropy) {
      lastEntropy = getEntropy();
    }

    const state = await ctrDrbgInstantiate(lastEntropy);
    const result = await ctrDrbgGenerate(state, numBytes);

    outputPanel.style.display = '';
    outputEl.textContent = toHex(result.output);
    renderSeedNote();
    section.querySelector<HTMLElement>('#ctr-state-key')!.textContent = result.newKey;
    section.querySelector<HTMLElement>('#ctr-state-v')!.textContent = result.newV;

    sameSeedBtn.disabled = false;
    compareBtn.disabled = false;
    copyBtn.disabled = false;
    announce(`CTR_DRBG generated ${numBytes} bytes`);
  }

  generateBtn.addEventListener('click', () => { void doGenerate(false); });
  sameSeedBtn.addEventListener('click', () => { void doGenerate(true); });

  compareBtn.addEventListener('click', async () => {
    if (!lastEntropy) return;
    const numBytes = parseInt(bytesSlider.value, 10);
    const entropy = lastEntropy;
    // Both constructions already run on this one click, so the speed row can be
    // a measurement instead of an assertion. Repeat enough times that the
    // figure is above timer noise, and report per-instantiate-plus-generate.
    const REPS = 40;

    async function timeIt(run: () => Promise<unknown>): Promise<number> {
      await run(); // warm up: first call pays for WebCrypto key import
      const t0 = performance.now();
      for (let i = 0; i < REPS; i++) await run();
      return (performance.now() - t0) / REPS;
    }

    const hmacEntropy = entropy.slice(0, 32);
    const ctrMs = await timeIt(async () => {
      const st = await ctrDrbgInstantiate(entropy);
      await ctrDrbgGenerate(st, numBytes);
    });
    const hmacMs = await timeIt(async () => {
      const st = await hmacDrbgInstantiate(hmacEntropy);
      await hmacDrbgGenerate(st, numBytes);
    });

    // One more of each, kept for display.
    const ctrState = await ctrDrbgInstantiate(entropy);
    const ctrResult = await ctrDrbgGenerate(ctrState, numBytes);
    const hmacState = await hmacDrbgInstantiate(hmacEntropy);
    const hmacResult = await hmacDrbgGenerate(hmacState, numBytes);

    comparisonPanel.style.display = '';
    section.querySelector<HTMLElement>('#ctr-cmp-output')!.textContent = toHex(ctrResult.output);
    section.querySelector<HTMLElement>('#ctr-cmp-hmac')!.textContent = toHex(hmacResult.output);

    const fmt = (ms: number): string => `${ms.toFixed(3)} ms`;
    section.querySelector<HTMLElement>('#cmp-speed-ctr')!.textContent = fmt(ctrMs);
    section.querySelector<HTMLElement>('#cmp-speed-hmac')!.textContent = fmt(hmacMs);

    const faster = ctrMs < hmacMs ? 'CTR_DRBG' : 'HMAC_DRBG';
    const ratio = Math.max(ctrMs, hmacMs) / Math.min(ctrMs, hmacMs);
    timingEl.innerHTML =
      `<strong>Measured just now, ${REPS} instantiate+generate rounds each of ${numBytes} bytes:</strong> ` +
      `CTR_DRBG ${fmt(ctrMs)}, HMAC_DRBG ${fmt(hmacMs)} — <strong>${faster} is ${ratio.toFixed(2)}× faster here</strong>. ` +
      `Whichever way it landed, read it narrowly: this times two WebCrypto calls through a JavaScript wrapper on ` +
      `${numBytes}-byte requests, dominated by per-call overhead rather than by throughput, and it says nothing about ` +
      `whether this machine has AES-NI. The "CTR_DRBG is faster with AES-NI" claim is about bulk native throughput, ` +
      `which no browser benchmark on this page can establish.`;
    announce(
      `Side-by-side comparison generated. Measured ${faster} ${ratio.toFixed(2)} times faster in this browser.`,
    );
  });

  copyBtn.addEventListener('click', () => {
    const text = outputEl.textContent ?? '';
    void navigator.clipboard.writeText(text).then(() => {
      copyBtn.textContent = 'Copied!';
      announce('Output copied to clipboard');
      setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500);
    });
  });
}
