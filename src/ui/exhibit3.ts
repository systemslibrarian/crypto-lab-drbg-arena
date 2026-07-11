/**
 * Exhibit 3 — CTR_DRBG (AES-based)
 * Interactive demo with side-by-side HMAC_DRBG comparison.
 */

import { ctrDrbgInstantiate, ctrDrbgGenerate } from '../crypto/ctr-drbg';
import { hmacDrbgInstantiate, hmacDrbgGenerate } from '../crypto/hmac-drbg';
import { toHex, fromHex, getRandomEntropy } from '../crypto/utils';

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
          each Generate call. Faster than HMAC_DRBG on hardware with AES-NI instructions.
          Required in many U.S. government and DoD environments.
        </p>
      </div>

      <div class="panel">
        <div class="panel-header"><span aria-hidden="true">⚙️</span> Controls</div>
        <div class="field-group">
          <label for="ctr-entropy">Entropy (hex or leave blank for auto)</label>
          <input type="text" id="ctr-entropy" placeholder="e.g. a1b2c3... (48 hex chars for AES-256)" autocomplete="off" spellcheck="false" />
        </div>
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
        <div class="hex-output" id="ctr-output" role="log" aria-live="polite" aria-label="CTR DRBG hex output"></div>
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
            <div class="hex-output" id="ctr-cmp-output" role="log" aria-live="polite" aria-label="CTR DRBG comparison output"></div>
          </div>
          <div>
            <div style="font-family:var(--font-mono);font-size:0.75rem;color:var(--green-clean);margin-bottom:0.25rem">HMAC_DRBG</div>
            <div class="hex-output" id="ctr-cmp-hmac" role="log" aria-live="polite" aria-label="HMAC DRBG comparison output"></div>
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header"><span aria-hidden="true">📊</span> Comparison</div>
        <div style="overflow-x:auto">
          <table class="cmp-table" aria-label="HMAC DRBG vs CTR DRBG comparison">
            <thead>
              <tr><th scope="col">Property</th><th scope="col">HMAC_DRBG</th><th scope="col">CTR_DRBG</th></tr>
            </thead>
            <tbody>
              <tr><td>Primitive</td><td>HMAC-SHA-256</td><td>AES-256-CTR</td></tr>
              <tr><td>Speed</td><td>Medium</td><td>Fast (AES-NI)</td></tr>
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

  let lastEntropy: Uint8Array | null = null;

  bytesSlider.addEventListener('input', () => {
    bytesDisplay.textContent = bytesSlider.value;
    bytesVal.textContent = bytesSlider.value;
  });

  function getEntropy(): Uint8Array {
    const val = entropyInput.value.trim();
    if (val.length > 0 && /^[0-9a-fA-F]+$/.test(val)) {
      const raw = fromHex(val);
      // Pad or trim to 48 bytes (seedlen for AES-256)
      const ent = new Uint8Array(48);
      ent.set(raw.slice(0, 48));
      return ent;
    }
    return getRandomEntropy(48);
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

    // CTR_DRBG
    const ctrState = await ctrDrbgInstantiate(lastEntropy);
    const ctrResult = await ctrDrbgGenerate(ctrState, numBytes);

    // HMAC_DRBG — using same entropy (padded/trimmed as needed)
    const hmacEntropy = lastEntropy.slice(0, 32);
    const hmacState = await hmacDrbgInstantiate(hmacEntropy);
    const hmacResult = await hmacDrbgGenerate(hmacState, numBytes);

    comparisonPanel.style.display = '';
    section.querySelector<HTMLElement>('#ctr-cmp-output')!.textContent = toHex(ctrResult.output);
    section.querySelector<HTMLElement>('#ctr-cmp-hmac')!.textContent = toHex(hmacResult.output);
    announce('Side-by-side comparison generated');
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
