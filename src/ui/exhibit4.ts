/**
 * Exhibit 4 — Hash_DRBG (simplest approved construction)
 * Interactive with three-way comparison table.
 */

import { hashDrbgInstantiate, hashDrbgGenerate } from '../crypto/hash-drbg';
import { toHex, fromHex, getRandomEntropy } from '../crypto/utils';

export function buildExhibit4(announce: (msg: string) => void): HTMLElement {
  const section = document.createElement('section');
  section.className = 'exhibit';
  section.setAttribute('aria-labelledby', 'exhibit4-title');

  section.innerHTML = `
    <h2 class="exhibit-title" id="exhibit4-title">Exhibit 4 — Hash_DRBG</h2>
    <div class="exhibit-body">
      <div class="panel">
        <div class="panel-header"><span aria-hidden="true">🧮</span> Simplest Approved Construction</div>
        <p style="font-size:0.85rem;line-height:1.7;color:var(--text-secondary)">
          Based on <strong style="color:var(--text-primary)">SHA-256</strong> or
          <strong style="color:var(--text-primary)">SHA-512</strong>. Internal state:
          <strong style="color:var(--text-primary)">V</strong> (seed value) and
          <strong style="color:var(--text-primary)">C</strong> (constant derived from V at seed time).
          C does not change between reseeds — simpler than HMAC_DRBG. Reseed interval:
          up to 2<sup>48</sup> Generate requests before mandatory reseed.
        </p>
      </div>

      <div class="panel">
        <div class="panel-header"><span aria-hidden="true">⚙️</span> Controls</div>
        <div class="field-group">
          <label for="hash-entropy">Entropy (hex or leave blank for auto)</label>
          <input type="text" id="hash-entropy" placeholder="e.g. a1b2c3d4..." autocomplete="off" spellcheck="false" />
        </div>
        <div class="field-group">
          <label for="hash-fn">Hash function</label>
          <select id="hash-fn">
            <option value="SHA-256" selected>SHA-256</option>
            <option value="SHA-512">SHA-512</option>
          </select>
        </div>
        <div class="field-group">
          <label for="hash-bytes">Output bytes: <span id="hash-bytes-val">32</span></label>
          <div class="slider-group">
            <input type="range" id="hash-bytes" min="16" max="256" value="32" aria-label="Output bytes" />
            <span class="slider-value" id="hash-bytes-display">32</span>
          </div>
        </div>
        <div class="controls-row">
          <button class="btn btn-primary" id="hash-generate" aria-label="Generate Hash DRBG output">Generate</button>
          <button class="copy-btn" id="hash-copy" disabled aria-label="Copy output to clipboard">Copy</button>
        </div>
      </div>

      <div class="panel" id="hash-output-panel" style="display:none">
        <div class="panel-header"><span aria-hidden="true">📤</span> Output</div>
        <div class="hex-output" id="hash-output" role="log" aria-live="polite" aria-label="Hash DRBG hex output"></div>
        <div style="display:flex;flex-direction:column;gap:0.5rem;margin-top:0.5rem">
          <div class="state-row"><span class="state-label">V:</span><span class="state-value" id="hash-state-v"></span></div>
          <div class="state-row">
            <span class="state-label">C:</span>
            <span class="state-value" id="hash-state-c"></span>
            <span style="font-size:0.75rem;color:var(--text-muted);margin-left:0.5rem">(constant between reseeds)</span>
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header"><span aria-hidden="true">📊</span> Three-Way Comparison</div>
        <div style="overflow-x:auto">
          <table class="cmp-table" aria-label="Comparison of all three NIST DRBGs">
            <thead>
              <tr><th scope="col">Property</th><th scope="col">Hash_DRBG</th><th scope="col">HMAC_DRBG</th><th scope="col">CTR_DRBG</th></tr>
            </thead>
            <tbody>
              <tr><td>Primitive</td><td>SHA-256/512</td><td>HMAC-SHA-256</td><td>AES-256-CTR</td></tr>
              <tr><td>State components</td><td>V, C</td><td>V, K</td><td>V, Key</td></tr>
              <tr><td>Speed</td><td>Medium</td><td>Medium</td><td>Fast (AES-NI)</td></tr>
              <tr><td>FIPS 140-2/3</td><td>✓</td><td>✓</td><td>✓</td></tr>
              <tr><td>Use when</td><td>Simplicity needed</td><td>General use</td><td>AES-NI hardware</td></tr>
              <tr><td>Avoid when</td><td>Performance needed</td><td>FIPS CTR required</td><td>No AES-NI</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <div class="callout" role="note">
        <strong>Why this matters:</strong> Hash_DRBG is the easiest NIST DRBG to implement
        correctly from scratch, with no key schedule or HMAC overhead. It is used in
        embedded systems and constrained environments. Its simplicity makes it the best
        choice for learning DRBG internals.
      </div>
    </div>
  `;

  requestAnimationFrame(() => wireExhibit4(section, announce));
  return section;
}

function wireExhibit4(section: HTMLElement, announce: (msg: string) => void): void {
  const entropyInput = section.querySelector<HTMLInputElement>('#hash-entropy')!;
  const hashSelect = section.querySelector<HTMLSelectElement>('#hash-fn')!;
  const bytesSlider = section.querySelector<HTMLInputElement>('#hash-bytes')!;
  const bytesDisplay = section.querySelector<HTMLSpanElement>('#hash-bytes-display')!;
  const bytesVal = section.querySelector<HTMLSpanElement>('#hash-bytes-val')!;
  const generateBtn = section.querySelector<HTMLButtonElement>('#hash-generate')!;
  const copyBtn = section.querySelector<HTMLButtonElement>('#hash-copy')!;
  const outputPanel = section.querySelector<HTMLElement>('#hash-output-panel')!;
  const outputEl = section.querySelector<HTMLElement>('#hash-output')!;

  bytesSlider.addEventListener('input', () => {
    bytesDisplay.textContent = bytesSlider.value;
    bytesVal.textContent = bytesSlider.value;
  });

  generateBtn.addEventListener('click', async () => {
    const numBytes = parseInt(bytesSlider.value, 10);
    const hashFn = hashSelect.value as 'SHA-256' | 'SHA-512';
    const seedLen = hashFn === 'SHA-256' ? 55 : 111;

    let entropy: Uint8Array;
    const val = entropyInput.value.trim();
    if (val.length > 0 && /^[0-9a-fA-F]+$/.test(val)) {
      entropy = fromHex(val);
    } else {
      entropy = getRandomEntropy(seedLen);
    }

    const nonce = getRandomEntropy(16);
    const state = await hashDrbgInstantiate(entropy, nonce, undefined, hashFn);
    const result = await hashDrbgGenerate(state, numBytes);

    outputPanel.style.display = '';
    outputEl.textContent = toHex(result.output);
    section.querySelector<HTMLElement>('#hash-state-v')!.textContent = result.newV;
    section.querySelector<HTMLElement>('#hash-state-c')!.textContent = result.newC;

    copyBtn.disabled = false;
    announce(`Hash_DRBG (${hashFn}) generated ${numBytes} bytes`);
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
