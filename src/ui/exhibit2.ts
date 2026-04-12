/**
 * Exhibit 2 — HMAC_DRBG Interactive Demo
 * Shows real HMAC_DRBG output with state visualization.
 */

import { hmacDrbgInstantiate, hmacDrbgGenerate, hmacDrbgReseed } from '../crypto/hmac-drbg';
import type { HmacDrbgState } from '../crypto/hmac-drbg';
import { toHex, fromHex, textToBytes, getRandomEntropy } from '../crypto/utils';

export function buildExhibit2(announce: (msg: string) => void): HTMLElement {
  const section = document.createElement('section');
  section.className = 'exhibit';
  section.setAttribute('aria-labelledby', 'exhibit2-title');

  section.innerHTML = `
    <h2 class="exhibit-title" id="exhibit2-title">Exhibit 2 — HMAC_DRBG</h2>
    <div class="exhibit-body">
      <div class="panel">
        <div class="panel-header"><span aria-hidden="true">🔐</span> The Recommended General-Purpose DRBG</div>
        <p style="font-size:0.85rem;line-height:1.7;color:var(--text-secondary)">
          Uses HMAC-SHA-256 to update both <strong style="color:var(--text-primary)">V</strong> (value) and
          <strong style="color:var(--text-primary)">K</strong> (key) on every Generate call.
          Both change after each call — this provides forward secrecy.
        </p>
      </div>

      <div class="panel">
        <div class="panel-header"><span aria-hidden="true">⚙️</span> Controls</div>
        <div class="field-group">
          <label for="hmac-entropy">Entropy (hex or leave blank for auto)</label>
          <input type="text" id="hmac-entropy" placeholder="e.g. a1b2c3d4... or leave empty" autocomplete="off" spellcheck="false" />
        </div>
        <div class="field-group">
          <label for="hmac-personal">Personalization string (optional)</label>
          <input type="text" id="hmac-personal" placeholder="e.g. my-app-v1" autocomplete="off" spellcheck="false" />
        </div>
        <div class="field-group">
          <label for="hmac-bytes">Output bytes: <span id="hmac-bytes-val">32</span></label>
          <div class="slider-group">
            <input type="range" id="hmac-bytes" min="16" max="256" value="32" aria-label="Output bytes" />
            <span class="slider-value" id="hmac-bytes-display">32</span>
          </div>
        </div>
        <div class="controls-row">
          <button class="btn btn-primary" id="hmac-generate" aria-label="Generate HMAC DRBG output">Generate</button>
          <button class="btn" id="hmac-same-seed" disabled aria-label="Generate again with same seed to demonstrate determinism">Same Seed Again</button>
          <button class="btn" id="hmac-reseed" disabled aria-label="Reseed HMAC DRBG with new entropy">Reseed</button>
          <button class="copy-btn" id="hmac-copy" disabled aria-label="Copy output to clipboard">Copy</button>
        </div>
      </div>

      <div class="panel" id="hmac-output-panel" style="display:none">
        <div class="panel-header"><span aria-hidden="true">📤</span> Output</div>
        <div class="hex-output" id="hmac-output" role="log" aria-live="polite" aria-label="HMAC DRBG hex output"></div>
      </div>

      <div class="panel" id="hmac-state-panel" style="display:none">
        <div class="panel-header"><span aria-hidden="true">🔍</span> State Visualizer</div>
        <p style="font-size:0.75rem;color:var(--text-muted);margin-bottom:0.5rem">
          Both K and V change on every Generate call — forward secrecy in action.
        </p>
        <div style="display:flex;flex-direction:column;gap:0.5rem">
          <div>
            <div style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-muted);margin-bottom:0.25rem">BEFORE</div>
            <div class="state-row"><span class="state-label">K:</span><span class="state-value" id="hmac-prev-k"></span></div>
            <div class="state-row"><span class="state-label">V:</span><span class="state-value" id="hmac-prev-v"></span></div>
          </div>
          <div style="text-align:center;color:var(--green-clean);font-family:var(--font-mono);font-size:0.8rem" aria-hidden="true">↓ Generate ↓</div>
          <div>
            <div style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-muted);margin-bottom:0.25rem">AFTER</div>
            <div class="state-row"><span class="state-label">K:</span><span class="state-value state-changed" id="hmac-new-k"></span></div>
            <div class="state-row"><span class="state-label">V:</span><span class="state-value state-changed" id="hmac-new-v"></span></div>
          </div>
        </div>
      </div>

      <div class="callout" role="note">
        <strong>Why this matters:</strong> HMAC_DRBG is used in OpenSSL, BoringSSL, and most
        TLS implementations worldwide. It is the direct, approved replacement for the
        backdoored Dual_EC_DRBG shown in
        <a href="https://systemslibrarian.github.io/crypto-lab-corrupted-oracle/"
           target="_blank" rel="noopener noreferrer"
           style="color:var(--blue-info);text-decoration:underline">Corrupted Oracle<span class="sr-only"> (opens in new tab)</span></a>.
        If your system generates keys or nonces, it is almost certainly using HMAC_DRBG
        or CTR_DRBG under the hood.
      </div>
    </div>
  `;

  // Wire up interactivity after DOM insertion
  requestAnimationFrame(() => wireExhibit2(section, announce));
  return section;
}

function wireExhibit2(section: HTMLElement, announce: (msg: string) => void): void {
  const entropyInput = section.querySelector<HTMLInputElement>('#hmac-entropy')!;
  const personalInput = section.querySelector<HTMLInputElement>('#hmac-personal')!;
  const bytesSlider = section.querySelector<HTMLInputElement>('#hmac-bytes')!;
  const bytesDisplay = section.querySelector<HTMLSpanElement>('#hmac-bytes-display')!;
  const bytesVal = section.querySelector<HTMLSpanElement>('#hmac-bytes-val')!;
  const generateBtn = section.querySelector<HTMLButtonElement>('#hmac-generate')!;
  const sameSeedBtn = section.querySelector<HTMLButtonElement>('#hmac-same-seed')!;
  const reseedBtn = section.querySelector<HTMLButtonElement>('#hmac-reseed')!;
  const copyBtn = section.querySelector<HTMLButtonElement>('#hmac-copy')!;
  const outputPanel = section.querySelector<HTMLElement>('#hmac-output-panel')!;
  const outputEl = section.querySelector<HTMLElement>('#hmac-output')!;
  const statePanel = section.querySelector<HTMLElement>('#hmac-state-panel')!;

  let currentState: HmacDrbgState | null = null;
  let lastEntropy: Uint8Array | null = null;
  let lastNonce: Uint8Array | null = null;
  let lastPersonal: Uint8Array | null = null;

  bytesSlider.addEventListener('input', () => {
    bytesDisplay.textContent = bytesSlider.value;
    bytesVal.textContent = bytesSlider.value;
  });

  function getEntropy(): Uint8Array {
    const val = entropyInput.value.trim();
    if (val.length > 0 && /^[0-9a-fA-F]+$/.test(val)) {
      return fromHex(val);
    }
    return getRandomEntropy(32);
  }

  async function doGenerate(reuseState: boolean): Promise<void> {
    const numBytes = parseInt(bytesSlider.value, 10);

    if (!reuseState || !currentState) {
      lastEntropy = getEntropy();
      lastNonce = getRandomEntropy(16);
      lastPersonal = personalInput.value.trim().length > 0
        ? textToBytes(personalInput.value.trim())
        : null;
      currentState = await hmacDrbgInstantiate(
        lastEntropy, lastNonce, lastPersonal ?? undefined
      );
    }

    if (reuseState && lastEntropy) {
      // Re-instantiate from same seed to show determinism
      currentState = await hmacDrbgInstantiate(
        lastEntropy, lastNonce ?? undefined, lastPersonal ?? undefined
      );
    }

    const result = await hmacDrbgGenerate(currentState, numBytes);
    currentState = result.state;

    outputPanel.style.display = '';
    statePanel.style.display = '';
    outputEl.textContent = toHex(result.output);

    section.querySelector<HTMLElement>('#hmac-prev-k')!.textContent = result.prevK;
    section.querySelector<HTMLElement>('#hmac-prev-v')!.textContent = result.prevV;
    section.querySelector<HTMLElement>('#hmac-new-k')!.textContent = result.newK;
    section.querySelector<HTMLElement>('#hmac-new-v')!.textContent = result.newV;

    sameSeedBtn.disabled = false;
    reseedBtn.disabled = false;
    copyBtn.disabled = false;
    announce(`HMAC_DRBG generated ${numBytes} bytes`);
  }

  generateBtn.addEventListener('click', () => { void doGenerate(false); });
  sameSeedBtn.addEventListener('click', () => { void doGenerate(true); });

  reseedBtn.addEventListener('click', async () => {
    if (!currentState) return;
    currentState = await hmacDrbgReseed(currentState);
    announce('HMAC_DRBG reseeded with new entropy');
    // Now generate to show change
    void doGenerate(false);
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
