/**
 * Exhibit 2 — HMAC_DRBG Interactive Demo
 * Shows real HMAC_DRBG output with state visualization.
 */

import { hmacDrbgInstantiate, hmacDrbgGenerate, hmacDrbgReseed } from '../crypto/hmac-drbg';
import type { HmacDrbgState } from '../crypto/hmac-drbg';
import { toHex, fromHex, textToBytes, getRandomEntropy } from '../crypto/utils';
import { glossary } from './glossary';

/** Truncate a hex string to a readable prefix for the state boxes. */
function short(hex: string): string {
  return hex.length > 24 ? hex.slice(0, 24) + '…' : hex;
}

/**
 * Render two hex strings stacked with per-nibble diff highlighting. Identical
 * characters read calm-green; differing characters get an amber box + underline
 * so the comparison survives colour-blindness and greyscale.
 */
function diffHex(a: string, b: string): string {
  const len = Math.max(a.length, b.length);
  let out = '';
  for (let i = 0; i < len; i++) {
    const ca = a[i] ?? '';
    const cb = b[i] ?? '';
    const same = ca === cb;
    out += `<span class="${same ? 'diff-same' : 'diff-diff'}">${cb || ca}</span>`;
  }
  return out;
}

function countDiff(a: string, b: string): number {
  const len = Math.max(a.length, b.length);
  let n = 0;
  for (let i = 0; i < len; i++) if ((a[i] ?? '') !== (b[i] ?? '')) n++;
  return n;
}

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
        ${glossary('entropy', 'seed', 'nonce')}
        <div class="field-group">
          <label for="hmac-personal">Personalization string (optional)</label>
          <input type="text" id="hmac-personal" placeholder="e.g. my-app-v1" autocomplete="off" spellcheck="false" />
        </div>
        ${glossary('personalization')}
        <div class="field-group">
          <label for="hmac-bytes">Output bytes: <span id="hmac-bytes-val">32</span></label>
          <div class="slider-group">
            <input type="range" id="hmac-bytes" min="16" max="256" value="32" aria-label="Output bytes" />
            <span class="slider-value" id="hmac-bytes-display">32</span>
          </div>
        </div>
        <div class="controls-row">
          <button class="btn btn-primary" id="hmac-generate" aria-label="Generate HMAC DRBG output">Generate</button>
          <button class="btn" id="hmac-same-seed" disabled aria-label="Generate again with the same seed to demonstrate determinism">Same Seed Again</button>
          <button class="btn" id="hmac-avalanche" disabled aria-label="Flip one hex digit of the seed and regenerate to show the avalanche effect">Flip 1 Seed Digit</button>
          <button class="btn" id="hmac-reseed" disabled aria-label="Reseed HMAC DRBG with new entropy">Reseed</button>
          <button class="copy-btn" id="hmac-copy" disabled aria-label="Copy output to clipboard">Copy</button>
        </div>
      </div>

      <div class="panel" id="hmac-output-panel" style="display:none">
        <div class="panel-header"><span aria-hidden="true">📤</span> Output</div>
        <div class="hex-output" id="hmac-output" role="log" aria-live="polite" aria-label="HMAC DRBG hex output"></div>
      </div>

      <div class="panel" id="hmac-state-panel" style="display:none">
        <div class="panel-header"><span aria-hidden="true">🔍</span> State Update — the One-Way Step</div>
        <p style="font-size:0.8rem;line-height:1.6;color:var(--text-secondary);margin-bottom:0.5rem">
          A Generate call is not a lookup — it runs the <em>old</em> state through
          HMAC (a one-way function) to fork out both the output bytes and a
          <em>brand-new</em> state. Watch the old value get destroyed:
        </p>
        <div class="update-flow" id="hmac-update-flow" role="img"
             aria-label="State update: old V feeds HMAC keyed by K, producing the output stream and a new K and V; the old state is discarded.">
          <div class="uf-box uf-old" style="grid-column:1;grid-row:1">
            <span class="uf-title">old V (input)</span>
            <span class="uf-hex" id="uf-old-v"></span>
          </div>
          <div class="uf-func" style="grid-row:1">
            HMAC(K, V)
            <small>keyed one-way function</small>
          </div>
          <div class="uf-box uf-out" style="grid-column:3;grid-row:1">
            <span class="uf-title">→ output stream</span>
            <span class="uf-hex" id="uf-out"></span>
          </div>
          <div class="uf-arrow" style="grid-column:2;grid-row:2" aria-hidden="true">┌── also updates ──┐</div>
          <div class="uf-box uf-new" style="grid-column:1;grid-row:3">
            <span class="uf-title">new K</span>
            <span class="uf-hex" id="uf-new-k"></span>
          </div>
          <div class="uf-box uf-new" style="grid-column:3;grid-row:3">
            <span class="uf-title">new V</span>
            <span class="uf-hex" id="uf-new-v"></span>
          </div>
        </div>
        <p class="uf-caption">
          <strong>The old state is destroyed by a one-way function; this is why the past can't be recovered.</strong>
          Even with the new (K, V) in hand, inverting HMAC to recover the old V is
          infeasible — so an attacker who steals the state now cannot reconstruct
          earlier output. That is exactly the <strong>backtracking resistance</strong>
          claimed in Exhibit 1, made mechanical.
        </p>
        <details class="gloss">
          <summary><span class="gloss-term">show full 64-hex-char K and V</span></summary>
          <div class="gloss-body" style="font-family:var(--font-mono)">
            <div class="state-row"><span class="state-label">old K:</span><span class="state-value" id="hmac-prev-k"></span></div>
            <div class="state-row"><span class="state-label">old V:</span><span class="state-value" id="hmac-prev-v"></span></div>
            <div class="state-row"><span class="state-label">new K:</span><span class="state-value state-changed" id="hmac-new-k"></span></div>
            <div class="state-row"><span class="state-label">new V:</span><span class="state-value state-changed" id="hmac-new-v"></span></div>
          </div>
        </details>
      </div>

      <div class="panel" id="hmac-determinism-panel" style="display:none">
        <div class="panel-header"><span aria-hidden="true">🎯</span> Determinism &amp; Seed Sensitivity</div>
        <p style="font-size:0.8rem;line-height:1.6;color:var(--text-secondary);margin:0">
          <strong style="color:var(--text-primary)">Same Seed Again</strong> re-instantiates from the stored seed;
          <strong style="color:var(--text-primary)">Flip 1 Seed Digit</strong> changes a single hex digit of that seed.
          The two streams below are diff-highlighted against the first Generate:
          <span class="diff-same">green = identical byte</span>,
          <span class="diff-diff">amber = differs</span>.
        </p>
        <div class="diff-stack" style="margin-top:0.5rem">
          <div class="diff-row">
            <span class="diff-tag">First Generate (reference)</span>
            <div class="diff-hex" id="diff-ref" tabindex="0" role="region" aria-label="Reference output stream"></div>
          </div>
          <div class="diff-row">
            <span class="diff-tag" id="diff-cmp-tag">Compared stream</span>
            <div class="diff-hex" id="diff-cmp" tabindex="0" role="region" aria-label="Compared output stream, diff-highlighted against the reference"></div>
          </div>
          <div class="diff-verdict" id="diff-verdict" role="status"></div>
        </div>
        <p style="font-size:0.78rem;line-height:1.6;color:var(--text-muted);margin:0.25rem 0 0">
          Same seed → same stream, every time: that's the <strong style="color:var(--text-primary)">Deterministic</strong> in DRBG.
          Flip one digit and the <em>entire</em> stream changes — the avalanche effect — so
          the output reveals nothing about nearby seeds.
        </p>
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
  const avalancheBtn = section.querySelector<HTMLButtonElement>('#hmac-avalanche')!;
  const reseedBtn = section.querySelector<HTMLButtonElement>('#hmac-reseed')!;
  const copyBtn = section.querySelector<HTMLButtonElement>('#hmac-copy')!;
  const outputPanel = section.querySelector<HTMLElement>('#hmac-output-panel')!;
  const outputEl = section.querySelector<HTMLElement>('#hmac-output')!;
  const statePanel = section.querySelector<HTMLElement>('#hmac-state-panel')!;
  const detPanel = section.querySelector<HTMLElement>('#hmac-determinism-panel')!;
  const updateFlow = section.querySelector<HTMLElement>('#hmac-update-flow')!;
  const diffRef = section.querySelector<HTMLElement>('#diff-ref')!;
  const diffCmp = section.querySelector<HTMLElement>('#diff-cmp')!;
  const diffCmpTag = section.querySelector<HTMLElement>('#diff-cmp-tag')!;
  const diffVerdict = section.querySelector<HTMLElement>('#diff-verdict')!;

  let currentState: HmacDrbgState | null = null;
  let lastEntropy: Uint8Array | null = null;
  let lastNonce: Uint8Array | null = null;
  let lastPersonal: Uint8Array | null = null;
  // The output of the most recent fresh Generate — the fixed reference the
  // Same-Seed and Avalanche streams are diffed against.
  let referenceOutput = '';

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

  /** Fresh instantiation from the current seed, then one Generate. */
  async function instantiateAndGenerate(): Promise<
    Awaited<ReturnType<typeof hmacDrbgGenerate>>
  > {
    const numBytes = parseInt(bytesSlider.value, 10);
    const state = await hmacDrbgInstantiate(
      lastEntropy!, lastNonce ?? undefined, lastPersonal ?? undefined
    );
    const result = await hmacDrbgGenerate(state, numBytes);
    return result;
  }

  // ── Fresh Generate: new seed, becomes the diff reference ──────
  async function doFreshGenerate(): Promise<void> {
    lastEntropy = getEntropy();
    lastNonce = getRandomEntropy(16);
    lastPersonal = personalInput.value.trim().length > 0
      ? textToBytes(personalInput.value.trim())
      : null;

    const result = await instantiateAndGenerate();
    currentState = result.state;
    referenceOutput = toHex(result.output);

    renderResult(result, `HMAC_DRBG generated ${result.output.length} bytes`);
    // Reset the determinism panel to just the reference until a comparison runs.
    detPanel.style.display = '';
    diffRef.innerHTML = referenceOutput
      .split('')
      .map((c) => `<span class="diff-same">${c}</span>`)
      .join('');
    diffCmp.innerHTML = '<span style="color:var(--text-muted)">Click “Same Seed Again” or “Flip 1 Seed Digit”…</span>';
    diffCmpTag.textContent = 'Compared stream';
    diffVerdict.className = 'diff-verdict';
    diffVerdict.textContent = '';
  }

  // ── Same seed again: identical stream, diffed to prove it ─────
  async function doSameSeed(): Promise<void> {
    if (!lastEntropy) return;
    const result = await instantiateAndGenerate();
    currentState = result.state;
    const out = toHex(result.output);
    renderResult(result, 'HMAC_DRBG re-run with the same seed — output is identical');

    diffCmpTag.textContent = 'Same seed, re-run';
    diffCmp.innerHTML = diffHex(referenceOutput, out);
    const diffs = countDiff(referenceOutput, out);
    diffVerdict.className = `diff-verdict ${diffs === 0 ? 'is-same' : 'is-diff'}`;
    diffVerdict.textContent = diffs === 0
      ? '✓ 0 hex digits differ — same seed → same stream, every time (this is the Deterministic in DRBG).'
      : `✗ ${diffs} hex digits differ (unexpected).`;
  }

  // ── Avalanche: flip ONE hex digit of the seed, whole stream changes ──
  async function doAvalanche(): Promise<void> {
    if (!lastEntropy) return;
    // Flip a single nibble of the entropy seed by XOR-ing one random byte's
    // low nibble with 1 — the smallest possible one-hex-digit change.
    const flipped = new Uint8Array(lastEntropy);
    const idx = Math.floor(Math.random() * flipped.length);
    flipped[idx] = flipped[idx]! ^ 0x01;
    lastEntropy = flipped;

    const result = await instantiateAndGenerate();
    currentState = result.state;
    const out = toHex(result.output);
    renderResult(result, 'Flipped one hex digit of the seed — the entire stream changed (avalanche)');

    // The flipped seed is the new reference going forward, but we diff the new
    // stream against the ORIGINAL reference so the avalanche is visible.
    diffCmpTag.textContent = 'One seed digit flipped';
    diffCmp.innerHTML = diffHex(referenceOutput, out);
    const diffs = countDiff(referenceOutput, out);
    const pct = Math.round((diffs / Math.max(referenceOutput.length, out.length)) * 100);
    diffVerdict.className = 'diff-verdict is-diff';
    diffVerdict.textContent =
      `~${pct}% of hex digits differ from one 1-bit seed change — the avalanche effect. Output leaks nothing about nearby seeds.`;
    // Reflect the flipped seed in the input so the learner sees what changed.
    entropyInput.value = toHex(lastEntropy);
  }

  function renderResult(
    result: Awaited<ReturnType<typeof hmacDrbgGenerate>>,
    message: string,
  ): void {
    outputPanel.style.display = '';
    statePanel.style.display = '';
    outputEl.textContent = toHex(result.output);

    // Mechanism boxes: old V in, output + new K/V out.
    section.querySelector<HTMLElement>('#uf-old-v')!.textContent = short(result.prevV);
    section.querySelector<HTMLElement>('#uf-out')!.textContent = short(toHex(result.output));
    section.querySelector<HTMLElement>('#uf-new-k')!.textContent = short(result.newK);
    section.querySelector<HTMLElement>('#uf-new-v')!.textContent = short(result.newV);
    // Re-trigger the one-shot animation.
    updateFlow.classList.remove('uf-animate');
    void updateFlow.offsetWidth; // force reflow
    updateFlow.classList.add('uf-animate');

    // Full-precision values in the expandable detail.
    section.querySelector<HTMLElement>('#hmac-prev-k')!.textContent = result.prevK;
    section.querySelector<HTMLElement>('#hmac-prev-v')!.textContent = result.prevV;
    section.querySelector<HTMLElement>('#hmac-new-k')!.textContent = result.newK;
    section.querySelector<HTMLElement>('#hmac-new-v')!.textContent = result.newV;

    sameSeedBtn.disabled = false;
    avalancheBtn.disabled = false;
    reseedBtn.disabled = false;
    copyBtn.disabled = false;
    announce(message);
  }

  generateBtn.addEventListener('click', () => { void doFreshGenerate(); });
  sameSeedBtn.addEventListener('click', () => { void doSameSeed(); });
  avalancheBtn.addEventListener('click', () => { void doAvalanche(); });

  reseedBtn.addEventListener('click', async () => {
    if (!currentState) return;
    // Reseed mixes fresh entropy into the *existing* state (this is what
    // provides prediction resistance), then generate from the reseeded state —
    // we do NOT re-instantiate, so the demo shows a genuine reseed.
    const numBytes = parseInt(bytesSlider.value, 10);
    currentState = await hmacDrbgReseed(currentState);
    const result = await hmacDrbgGenerate(currentState, numBytes);
    currentState = result.state;
    renderResult(result, `HMAC_DRBG reseeded with fresh entropy, then generated ${numBytes} bytes`);
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
