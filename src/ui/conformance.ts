/**
 * Live Conformance Check panel.
 *
 * Runs the NIST CAVP known-answer self-check in the browser on load and shows,
 * per algorithm, that the output exactly equals NIST's published reference
 * bytes. This is the demo proving its own correctness — not asking to be
 * trusted.
 */

import { runSelfCheck, NIST_VECTORS, type KatResult } from '../crypto/self-check';

function shorten(hex: string): string {
  return hex.length > 32 ? `${hex.slice(0, 16)}…${hex.slice(-16)}` : hex;
}

export function buildConformancePanel(announce: (msg: string) => void): HTMLElement {
  const section = document.createElement('section');
  section.className = 'exhibit';
  section.setAttribute('aria-labelledby', 'conformance-title');

  section.innerHTML = `
    <h2 class="exhibit-title" id="conformance-title">Live Conformance Check</h2>
    <div class="exhibit-body">
      <div class="panel">
        <div class="panel-header"><span aria-hidden="true">🔬</span> Verified Against NIST CAVP Vectors</div>
        <p style="font-size:0.85rem;line-height:1.7;color:var(--text-secondary)">
          Every byte these DRBGs produce is computed in your browser and checked,
          right now, against the official known-answer vectors from NIST's
          <a href="https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/random-number-generators"
             target="_blank" rel="noopener noreferrer"
             style="color:var(--blue-info);text-decoration:underline">DRBG Validation System<span class="sr-only"> (opens in new tab)</span></a>.
          Same vectors run in CI on every commit (<code style="font-family:var(--font-mono)">npm&nbsp;test</code>) — the build does not deploy unless they pass.
        </p>
        <div id="conformance-status" role="status" aria-live="polite"
             style="font-family:var(--font-mono);font-size:0.85rem;color:var(--text-secondary)">
          Verifying ${NIST_VECTORS.length} algorithms against NIST reference vectors…
        </div>
        <div id="conformance-rows" style="display:flex;flex-direction:column;gap:0.75rem"></div>
      </div>
    </div>
  `;

  const rowsEl = section.querySelector<HTMLElement>('#conformance-rows')!;
  const statusEl = section.querySelector<HTMLElement>('#conformance-status')!;

  void runSelfCheck()
    .then((results: KatResult[]) => {
      const allPass = results.every((r) => r.pass);
      statusEl.textContent = allPass
        ? `✓ All ${results.length} algorithms match their NIST reference vectors exactly.`
        : `✗ A conformance check FAILED — output does not match the NIST vector.`;
      statusEl.className = allPass ? 'stat-pass' : 'stat-fail';
      statusEl.style.fontFamily = 'var(--font-mono)';
      statusEl.style.fontSize = '0.85rem';

      for (const r of results) {
        const row = document.createElement('div');
        row.style.cssText =
          'border:1px solid var(--border-color);border-radius:4px;padding:0.6rem 0.75rem;background-color:var(--bg-secondary)';
        row.innerHTML = `
          <div style="display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap">
            <span class="${r.pass ? 'stat-pass' : 'stat-fail'}" style="font-family:var(--font-mono)">
              ${r.pass ? 'PASS ✓' : 'FAIL ✗'}
            </span>
            <strong style="font-family:var(--font-mono);font-size:0.8rem;color:var(--green-clean)">${r.algorithm}</strong>
            <span style="font-size:0.75rem;color:var(--text-muted)">${r.detail}</span>
          </div>
          <div class="state-row" style="margin-top:0.4rem">
            <span class="state-label">NIST:</span>
            <span class="state-value">${shorten(r.expected)}</span>
          </div>
          <div class="state-row">
            <span class="state-label">Ours:</span>
            <span class="state-value" style="color:${r.pass ? 'var(--green-clean)' : 'var(--red-corrupt)'}">${shorten(r.actual)}</span>
          </div>
        `;
        rowsEl.appendChild(row);
      }
      announce(
        allPass
          ? 'Conformance check complete: all DRBGs match NIST reference vectors.'
          : 'Conformance check failed: a DRBG did not match its NIST vector.',
      );
    })
    .catch((err) => {
      statusEl.textContent = `Conformance check could not run: ${String(err)}`;
      statusEl.className = 'stat-fail';
    });

  return section;
}
