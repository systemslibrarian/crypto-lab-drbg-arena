import { analyzeBlocks, expectedBins } from '../stats/signed-monobit';
import type { Calibration } from '../stats/signed-monobit';

export function buildSignedMonobit(): HTMLElement {
  const panel = document.createElement('section');
  panel.className = 'panel';
  panel.setAttribute('aria-labelledby', 'signed-monobit-title');
  panel.innerHTML = `<h3 id="signed-monobit-title">What a two-sided P value hides</h3>
    <p>Predict: complement every block with more zeros than ones. Will its two-sided monobit P value change?
    Compare P with Q, the signed survival transform. Q here is not a false-discovery-rate q value.</p>
    <div class="field-group"><label for="signed-length">Bits per block</label><select id="signed-length"><option>8</option><option selected>16</option><option>32</option><option>64</option></select></div>
    <div class="field-group"><label for="signed-count">Number of blocks</label><select id="signed-count"><option>100</option><option selected>1000</option><option>4000</option></select></div>
    <div class="field-group"><label for="signed-calibration">Tail calibration</label><select id="signed-calibration"><option value="normal">Normal approximation</option><option value="exact">Exact binomial tails (inclusive)</option></select></div>
    <button class="btn btn-primary" type="button" id="signed-run">Compare original and complemented blocks</button>
    <div id="signed-result" aria-live="polite"></div>
    <p>The null is independent fair bits within and across blocks. Samples come from the browser CSPRNG as an illustrative source; independence is a model assumption.
    Bins are [i/10, (i+1)/10), with 1 in the final bin. Expected counts enumerate every possible one count with its Binomial(n, ½) mass, using unrounded values.
    The continuous-normal uniform reference is blocks/10; short finite blocks have discrete tails and ties, so that reference can miscalibrate both P and Q.
    Zero signed statistics are left unchanged; normal Q = ½ there, while an inclusive exact tail includes the tie mass.</p>
    <p>This is a diagnostic comparison, without a calibrated second-level reject threshold or rejection-rate claim. A test may fail to reject a null; it never certifies randomness.</p>
    <p>Source: <a href="https://eprint.iacr.org/2016/863" target="_blank" rel="noopener noreferrer">More Powerful and Reliable Second-level Statistical Randomness Tests</a>, pp. 7–10, 14–17. Finite-binomial calibration is this lab's teaching adaptation.</p>`;
  let bits: Uint8Array<ArrayBuffer> | null = null;
  const length = panel.querySelector<HTMLSelectElement>('#signed-length')!;
  const count = panel.querySelector<HTMLSelectElement>('#signed-count')!;
  const calibration = panel.querySelector<HTMLSelectElement>('#signed-calibration')!;
  function render() {
    const n = Number(length.value), blocks = Number(count.value), mode = calibration.value as Calibration;
    if (!bits || bits.length !== n * blocks) {
      bits = new Uint8Array(n * blocks);
      // getRandomValues has a 65,536-byte per-call limit.
      for (let i = 0; i < bits.length; i += 65536) crypto.getRandomValues(bits.subarray(i, i + 65536));
      bits = bits.map(b => b & 1);
    }
    const original = analyzeBlocks(bits, n, mode), folded = analyzeBlocks(bits, n, mode, true);
    const first = original.rows.findIndex(r => r.signed < 0);
    const row = first >= 0 ? first : 0;
    const a = original.rows[row], b = folded.rows[row];
    const example = document.createElement('p');
    example.textContent = `Block ${row + 1}: signed ${a.signed.toFixed(4)} → ${b.signed.toFixed(4)}; |statistic| ${a.absolute.toFixed(4)} → ${b.absolute.toFixed(4)}; P ${a.p.toPrecision(6)} → ${b.p.toPrecision(6)}; Q ${a.q.toPrecision(6)} → ${b.q.toPrecision(6)}. ${blocks} blocks × ${n} bits; ${original.rows.filter(r => r.signed === 0).length} ties.`;
    const table = document.createElement('table'); table.className = 'cmp-table';
    table.innerHTML = '<caption>Observed counts and exact finite-null expectations for the selected tail calibration</caption><thead><tr><th scope="col">Bin</th><th scope="col">P original / folded</th><th scope="col">P null</th><th scope="col">Q original / folded</th><th scope="col">Q null</th></tr></thead>';
    const body = table.createTBody();
    const ep = expectedBins(n, 'p', mode), eq = expectedBins(n, 'q', mode);
    for (let i = 0; i < 10; i++) {
      const tr = body.insertRow();
      for (const text of [`${(i/10).toFixed(1)}–${((i+1)/10).toFixed(1)}${i === 9 ? ' inclusive' : ''}`, `${original.p[i]} / ${folded.p[i]}`, (ep[i] * blocks).toFixed(2), `${original.q[i]} / ${folded.q[i]}`, (eq[i] * blocks).toFixed(2)]) tr.insertCell().textContent = text;
    }
    const note = document.createElement('p');
    const sparse = ep.concat(eq).filter(m => m * blocks < 5).length;
    note.textContent = `Continuous uniform reference: ${blocks / 10} per bin. ${sparse} of 20 finite-null bin expectations are below 5, including empty bins; a naive chi-squared approximation is unsuitable here. Complementing every negative block preserves P and puts all signed statistics at or above zero.`;
    const wrap = document.createElement('div'); wrap.style.overflowX = 'auto'; wrap.append(table);
    panel.querySelector('#signed-result')!.replaceChildren(example, wrap, note);
  }
  panel.querySelector('#signed-run')!.addEventListener('click', () => { bits = null; render(); });
  for (const control of [length, count, calibration]) control.addEventListener('change', render);
  return panel;
}
