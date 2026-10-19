import { entropyRouting } from '../crypto/entropy-routing';
import { hashDrbgInstantiate, hashDrbgGenerate, hashDrbgReseed } from '../crypto/hash-drbg';
import { toHex } from '../crypto/utils';

export function buildEntropyRouting(): HTMLElement {
  const section = document.createElement('section');
  section.className = 'exhibit'; section.id = 'entropy-routing';
  section.innerHTML = `<h2 class="exhibit-title">Which input earns entropy credit?</h2>
  <div class="exhibit-body"><div class="panel">
  <p>Two inputs can change a generator’s output while contributing different amounts of credited entropy.
  Choose a route, then test the accounting. This lesson models a 256-bit-strength Hash_DRBG reseed,
  using the published SP 800-90C final (25 September 2025), §3.1 interface rule.</p>
  <fieldset><legend>Source A — hypothetical assessed source, 256 bits per request</legend>
  <label><input id="routing-validated" type="checkbox" checked> Validated for this operating environment (modeled)</label>
  <label><input id="routing-healthy" type="checkbox" checked> Health checks pass (modeled)</label>
  <label><input id="routing-fresh" type="checkbox" checked> Fresh input available; not a replay (modeled)</label></fieldset>
  <fieldset><legend>Source B — unvalidated extra input, 32 bytes</legend>
  <label><input id="routing-extra" type="checkbox" checked> Include source B</label>
  <label for="routing-route">Where should B go?</label>
  <select id="routing-route"><option value="additional">Separate DRBG additional_input</option>
  <option value="external">External conditioner via Get_entropy_bitstring</option></select></fieldset>
  <div id="routing-ledger" role="status" aria-live="polite"></div>
  <button id="routing-run" class="btn btn-primary">Compare real Hash_DRBG outputs</button>
  <div id="routing-output" role="status" aria-live="polite"></div>
  <p><strong>Real arithmetic, hypothetical source claims.</strong> The run uses fixed public placeholder bytes for A,
  B, and the starting state. All outputs are reproducible and unsuitable for secrets. The 256-bit credit is an assumption
  of the source model, not a measurement of these bytes. Different output proves influence, not added entropy.
  This is not a full-entropy RBG3 implementation or an entropy-source validation.</p>
  <details><summary>What is required, and what is Hill’s analysis?</summary>
  <p>The 2025 final §3.1 separates validated-source access from other inputs. Hash_DRBG’s reseed operation mixes
  entropy_input and optional additional_input (SP 800-90A Rev. 1, §10.1.1.3). This panel deliberately requires source A
  for every modeled reseed; it does not prescribe a universal failure policy for all RBG classes.</p>
  <p>Joshua E. Hill examines the engineering consequences of the interface restriction and proposes a broader design.
  His RBGC proposal and discussion of draft interpretation guidance are not adopted as rules by this experiment.</p></details>
  <p class="routing-credit">Credit: <strong>Joshua E. Hill</strong>,
  <a href="https://www.untruth.org/~josh/sp80090b/N20b%20HillJ%20Get_entropy_bitstring%20Restrictions%2020260422.pdf" target="_blank" rel="noopener noreferrer">(Current) Limitations on SP 800-90C External Conditioners and How to Overcome (Some of) Them</a>,
  ICMC N20b, version 20260422, slides 2–8. Original Crypto Lab interaction and code; no endorsement implied.
  Standards: <a href="https://csrc.nist.gov/pubs/sp/800/90/c/final" target="_blank" rel="noopener noreferrer">SP 800-90C final</a> ·
  <a href="https://csrc.nist.gov/pubs/sp/800/90/a/r1/final" target="_blank" rel="noopener noreferrer">SP 800-90A Rev. 1</a>.</p>
  </div></div>`;
  const input = (id: string) => section.querySelector<HTMLInputElement>(id)!;
  const select = section.querySelector<HTMLSelectElement>('#routing-route')!;
  const button = section.querySelector<HTMLButtonElement>('#routing-run')!;
  const output = section.querySelector<HTMLElement>('#routing-output')!;
  let version = 0;
  const settings = () => ({validated: input('#routing-validated').checked, healthy: input('#routing-healthy').checked,
    fresh: input('#routing-fresh').checked, includeExtra: input('#routing-extra').checked,
    route: select.value as 'additional' | 'external'});
  const update = () => {
    version++;
    const result = entropyRouting(settings());
    section.querySelector('#routing-ledger')!.textContent = `Modeled credit: A = ${result.creditedBits} bits; B = ${result.extraBits} bits. ${result.reason}`;
    button.disabled = !result.allowed;
    output.replaceChildren();
  };
  section.querySelectorAll('input, select').forEach(e => e.addEventListener('change', update));
  button.addEventListener('click', async () => {
    const current = version, s = settings();
    if (!entropyRouting(s).allowed) return;
    button.disabled = true;
    output.textContent = 'Computing three reproducible reseeds…';
    try {
      const state = await hashDrbgInstantiate(new Uint8Array(48).fill(0x11));
      const a = new Uint8Array(32).fill(0xa1), b = new Uint8Array(32).fill(0xb2), changedB = new Uint8Array(b);
      changedB[0] ^= 1;
      const outputs: string[] = [];
      for (const extra of [undefined, s.includeExtra ? b : undefined, s.includeExtra ? changedB : undefined]) {
        const reseeded = await hashDrbgReseed(state, a, extra);
        outputs.push(toHex((await hashDrbgGenerate(reseeded, 32)).output));
      }
      if (version !== current) return;
      output.innerHTML = `<p>Same source A and initial state in every row. Credited budget remains 256 modeled bits.</p>
      <dl>${['A alone', 'A plus selected B', 'A plus B with one bit changed'].map((label, i) => `<dt>${label}</dt><dd><code>${outputs[i]}</code></dd>`).join('')}</dl>
      <p>${outputs[0] === outputs[1] ? 'Outputs match: B was excluded.' : 'B changed the output; it still received zero credited entropy bits.'}</p>`;
    } catch { if (version === current) output.textContent = 'The browser could not complete the Hash_DRBG calculation. No output comparison is available.'; }
    finally { if (version === current) button.disabled = !entropyRouting(settings()).allowed; }
  });
  update();
  return section;
}
