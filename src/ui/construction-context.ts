/** A source-request teaching model; not a validated RBG implementation. */
export type RbgClass = 'RBG1' | 'RBG2' | 'RBG3' | 'RBGC';
export const CLASS_NOTES: Record<RbgClass, string> = {
 RBG1: 'Externally instantiated once; no internal source or reseeding after instantiation. It cannot provide prediction resistance or compromise recovery.',
 RBG2: 'DRBG and validated entropy source(s) share a boundary; supported reseeding can supply prediction resistance. Its ordinary output is pseudorandom, not full-entropy RBG3 output.',
 RBG3: 'Physical-entropy-based constructions supply full-entropy output under their complete requirements; plain DRBG expansion is not this construction.',
 RBGC: 'A tree of DRBGs transfers seed material on one physical platform. Parent/ancestor source trust and permitted reseeding paths matter; children cannot seed their ancestors.',
};
export function modeledSourceRequest(kind: RbgClass, freshAvailable: boolean, healthy: boolean, predictionResistanceRequested = true): string {
 if (!predictionResistanceRequested) return 'No prediction-resistance request modeled. Ordinary generation policy depends on the construction; RBG3 full-entropy generation still requires its fresh-input path.';
 if (kind === 'RBG1') return 'Unsupported after instantiation: RBG1 has no reseed source. No prediction-resistance or healing claim.';
 if (!(kind in CLASS_NOTES)) throw new Error('Unknown construction class.');
 if (!healthy) return 'Blocked source request: simulated health failure. No new input is supplied by this model.';
 if (!freshAvailable) return 'Source unavailable: no independent fresh entropy in this model. A stolen DRBG state remains predictive.';
 return 'Simulated source request succeeds. This panel generates no bytes and proves neither full entropy nor recovery; run the existing stolen-state/reseed experiment below for its actual verifier outcomes.';
}
export function buildConstructionContext(): HTMLElement {
 const section = document.createElement('section'); section.className = 'exhibit'; section.id = 'construction-context';
 section.innerHTML = `<h2 class="exhibit-title">From a DRBG mechanism to an RBG system</h2>
 <div class="exhibit-body"><div class="panel">
 <p><a style="color:inherit;text-decoration:underline" href="https://csrc.nist.gov/pubs/sp/800/90/c/final" target="_blank" rel="noopener noreferrer">SP 800-90C final (25 September 2025)</a> connects 90A DRBG mechanisms with 90B entropy-source requirements. This browser lab is not NIST-validated.</p>
 <label for="construction-class">Construction class</label><select id="construction-class"><option>RBG1</option><option selected>RBG2</option><option>RBG3</option><option>RBGC</option></select>
 <p id="construction-description"></p>
 <fieldset><legend>Model a request for new source input</legend>
 <label><input type="checkbox" id="construction-pr" checked> Prediction resistance requested (modeled)</label>
 <label><input type="checkbox" id="construction-fresh" checked> Independent fresh entropy is available (modeled)</label>
 <label><input type="checkbox" id="construction-healthy" checked> Source health status is passing (modeled)</label></fieldset>
 <p id="construction-result" role="status" aria-live="polite"></p>
 <p>This only models the source request; it does not prescribe one failure/continued-generation policy for all classes. Prediction-resistance requests need the supported fresh-input path, not repeated seed bytes or a statistical pass.</p>
 <p><a style="color:inherit;text-decoration:underline" href="https://systemslibrarian.github.io/crypto-lab-quantum-entropy/">Quantum Entropy</a> shows the source → health → conditioning architecture; <a style="color:inherit;text-decoration:underline" href="https://systemslibrarian.github.io/crypto-lab-noise-to-numbers/">Noise to Numbers</a> studies source assessment; <a style="color:inherit;text-decoration:underline" href="https://systemslibrarian.github.io/crypto-lab-entropy-collapse/">Entropy Collapse</a> demonstrates cloned states and reseeding. See <a style="color:inherit;text-decoration:underline" href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90C.pdf" target="_blank" rel="noopener noreferrer">90C §§4–7</a> for the complete class requirements. Reviewed 12 October 2026.</p>
 </div></div>`;
 const select = section.querySelector<HTMLSelectElement>('#construction-class')!;
 const requested = section.querySelector<HTMLInputElement>('#construction-pr')!;
 const fresh = section.querySelector<HTMLInputElement>('#construction-fresh')!;
 const healthy = section.querySelector<HTMLInputElement>('#construction-healthy')!;
 const update = () => {
  const kind = select.value as RbgClass;
  section.querySelector('#construction-description')!.textContent = CLASS_NOTES[kind];
  section.querySelector('#construction-result')!.textContent = modeledSourceRequest(kind, fresh.checked, healthy.checked, requested.checked);
 };
 for (const input of [select, fresh, healthy, requested]) input.addEventListener('change', update);
 update(); return section;
}
