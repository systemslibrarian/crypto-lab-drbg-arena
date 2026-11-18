/** Exhibit 6 — Steal the state. */

import { runCompromise, summarize, type AttackResult, type CompromiseInputs, type CompromiseRun } from '../crypto/compromise';
import { fromHex, getRandomEntropy } from '../crypto/utils';

const ROUND_BYTES = 32;
const ADDITIONAL_INPUT = 'DRBG Arena Exhibit 6';

export function buildExhibit6(announce: (msg: string) => void): HTMLElement {
  const section = document.createElement('section');
  section.className = 'exhibit';
  section.setAttribute('aria-labelledby', 'exhibit6-title');

  section.innerHTML = `
    <h2 class="exhibit-title" id="exhibit6-title">Exhibit 6 — Steal the state</h2>
    <div class="exhibit-body">
      <div class="panel">
        <div class="panel-header"><span aria-hidden="true">🕵️</span> The claim being tested</div>
        <p style="font-size:0.85rem;line-height:1.7;color:var(--text-secondary)">
          Exhibit 2 says an attacker who steals the internal state cannot reconstruct earlier
          output. Recovery and guess confirmation are tested here using the
          <strong style="color:var(--text-primary)">same entropy</strong>: the approved
          <strong style="color:var(--text-primary)">HMAC_DRBG</strong> (SP 800-90A §10.1.2), and
          <strong style="color:var(--red-corrupt)">CTR-no-update</strong> — the approved CTR_DRBG
          with one line deleted, the <code>CTR_DRBG_Update</code> call after Generate. Nothing
          else differs.
        </p>
        <p style="font-size:0.85rem;line-height:1.7;color:var(--text-secondary)">
          Both emit three ${ROUND_BYTES}-byte rounds. The state is stolen
          <strong style="color:var(--text-primary)">immediately after round 2</strong>, exfiltrated
          as hex and rebuilt on the attacker's side. The confirmation check uses a candidate
          final block from round 2 and compares <code>HMAC(K_stolen, candidate)</code> with
          <code>V_stolen</code>. A full match confirms the guess. The check itself produces
          only a match verdict.
        </p>
        <p style="font-size:0.8rem;line-height:1.7;color:var(--text-secondary)">
          Woodage and Shumow, <a style="color:inherit;text-decoration:underline" href="https://eprint.iacr.org/2018/349">An Analysis of the NIST SP 800-90A Standard</a>, ePrint 2018/349, §7.1 (EUROCRYPT 2019, §6.1).
        </p>
      </div>

      <div class="panel">
        <div class="panel-header"><span aria-hidden="true">⚙️</span> Controls</div>
        <div class="field-group">
          <label for="compromise-entropy">Seed entropy (hex, or leave blank for fresh OS entropy)</label>
          <input type="text" id="compromise-entropy" placeholder="e.g. 00112233..." autocomplete="off" spellcheck="false" />
        </div>
        <div class="field-group">
          <label><input type="checkbox" id="compromise-additional-input" /> Use additional input for HMAC_DRBG</label>
          <span style="color:var(--text-secondary)">Public input when enabled (UTF-8) <code>${ADDITIONAL_INPUT}</code></span>
        </div>
        <div class="controls-row">
          <button class="btn btn-primary" id="compromise-run" aria-label="Steal the state & attack: seed both generators and run all five checks">Steal the state &amp; attack</button>
        </div>
      </div>

      <div class="panel" id="compromise-timeline-panel" style="display:none">
        <div class="panel-header"><span aria-hidden="true">🧾</span> What actually happened</div>
        <div style="display:flex;flex-direction:column;gap:0.5rem">
          <div class="state-row"><span class="state-label">seed:</span><span class="state-value" id="compromise-seed"></span></div>
          <div class="state-row"><span class="state-label">stolen HMAC_DRBG state:</span><span class="state-value" id="compromise-stolen-hmac"></span></div>
          <div class="state-row"><span class="state-label">stolen CTR-no-update state:</span><span class="state-value" id="compromise-stolen-noupdate"></span></div>
        </div>
      </div>

      <div class="panel" id="compromise-results-panel" style="display:none">
        <div class="panel-header"><span aria-hidden="true">📊</span> Recovery, confirmation, and prediction</div>
        <div style="overflow-x:auto">
          <table tabindex="0" class="cmp-table" id="compromise-results" aria-label="Byte matches and verdicts for each state compromise check">
            <thead>
              <tr>
                <th scope="col">Attack from the stolen state</th>
                <th scope="col">HMAC_DRBG (approved)</th>
                <th scope="col">CTR-no-update (defective)</th>
              </tr>
            </thead>
            <tbody id="compromise-rows"></tbody>
          </table>
        </div>
        <p style="font-size:0.78rem;line-height:1.7;color:var(--text-muted);margin-top:0.6rem" id="compromise-chance"></p>
        <div class="callout" role="status" id="compromise-headline" style="margin-top:0.75rem"></div>
      </div>

      <div class="panel" id="compromise-detail-panel" style="display:none">
        <div class="panel-header"><span aria-hidden="true">🔬</span> The round-2 recovery, byte for byte</div>
        <p style="font-size:0.8rem;line-height:1.7;color:var(--text-secondary);margin-bottom:0.5rem">
          The round the victim emitted just before the theft, next to what each attacker produced.
          <span class="diff-same">green = byte recovered</span>,
          <span class="diff-diff">amber = wrong byte</span>.
        </p>
        <div class="diff-stack">
          <div class="diff-row">
            <span class="diff-tag">HMAC_DRBG — stream generated from the stolen state</span>
            <div class="diff-hex" id="compromise-diff-hmac" tabindex="0" role="region" aria-label="HMAC_DRBG attacker attempt, diffed against the true round 2 output"></div>
          </div>
          <div class="diff-row">
            <span class="diff-tag">CTR-no-update — counter stepped back two blocks</span>
            <div class="diff-hex" id="compromise-diff-noupdate" tabindex="0" role="region" aria-label="CTR-no-update attacker attempt, diffed against the true round 2 output"></div>
          </div>
        </div>
        <p style="font-size:0.78rem;line-height:1.7;color:var(--text-muted);margin-top:0.6rem">
          The HMAC_DRBG recovery attempt compares the stream generated from the stolen state
          with the earlier output. CTR-no-update provides a positive control because stepping
          its counter back exactly reproduces the earlier stream.
        </p>
      </div>

      <div class="callout" role="note">
        <strong>Why this matters</strong>
        Recovery, confirmation, and prediction measure different effects of a state compromise.
        The final row measures how a reseed with fresh entropy changes the next output.
      </div>
    </div>
  `;

  requestAnimationFrame(() => wireExhibit6(section, announce));
  return section;
}

function verdictCell(r: AttackResult, confirmation: boolean): string {
  if (confirmation) {
    const confirmed = r.verdict === 'confirmed';
    return `<span class="${confirmed ? 'stat-fail' : 'stat-pass'}">${r.matchedBytes}/${r.totalBytes} bytes — ${confirmed ? 'CONFIRMED' : 'not confirmed'}</span>`;
  }
  const cls =
    r.verdict === 'recovered' ? 'stat-fail' : r.verdict === 'failed' ? 'stat-pass' : 'stat-fail';
  const word =
    r.verdict === 'recovered'
      ? 'RECOVERED'
      : r.verdict === 'failed'
        ? 'failed'
        : 'PARTIAL — unexpected';
  return `<span class="${cls}">${r.matchedBytes}/${r.totalBytes} bytes — ${word}</span>`;
}

/** Byte-level diff of an attacker attempt against the truth. */
function renderDiff(el: HTMLElement, truth: Uint8Array, attempt: Uint8Array): void {
  el.replaceChildren();
  for (let i = 0; i < truth.length; i++) {
    const span = document.createElement('span');
    span.className = truth[i] === attempt[i] ? 'diff-same' : 'diff-diff';
    span.textContent = (attempt[i] ?? 0).toString(16).padStart(2, '0');
    el.appendChild(span);
    el.appendChild(document.createTextNode(' '));
  }
}

function wireExhibit6(section: HTMLElement, announce: (msg: string) => void): void {
  const entropyInput = section.querySelector<HTMLInputElement>('#compromise-entropy')!;
  const runBtn = section.querySelector<HTMLButtonElement>('#compromise-run')!;
  const timelinePanel = section.querySelector<HTMLElement>('#compromise-timeline-panel')!;
  const resultsPanel = section.querySelector<HTMLElement>('#compromise-results-panel')!;
  const detailPanel = section.querySelector<HTMLElement>('#compromise-detail-panel')!;
  const rowsBody = section.querySelector<HTMLElement>('#compromise-rows')!;

  const additional = section.querySelector<HTMLInputElement>('#compromise-additional-input')!;
  let lastInputs: CompromiseInputs | undefined;
  let runNumber = 0;

  function readInputs(): CompromiseInputs {
    const typed = entropyInput.value.trim();
    const entropy =
      typed.length > 0 && /^[0-9a-fA-F]+$/.test(typed) ? fromHex(typed) : getRandomEntropy(48);
    return { entropy, reseedEntropy: getRandomEntropy(48), roundBytes: ROUND_BYTES };
  }

  async function execute(inputs: CompromiseInputs): Promise<void> {
    lastInputs = inputs;
    const currentRun = ++runNumber;
    runBtn.disabled = true;
    let run: CompromiseRun;
    try {
      run = await runCompromise({
        ...inputs,
        additionalInput: additional.checked ? new TextEncoder().encode(ADDITIONAL_INPUT) : undefined,
      });
    } finally {
      if (currentRun === runNumber) runBtn.disabled = false;
    }

    if (currentRun !== runNumber) return;

    section.querySelector<HTMLElement>('#compromise-seed')!.textContent = run.entropyHex;
    section.querySelector<HTMLElement>('#compromise-stolen-hmac')!.textContent = run.stolenHmac;
    section.querySelector<HTMLElement>('#compromise-stolen-noupdate')!.textContent =
      run.stolenNoUpdate;

    rowsBody.replaceChildren();
    for (const row of run.rows) {
      const tr = document.createElement('tr');
      tr.id = `compromise-row-${row.id}`;
      const th = document.createElement('td');
      th.textContent = row.label;
      const a = document.createElement('td');
      a.id = `compromise-cell-${row.id}-hmac`;
      a.innerHTML = verdictCell(row.hmac, row.id === 'confirm-last-block');
      const b = document.createElement('td');
      b.id = `compromise-cell-${row.id}-noupdate`;
      if (row.noUpdate) b.innerHTML = verdictCell(row.noUpdate, false);
      else b.textContent = 'Not applicable';
      tr.append(th, a, b);
      rowsBody.appendChild(tr);
    }

    section.querySelector<HTMLElement>('#compromise-chance')!.textContent =
      `For recovery and prediction, two unrelated ${run.roundBytes}-byte strings agree on about ${run.expectedByChance.toFixed(2)} bytes by accident, ` +
      `so anything at or below ${run.chanceCeiling} matching bytes is scored “failed”. A full ${run.roundBytes}/${run.roundBytes} ` +
      `is scored “RECOVERED”. Anything in between would be scored “PARTIAL” and is not expected to occur — the threshold ` +
      `is not a rounding of the answer. Confirmation requires a full match against the stolen V.`;

    const past2 = run.rows.find((r) => r.id === 'past-2')!;
    renderDiff(
      section.querySelector<HTMLElement>('#compromise-diff-hmac')!,
      past2.hmac.truth,
      past2.hmac.attempt
    );
    renderDiff(
      section.querySelector<HTMLElement>('#compromise-diff-noupdate')!,
      past2.noUpdate!.truth,
      past2.noUpdate!.attempt
    );

    const summary = summarize(run);
    const headline = section.querySelector<HTMLElement>('#compromise-headline')!;
    headline.textContent = summary.headline;
    headline.append(
      document.createTextNode(
        summary.bothPredictableForward
          ? ' Both generators handed over the next round exactly, so neither provides prediction resistance on its own.'
          : ' At least one generator did not hand over the next round, which the construction does not promise — check the no-reseed row.'
      ),
      document.createTextNode(
        summary.reseedRestoresBoth
          ? ' After a reseed from fresh entropy, both attackers were locked out.'
          : ' A reseed did not lock the attacker out, which contradicts SP 800-90A §8.6.8 — check the reseed row.'
      )
    );

    timelinePanel.style.display = '';
    resultsPanel.style.display = '';
    detailPanel.style.display = '';
    announce(
      `State compromise run complete. HMAC_DRBG past recovery: ${past2.hmac.matchedBytes} of ${past2.hmac.totalBytes} bytes. ` +
        `CTR-no-update past recovery: ${past2.noUpdate!.matchedBytes} of ${past2.noUpdate!.totalBytes} bytes.`
    );
  }

  runBtn.addEventListener('click', () => execute(readInputs()));
  additional.addEventListener('change', () => execute(lastInputs ?? readInputs()));
}
