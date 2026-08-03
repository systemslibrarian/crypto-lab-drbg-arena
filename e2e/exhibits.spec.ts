import { expect, test, type Page } from '@playwright/test';

/**
 * Behaviour gates for the claims the exhibits print.
 *
 * These exist because the defects they cover were not crypto bugs — every
 * primitive underneath was already correct and KAT-verified. They were the page
 * saying one thing while its own values said another, which no unit test on
 * `src/crypto` can catch.
 */

async function open(page: Page): Promise<void> {
  await page.goto('.');
  await expect(page.locator('#hmac-generate')).toBeVisible();
}

test('Flip a seed digit, then Same Seed Again, and determinism still holds', async ({ page }) => {
  // The regression: "Flip 1 Seed Digit" moved the live seed but left the diff
  // reference pinned to the pre-flip stream, so the very next "Same Seed Again"
  // diffed the flipped seed's output against the old seed's and rendered
  // "✗ N hex digits differ (unexpected)" — inside the panel whose entire
  // subject is that the same seed reproduces the same stream.
  await open(page);
  await page.locator('#hmac-generate').click();
  await expect(page.locator('#diff-ref')).not.toBeEmpty();

  await page.locator('#hmac-same-seed').click();
  await expect(page.locator('#diff-verdict')).toContainText('0 hex digits differ');

  await page.locator('#hmac-avalanche').click();
  await expect(page.locator('#diff-verdict')).toContainText('avalanche effect');
  await expect(page.locator('#diff-ref-tag')).toHaveText('Before the flip (reference)');

  await page.locator('#hmac-same-seed').click();
  await expect(page.locator('#diff-verdict')).toContainText('0 hex digits differ');
  await expect(page.locator('#diff-verdict')).not.toContainText('unexpected');
});

test('the seed material that determines the stream is all on screen', async ({ page }) => {
  // A fresh nonce was drawn on every Generate and never displayed, so a learner
  // who typed fixed entropy and pressed Generate twice got different output
  // from what looked like the same seed.
  await open(page);
  await page.locator('#hmac-entropy').fill('00112233445566778899aabbccddeeff');
  await page.locator('#hmac-generate').click();

  const nonce = await page.locator('#hmac-seed-nonce').textContent();
  expect(nonce).toMatch(/^[0-9a-f]{32}$/);
  await expect(page.locator('#hmac-seed-entropy')).toHaveText('00112233445566778899aabbccddeeff');

  // Generate again: the entropy is unchanged, so any difference in the stream
  // must be visible in the nonce line rather than hidden.
  await page.locator('#hmac-generate').click();
  await expect(page.locator('#hmac-seed-nonce')).not.toHaveText(nonce ?? '');
});

test('under-seeding CTR_DRBG is disclosed with the entropy it actually has', async ({ page }) => {
  // Typing "ff" was silently zero-padded to the 48-byte seedlen and presented
  // as a full-strength instantiation.
  await open(page);
  await page.locator('#ctr-entropy').fill('ff');
  await page.locator('#ctr-generate').click();
  const note = page.locator('#ctr-seed-note');
  await expect(note).toContainText('Under-seeded');
  await expect(note).toContainText('1 byte');
  await expect(note).toContainText('8 bits');

  // A full-length seed must not be flagged.
  await page.locator('#ctr-entropy').fill('ab'.repeat(48));
  await page.locator('#ctr-generate').click();
  await expect(note).toContainText('Nothing was padded');
});

test('the CTR vs HMAC speed row is measured, not asserted', async ({ page }) => {
  // The table shipped "Speed: Medium / Fast (AES-NI)" with nothing timed, even
  // though both constructions run on the Compare click.
  await open(page);
  await expect(page.locator('#cmp-speed-ctr')).toHaveText('— press Compare');
  await page.locator('#ctr-generate').click();
  await page.locator('#ctr-compare').click();
  await expect(page.locator('#cmp-speed-ctr')).toContainText('ms');
  await expect(page.locator('#cmp-speed-hmac')).toContainText('ms');
  await expect(page.locator('#ctr-timing')).toContainText('Measured just now');
  await expect(page.locator('#ctr-timing')).toContainText('× faster here');
});

test('the broken-generator grid backs its visual claim with measured numbers', async ({ page }) => {
  // The grid used to paint the LCG's HIGH byte — its good bits — under a
  // caption promising "visible diagonal banding". It now paints the low byte,
  // whose period is exactly the grid width, and prints the correlation and the
  // test tally for both streams.
  await open(page);
  await page.locator('#stat-run-all').click();
  await expect(page.locator('#metric-lcg')).toContainText('1.000');
  await expect(page.locator('#metric-lcg')).toContainText('passes 0 of 4');
  await expect(page.locator('#metric-drbg')).toContainText('passes 4 of 4');
  await expect(page.locator('#grid-verdict')).toContainText('Measured on these two streams');

  // The entropy note must quote the run's own numbers rather than "8.00".
  const note = await page.locator('#entropy-note').textContent();
  expect(note).toMatch(/between 7\.\d\d and 7\.\d\d bits\/byte/);
});

// ── Exhibit 6 — steal the state ────────────────────────────────────────────
// Exhibit 2 asserts backtracking resistance in prose. Exhibit 6 measures it,
// against a positive control that is supposed to fail. These specs pin both
// sides: if the control ever stopped surrendering its past, the experiment
// would be blind and the "HMAC_DRBG gave up nothing" verdict would mean
// nothing — so the control's failure is asserted as hard as the pass.

// 48 bytes, fixed, so every number below is exact rather than probabilistic.
const PINNED_SEED =
  '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f';

async function runCompromise(page: Page): Promise<void> {
  await open(page);
  await page.locator('#compromise-entropy').fill(PINNED_SEED);
  await page.locator('#compromise-run').click();
  await expect(page.locator('#compromise-rows tr')).toHaveCount(4);
}

test('the defective control surrenders its entire past — the experiment can see a failure', async ({ page }) => {
  await runCompromise(page);
  await expect(page.locator('#compromise-cell-past-1-noupdate')).toContainText('32/32 bytes — RECOVERED');
  await expect(page.locator('#compromise-cell-past-2-noupdate')).toContainText('32/32 bytes — RECOVERED');
  // And the byte diff shows it: every byte green, none amber.
  await expect(page.locator('#compromise-diff-noupdate .diff-same')).toHaveCount(32);
  await expect(page.locator('#compromise-diff-noupdate .diff-diff')).toHaveCount(0);
});

test('HMAC_DRBG gives up no past output under the same theft', async ({ page }) => {
  await runCompromise(page);
  await expect(page.locator('#compromise-cell-past-1-hmac')).toContainText('failed');
  await expect(page.locator('#compromise-cell-past-2-hmac')).toContainText('failed');
  await expect(page.locator('#compromise-cell-past-1-hmac')).not.toContainText('RECOVERED');
  // The verdict must agree with the diff rendered beneath it: chance-level only.
  const recovered = await page.locator('#compromise-diff-hmac .diff-same').count();
  expect(recovered).toBeLessThanOrEqual(3);
});

test('both generators hand over the NEXT round — prediction resistance is not claimed', async ({ page }) => {
  await runCompromise(page);
  await expect(page.locator('#compromise-cell-future-3-hmac')).toContainText('32/32 bytes — RECOVERED');
  await expect(page.locator('#compromise-cell-future-3-noupdate')).toContainText('32/32 bytes — RECOVERED');
});

test('a reseed from fresh entropy locks both attackers out', async ({ page }) => {
  await runCompromise(page);
  await expect(page.locator('#compromise-cell-future-3-reseeded-hmac')).toContainText('failed');
  await expect(page.locator('#compromise-cell-future-3-reseeded-noupdate')).toContainText('failed');
});

test('the headline is written from the run, and names the control', async ({ page }) => {
  await runCompromise(page);
  const headline = page.locator('#compromise-headline');
  await expect(headline).toContainText('measured, not assumed');
  await expect(headline).toContainText('rewinds CTR-no-update completely');
  await expect(headline).toContainText('neither provides prediction resistance');
  await expect(headline).toContainText('both attackers were locked out');
  await expect(headline).not.toContainText('inconclusive');
  await expect(headline).not.toContainText('contradicts SP 800-90A');
});

test('the run is deterministic in the seed the learner supplies', async ({ page }) => {
  await runCompromise(page);
  const first = await page.locator('#compromise-stolen-hmac').innerText();
  await page.locator('#compromise-run').click();
  await expect(page.locator('#compromise-stolen-hmac')).toHaveText(first);
  // A different seed must move the stolen state, or nothing here is seed-driven.
  await page.locator('#compromise-entropy').fill('ff' + PINNED_SEED.slice(2));
  await page.locator('#compromise-run').click();
  await expect(page.locator('#compromise-stolen-hmac')).not.toHaveText(first);
});
