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
