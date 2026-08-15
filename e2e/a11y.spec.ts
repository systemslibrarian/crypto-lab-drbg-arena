import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches: the arrival state, where all
 * eleven output panels are absent and eight controls are locked; the skip link
 * focused; the CAVP conformance check; glossary disclosures opened through their
 * summaries; HMAC_DRBG generated at its maximum byte length (which is what makes
 * its `role="log"` output region overflow at all), then re-run on the same seed
 * for the identical-stream diff, then one seed digit flipped for the avalanche
 * diff, then reseeded, then copied — including the 1500ms confirmation flash;
 * CTR_DRBG from full-length entropy and then UNDER-SEEDED, which is the only
 * state on the page that paints the amber warning ink as prose, then compared
 * against HMAC with measured timings; Hash_DRBG on both hash functions, since
 * SHA-512 is the only route to the longer seedlen; every statistical battery and
 * the Dual_EC panel; and the state-compromise run with both byte diffs. Every
 * one of those states is scanned, in both themes, at desktop and phone width.
 *
 * Clipboard permission is granted because the three copy buttons call
 * `navigator.clipboard.writeText` with no `.catch()`: without the grant the
 * promise rejects, nothing changes on screen, and the drive would be asserting
 * against a state the code never reached.
 *
 * See `gate.ts` for why nothing is injected into the page (this lab animates
 * `<body>` itself, forever), why no panel is force-revealed, why the lab's
 * defaults are asserted rather than assumed, and why `violations` is not the
 * whole oracle.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page, context }) => {
    test.setTimeout(900_000);
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    reportCollected();
    expectBaselineNotStale();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page, context }) => {
    test.setTimeout(900_000);
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    reportCollected();
    expectBaselineNotStale();
  });
}
