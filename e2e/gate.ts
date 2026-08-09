import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, each one a correction of the gate this
 * replaces:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. `neutralizeMotion()`
 *     pushed `animation:none!important; transition:none!important` through
 *     `addStyleTag`. That BYPASSED this stylesheet's own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising it,
 *     and on this page the block does real work that the injection could not
 *     reproduce: it also sets `body::after { display: none }`, removing a fixed
 *     full-viewport scanline overlay, and cancels `.pulse-border`.
 *
 *     It also mattered arithmetically. `<body>` runs `crt-flicker 4s infinite`,
 *     which holds the ENTIRE DOCUMENT between `opacity: 1` and `0.97` forever.
 *     A gate that scans without reduced motion is measuring a page whose every
 *     colour is drifting, at a phase nobody chose. `boot` asks for the
 *     preference and ASSERTS it took effect, which pins the document at 1 and
 *     removes the overlay — a single, reproducible rendering.
 *
 *     The reduced-motion block was checked for the defect where cancelling an
 *     animation strands an element at its start value. It does not: `crt-flicker`
 *     and `uf-fade` both END at `opacity: 1`, which is also the declared value,
 *     so `animation: none` leaves them visible. `expectNotBlank` measures that
 *     in every state rather than trusting the reading.
 *
 *  2. IT FORCE-REVEALED EVERY PANEL. `revealInline()` opened every `<details>`
 *     and then cleared the inline `display:none` from every element that had
 *     one. This lab hides ELEVEN output panels that way — the HMAC output,
 *     state and determinism panels, the CTR output and comparison panels, the
 *     Hash output panel, the statistical results and Dual_EC panels, and the
 *     three compromise panels. Only one exhibit was ever run, so the other ten
 *     were revealed EMPTY: a document with every panel open and almost nothing
 *     in them, which no visitor can load and which no assertion about it
 *     describes. This gate never touches `display` or `open`; every panel is
 *     revealed by the button that reveals it, and every disclosure is opened by
 *     clicking its own `<summary>`.
 *
 *  3. IT SCANNED ONCE, AT ONE VIEWPORT, AFTER ONE EXHIBIT. The whole drive was
 *     `#compromise-run`. Five exhibits, eight controls that ship DISABLED until
 *     a prerequisite runs, the byte-length sliders, both hash functions and the
 *     entire 380px column had never been scanned at all. This drive scans after
 *     every step, in {dark, light} × {1280, 380}.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`. Two things on this page
 *     are invisible to a violations-only assertion in particular: every hex
 *     readout sits on `rgba(0,0,0,0.4)` over an unknown backdrop, which axe
 *     files under `incomplete`; and an `aria-label` on a role-less element is
 *     PROHIBITED and lands in `incomplete` too, never in `violations`.
 *
 *  5. IT HAD NO REFLOW OR KEYBOARD-SCROLLER ORACLE, and this page needs both.
 *     The five `.hex-output` regions are `role="log"` with `overflow-y: auto`
 *     under a 6rem cap at phone width — they do not overflow at all until enough
 *     bytes are asked for, so the 2.1.1 failure only exists in states a drive
 *     has to go and build.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 *
 * This page cannot currently be in that shape, and the assertion is what makes
 * that a measurement: `style.css` contains no `@keyframes`, no `animation`
 * property and — checked separately — not a single `opacity` declaration
 * anywhere in it. Its reduced-motion block only clamps durations. The check runs
 * in every state regardless, because all three of those are properties of the
 * current stylesheet rather than of the page, and this is the cheapest place to
 * catch the first exception.
 *
 * `aria-hidden` subtrees are excluded. The cost of that exclusion is stated
 * plainly: text removed from the accessibility tree AND painted at zero opacity
 * is not checked here — which on this page would mean the seven SVG charts,
 * whose labels are instead measured by hand (see the header of `contrast.ts`).
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. A renderer that throws halfway through leaves an earlier state on
 * screen, and a gate that scans that state reports green for a page that is
 * broken. Attach before `boot`, assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark: the shared bar.
 *
 * This page puts its hero INSIDE `<main id="app">`, which scopes the hero
 * `<header>` out of the banner role on its own — and `index.html`'s
 * `dedupeBanner()` explicitly skips it for that reason (`el.closest('main, …')`
 * returns early). So unlike most labs in this fleet, nothing here demotes
 * anything; the single banner is a property of the markup. Asserting the OUTCOME
 * rather than either mechanism means a change to the nesting is caught too.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * The eleven output panels that ship hidden behind an inline `display:none`,
 * with the control that reveals each.
 *
 * This is the list the gate this replaces walked in order to STRIP the
 * `display:none` from all of them at once. Here it is used the other way round:
 * to assert every one is genuinely absent on arrival, and then to reach each
 * through the button a reader would press.
 */
export const HIDDEN_PANELS = [
  { sel: '#hmac-output-panel', by: '#hmac-generate' },
  { sel: '#hmac-state-panel', by: '#hmac-generate' },
  { sel: '#hmac-determinism-panel', by: '#hmac-same-seed' },
  { sel: '#ctr-output-panel', by: '#ctr-generate' },
  { sel: '#ctr-comparison-panel', by: '#ctr-compare' },
  { sel: '#hash-output-panel', by: '#hash-generate' },
  { sel: '#stat-results', by: '#stat-run-all' },
  { sel: '#stat-dualec-panel', by: '#stat-run-all' },
  { sel: '#compromise-timeline-panel', by: '#compromise-run' },
  { sel: '#compromise-results-panel', by: '#compromise-run' },
  { sel: '#compromise-detail-panel', by: '#compromise-run' },
] as const;

/** The eight controls that ship DISABLED until a prerequisite has been run. */
export const LOCKED_CONTROLS = [
  '#hmac-same-seed',
  '#hmac-avalanche',
  '#hmac-reseed',
  '#hmac-copy',
  '#ctr-same-seed',
  '#ctr-compare',
  '#ctr-copy',
  '#hash-copy',
] as const;

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page — including the
 * lab's DEFAULTS, which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page. On this page an emulation that silently did
 * nothing would leave every measurement drifting: `<body>` runs
 * `crt-flicker 4s infinite`, so the whole document's opacity cycles between 1
 * and 0.97 for as long as the tab is open, and a fixed `body::after` scanline
 * overlay is painted over every pixel. Reduced motion cancels the first and
 * removes the second, which is the only rendering of this page that is stable
 * enough to assert exact ratios about.
 *
 * The theme is seeded through `localStorage` rather than by clicking the toggle,
 * which also pins down a real failure mode: `index.html`'s anti-flash script
 * reads `localStorage.getItem('theme')` and the toggle writes
 * `localStorage.setItem('theme', …)`. If those keys drift apart the theme
 * silently stops persisting, and this boot fails on `data-theme` rather than
 * quietly scanning dark twice.
 *
 * The defaults are asserted at length because this lab ships almost entirely
 * EMPTY. Eleven output panels are behind an inline `display:none`, eight
 * controls ship `disabled`, and seven glossary disclosures ship shut — so the
 * arrival state is a page of controls and prose with no generated bytes on it
 * anywhere. That is a real state, it is the first one every reader sees, and the
 * gate this replaces never scanned it: it stripped the `display:none` from all
 * eleven panels before its only scan, producing a document with every panel open
 * and ten of them empty.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the whole
  // test timeout and reports nothing useful. 20s turns that silent hang into a
  // named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await assertSingleBanner(page);

  // The reduced-motion block's two side effects, asserted rather than assumed:
  // the document is pinned opaque and the scanline overlay is not painted.
  expect(
    await page.evaluate(() => getComputedStyle(document.body).opacity),
    'reduced motion must pin the document opaque, not leave crt-flicker running'
  ).toBe('1');
  expect(
    await page.evaluate(() => getComputedStyle(document.body, '::after').display),
    'reduced motion must remove the fixed scanline overlay'
  ).toBe('none');

  // Every exhibit is mounted by `src/main.ts`, so a navigation that resolves
  // proves nothing.
  for (const id of ['hmac-generate', 'ctr-generate', 'hash-generate', 'stat-run-all', 'compromise-run']) {
    await expect(page.locator(`#${id}`)).toBeEnabled();
  }

  // ── Everything this lab generates ships absent ───────────────────────────
  for (const { sel } of HIDDEN_PANELS) await expect(page.locator(sel)).toBeHidden();
  for (const sel of LOCKED_CONTROLS) await expect(page.locator(sel)).toBeDisabled();

  // ── Every shipped control default ────────────────────────────────────────
  await expect(page.locator('#hmac-entropy')).toHaveValue('');
  await expect(page.locator('#hmac-personal')).toHaveValue('');
  await expect(page.locator('#hmac-bytes')).toHaveValue('32');
  await expect(page.locator('#ctr-entropy')).toHaveValue('');
  await expect(page.locator('#ctr-bytes')).toHaveValue('32');
  await expect(page.locator('#hash-entropy')).toHaveValue('');
  await expect(page.locator('#hash-bytes')).toHaveValue('32');
  await expect(page.locator('#hash-fn')).toHaveValue('SHA-256');
  await expect(page.locator('#compromise-entropy')).toHaveValue('');

  // Seven inline glossary disclosures, all shut.
  await expect(page.locator('details.gloss')).toHaveCount(7);
  await expect(page.locator('details[open]')).toHaveCount(0);

  // The CAVP conformance banner runs on mount and is the one thing that HAS
  // produced a result at first paint.
  await expect(page.locator('#conformance-status')).not.toBeEmpty();

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this page is
 * the shape that breaks it: eleven sections of wide tables (a twelve-row
 * payroll, eight deployment rows with provenance prose, the equivalence-class
 * table, the released-answers ledger) and seven SVG charts. Each table is meant
 * to scroll inside its own `.scroller`; the assertion here is that none of them
 * scrolls the DOCUMENT.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow-x: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. That cost
    // a run elsewhere in this fleet, and this page has a decoy behind every
    // `.scroller`.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1). If
 * it holds no focusable content it needs `tabindex="0"`, so it becomes a focus
 * target arrow keys can then scroll.
 *
 * This lab already handles its known case — `dom.ts`'s `scroller()` builds every
 * one with `role="region"`, `tabindex="0"` and an `aria-label`, and it is the
 * only route by which a wide table gets on this page. The assertion stays
 * because the helper is a convention, not an enforcement, and because the
 * content inside those scrollers is the evidence for most of what the page
 * claims: the payroll it attacks, the equivalence classes, the ledger, and the
 * data-table alternative that is the accessible form of every chart.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * SC 1.4.11 (non-text contrast) for interactive controls: a control's boundary
 * has to be perceivable against what surrounds it.
 *
 * This is the old spec's check, kept because it was right, with its aim
 * corrected. It used to query `select, textarea, input[type='text']` — which is
 * exactly the set the palette's `--control-border` token was written for, and
 * correctly applied to. Pointing a check only at the place a rule is already
 * kept is the same as not having it, and every BUTTON-shaped control on this
 * page draws its border from `--border-strong`, a SURFACE divider, which was
 * never measured against anything.
 *
 * A control passes if EITHER
 *   - its fill differs from the surface behind it (how `.btn` works: a
 *     transparent border over an `--accent` fill), or
 *   - it has a border that stands out from the surface behind it AND from its
 *     own fill (how a `<select>` works: a near-panel fill with a drawn edge).
 * so the score is `max(fill-vs-outside, min(border-vs-outside, border-vs-fill))`.
 * Taking the max of the two mechanisms is what keeps this from failing a
 * perfectly delineated solid button for having no border.
 *
 * Two deliberate exclusions:
 *  - `disabled` controls. WCAG exempts inactive components, and this page ships
 *    `#guess-yes` / `#guess-no` disabled until a release has been dealt.
 *  - anything outside `#app`. The shared top bar is not this lab's to change —
 *    every repo in the fleet carries a copy — and its `.cl-btn` boundary
 *    (`color-mix(in srgb, var(--accent) 38%, transparent)` over `#0b1512`)
 *    measures 1.68:1 in dark and 1.23:1 in light here. That is reported upward
 *    as a fleet-wide observation rather than patched in one repo, and it is
 *    written down here so the exclusion is a decision and not an oversight.
 */
export async function auditControlBoundaries(
  page: Page
): Promise<Array<{ sel: string; ratio: number }>> {
  return page.evaluate(() => {
    type C = { r: number; g: number; b: number; a: number };
    // Resolve through a canvas rather than a regex: this palette is full of
    // `color-mix()`, which `getComputedStyle` reports unchanged and which a
    // regex reads as null — landing the walk on the wrong backdrop.
    const cv = document.createElement('canvas');
    cv.width = cv.height = 1;
    const ctx = cv.getContext('2d', { willReadFrequently: true })!;
    const parse = (s: string): C => {
      if (!s) return { r: 0, g: 0, b: 0, a: 0 };
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = '#000';
      ctx.fillStyle = s;
      const a = ctx.fillStyle;
      ctx.fillStyle = '#fff';
      ctx.fillStyle = s;
      if (a !== ctx.fillStyle) return { r: 0, g: 0, b: 0, a: 0 };
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = s;
      ctx.fillRect(0, 0, 1, 1);
      const d = ctx.getImageData(0, 0, 1, 1).data;
      return { r: d[0], g: d[1], b: d[2], a: d[3] / 255 };
    };
    const over = (fg: C, bg: C): C => {
      const a = fg.a + bg.a * (1 - fg.a);
      if (a === 0) return { r: 0, g: 0, b: 0, a: 0 };
      return {
        r: (fg.r * fg.a + bg.r * bg.a * (1 - fg.a)) / a,
        g: (fg.g * fg.a + bg.g * bg.a * (1 - fg.a)) / a,
        b: (fg.b * fg.a + bg.b * bg.a * (1 - fg.a)) / a,
        a,
      };
    };
    const lum = (c: C): number => {
      const f = (v: number): number => {
        const s = v / 255;
        return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
      };
      return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
    };
    const ratio = (a: C, b: C): number => {
      const la = lum(a);
      const lb = lum(b);
      return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
    };
    const backdrop = (start: Element | null): C => {
      const stack: C[] = [];
      for (let n = start; n; n = n.parentElement) {
        const c = parse(getComputedStyle(n).backgroundColor);
        if (c.a > 0) {
          stack.push(c);
          if (c.a >= 1) break;
        }
      }
      let out: C = { r: 255, g: 255, b: 255, a: 1 };
      for (let i = stack.length - 1; i >= 0; i--) out = over(stack[i], out);
      return out;
    };
    const describe = (el: Element): string => {
      const cls = el.getAttribute('class');
      return (
        el.tagName.toLowerCase() +
        (el.id ? `#${el.id}` : '') +
        (cls ? `.${cls.trim().split(/\s+/).join('.')}` : '')
      );
    };

    const out: Array<{ sel: string; ratio: number }> = [];
    const app = document.getElementById('app');
    if (!app) return out;
    app
      .querySelectorAll<HTMLElement>("button, select, textarea, input[type='text']")
      .forEach((el) => {
        const r = el.getBoundingClientRect();
        if (r.width === 0 || r.height === 0) return;
        if ((el as HTMLButtonElement).disabled) return;
        if (el.closest('[hidden]')) return;
        const cs = getComputedStyle(el);
        const outside = backdrop(el.parentElement);
        const fillRaw = parse(cs.backgroundColor);
        const fill = fillRaw.a > 0 ? over(fillRaw, outside) : outside;
        const byFill = ratio(fill, outside);
        let byBorder = 1;
        if (parseFloat(cs.borderTopWidth) > 0) {
          const border = over(parse(cs.borderTopColor), fill);
          byBorder = Math.min(ratio(border, outside), ratio(border, fill));
        }
        out.push({
          sel: describe(el),
          ratio: Math.round(Math.max(byFill, byBorder) * 100) / 100,
        });
      });
    return out;
  });
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run. It
 * is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the committed
 * workflow, and a run with it set prints every finding as it happens and then
 * fails at the end, so a green collection run cannot be mistaken for a green
 * gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function expectScrollersReachableSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectScrollersReachable(page, label);
  try {
    await expectScrollersReachable(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

async function expectNoHorizontalOverflowSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectNoHorizontalOverflow(page, label);
  try {
    await expectNoHorizontalOverflow(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

/**
 * Scan the page as it currently stands.
 *
 * Seven assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those ratios
 *    arithmetically — which matters more here than in most labs, since all three
 *    verdict surfaces are `color-mix(in oklab, …)` that axe declines to resolve.
 *    Everything else in that bucket is a real result axe simply could not finish
 *    — including `aria-prohibited-attr`, which is where an `aria-label` on a
 *    role-less element hides, a defect that never reaches the violations array
 *    at all. That one is live here: `dom.ts`'s `scroller()` puts an `aria-label`
 *    on a `<div>` and makes it legal with `role="region"`, and the role is easy
 *    to drop by accident.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - non-text contrast for interactive controls — SC 1.4.11, which axe has no
 *    rule for; see `auditControlBoundaries`.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page })
    .withTags(TAGS)
    // These four are axe "best-practice" rules rather than WCAG-tagged ones, so
    // `withTags` alone does not run them. This page has a shared sticky
    // <header role="banner"> above a <main> that contains a second <header>, and
    // the hero's <aside role="complementary"> inside it — exactly the shape they
    // catch, and none of them was enabled before.
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  const boundaries = await auditControlBoundaries(page);
  expect(boundaries.length, `no controls found to measure in state: ${label}`).toBeGreaterThan(0);
  const undelineated = Array.from(
    new Set(boundaries.filter((b) => b.ratio < 3).map((b) => `${b.ratio}:1 ${b.sel}`))
  );
  softExpect(undelineated, `control boundaries under 3:1 (SC 1.4.11) in state: ${label}`, []);

  await expectScrollersReachableSoft(page, label);
  await expectNoHorizontalOverflowSoft(page, label);
}


// ── The drive ───────────────────────────────────────────────────────────────

/** Open one `<details class="gloss">` by clicking its summary, and assert it opened. */
async function openGloss(page: Page, index: number): Promise<void> {
  const d = page.locator('details.gloss').nth(index);
  await d.locator('summary').click();
  await expect(d).toHaveAttribute('open', '');
}

/**
 * Open every VISIBLE shut disclosure by clicking its summary.
 *
 * `:visible` is load-bearing: the seventh disclosure ("show full 64-hex-char K
 * and V") lives inside `#hmac-state-panel`, which ships `display:none`, so it is
 * doubly hidden and unclickable until Exhibit 2 has been generated. Reaching for
 * it before that would hang on an element no reader can see — and forcing it
 * open from script is exactly what the gate this replaces did to all seven.
 */
async function openAllDisclosures(page: Page, expectSome = true): Promise<void> {
  const shut = page.locator('details:not([open]) > summary:visible');
  let opened = 0;
  for (let i = await shut.count(); i > 0 && opened < 40; i = await shut.count()) {
    await shut.first().click();
    opened += 1;
  }
  await expect(page.locator('details:not([open]) > summary:visible')).toHaveCount(0);
  // The first call must find something — if it does not, the drive has not
  // revealed the panel the seventh disclosure lives in and the state it claims
  // to scan is not the state on screen. The final sweep may legitimately find
  // nothing left, because the earlier call already opened everything reachable.
  if (expectSome) {
    expect(opened, 'no shut disclosure was found where one was expected').toBeGreaterThan(0);
  }
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Six things shape this drive:
 *
 *  - IT STARTS EMPTY, AND THE EMPTY STATE IS SCANNED FIRST. Eleven output panels
 *    ship behind an inline `display:none`, eight controls ship `disabled`, and
 *    the arrival state has no generated bytes on it anywhere. The gate this
 *    replaces cleared the `display:none` from all eleven before its only scan,
 *    which meant it never measured the state a reader arrives in AND measured
 *    ten panels in a populated-looking layout with nothing in them.
 *
 *  - EVERY PREREQUISITE IS SCANNED BEFORE ITS UNLOCK. Each of the eight locked
 *    controls is asserted disabled, then the control that unlocks it is pressed,
 *    then it is asserted enabled — so the "before" rendering, which is what a
 *    reader meets, is measured as well as the "after".
 *
 *  - EVERY BRANCH THAT ONLY ONE INPUT REACHES. `#hash-fn` = SHA-512 is the only
 *    route to the 111-byte seedlen state. An under-length `#ctr-entropy` is the
 *    only route to the amber "Under-seeded" warning, which is the single place
 *    on the page where `--amber-warn` is painted as prose — a whole ink that no
 *    other state exercises. Both are driven.
 *
 *  - THE BYTE SLIDERS ARE MOVED TO THEIR MAXIMUM, deliberately. The five
 *    `.hex-output` regions are `role="log"` with `overflow-y: auto` under a cap
 *    that drops to 6rem at phone width; at the default 32 bytes they do not
 *    overflow and there is nothing to find. At 256 bytes they do, and whether
 *    they can then be scrolled from a keyboard is a WCAG 2.1.1 question that
 *    only exists in a state a drive has to go and build.
 *
 *  - THE THREE DIFF VIEWS IN BOTH OUTCOMES. `#diff-verdict` renders `is-same`
 *    (same seed, identical stream) and `is-diff` (one flipped digit, avalanche),
 *    and Exhibit 6's byte diffs render a stream that was fully recovered beside
 *    one that was not. Those are the states where `.diff-same` and `.diff-diff`
 *    sit next to each other, which is the comparison the whole lab is for.
 *
 *  - NO FIXED TIMEOUTS. Every exhibit is real WebCrypto on the main thread, and
 *    every one of them has a DOM completion signal: a panel becoming visible, a
 *    row count, a button returning from `disabled`. The drive waits on those.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('first paint, every output panel absent and eight controls locked');

  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('skip link focused');

  // The conformance check runs itself on mount; this is the one result already
  // on screen, and it is the only place `stat-pass` appears before any click.
  await expect(page.locator('#conformance-status')).toHaveText(/^✓ All 3 algorithms match/);
  await expect(page.locator('#conformance-rows > div')).toHaveCount(3);
  await scanAt('CAVP conformance check complete');

  // Two of the seven glossary disclosures, opened the way a reader opens them.
  await openGloss(page, 0);
  await openGloss(page, 3);
  await scanAt('glossary disclosures open');

  // ── Exhibit 2: HMAC_DRBG ────────────────────────────────────────────────
  for (const sel of ['#hmac-same-seed', '#hmac-avalanche', '#hmac-reseed', '#hmac-copy']) {
    await expect(page.locator(sel)).toBeDisabled();
  }
  // 256 bytes, so the `role="log"` output region actually overflows its cap and
  // the 2.1.1 question about it becomes answerable.
  await page.locator('#hmac-bytes').fill('256');
  await expect(page.locator('#hmac-bytes-val')).toHaveText('256');
  await page.fill('#hmac-personal', 'gate-run-v1');
  await page.click('#hmac-generate');
  await expect(page.locator('#hmac-output-panel')).toBeVisible();
  await expect(page.locator('#hmac-state-panel')).toBeVisible();
  await expect(page.locator('#uf-new-v')).not.toBeEmpty();
  await expect(page.locator('#hmac-seed-personal')).toHaveText('gate-run-v1');
  for (const sel of ['#hmac-same-seed', '#hmac-avalanche', '#hmac-reseed', '#hmac-copy']) {
    await expect(page.locator(sel)).toBeEnabled();
  }
  await scanAt('HMAC_DRBG generated 256 bytes, state and update flow shown');

  // The nested disclosure that only exists once the state panel is revealed.
  await openAllDisclosures(page);
  await scanAt('the full 64-hex K and V disclosure open');

  await page.click('#hmac-same-seed');
  await expect(page.locator('#diff-verdict')).toHaveClass(/is-same/);
  await expect(page.locator('#diff-verdict')).toContainText('same seed → same stream');
  await expect(page.locator('#diff-cmp .diff-diff')).toHaveCount(0);
  await scanAt('same seed re-run, streams identical');

  await page.click('#hmac-avalanche');
  await expect(page.locator('#diff-verdict')).toHaveClass(/is-diff/);
  await expect(page.locator('#diff-verdict')).toContainText('the avalanche effect');
  await expect(page.locator('#diff-cmp .diff-diff').first()).toBeVisible();
  await scanAt('one seed digit flipped, avalanche across the stream');

  await page.click('#hmac-reseed');
  await expect(page.locator('#hmac-output')).not.toBeEmpty();
  await scanAt('HMAC_DRBG reseeded with fresh entropy');

  // The 1500ms "Copied!" flash. Clipboard permission is granted by the spec, so
  // this drives the resolved path rather than a silently rejected promise.
  await page.click('#hmac-copy');
  await expect(page.locator('#hmac-copy')).toHaveText('Copied!');
  await scanAt('copy confirmation flashed on the button');
  await expect(page.locator('#hmac-copy')).toHaveText('Copy', { timeout: 5_000 });

  // ── Exhibit 3: CTR_DRBG, including the under-seeded warning ─────────────
  await expect(page.locator('#ctr-same-seed')).toBeDisabled();
  await expect(page.locator('#ctr-compare')).toBeDisabled();
  await page.locator('#ctr-bytes').fill('256');
  await page.click('#ctr-generate');
  await expect(page.locator('#ctr-output-panel')).toBeVisible();
  await expect(page.locator('#ctr-seed-note')).toContainText('Nothing was padded');
  await expect(page.locator('#ctr-same-seed')).toBeEnabled();
  await scanAt('CTR_DRBG generated from full-length entropy');

  // The only route to the amber warning, and the only state on the page that
  // paints `--amber-warn` as prose rather than as a chart bar.
  await page.fill('#ctr-entropy', 'ff');
  await page.click('#ctr-generate');
  await expect(page.locator('#ctr-seed-note')).toContainText('Under-seeded:');
  await expect(page.locator('#ctr-seed-note')).toContainText('1 byte');
  await scanAt('CTR_DRBG under-seeded, the amber warning');

  await page.click('#ctr-same-seed');
  await expect(page.locator('#ctr-seed-note')).toContainText('Under-seeded:');
  await scanAt('under-seeded run repeated with the same seed');

  await page.click('#ctr-compare');
  await expect(page.locator('#ctr-comparison-panel')).toBeVisible();
  await expect(page.locator('#cmp-speed-ctr')).toHaveText(/ms$/);
  await expect(page.locator('#cmp-speed-hmac')).toHaveText(/ms$/);
  await expect(page.locator('#ctr-timing')).toContainText('Measured just now');
  await scanAt('CTR vs HMAC side by side with measured timings');

  // ── Exhibit 4: Hash_DRBG, both hash functions ───────────────────────────
  await expect(page.locator('#hash-copy')).toBeDisabled();
  await page.locator('#hash-bytes').fill('256');
  await page.click('#hash-generate');
  await expect(page.locator('#hash-output-panel')).toBeVisible();
  await expect(page.locator('#hash-state-c')).not.toBeEmpty();
  await expect(page.locator('#hash-copy')).toBeEnabled();
  await scanAt('Hash_DRBG on SHA-256');

  // SHA-512 is the only route to the 111-byte seedlen state.
  const sha256StateLen = (await page.locator('#hash-state-v').textContent())?.length ?? 0;
  await page.selectOption('#hash-fn', 'SHA-512');
  await page.click('#hash-generate');
  await expect(page.locator('#hash-state-v')).not.toBeEmpty();
  expect(
    (await page.locator('#hash-state-v').textContent())?.length ?? 0,
    'SHA-512 must produce a longer internal state than SHA-256'
  ).toBeGreaterThan(sha256StateLen);
  await scanAt('Hash_DRBG on SHA-512, a longer seedlen');

  // ── Exhibit 5: the statistical batteries and the Dual_EC panel ──────────
  await expect(page.locator('#stat-results')).toBeHidden();
  await page.click('#stat-run-all');
  // The button returning from `disabled` is the completion signal the code
  // itself defines, in a `finally`; the Dual_EC panel is revealed last.
  await expect(page.locator('#stat-run-all')).toBeEnabled({ timeout: 60_000 });
  await expect(page.locator('#stat-run-all')).toHaveText('Test All Three DRBGs');
  await expect(page.locator('#stat-dualec-panel')).toBeVisible();
  await expect(page.locator('#stat-tbody tr')).toHaveCount(4);
  await expect(page.locator('#dualec-tbody tr')).toHaveCount(4);
  await expect(page.locator('#entropy-chart .bar-col')).toHaveCount(3);
  await expect(page.locator('#grid-verdict')).toContainText('Measured on these two streams');
  await scanAt('all statistical batteries run, both pixel grids painted');

  // ── Exhibit 6: steal the state ──────────────────────────────────────────
  await expect(page.locator('#compromise-results-panel')).toBeHidden();
  await page.click('#compromise-run');
  await expect(page.locator('#compromise-rows tr')).toHaveCount(4);
  await expect(page.locator('#compromise-detail-panel')).toBeVisible();
  await expect(page.locator('#compromise-headline')).not.toBeEmpty();
  // The two byte-diff regions, one fully recovered and one not — which is the
  // comparison the whole exhibit exists to make.
  await expect(page.locator('#compromise-diff-noupdate .diff-same')).toHaveCount(32);
  await expect(page.locator('#compromise-diff-hmac .diff-diff').first()).toBeVisible();
  await scanAt('state stolen, four attacks scored, byte diffs rendered');

  // Everything on the page is now populated; open whatever is still shut.
  await openAllDisclosures(page, false);
  await scanAt('the finished page with every disclosure open');
}
