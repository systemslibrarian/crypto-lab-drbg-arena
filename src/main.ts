/**
 * DRBG Arena — Main Entry
 * Initializes the five-exhibit demo with theme toggle and accessibility.
 */

import './style.css';
import { buildExhibit1 } from './ui/exhibit1';
import { buildConformancePanel } from './ui/conformance';
import { buildExhibit2 } from './ui/exhibit2';
import { buildExhibit3 } from './ui/exhibit3';
import { buildExhibit4 } from './ui/exhibit4';
import { buildExhibit5 } from './ui/exhibit5';

function announce(message: string): void {
  const el = document.getElementById('sr-announcer');
  if (el) {
    el.textContent = '';
    requestAnimationFrame(() => { el.textContent = message; });
  }
}

function initUI(): void {
  const app = document.getElementById('app');
  if (!app) return;

  app.innerHTML = '';

  // The shared crypto-lab topbar already ships a .cl-skip-link and the single
  // banner landmark, so this lab renders no in-page skip link or header here
  // (a redundant skip link child of #app trips axe `region`).

  // ─── Main content ───────────────────────────────────────────
  const main = document.createElement('main');
  main.id = 'main-content';
  main.setAttribute('tabindex', '-1');
  main.style.cssText = 'padding:1rem 1.5rem;max-width:960px;margin:0 auto';

  // ─── Hero (fleet standard) ──────────────────────────────────
  // Rendered as a <div class="cl-hero"> (not <header>) so it never becomes a
  // second banner landmark alongside the shared .cl-topbar; the shared
  // dedupeBanner only demotes <header> children of <body>, not of #app/<main>.
  // CSS is keyed on the .cl-hero class, so styling is identical.
  const hero = document.createElement('div');
  hero.className = 'cl-hero';
  hero.innerHTML = `
    <div class="cl-hero-main">
      <h1 class="cl-hero-title">DRBG Arena</h1>
      <p class="cl-hero-sub">HMAC · CTR · Hash_DRBG · NIST SP 800-90A</p>
      <p class="cl-hero-desc">Seed each of the three NIST-approved DRBGs and watch a high-entropy seed expand through the seed → state → output → reseed lifecycle into a deterministic pseudorandom stream.</p>
    </div>
    <aside class="cl-hero-why" aria-label="Why it matters">
      <span class="cl-hero-why-label">WHY IT MATTERS</span>
      <p class="cl-hero-why-text">Keys, nonces, and IVs are only as safe as the generator behind them. A DRBG must stay unpredictable even if its state leaks, and passing statistical tests proves nothing — Dual_EC looked random too.</p>
    </aside>
  `;
  main.appendChild(hero);

  // Intro
  const intro = document.createElement('div');
  intro.style.cssText = 'margin-bottom:2rem';
  intro.innerHTML = `
    <p style="font-size:0.95rem;line-height:1.8;color:var(--text-primary);margin-bottom:0.75rem">
      <strong style="color:var(--green-clean)">Corrupted Oracle</strong> shows what happens when a DRBG is deliberately
      backdoored (Dual_EC_DRBG). <strong>This demo shows the three NIST SP 800-90A approved DRBGs
      that should be used instead</strong> — how they work, how to seed them correctly, and how to
      evaluate output quality.
    </p>
    <p style="font-size:0.85rem;line-height:1.7;color:var(--text-secondary)">
      Together the two demos tell the complete DRBG story: here is the failure case, here is the right way.
    </p>
  `;
  main.appendChild(intro);

  // Build all five exhibits. The conformance panel sits right after the
  // fundamentals so the learner meets the proof before exploring the demos.
  main.appendChild(buildExhibit1());
  main.appendChild(buildConformancePanel(announce));
  main.appendChild(buildExhibit2(announce));
  main.appendChild(buildExhibit3(announce));
  main.appendChild(buildExhibit4(announce));
  main.appendChild(buildExhibit5(announce));

  app.appendChild(main);
}

initUI();
