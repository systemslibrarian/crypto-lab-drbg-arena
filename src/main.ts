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

  // ─── Skip link ──────────────────────────────────────────────
  const skipLink = document.createElement('a');
  skipLink.href = '#main-content';
  skipLink.className = 'skip-link';
  skipLink.textContent = 'Skip to content';
  app.appendChild(skipLink);

  // ─── Header ─────────────────────────────────────────────────
  const header = document.createElement('header');
  header.style.cssText = 'display:flex;align-items:center;justify-content:space-between;padding:1rem 1.5rem;border-bottom:1px solid var(--border-color);flex-wrap:wrap;gap:0.5rem 1rem';

  // Title + subtitle as one left-hand group so the toggle (right) never overlaps them.
  const titleGroup = document.createElement('div');
  titleGroup.style.cssText = 'display:flex;align-items:baseline;gap:0.75rem;flex-wrap:wrap;min-width:0';

  const h1 = document.createElement('h1');
  h1.style.cssText = 'font-family:var(--font-mono);font-size:1.1rem;letter-spacing:0.15em;color:var(--green-clean);margin:0';
  h1.textContent = 'DRBG ARENA';
  titleGroup.appendChild(h1);

  const subtitle = document.createElement('span');
  subtitle.style.cssText = 'font-size:0.75rem;color:var(--text-secondary);font-family:var(--font-sans)';
  subtitle.textContent = 'NIST SP 800-90A';
  titleGroup.appendChild(subtitle);

  header.appendChild(titleGroup);

  // Theme toggle
  const themeToggle = document.createElement('button');
  themeToggle.className = 'theme-toggle';
  const initTheme = document.documentElement.getAttribute('data-theme') ?? 'dark';
  themeToggle.textContent = initTheme === 'dark' ? '🌙' : '☀️';
  themeToggle.setAttribute('aria-label', initTheme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
  themeToggle.addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    themeToggle.textContent = next === 'dark' ? '🌙' : '☀️';
    themeToggle.setAttribute('aria-label', next === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
    announce(`Switched to ${next} mode`);
  });
  header.appendChild(themeToggle);
  app.appendChild(header);

  // ─── Main content ───────────────────────────────────────────
  const main = document.createElement('main');
  main.id = 'main-content';
  main.setAttribute('tabindex', '-1');
  main.style.cssText = 'padding:1rem 1.5rem;max-width:960px;margin:0 auto';

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
