// Package auth serves Meerkat's own authentication pages and endpoints. The
// pages are deliberately vanilla HTML (PAGE-01): light, framework-free, and
// meant to become integrator-customizable (theme, logo, layouts — PAGE-02/03).
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"

	"github.com/softwarity/meerkat/internal/mail"
	"github.com/softwarity/meerkat/internal/session"
	"github.com/softwarity/meerkat/internal/store"
)

// flowPage assembles a user-flow page (PAGE-01) from the shared chrome: ONE
// copy of the design tokens and layout for every page of the flow — the token
// block the theme editor rewrites at runtime (THEME-04) must exist exactly
// once. Titles and texts come from the request's locale (flowChrome.T);
// bodies differ, the chrome never does.
func flowPage(name, body string) *template.Template {
	page := strings.Replace(flowTop, "__TITLE__", "{{.Title}}", 1) + body + flowBottom
	return template.Must(template.New(name).Parse(page))
}

var (
	loginPage           = flowPage("login", loginBody)
	selectTenantPage    = flowPage("select-tenant", selectTenantBody)
	updatePasswordPage  = flowPage("update-password", updatePasswordBody)
	profilePage         = flowPage("profile", profileBody)
	profilePasswordPage = flowPage("profile-password", profilePasswordBody)
	profileSecurityPage = flowPage("profile-security", profileSecurityBody)
	profileDevPage      = flowPage("profile-dev", profileDevBody)
	profileDevCertPage  = flowPage("profile-dev-cert", profileDevCertBody)
	specimenPage        = flowPage("specimen", specimenBody)
)

// specimenBody is the REAL login screen with its error state made visible —
// one honest screen, and together its elements already exercise every theme
// token (fields, card, CTA, texts, outline, error, glow).
const specimenBody = `    <form onsubmit="return false">
      <p class="error">Access refused: outside your working hours.</p>
      <label class="field">
        <span>Username</span>
        <input value="alice" readonly>
      </label>
      <label class="field">
        <span>Password</span>
        <input type="password" value="secret-secret" readonly>
      </label>
      <button type="button">Sign in</button>
    </form>
    <script>
    // Live preview: the theme editor posts token values as the admin drags a
    // color — applied straight to :root, no reload. Specimen page ONLY (the
    // real flow pages never embed this). Same-origin messages, --mk-* vars
    // carrying light-dark(#hex, #hex) values, nothing else passes.
    let hiTimer = null, hiVar = null, hiPrev = '';
    function clearHighlight() {
      if (hiTimer) { clearInterval(hiTimer); hiTimer = null; }
      if (hiVar) {
        if (hiPrev) document.documentElement.style.setProperty(hiVar, hiPrev);
        else document.documentElement.style.removeProperty(hiVar);
        hiVar = null; hiPrev = '';
      }
    }
    addEventListener('message', (e) => {
      if (e.origin !== location.origin || !e.data || e.data.type !== 'meerkat-theme') return;
      if (e.data.vars && hiTimer) clearHighlight();
      for (const [k, v] of Object.entries(e.data.vars || {})) {
        // --mk-glow is the flat-design switch (1 = full effects, 0 = flat): a
        // bare 0|1, not a color — accept it explicitly, everything else must be
        // a --mk-* light-dark(#hex, #hex) pair.
        if (k === '--mk-glow' && /^[01]$/.test(v)) {
          document.documentElement.style.setProperty(k, v);
        } else if (/^--mk-[a-z-]+$/.test(k) && /^light-dark\((#[0-9a-f]{3,8}|black), (#[0-9a-f]{3,8}|black)\)$/.test(v)) {
          document.documentElement.style.setProperty(k, v);
        }
      }
      if ('highlight' in e.data) {
        // Hovering a token name in the editor BLINKS that token's value here:
        // whatever it drives visibly flip-flops — the clearest possible "this
        // is what changes". Hot pink on purpose: never part of a theme.
        clearHighlight();
        const k = e.data.highlight;
        if (/^--mk-[a-z-]+$/.test(k)) {
          hiVar = k;
          hiPrev = document.documentElement.style.getPropertyValue(k);
          let on = false;
          const flash = () => {
            on = !on;
            if (on) document.documentElement.style.setProperty(k, '#ff2d95');
            else if (hiPrev) document.documentElement.style.setProperty(k, hiPrev);
            else document.documentElement.style.removeProperty(k);
          };
          flash();
          hiTimer = setInterval(flash, 400);
        }
      }
      const brand = e.data.brand;
      if (brand) {
        const w = document.querySelector('.wordmark');
        if (w && typeof brand.name === 'string') w.textContent = brand.name || 'MEERKAT';
        const tl = document.querySelector('.tagline');
        if (tl && typeof brand.tagline === 'string') tl.textContent = brand.tagline;
        const mark = document.querySelector('.mark');
        const svg = mark && mark.querySelector('svg');
        let img = mark && mark.querySelector('img.applogo');
        const okLogo = typeof brand.logo === 'string' &&
          /^data:image\/(png|jpeg|webp|svg\+xml);base64,[a-zA-Z0-9+/=]+$/.test(brand.logo);
        if (mark && okLogo) {
          if (!img) { img = document.createElement('img'); img.className = 'applogo'; mark.prepend(img); }
          img.src = brand.logo; img.style.display = '';
          if (svg) svg.style.display = 'none';
        } else {
          if (img) img.style.display = 'none';
          if (svg) svg.style.display = '';
        }
      }
    });
    </script>
`

const flowTop = `<!doctype html>
<html lang="{{.Lang}}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" type="image/svg+xml" href="/meerkat/favicon.svg">
  <title>__TITLE__</title>
  <style>
    {{.ThemeCSS}}
    {{if ne .Scheme "auto"}}:root { color-scheme: {{.Scheme}}; }{{end}}
    * { box-sizing: border-box; }
    body {
      font-family: var(--mk-font); min-height: 100vh; margin: 0;
      display: grid; place-items: center; color: var(--mk-on-surface);
      overflow-x: hidden;
      padding: 32px 16px;
      background:
        radial-gradient(1000px 720px at 80% -12%, color-mix(in srgb, var(--mk-night) calc(62% * var(--mk-glow, 1)), transparent), transparent 62%),
        radial-gradient(760px 460px at 50% 120%, color-mix(in srgb, var(--mk-primary) calc(15% * var(--mk-glow, 1)), transparent), transparent 60%),
        var(--mk-surface);
    }
    /* desert-dusk grain over the whole field */
    body::after {
      content: ''; position: fixed; inset: 0; pointer-events: none; z-index: 2; opacity: .04;
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='140' height='140'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.8' numOctaves='2' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");
    }
    .watch {
      position: relative; z-index: 3; width: min(360px, 90vw);
      display: grid; justify-items: center; text-align: center;
    }
    /* the sentinel, with the alarm signal radiating behind it */
    .mark {
      position: relative; margin-bottom: 24px;
      display: grid; place-items: center;
      animation: rise .7s both;
    }
    .meerkat {
      position: relative; z-index: 1; width: 44px; height: auto;
      color: var(--mk-primary);
      --meerkat-eye: var(--mk-surface);
      filter: drop-shadow(0 0 calc(14px * var(--mk-glow, 1)) color-mix(in srgb, var(--mk-primary) calc(55% * var(--mk-glow, 1)), transparent));
    }
    .applogo {
      position: relative; z-index: 1; width: 56px; height: 56px; object-fit: contain;
      filter: drop-shadow(0 0 calc(14px * var(--mk-glow, 1)) color-mix(in srgb, var(--mk-primary) calc(45% * var(--mk-glow, 1)), transparent));
    }
    .generic {
      position: relative; z-index: 1; width: 52px; height: 52px;
      color: var(--mk-primary); opacity: .9;
    }
    .mark.pulse::before, .mark.pulse::after {
      content: ''; position: absolute; top: 62%; left: 50%; width: 16px; height: 16px;
      transform: translate(-50%, -50%); border-radius: 50%;
      border: 1px solid var(--mk-primary); opacity: 0;
      animation: ping 2.8s ease-out infinite;
    }
    .mark.pulse::after { animation-delay: 1.4s; }
    .wordmark {
      margin: 0; font-weight: 800; font-size: 2.6rem; line-height: 1;
      letter-spacing: .34em; text-indent: .34em;
      background: linear-gradient(180deg, var(--mk-on-surface), color-mix(in srgb, var(--mk-primary) calc(100% * var(--mk-glow, 1)), var(--mk-on-surface)));
      -webkit-background-clip: text; background-clip: text; color: transparent;
      animation: rise .7s .08s both;
    }
    .tagline {
      margin: 8px 0 24px; font-family: var(--mk-mono); font-size: .68rem;
      letter-spacing: .22em; text-transform: uppercase; color: var(--mk-on-surface-variant);
      animation: rise .7s .16s both;
    }
    form {
      margin-top: 10px; width: 100%; text-align: left;
      display: grid; gap: 16px; padding: 26px 24px 24px;
      background: color-mix(in srgb, var(--mk-surface-container) calc(82% + 18% * (1 - var(--mk-glow, 1))), transparent);
      border: 1px solid var(--mk-outline); border-radius: var(--mk-radius);
      backdrop-filter: blur(calc(6px * var(--mk-glow, 1))); position: relative;
      animation: rise .7s .24s both;
    }
    /* hairline mint accent along the top edge of the card */
    form::before {
      content: ''; position: absolute; inset: 0 0 auto 0; height: 2px;
      border-radius: var(--mk-radius) var(--mk-radius) 0 0;
      background: linear-gradient(90deg, transparent, var(--mk-primary), transparent);
      opacity: calc(.85 * var(--mk-glow, 1));
    }
    .field { display: grid; gap: 7px; }
    /* show/hide toggle injected into every password input */
    .pw-wrap { position: relative; display: grid; }
    .pw-wrap input { width: 100%; padding-right: 42px; }
    .pw-toggle {
      position: absolute; right: 6px; top: 50%; transform: translateY(-50%);
      margin: 0; padding: 6px; border: 0; background: none; box-shadow: none;
      color: var(--mk-on-surface-variant); cursor: pointer; line-height: 0;
    }
    .pw-toggle:hover { color: var(--mk-primary); filter: none; box-shadow: none; transform: translateY(-50%); }
    .pw-toggle svg { display: block; }
    .field > span {
      font-family: var(--mk-mono); font-size: .64rem; letter-spacing: .18em;
      text-transform: uppercase; color: var(--mk-on-surface-variant);
    }
    input {
      padding: 11px 13px; border-radius: var(--mk-radius-small);
      border: 1px solid var(--mk-outline); background: var(--mk-surface-container-high);
      color: inherit; font-size: 1rem; font-family: var(--mk-mono);
      transition: border-color .15s, box-shadow .15s;
    }
    input:focus {
      outline: none; border-color: var(--mk-primary);
      box-shadow: 0 0 0 3px color-mix(in srgb, var(--mk-primary) 22%, transparent);
    }
    /* A browser fills a remembered field with a background of its own, and
       background-color cannot override it: the browser applies it internally,
       above any author rule. An INSET box-shadow can, because it paints over
       that background instead of replacing it. Without this, a dark theme gets
       Chrome's pale yellow blended into it, which reads as an olive slab.
       :autofill is the standard name, :-webkit-autofill what most engines still
       answer to, so both are given. The focus ring is repeated in the focused
       case or this more specific rule would drop it. */
    input:-webkit-autofill,
    input:-webkit-autofill:hover,
    input:autofill {
      -webkit-text-fill-color: var(--mk-on-surface);
      -webkit-box-shadow: 0 0 0 1000px var(--mk-surface-container-high) inset;
      box-shadow: 0 0 0 1000px var(--mk-surface-container-high) inset;
      caret-color: var(--mk-on-surface);
    }
    input:-webkit-autofill:focus,
    input:autofill:focus {
      -webkit-box-shadow: 0 0 0 3px color-mix(in srgb, var(--mk-primary) 22%, transparent),
                          0 0 0 1000px var(--mk-surface-container-high) inset;
      box-shadow: 0 0 0 3px color-mix(in srgb, var(--mk-primary) 22%, transparent),
                  0 0 0 1000px var(--mk-surface-container-high) inset;
    }
    button {
      margin-top: 4px; padding: 12px; border: 0; border-radius: var(--mk-radius-small);
      background: var(--mk-primary); color: var(--mk-on-primary);
      font-size: .95rem; font-weight: 700; letter-spacing: .02em; cursor: pointer;
      box-shadow: 0 8px calc(24px * var(--mk-glow, 1)) color-mix(in srgb, var(--mk-primary) calc(26% * var(--mk-glow, 1)), transparent);
      transition: transform .12s, box-shadow .2s, filter .2s;
    }
    button:hover { filter: brightness(1.06); box-shadow: 0 10px calc(30px * var(--mk-glow, 1)) color-mix(in srgb, var(--mk-primary) calc(40% * var(--mk-glow, 1)), transparent); }
    button:active { transform: translateY(1px); }
    .error {
      margin: 0; padding: 9px 12px; border-radius: var(--mk-radius-small);
      color: var(--mk-error); font-size: .82rem;
      background: color-mix(in srgb, var(--mk-error) 12%, transparent);
      border: 1px solid color-mix(in srgb, var(--mk-error) 30%, transparent);
    }
    .foot {
      margin: 22px 0 0; font-family: var(--mk-mono); font-size: .64rem;
      letter-spacing: .2em; text-transform: uppercase; color: var(--mk-on-surface-variant);
      display: inline-flex; align-items: center; gap: 8px;
      animation: rise .7s .32s both;
    }
    .foot::before {
      content: ''; width: 6px; height: 6px; border-radius: 50%;
      background: var(--mk-primary); box-shadow: 0 0 calc(8px * var(--mk-glow, 1)) var(--mk-primary);
    }
    /* tenant selection (TENANT-03) */
    .lead {
      margin: 0; font-family: var(--mk-mono); font-size: .68rem;
      letter-spacing: .18em; text-transform: uppercase; color: var(--mk-on-surface-variant);
    }
    button.choice, a.choice {
      margin: 0; padding: 13px 16px; display: flex; align-items: center; gap: 12px;
      background: var(--mk-surface-container-high); color: var(--mk-on-surface);
      border: 1px solid var(--mk-outline); box-shadow: none; font-weight: 500;
      transition: border-color .15s, transform .12s;
    }
    button.choice:hover, a.choice:hover { border-color: var(--mk-primary); filter: none; box-shadow: none; }
    a.choice { justify-content: center; text-decoration: none; border-radius: 10px; }
    /* "or sign in with", set apart from the form above it */
    .sep {
      margin: 18px 0 10px; text-align: center; font-size: .85rem;
      color: var(--mk-on-surface-variant);
    }
    .choice-name { flex: 1; text-align: left; }
    .choice-type {
      font-family: var(--mk-mono); font-size: .62rem; letter-spacing: .14em;
      color: var(--mk-on-surface-variant);
    }
    /* public routes reachable without signing in, offered under the form */
    .public { margin-top: 20px; animation: rise .7s .36s both; }
    .public-links {
      display: flex; flex-wrap: wrap; gap: 8px; justify-content: center; margin-top: 10px;
    }
    .public-links a {
      padding: 6px 14px; border-radius: 999px; border: 1px solid var(--mk-outline);
      color: var(--mk-on-surface); text-decoration: none; font-size: .82rem;
      background: var(--mk-surface-container);
    }
    .public-links a:hover { border-color: var(--mk-primary); }
    /* button.pk-btn: must out-rank button.choice, whose margin: 0 wins over
       a bare class selector */
    button.pk-btn { margin-top: 22px; width: 100%; justify-content: center; }
    /* language / color-scheme switchers — persisted in cookies, applied
       server-side on the next render (no flash) */
    .prefs {
      margin-top: 18px; display: flex; align-items: center; gap: 4px;
      animation: rise .7s .4s both;
    }
    .prefs button {
      margin: 0; padding: 4px 9px; font-family: var(--mk-mono); font-size: .62rem;
      letter-spacing: .12em; text-transform: uppercase; font-weight: 600;
      background: transparent; color: var(--mk-on-surface-variant);
      border: 1px solid transparent; border-radius: 999px; box-shadow: none; cursor: pointer;
    }
    .prefs button:hover { border-color: var(--mk-outline); filter: none; box-shadow: none; transform: none; }
    .prefs button.on { color: var(--mk-primary); border-color: var(--mk-outline); background: var(--mk-surface-container); }
    .prefs .sep { width: 1px; height: 14px; background: var(--mk-outline); margin: 0 5px; }
    /* language icon-menu + the single 3-state scheme button */
    .langbox { position: relative; display: inline-flex; }
    .lang-toggle svg { display: block; }
    .lang-menu {
      position: absolute; bottom: calc(100% + 8px); left: 50%; transform: translateX(-50%);
      display: grid; gap: 2px; min-width: 150px; padding: 6px;
      background: var(--mk-surface-container); border: 1px solid var(--mk-outline);
      border-radius: var(--mk-radius-small); z-index: 5;
      box-shadow: 0 8px 24px rgb(0 0 0 / .25);
    }
    .lang-menu button {
      font-family: inherit; letter-spacing: 0; text-transform: none; font-size: .8rem;
      text-align: left; padding: 6px 10px; border-radius: 7px;
    }
    .lang-menu button.on { color: var(--mk-primary); }
    /* the author display:grid above would beat the UA's [hidden] rule */
    .lang-menu[hidden] { display: none; }
    @keyframes rise { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: none; } }
    @keyframes ping {
      0% { opacity: .5; transform: translate(-50%, -50%) scale(1); }
      80%, 100% { opacity: 0; transform: translate(-50%, -50%) scale(6); }
    }
    @media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation: none !important; } }
  </style>
</head>
<body>
  <main class="watch">
    <div class="mark{{if .Brand.Meerkat}} pulse{{end}}" aria-hidden="true">
      {{if .Brand.LogoURL}}<img class="applogo" src="{{.Brand.LogoURL}}" alt="">{{end}}
      {{if not .Brand.Meerkat}}<svg class="generic"{{if .Brand.LogoURL}} style="display:none"{{end}} viewBox="0 0 56 56" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect x="3" y="3" width="50" height="50" rx="12" stroke="currentColor" stroke-width="2.5" stroke-dasharray="7 6"/>
        <circle cx="21" cy="21" r="5" fill="currentColor" opacity=".85"/>
        <path d="M12 42l11-12 8 9 5-5 8 8" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>{{end}}
      {{if .Brand.Meerkat}}<svg class="meerkat"{{if .Brand.LogoURL}} style="display:none"{{end}} viewBox="0 0 44 64" fill="currentColor" xmlns="http://www.w3.org/2000/svg">
        <path d="M29 43c8.2 1.8 11.4 8.8 8.1 17.1-.4 1-1.9 1-2.5.1-1.8-2.6-2.4-5.2-2.4-7.9 0-3.7-1.5-7.1-4.4-9.4z" opacity=".85"/>
        <path d="M22 2c-4.8 0-8.6 3.8-8.6 8.6 0 2.5 1 4.7 2.7 6.3-3.5 3-5.7 7.9-5.7 14.6 0 13 5.1 23.1 11.6 23.1s11.6-10.1 11.6-23.1c0-6.7-2.2-11.6-5.7-14.6 1.7-1.6 2.7-3.8 2.7-6.3C30.6 5.8 26.8 2 22 2z"/>
        <circle cx="15.4" cy="6.4" r="3.1"/>
        <circle cx="28.6" cy="6.4" r="3.1"/>
        <ellipse cx="18.3" cy="10.3" rx="1.8" ry="2.5" fill="var(--meerkat-eye)"/>
        <ellipse cx="25.7" cy="10.3" rx="1.8" ry="2.5" fill="var(--meerkat-eye)"/>
        <path d="M22 14l2.5 2.1-2.5 1.3-2.5-1.3z" fill="var(--meerkat-eye)"/>
      </svg>{{end}}
    </div>
    <h1 class="wordmark">{{.Brand.AppName}}</h1>
    <p class="tagline">{{.Brand.Tagline}}</p>
`

const flowBottom = `    {{if .Brand.Meerkat}}<p class="foot">on watch</p>{{end}}
    {{if or .SchemeSwitch (gt (len .Langs) 1)}}<div class="prefs">
      {{if gt (len .Langs) 1}}<div class="langbox">
        <button type="button" class="lang-toggle" id="lang-toggle" aria-haspopup="menu" title="{{.T.languages}}">
          <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.4 3.8 5.6 3.8 9s-1.3 6.6-3.8 9c-2.5-2.4-3.8-5.6-3.8-9s1.3-6.6 3.8-9z"/></svg>
        </button>
        <div class="lang-menu" id="lang-menu" hidden>
          {{range .Langs}}<button type="button" data-lang="{{.}}"{{if eq . $.Lang}} class="on"{{end}}>{{index $.LangNames .}}</button>{{end}}
        </div>
      </div>{{end}}
      {{if and .SchemeSwitch (gt (len .Langs) 1)}}<span class="sep"></span>{{end}}
      {{if .SchemeSwitch}}<button type="button" class="scheme-cycle" data-scheme-next="{{.SchemeNext}}" title="{{.T.colorScheme}}">{{.SchemeIcon}}</button>{{end}}
    </div>{{end}}
  </main>
  <script>
  // Every password input gets a show/hide eye (generic: login, update,
  // profile — one place).
  (() => {
    const eye = '<svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M2 12s3.6-6.4 10-6.4S22 12 22 12s-3.6 6.4-10 6.4S2 12 2 12z"/><circle cx="12" cy="12" r="2.6"/></svg>';
    const eyeOff = '<svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M2 12s3.6-6.4 10-6.4S22 12 22 12s-3.6 6.4-10 6.4S2 12 2 12z"/><circle cx="12" cy="12" r="2.6"/><path d="M4 20 20 4"/></svg>';
    for (const inp of document.querySelectorAll('input[type="password"]')) {
      const wrap = document.createElement('div');
      wrap.className = 'pw-wrap';
      inp.parentNode.insertBefore(wrap, inp);
      wrap.appendChild(inp);
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'pw-toggle';
      btn.innerHTML = eye;
      wrap.appendChild(btn);
      btn.addEventListener('click', () => {
        const show = inp.type === 'password';
        inp.type = show ? 'text' : 'password';
        btn.innerHTML = show ? eyeOff : eye;
        inp.focus();
      });
    }
  })();
  // Preferences ride cookies so the SERVER renders the next page right.
  const setPref = (k, v) => {
    document.cookie = k + '=' + v + ';path=/;max-age=31536000;SameSite=Lax';
    location.reload();
  };
  const lt = document.getElementById('lang-toggle'), lm = document.getElementById('lang-menu');
  if (lt) {
    lt.addEventListener('click', (e) => { e.stopPropagation(); lm.hidden = !lm.hidden; });
    document.addEventListener('click', () => { lm.hidden = true; });
  }
  for (const b of document.querySelectorAll('[data-lang]')) b.addEventListener('click', () => setPref('MEERKAT_LANG', b.dataset.lang));
  const sc = document.querySelector('[data-scheme-next]');
  if (sc) sc.addEventListener('click', () => setPref('MEERKAT_SCHEME', sc.dataset.schemeNext));
  </script>
</body>
</html>`

const loginBody = `    {{if .Shut}}<p class="lead">{{.T.noWayIn}}</p>
    {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
    {{end}}
    {{if .Credentials}}<form method="post" action="login">
      {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
      <label class="field">
        <span>{{.T.username}}</span>
        <input name="username" autocomplete="username" autofocus required>
      </label>
      <label class="field">
        <span>{{.T.password}}</span>
        <input name="password" type="password" autocomplete="current-password" required>
      </label>
      <input type="hidden" name="next" value="{{.Next}}">
      <button type="submit">{{.T.signIn}}</button>
    </form>
    {{else if and .Error (not .Shut)}}<p class="error">{{.Error}}</p>{{end}}
    {{if .Providers}}
    <p class="sep">{{.T.orSignInWith}}</p>
    {{range .Providers}}<a class="choice" href="/login/{{.ID}}?next={{$.Next}}">{{.Name}}</a>{{end}}
    {{end}}
    {{if .Forgot}}<p class="back"><a href="/forgot-password">{{.T.forgotLink}}</a></p>{{end}}
    {{if .Register}}<p class="back"><a href="/register">{{.T.createAccount}}</a></p>{{end}}
    {{if .Passkeys}}
    <button type="button" class="choice pk-btn" id="pk-login" data-next="{{.Next}}" hidden>{{.T.signInPasskey}}</button>
    <p class="error" id="pk-error" hidden></p>
    <script>
    (() => {
      const b64d = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
      const b64e = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/[+]/g, '-').replace(/[/]/g, '_').replace(/=+$/, '');
      const btn = document.getElementById('pk-login');
      const err = document.getElementById('pk-error');
      if (!window.PublicKeyCredential) return;
      btn.hidden = false;
      btn.addEventListener('click', async () => {
        err.hidden = true;
        try {
          const start = await fetch('/login/passkey/start', { method: 'POST' }).then((r) => r.json());
          const pk = start.options.publicKey;
          pk.challenge = b64d(pk.challenge);
          (pk.allowCredentials || []).forEach((c) => { c.id = b64d(c.id); });
          const cred = await navigator.credentials.get({ publicKey: pk });
          const body = {
            id: cred.id, rawId: b64e(cred.rawId), type: cred.type,
            response: {
              authenticatorData: b64e(cred.response.authenticatorData),
              clientDataJSON: b64e(cred.response.clientDataJSON),
              signature: b64e(cred.response.signature),
              userHandle: cred.response.userHandle ? b64e(cred.response.userHandle) : null,
            },
          };
          const fin = await fetch('/login/passkey/finish?challenge=' + start.challenge +
            '&next=' + encodeURIComponent(btn.dataset.next || ''), {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
          });
          if (fin.redirected) { location.href = fin.url; return; }
          if (fin.ok) { location.href = '/'; return; }
          throw new Error(await fin.text());
        } catch (e) {
          err.textContent = {{.T.errPasskey}};
          err.hidden = false;
        }
      });
    })();
    </script>
    {{end}}
    {{if .Public}}<div class="public">
      <p class="lead">{{.T.continueWithout}}</p>
      <nav class="public-links">
        {{range .Public}}<a href="{{.Href}}">{{.Name}}</a>{{end}}
      </nav>
    </div>{{end}}
`

const updatePasswordBody = `    <form method="post" action="update-password">
      <p class="lead">{{.T.mustChangeLead}}</p>
      {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
      <label class="field">
        <span>{{.T.newPassword}}</span>
        <input name="password" type="password" autocomplete="new-password" autofocus required minlength="8">
      </label>
      <label class="field">
        <span>{{.T.confirmPassword}}</span>
        <input name="confirm" type="password" autocomplete="new-password" required minlength="8">
      </label>
      <button type="submit">{{.T.changePassword}}</button>
    </form>
`

const selectTenantBody = `    <form method="post" action="select-tenant">
      <p class="lead">{{.T.chooseTenantLead}}</p>
      {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
      {{/* The membership type stays out on purpose: this is the APP side —
           administration lives on the admin port, which shows what you
           administer. */}}
      {{range .Tenants}}
      <button class="choice" type="submit" name="tenant" value="{{.TenantID}}">
        <span class="choice-name">{{.TenantName}}</span>
      </button>
      {{end}}
    </form>
`

// profileBody is the self-service profile page (data plane, "Moi" scope): the
// user's identity + a change-password form (needs the CURRENT password) + sign
// out. Avatar is generated initials — NO Gravatar, which would be an external
// request and break the offline-first rule for the flow pages.
const profileBody = `    <style>
      .avatar {
        width: 72px; height: 72px; border-radius: 50%;
        display: grid; place-items: center;
        background: var(--mk-primary); color: var(--mk-on-primary);
        font-weight: 800; font-size: 1.7rem; letter-spacing: .02em;
      }
      .avatar-form { display: grid; justify-items: center; gap: 6px; margin: 0 0 16px; }
      .avatar-wrap { position: relative; cursor: pointer; display: block; }
      .avatar-img { width: 72px; height: 72px; border-radius: 50%; object-fit: cover; display: block; }
      .avatar-edit {
        position: absolute; right: -4px; bottom: -2px; width: 24px; height: 24px;
        display: grid; place-items: center; font-size: .8rem; border-radius: 50%;
        background: var(--mk-surface-container-high); border: 1px solid var(--mk-outline);
        color: var(--mk-on-surface-variant);
      }
      .avatar-wrap:hover .avatar-edit { color: var(--mk-primary); border-color: var(--mk-primary); }
      .avatar-clear {
        margin: 0; padding: 2px 10px; border: 0; background: none; box-shadow: none;
        color: var(--mk-on-surface-variant); font-size: .72rem; cursor: pointer;
      }
      .avatar-clear:hover { color: var(--mk-error); filter: none; box-shadow: none; transform: none; }
      .facts { margin: 0 0 8px; display: grid; gap: 10px; width: 100%; }
      .facts > div { display: flex; justify-content: space-between; align-items: baseline; gap: 14px; }
      .facts dt {
        font-family: var(--mk-mono); font-size: .62rem; letter-spacing: .16em;
        text-transform: uppercase; color: var(--mk-on-surface-variant);
      }
      .facts dd { margin: 0; text-align: right; overflow-wrap: anywhere; font-size: .92rem; }
      .notice {
        margin: 0; padding: 9px 12px; border-radius: var(--mk-radius-small);
        color: var(--mk-primary); font-size: .82rem;
        background: color-mix(in srgb, var(--mk-primary) 12%, transparent);
        border: 1px solid color-mix(in srgb, var(--mk-primary) 30%, transparent);
      }
      form.signout { margin-top: 14px; }
      .mfa-link {
        display: flex; align-items: center; gap: 12px; width: 100%;
        margin: 6px 0 2px; padding: 13px 16px; text-decoration: none;
        background: var(--mk-surface-container-high); color: var(--mk-on-surface);
        border: 1px solid var(--mk-outline); border-radius: var(--mk-radius-small);
        transition: border-color .15s;
      }
      .mfa-link:hover { border-color: var(--mk-primary); }
      .mfa-link .mfa-label { flex: 1; font-size: .9rem; }
      .mfa-link .mfa-state {
        font-family: var(--mk-mono); font-size: .62rem; letter-spacing: .14em;
        text-transform: uppercase; color: var(--mk-on-surface-variant);
      }
      .mfa-link .mfa-state.on { color: var(--mk-primary); }
      /* the way back into the applications, right from the hub */
      .apps { width: 100%; margin-top: 14px; padding-top: 14px; border-top: 1px solid var(--mk-outline); display: grid; gap: 8px; }
      .apps-title {
        font-family: var(--mk-mono); font-size: .62rem; letter-spacing: .16em;
        text-transform: uppercase; color: var(--mk-on-surface-variant); text-align: left;
      }
      .apps .public-links { justify-content: flex-start; margin-top: 0; }
    </style>
    {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
    <form method="post" action="/profile/avatar" enctype="multipart/form-data" class="avatar-form">
      <label class="avatar-wrap" title="{{.T.changePhoto}}">
        {{if .Avatar}}<img class="avatar-img" src="{{.Avatar}}" alt="">{{else}}<div class="avatar">{{.Initials}}</div>{{end}}
        <span class="avatar-edit" aria-hidden="true">&#9998;</span>
        <input type="file" name="avatar" accept="image/png,image/jpeg,image/webp" onchange="this.form.submit()" hidden>
      </label>
      {{if .Avatar}}<button class="avatar-clear" type="submit" name="step" value="clear">{{.T.removePhoto}}</button>{{end}}
    </form>
    <dl class="facts">
      <div><dt>{{.T.factUser}}</dt><dd>{{.Username}}</dd></div>
      {{if .Fullname}}<div><dt>{{.T.factName}}</dt><dd>{{.Fullname}}</dd></div>{{end}}
      {{if .Email}}<div><dt>{{.T.factEmail}}</dt><dd>{{.Email}}</dd></div>{{end}}
      {{if .TenantName}}<div><dt>{{.T.factOrganisation}}</dt><dd>{{.TenantName}}</dd></div>{{end}}
    </dl>
    <a class="mfa-link" href="/profile/security">
      <span class="mfa-label">{{.T.security}}</span>
      <span class="mfa-state">&rsaquo;</span>
    </a>
    {{if .IsDev}}
    <a class="mfa-link" href="/profile/dev">
      <span class="mfa-label">{{.T.developer}}</span>
      <span class="mfa-state">&rsaquo;</span>
    </a>
    {{end}}
    {{if .Apps}}
    <div class="apps">
      <span class="apps-title">{{.T.applications}}</span>
      <nav class="public-links">
        {{range .Apps}}<a href="{{.Href}}">{{.Name}}</a>{{end}}
      </nav>
    </div>
    {{end}}
    <form method="post" action="logout" class="signout">
      <button class="choice" type="submit">{{.T.signOut}}</button>
    </form>
`

// profileSecurityBody groups everything security: the second factor, the
// password, and the passkeys — reached from the profile hub.
const profileSecurityBody = `    <style>
      .mfa-link {
        display: flex; align-items: center; gap: 12px; width: 100%;
        margin: 6px 0 2px; padding: 13px 16px; text-decoration: none;
        background: var(--mk-surface-container-high); color: var(--mk-on-surface);
        border: 1px solid var(--mk-outline); border-radius: var(--mk-radius-small);
        transition: border-color .15s;
      }
      .mfa-link:hover { border-color: var(--mk-primary); }
      .mfa-link .mfa-label { flex: 1; font-size: .9rem; text-align: left; }
      .mfa-link .mfa-state {
        font-family: var(--mk-mono); font-size: .62rem; letter-spacing: .14em;
        text-transform: uppercase; color: var(--mk-on-surface-variant);
      }
      .mfa-link .mfa-state.on { color: var(--mk-primary); }
      .sec {
        width: 100%; margin-top: 14px; padding-top: 14px;
        border-top: 1px solid var(--mk-outline); display: grid; gap: 8px;
      }
      .sec-title {
        font-family: var(--mk-mono); font-size: .62rem; letter-spacing: .16em;
        text-transform: uppercase; color: var(--mk-on-surface-variant); text-align: left;
      }
      .pk-row { display: flex; align-items: center; gap: 10px; }
      .pk-name { flex: 1; font-size: .88rem; text-align: left; }
      .pk-date { font-family: var(--mk-mono); font-size: .68rem; color: var(--mk-on-surface-variant); }
      .pk-this {
        font-family: var(--mk-mono); font-size: .58rem; letter-spacing: .12em;
        text-transform: uppercase; color: var(--mk-primary);
        padding: 2px 8px; border-radius: 999px;
        background: color-mix(in srgb, var(--mk-primary) 12%, transparent);
      }
      /* the row's form must NOT be the flow card: strip it entirely */
      .pk-row form {
        margin: 0; padding: 0; width: auto; display: inline-grid;
        background: none; border: 0; box-shadow: none; backdrop-filter: none;
        animation: none;
      }
      .pk-row form::before { display: none; }
      /* small round button, same family as the scheme switch pills */
      .pk-x {
        margin: 0; padding: 0; width: 28px; height: 28px;
        border: 1px solid transparent; border-radius: 50%;
        background: none; box-shadow: none; color: var(--mk-on-surface-variant);
        cursor: pointer; display: grid; place-items: center;
      }
      .pk-x svg { display: block; }
      .pk-x:hover {
        color: var(--mk-error); border-color: var(--mk-outline);
        background: var(--mk-surface-container); filter: none; box-shadow: none;
      }
      .pk-x:active { transform: none; }
      .hint-line { margin: 0; font-size: .74rem; color: var(--mk-on-surface-variant); }
    </style>
    <p class="lead">{{.T.security}}</p>
    {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
    <a class="mfa-link" href="/profile/mfa">
      <span class="mfa-label">{{.T.twoFactor}}</span>
      <span class="mfa-state{{if .MFAEnrolled}} on{{end}}">{{if .MFAEnrolled}}{{.T.mfaOn}}{{else if .MFARequired}}{{.T.mfaRequired}}{{else}}{{.T.mfaOff}}{{end}}</span>
    </a>
    <a class="mfa-link" href="/profile/password">
      <span class="mfa-label">{{.T.changePasswordLead}}</span>
      <span class="mfa-state">&rsaquo;</span>
    </a>
    <a class="mfa-link" href="/profile/history">
      <span class="mfa-label">{{.T.signinHistory}}</span>
      <span class="mfa-state">&rsaquo;</span>
    </a>
    {{if .APITokens}}
    <a class="mfa-link" href="/profile/tokens">
      <span class="mfa-label">{{.T.apiTokens}}</span>
      <span class="mfa-state">&rsaquo;</span>
    </a>
    {{end}}
    {{if .PasskeysAllowed}}
    <div class="sec">
      <span class="sec-title">{{.T.passkeys}}</span>
      {{range .Passkeys}}
      <div class="pk-row">
        <span class="pk-name">{{.Label}}</span>
        {{if .Current}}<span class="pk-this">{{$.T.thisBrowser}}</span>{{end}}
        <span class="pk-date">{{.Created}}</span>
        <form method="post" action="/profile/passkeys/delete">
          <input type="hidden" name="id" value="{{.ID}}">
          <button class="pk-x" type="submit" title="{{$.T.passkeyRemove}}" aria-label="{{$.T.passkeyRemove}}"><svg viewBox="0 -960 960 960" width="15" height="15" fill="currentColor" aria-hidden="true"><path d="m256-200-56-56 224-224-224-224 56-56 224 224 224-224 56 56-224 224 224 224-56 56-224-224-224 224Z"/></svg></button>
        </form>
      </div>
      {{end}}
      <button type="button" class="choice" id="pk-add">{{.T.addPasskey}}</button>
      <p class="hint-line" id="pk-msg" hidden></p>
    </div>
    <script>
    (() => {
      const b64d = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
      const b64e = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/[+]/g, '-').replace(/[/]/g, '_').replace(/=+$/, '');
      const btn = document.getElementById('pk-add');
      const msg = document.getElementById('pk-msg');
      if (!btn) return;
      if (!window.PublicKeyCredential) { btn.disabled = true; return; }
      btn.addEventListener('click', async () => {
        msg.hidden = true;
        try {
          const start = await fetch('/profile/passkeys/register/start', { method: 'POST' }).then((r) => r.json());
          const pk = start.options.publicKey;
          pk.challenge = b64d(pk.challenge);
          pk.user.id = b64d(pk.user.id);
          (pk.excludeCredentials || []).forEach((c) => { c.id = b64d(c.id); });
          const cred = await navigator.credentials.create({ publicKey: pk });
          const body = {
            id: cred.id, rawId: b64e(cred.rawId), type: cred.type,
            response: {
              attestationObject: b64e(cred.response.attestationObject),
              clientDataJSON: b64e(cred.response.clientDataJSON),
            },
          };
          const fin = await fetch('/profile/passkeys/register/finish?challenge=' + start.challenge, {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
          });
          if (!fin.ok) throw new Error(await fin.text());
          location.reload();
        } catch (e) {
          msg.textContent = String((e && e.message) || e);
          msg.hidden = false;
        }
      });
    })();
    </script>
    {{end}}
    <p class="back"><a href="/profile">{{.T.backToProfile}}</a></p>
`

// profileDevBody is the DEVELOPER hub: one entry per developer tool. Two for
// now — the public certificate (to plug services) and the API documentation —
// and room for more (the install command will land next to the cert). Each
// entry is a two-line link: what it is, and a short why.
const profileDevBody = `    <style>
      .dev-link {
        width: 100%; display: grid; gap: 3px; text-align: left;
        padding: 12px 14px; margin-top: 8px;
        border: 1px solid var(--mk-outline); border-radius: var(--mk-radius-small);
        background: var(--mk-surface-container); text-decoration: none;
      }
      .dev-link:hover { border-color: var(--mk-primary); filter: none; box-shadow: none; transform: none; }
      .dev-link .dl-row { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; }
      .dev-link .dl-label { font-size: .95rem; color: var(--mk-on-surface); }
      .dev-link .dl-state {
        font-family: var(--mk-mono); font-size: .62rem; letter-spacing: .14em;
        text-transform: uppercase; color: var(--mk-on-surface-variant);
      }
      .dev-link .dl-state.on { color: var(--mk-primary); }
      .dev-link .dl-desc { margin: 0; font-size: .76rem; color: var(--mk-on-surface-variant); }
    </style>
    <p class="lead">{{.T.developer}}</p>
    {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
    <a class="dev-link" href="/profile/dev/cert">
      <span class="dl-row">
        <span class="dl-label">{{.T.devCert}}</span>
        <span class="dl-state{{if .DevCertFingerprint}} on{{end}}">{{if .DevCertFingerprint}}{{.T.devCertSet}}{{else}}&rsaquo;{{end}}</span>
      </span>
      <p class="dl-desc">{{.T.devCertDesc}}</p>
    </a>
    <a class="dev-link" href="/meerkat/apidocs/">
      <span class="dl-row">
        <span class="dl-label">{{.T.devApi}}</span>
        <span class="dl-state">&rsaquo;</span>
      </span>
      <p class="dl-desc">{{.T.devApiDesc}}</p>
    </a>
    <p class="back"><a href="/profile">{{.T.backToProfile}}</a></p>
`

// profileDevCertBody is the certificate sub-page: paste a PUBLIC PEM so plugged
// services authenticate with it. (The install command will join it here.)
const profileDevCertBody = `    <style>
      .facts { margin: 0 0 8px; display: grid; gap: 10px; width: 100%; }
      .facts > div { display: flex; justify-content: space-between; align-items: baseline; gap: 14px; }
      .facts dt {
        font-family: var(--mk-mono); font-size: .62rem; letter-spacing: .16em;
        text-transform: uppercase; color: var(--mk-on-surface-variant);
      }
      .facts dd { margin: 0; text-align: right; overflow-wrap: anywhere; font-size: .92rem; }
      .dc-form { display: grid; gap: 8px; width: 100%; }
      .dc-form textarea {
        width: 100%; resize: vertical; padding: 8px 10px;
        font-family: var(--mk-mono); font-size: .68rem;
        background: var(--mk-surface-container); color: var(--mk-on-surface);
        border: 1px solid var(--mk-outline); border-radius: var(--mk-radius-small);
      }
      .dc-mono { font-family: var(--mk-mono); font-size: .72rem; }
      .dc-hint { margin: 0; font-size: .74rem; color: var(--mk-on-surface-variant); }
      .dc-clear {
        margin: 0; padding: 2px 10px; border: 0; background: none; box-shadow: none;
        color: var(--mk-on-surface-variant); font-size: .72rem; cursor: pointer; justify-self: start;
      }
      .dc-clear:hover { color: var(--mk-error); filter: none; box-shadow: none; transform: none; }
    </style>
    <p class="lead">{{.T.devCert}}</p>
    {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
    {{if .DevCertFingerprint}}
    <dl class="facts">
      {{if .DevCertSubject}}<div><dt>{{.T.devCertSubject}}</dt><dd>{{.DevCertSubject}}</dd></div>{{end}}
      <div><dt>{{.T.devCertFingerprint}}</dt><dd class="dc-mono">{{.DevCertFingerprint}}</dd></div>
      <div><dt>{{.T.devCertExpires}}</dt><dd>{{.DevCertExpires}}</dd></div>
    </dl>
    <form method="post" action="/profile/dev-cert">
      <input type="hidden" name="action" value="clear">
      <button class="dc-clear" type="submit">{{.T.devCertRemove}}</button>
    </form>
    {{else}}
    <form method="post" action="/profile/dev-cert" class="dc-form">
      <textarea name="cert" rows="5" placeholder="-----BEGIN CERTIFICATE-----" required></textarea>
      <button type="submit">{{.T.devCertSave}}</button>
    </form>
    <p class="dc-hint">{{.T.devCertHint}}</p>
    {{end}}
    <p class="back"><a href="/profile/dev">{{.T.backToDeveloper}}</a></p>
`

// faviconSVG is the sentinel in Sentinel cyan, squared for a browser tab —
// the same silhouette as the console's meerkat.svg, with fixed colors (a
// favicon has no CSS context). Served on BOTH planes under /meerkat/.
const faviconSVG = `<svg viewBox="-14 -4 72 72" xmlns="http://www.w3.org/2000/svg">
<path d="M29 43c8.2 1.8 11.4 8.8 8.1 17.1-.4 1-1.9 1-2.5.1-1.8-2.6-2.4-5.2-2.4-7.9 0-3.7-1.5-7.1-4.4-9.4z" fill="#25c2e0" opacity=".85"/>
<path d="M22 2c-4.8 0-8.6 3.8-8.6 8.6 0 2.5 1 4.7 2.7 6.3-3.5 3-5.7 7.9-5.7 14.6 0 13 5.1 23.1 11.6 23.1s11.6-10.1 11.6-23.1c0-6.7-2.2-11.6-5.7-14.6 1.7-1.6 2.7-3.8 2.7-6.3C30.6 5.8 26.8 2 22 2z" fill="#25c2e0"/>
<circle cx="15.4" cy="6.4" r="3.1" fill="#25c2e0"/>
<circle cx="28.6" cy="6.4" r="3.1" fill="#25c2e0"/>
<ellipse cx="18.3" cy="10.3" rx="1.8" ry="2.5" fill="#12222f"/>
<ellipse cx="25.7" cy="10.3" rx="1.8" ry="2.5" fill="#12222f"/>
<path d="M22 14l2.5 2.1-2.5 1.3-2.5-1.3z" fill="#12222f"/>
</svg>`

func (h *Handler) favicon(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write([]byte(faviconSVG))
}

// profilePasswordBody is the dedicated self-service change-password page, reached
// by a link from the profile (mirrors /profile/mfa). It needs the CURRENT
// password; on success the handler redirects back to /profile.
const profilePasswordBody = `    <form method="post" action="/profile/password">
      <p class="lead">{{.T.changePasswordLead}}</p>
      {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
      <label class="field">
        <span>{{.T.currentPassword}}</span>
        <input name="current" type="password" autocomplete="current-password" autofocus required>
      </label>
      <label class="field">
        <span>{{.T.newPassword}}</span>
        <input name="password" type="password" autocomplete="new-password" required minlength="8">
      </label>
      <label class="field">
        <span>{{.T.confirmPassword}}</span>
        <input name="confirm" type="password" autocomplete="new-password" required minlength="8">
      </label>
      <button type="submit">{{.T.changePassword}}</button>
    </form>
    <p class="back"><a href="/profile">{{.T.cancel}}</a></p>
    <style>
      .back { margin: 6px 0 0; text-align: center; font-size: .8rem; }
      .back a { color: var(--mk-primary); text-decoration: none; }
    </style>
`

// Handler serves the user-flow pages (login, select-tenant, logout). The two
// planes get different rules: the DATA plane runs the full flow — tenant
// selection (TENANT-03), working-hours enforcement (TENANT-04), resolved TTL
// (TENANT-05) — while the ADMIN plane stays a plain credentials check with the
// global TTL: operators are never locked out by application access windows,
// and the console needs no active tenant.
type Handler struct {
	st         *store.Store
	sm         *session.Manager
	adminPlane bool

	// Mailer sends outbound e-mail (confirmations, admin notifications). nil
	// behaves as "SMTP not configured"; main wires the real sender, tests a
	// recording fake.
	Mailer func(ctx context.Context, msg mail.Message) error

	// regLimit throttles the unauthenticated registration writes per IP.
	regLimit *rateLimiter

	themeMu     sync.Mutex
	themeCache  template.CSS
	brandCache  brandView
	themeReadAt time.Time
	langsCache  []string
	langsReadAt time.Time
}

// New builds the data-plane auth handler (full flow).
func New(st *store.Store, sm *session.Manager) *Handler {
	return &Handler{st: st, sm: sm, regLimit: newRateLimiter()}
}

// NewAdmin builds the admin-plane auth handler (credentials only).
func NewAdmin(st *store.Store, sm *session.Manager) *Handler {
	return &Handler{st: st, sm: sm, adminPlane: true, regLimit: newRateLimiter()}
}

// brandView is the branding as the templates consume it (THEME-02). LogoURL
// is template.URL because a validated data: URI must survive html/template's
// URL filter — store.SanitizeBranding is the gatekeeper.
type brandView struct {
	AppName string
	Tagline string
	LogoURL template.URL
	// Meerkat marks the ADMIN plane's built-in identity: the sentinel mark and
	// its pulse are Meerkat lore — an integrator's app gets a neutral
	// placeholder and no animation.
	Meerkat bool
}

func toBrandView(b store.Branding) brandView {
	return brandView{AppName: b.AppName, Tagline: b.Tagline, LogoURL: template.URL(b.Logo)} //nolint:gosec // sanitized data URI
}

// chrome returns the flow pages' shared skin — ACTIVE theme CSS + branding —
// cached briefly so pages never pay reads per request and pick changes up
// within seconds.
func (h *Handler) chrome() (template.CSS, brandView) {
	// The ADMIN plane keeps Meerkat's own look: the console is a product, not
	// the integrator's application — the theme editor only ever restyles the
	// DATA plane's flow pages (:8080).
	if h.adminPlane {
		brand := toBrandView(store.MeerkatBranding())
		brand.Meerkat = true
		return template.CSS(store.DefaultTheme().CSS()), brand //nolint:gosec // built-in constants
	}
	h.themeMu.Lock()
	defer h.themeMu.Unlock()
	if time.Since(h.themeReadAt) < 5*time.Second && h.themeCache != "" {
		return h.themeCache, h.brandCache
	}
	t, err := h.st.GetActiveTheme(context.Background())
	if err != nil {
		t = store.DefaultTheme()
	}
	b := store.DefaultBranding()
	if err := h.st.GetSetting(context.Background(), store.SettingBranding, &b); err != nil {
		b = store.DefaultBranding()
	}
	h.themeCache = template.CSS(t.CSS()) //nolint:gosec // store sanitizes hex-only tokens
	h.brandCache = toBrandView(b)
	h.themeReadAt = time.Now()
	return h.themeCache, h.brandCache
}

// WriteThemePreview renders the flow-page SPECIMEN (every element of the flow
// design system) with an arbitrary theme, one scheme forced — the console's
// theme editor iframes it twice, dark and light side by side. No session, no
// side effect.
func WriteThemePreview(w http.ResponseWriter, t store.Theme, b store.Branding, scheme string) {
	css := t.CSS()
	if scheme == "dark" || scheme == "light" {
		css += "\n    :root { color-scheme: " + scheme + "; }"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = specimenPage.Execute(w, struct {
		flowChrome
		Next  string
		Error string
	}{flowChrome: flowChrome{
		ThemeCSS: template.CSS(css), //nolint:gosec // store sanitizes hex-only tokens
		Brand:    toBrandView(b),
		Title:    "Theme preview · Meerkat",
		Lang:     "en",
		Langs:    []string{"en"},
		Scheme:   "auto",
		T:        messages["en"],
	}})
}

// Register mounts the auth endpoints on mux.
func (h *Handler) Register(mux *http.ServeMux) {
	if !h.adminPlane {
		mux.HandleFunc("GET /select-tenant", h.showSelectTenant)
		mux.HandleFunc("POST /select-tenant", h.doSelectTenant)
		mux.HandleFunc("GET /select-group", h.showSelectGroup)
		mux.HandleFunc("POST /select-group", h.doSelectGroup)
		mux.HandleFunc("GET /profile", h.showProfile)
		mux.HandleFunc("POST /profile/avatar", h.doProfileAvatar)
		mux.HandleFunc("POST /profile/dev-cert", h.doProfileDevCert)
		mux.HandleFunc("POST /profile/passkeys/register/start", h.passkeyRegisterStart)
		mux.HandleFunc("POST /profile/passkeys/register/finish", h.passkeyRegisterFinish)
		mux.HandleFunc("POST /profile/passkeys/delete", h.passkeyDelete)
		mux.HandleFunc("POST /login/passkey/start", h.passkeyLoginStart)
		mux.HandleFunc("POST /login/passkey/finish", h.passkeyLoginFinish)
		mux.HandleFunc("GET /profile/password", h.showProfilePassword)
		mux.HandleFunc("GET /profile/security", h.showProfileSecurity)
		mux.HandleFunc("GET /profile/history", h.showProfileHistory)
		// Personal API tokens (AUTH-16) — the pages 404 while the policy is off.
		mux.HandleFunc("GET /profile/tokens", h.showTokens)
		mux.HandleFunc("POST /profile/tokens", h.doTokens)
		mux.HandleFunc("GET /profile/dev", h.showProfileDev)
		mux.HandleFunc("GET /profile/dev/cert", h.showProfileDevCert)
		mux.HandleFunc("POST /profile/password", h.doProfilePassword)
		// Self-service second-factor management (MFA-01): enrol, renew, disable.
		mux.HandleFunc("GET /profile/mfa", h.showProfileMFA)
		mux.HandleFunc("POST /profile/mfa", h.doProfileMFA)
		// Self-registration (AUTH-20) — the pages 404 while the policy is off.
		mux.HandleFunc("GET /register", h.showRegister)
		mux.HandleFunc("POST /register", h.doRegister)
		mux.HandleFunc("POST /register/captcha", h.doRegisterCaptcha)
		mux.HandleFunc("GET /confirm", h.doConfirm)
		mux.HandleFunc("GET /account-pending", h.showAccountPending)
		// The injected <meerkat-user-button> web component (UI routes).
		h.registerUserButton(mux)
		// Issue reports filed from the component's panel (ISSUE-01).
		h.registerIssues(mux)
	}
	// External authentication (AUTH-19): one pair per redirect authority.
	mux.HandleFunc("GET /login/{provider}", h.startExternal)
	mux.HandleFunc("GET /login/{provider}/callback", h.finishExternal)

	mux.HandleFunc("GET /update-password", h.showUpdatePassword)
	mux.HandleFunc("POST /update-password", h.doUpdatePassword)
	// Forgot password (AUTH-21) — both planes, like /update-password; the
	// pages 404 while no SMTP is configured.
	mux.HandleFunc("GET /forgot-password", h.showForgot)
	mux.HandleFunc("POST /forgot-password", h.doForgot)
	mux.HandleFunc("GET /reset-password", h.showReset)
	mux.HandleFunc("POST /reset-password", h.doReset)
	// The MFA login-flow steps live on both planes (like /update-password): a
	// challenge for the enrolled, forced enrolment when MFA is mandatory.
	mux.HandleFunc("GET /totp", h.showTOTP)
	mux.HandleFunc("POST /totp", h.doTOTP)
	mux.HandleFunc("GET /totp-enroll", h.showTOTPEnroll)
	mux.HandleFunc("POST /totp-enroll", h.doTOTPEnroll)
	mux.HandleFunc("GET /meerkat/favicon.svg", h.favicon)
	mux.HandleFunc("GET /login", h.showLogin)
	mux.HandleFunc("POST /login", h.doLogin)
	mux.HandleFunc("POST /logout", h.doLogout)
}

func (h *Handler) showLogin(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, r.URL.Query().Get("next"), "", http.StatusOK)
}

// localPasswordAllowed says whether one may still come in with a LOCAL
// password (AUTH-24). The accounts held here are an authority in the list, and
// disabling it is what makes the remaining authorities exclusive: while it
// answers, every local password is a door that bypasses them.
//
// The ADMIN PLANE always says yes, and that is deliberate. The console is what
// one repairs a broken authority with; putting it behind that same authority
// is how an installation becomes unrecoverable at the worst possible moment.
func (h *Handler) localPasswordAllowed(ctx context.Context) bool {
	return h.adminPlane || h.st.LocalSignInEnabled(ctx)
}

// credentialFormOpen says whether the username/password form is still of any
// use. It closes only when NOTHING can answer it: local accounts disabled and
// no directory to ask — the form is not only the local password's, it is also
// how a directory is queried.
func (h *Handler) credentialFormOpen(ctx context.Context) bool {
	return h.localPasswordAllowed(ctx) || h.hasDirectory(ctx)
}

// anyWayIn: is there a single mechanism left that could sign someone in here?
// Every authority off closes the form, the buttons AND the passkeys, and the
// page then has nothing to offer but a sentence.
func (h *Handler) anyWayIn(ctx context.Context) bool {
	return h.credentialFormOpen(ctx) || len(h.redirectProviders(ctx)) > 0 ||
		(h.st.PasskeysAllowed(ctx) && h.anyAuthorityEnabled(ctx))
}

func (h *Handler) doLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	next := r.PostFormValue("next")

	// Brute-force throttle (SEC-10): FAILED attempts per IP+account within
	// the configured window; a success forgives. Refusing BEFORE the bcrypt
	// keeps a blocked attacker from burning CPU too.
	pol := h.st.GetRateLimitPolicy(r.Context())
	window := 15 * time.Minute
	if d, err := store.ParseISODuration(pol.LoginWindow); err == nil && d > 0 {
		window = d
	}
	loginKey := "login|" + clientIP(r) + "|" + strings.ToLower(username)
	if pol.LoginAttempts > 0 && h.regLimit.count(loginKey, window) >= pol.LoginAttempts {
		h.render(w, r, next, h.tr(r, "errTooManyAttempts"), http.StatusTooManyRequests)
		return
	}
	fail := func() {
		h.regLimit.hit(loginKey, window)
		h.render(w, r, next, h.tr(r, "errInvalidCreds"), http.StatusUnauthorized)
	}

	user, err := h.st.GetUserByUsername(r.Context(), username)
	// Same code path and same message whether the user is unknown or the
	// password is wrong (SEC-09: no account enumeration). A directory may
	// still know this pair, so it gets asked before the refusal — and an
	// account that exists here only as an external identity carries no local
	// hash, which never matches.
	if err != nil {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password)) // equalize timing
		if h.tryCredentialProviders(w, r, username, password, next) {
			h.regLimit.reset(loginKey)
			return
		}
		fail()
		return
	}
	// A password that is CORRECT but no longer accepted (AUTH-24) takes the
	// same path as a wrong one: the directories are still asked — someone whose
	// local and LDAP passwords match must come in through the directory — and
	// the refusal is worded identically, so nothing is enumerated.
	if user.PasswordHash == "" ||
		bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil ||
		!h.localPasswordAllowed(r.Context()) {
		if h.tryCredentialProviders(w, r, username, password, next) {
			h.regLimit.reset(loginKey)
			return
		}
		fail()
		return
	}
	// A disabled account answers exactly like a bad password (SEC-09), and its
	// disabling takes effect immediately (SEC-07) since sessions resolve users.
	if !user.Enabled {
		fail()
		return
	}
	h.regLimit.reset(loginKey)
	// A self-registered account stays unusable until its address is confirmed
	// (AUTH-20). Only revealed to someone holding the CORRECT password, and
	// the confirmation is re-sent (rate-limited) — the usual lost-mail rescue.
	if user.SelfRegistered && !user.EmailVerified {
		if h.registerAllow(clientIP(r)) {
			if err := h.sendConfirmation(r, user); err != nil {
				slog.Warn("confirmation re-send failed", "user", user.Username, "err", err)
			}
		}
		writeFlow(w, registerSentPage, struct{ flowChrome }{h.flowData(r, "titleRegister")}, http.StatusOK)
		return
	}

	// The destination is validated ONCE here (safeNext); it then rides on the
	// session, immutable by the client, through the rest of the flow.
	dest := safeNext(next)

	// AUTH-05 step 1: a temporary/expired password must be changed before
	// anything else — the session is issued with the step pending, and every
	// navigation is redirected to it until done (gateway + flow pages enforce).
	if user.MustChangePassword {
		h.issueAndGoPending(w, r, user, stepUpdatePassword, dest)
		return
	}

	// AUTH-05 step 2: the second factor. A fresh login issues the session stuck
	// on the MFA step; it is cleared once the code (or forced enrolment) passes.
	step, err := h.nextStepAfterPassword(r.Context(), user.ID, trustTokenOf(r))
	if err != nil {
		slog.Error("MFA step decision failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if step != "" {
		h.issueAndGoPending(w, r, user, step, dest)
		return
	}

	h.resolveTenantAndGo(w, r, user, dest, next, loginMethodPassword)
}

// resolveTenantAndGo issues the final session once the flow's earlier steps are
// clear: admin plane is done; on the data plane the active tenant is resolved
// 0/1/N (TENANT-03). method names how the user authenticated (history).
func (h *Handler) resolveTenantAndGo(w http.ResponseWriter, r *http.Request, user store.User, dest, next, method string) {
	if h.adminPlane {
		h.issueAndGo(w, r, user, "", dest, dest, method)
		return
	}

	memberships, err := h.activeMemberships(r.Context(), user.ID)
	if err != nil {
		slog.Error("memberships lookup failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	switch len(memberships) {
	case 0:
		// Confirmed but nothing granted yet: land on the waiting room instead
		// of the data plane's catch-all (AUTH-20) — unless a precise
		// destination was asked for.
		if waitingRoom(user, 0) && dest == "/" {
			dest = "/account-pending"
		}
		h.issueAndGo(w, r, user, "", dest, dest, method)
	case 1:
		tid := memberships[0].TenantID
		if !h.withinHours(r.Context(), user.ID, tid) {
			// A closed window is refused EXPLICITLY (TENANT-04) — unlike bad
			// credentials, there is nothing to enumerate here.
			h.render(w, r, next, h.tr(r, "errOutsideHours"), http.StatusForbidden)
			return
		}
		h.issueAndGo(w, r, user, tid, dest, dest, method)
	default:
		h.issueAndGo(w, r, user, "", dest, "/select-tenant", method)
	}
}

// issueAndGo resolves the applicable TTL (membership → tenant → global,
// TENANT-05), issues the session carrying the post-login destination `next`, and
// redirects to `dest` (usually `next`, or the select-tenant step).
func (h *Handler) issueAndGo(w http.ResponseWriter, r *http.Request, user store.User, tenantID, next, dest, method string) {
	ttl := 30 * time.Minute
	if iso, err := h.st.ResolveSessionTTL(r.Context(), user.ID, tenantID); err == nil {
		if d, err := store.ParseISODuration(iso); err == nil {
			ttl = d
		} else {
			slog.Warn("configured session TTL is invalid, using 30m", "ttl", iso, "err", err)
		}
	}
	// Exclusive group mode (RBAC-03): a lone group is stamped ON the fresh
	// session (the new cookie rides the response, not the request); several
	// groups land on the /select-group step after the redirect.
	groupID, groupChoice := h.groupForTenant(r.Context(), user.ID, tenantID)
	if groupChoice {
		dest = "/select-group"
	}
	if _, err := h.sm.IssueWith(r.Context(), w, r, user.ID, tenantID, groupID, ttl, "", next); err != nil {
		slog.Error("session issue failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := h.st.TouchLastConnection(r.Context(), user.ID); err != nil {
		slog.Warn("last connection stamp failed", "user", user.Username, "err", err)
	}
	// The session is issued: THIS is a completed sign-in (a refused window or
	// a failed issue above never lands in the history).
	h.recordLogin(w, r, user.ID, method)
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// AUTH-05 login-flow step slugs, in order: a forced password change, then the
// second factor (a challenge for an enrolled user, or forced enrolment when MFA
// is mandatory and the user has none), then tenant/group selection.
const (
	stepUpdatePassword = "update-password"
	stepTOTP           = "totp"        // enrolled: enter a code
	stepTOTPEnroll     = "totp-enroll" // required but not enrolled: set it up now
)

// nextStepAfterPassword decides which second-factor step (if any) a user owes
// once their password is accepted (MFA-01/04): an enrolled user is challenged,
// UNLESS this browser is trusted (MFA-03); a user with no factor is forced to
// enrol only when MFA is mandatory for them; otherwise "" — no step, proceed to
// tenant selection.
func (h *Handler) nextStepAfterPassword(ctx context.Context, userID, trustToken string) (string, error) {
	totp, err := h.st.GetUserTOTP(ctx, userID)
	if err != nil {
		return "", err
	}
	if totp.Enrolled {
		if h.browserTrusted(ctx, userID, trustToken) {
			return "", nil
		}
		return stepTOTP, nil
	}
	required, err := h.st.MFARequiredForUser(ctx, userID)
	if err != nil {
		return "", err
	}
	if required {
		return stepTOTPEnroll, nil
	}
	return "", nil
}

// issueAndGoPending issues a session stuck on a login-flow step: the global
// TTL applies (the tenant is not known yet) and every navigation redirects to
// the step until it completes.
func (h *Handler) issueAndGoPending(w http.ResponseWriter, r *http.Request, user store.User, pending, next string) {
	ttl := 30 * time.Minute
	if iso, err := h.st.ResolveSessionTTL(r.Context(), user.ID, ""); err == nil {
		if d, err := store.ParseISODuration(iso); err == nil {
			ttl = d
		}
	}
	if _, err := h.sm.IssueWith(r.Context(), w, r, user.ID, "", "", ttl, pending, next); err != nil {
		slog.Error("session issue failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// The destination now rides on the session — the step URL stays clean.
	http.Redirect(w, r, "/"+pending, http.StatusSeeOther)
}

// continueAfterStep resumes the flow once a step completed: on the data plane
// the tenant remains to be resolved (0/1/N — TENANT-03), on the admin plane we
// are done.
func (h *Handler) continueAfterStep(w http.ResponseWriter, r *http.Request, userID, next string) {
	if h.adminPlane {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	memberships, err := h.activeMemberships(r.Context(), userID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	switch len(memberships) {
	case 0:
		if next == "/" {
			if u, err := h.st.GetUserByID(r.Context(), userID); err == nil && waitingRoom(u, 0) {
				next = "/account-pending"
			}
		}
		http.Redirect(w, r, next, http.StatusSeeOther)
	case 1:
		if !h.withinHours(r.Context(), userID, memberships[0].TenantID) {
			h.render(w, r, next, h.tr(r, "errOutsideHours"), http.StatusForbidden)
			return
		}
		if err := h.sm.SetTenant(r.Context(), r, memberships[0].TenantID); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if h.applyGroupStep(r, userID, memberships[0].TenantID) {
			next = "/select-group"
		}
		http.Redirect(w, r, next, http.StatusSeeOther)
	default:
		http.Redirect(w, r, "/select-tenant", http.StatusSeeOther)
	}
}

type updatePasswordData struct {
	flowChrome
	Error string
}

// showUpdatePassword renders the forced password-change page (AUTH-05 step 1).
func (h *Handler) showUpdatePassword(w http.ResponseWriter, r *http.Request) {
	sess, err := h.sm.Resolve(r.Context(), r)
	if err != nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.String()), http.StatusSeeOther)
		return
	}
	if sess.Pending != stepUpdatePassword {
		// Not in the forced flow: nothing to do here. Self-service password
		// change (with the current password) belongs to the profile page.
		http.Redirect(w, r, safeNext(sess.Next), http.StatusSeeOther)
		return
	}
	h.renderUpdatePassword(w, r, "", http.StatusOK)
}

// doUpdatePassword replaces the password, clears the pending step and resumes
// the flow. The policy chantier (AUTH-10) will plug its validators here; until
// then a minimal length floor applies.
func (h *Handler) doUpdatePassword(w http.ResponseWriter, r *http.Request) {
	sess, err := h.sm.Resolve(r.Context(), r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if sess.Pending != stepUpdatePassword {
		// Outside the forced step this endpoint would let a hijacked session
		// take the account over without knowing the current password — refuse.
		http.Error(w, "no password change is pending on this session", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	password := r.PostFormValue("password")
	confirm := r.PostFormValue("confirm")
	if len(password) < 8 {
		h.renderUpdatePassword(w, r, h.tr(r, "errPwTooShort"), http.StatusUnprocessableEntity)
		return
	}
	if password != confirm {
		h.renderUpdatePassword(w, r, h.tr(r, "errPwMismatch"), http.StatusUnprocessableEntity)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := h.st.SetUserPassword(r.Context(), sess.UserID, string(hash), false); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.advanceAfterPassword(w, r, sess)
}

// advanceAfterPassword moves an existing session past the completed password
// step: onto the MFA step if the user owes one (AUTH-05 step 2), otherwise
// straight to tenant resolution.
func (h *Handler) advanceAfterPassword(w http.ResponseWriter, r *http.Request, sess store.Session) {
	step, err := h.nextStepAfterPassword(r.Context(), sess.UserID, trustTokenOf(r))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if step != "" {
		if err := h.sm.SetPending(r.Context(), r, step); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/"+step, http.StatusSeeOther)
		return
	}
	h.finishFlow(w, r, sess)
}

// finishFlow clears the login-flow step and resumes tenant resolution — the
// terminal transition once every AUTH-05 step (password, MFA) is satisfied.
func (h *Handler) finishFlow(w http.ResponseWriter, r *http.Request, sess store.Session) {
	if err := h.sm.ClearPending(r.Context(), r); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// The step just cleared names how this sign-in completed: through the
	// second factor, or password-only (forced password change without MFA).
	method := loginMethodPassword
	if sess.Pending == stepTOTP || sess.Pending == stepTOTPEnroll {
		method = loginMethodTOTP
	}
	h.recordLogin(w, r, sess.UserID, method)
	h.continueAfterStep(w, r, sess.UserID, safeNext(sess.Next))
}

func (h *Handler) renderUpdatePassword(w http.ResponseWriter, r *http.Request, errMsg string, status int) {
	writeFlow(w, updatePasswordPage, updatePasswordData{
		flowChrome: h.flowData(r, "titleUpdatePassword"), Error: errMsg}, status)
}

// profileData is the self-service profile page's model (the "Moi" scope). Each
// action (password, two-factor) is its own dedicated page reached by a link —
// nothing is edited inline here.
type profileData struct {
	flowChrome
	Avatar     template.URL
	Error      string
	Initials   string
	Username   string
	Fullname   string
	Email      string
	TenantName string
	IsDev      bool
	// Apps: the UI routes this session may open — the way back into the
	// applications from the profile flow.
	Apps []publicLink
}

// profileSecurityData drives the Security page: second factor, password,
// passkeys.
type profileSecurityData struct {
	flowChrome
	Error       string
	MFAEnrolled bool
	MFARequired bool
	// PasskeysAllowed mirrors the gateway-wide policy: when off the whole
	// passkey section disappears (the ceremonies refuse server-side too).
	PasskeysAllowed bool
	Passkeys        []passkeyView
	// APITokens mirrors the gateway-wide personal-token policy (AUTH-16).
	APITokens bool
}

// profileDevData drives the Developer hub AND its certificate sub-page (dev
// users only).
type profileDevData struct {
	flowChrome
	Error              string
	DevCertSubject     string
	DevCertFingerprint string
	DevCertExpires     string
}

// passkeyView is one profile row: name it, date it, revoke it.
type passkeyView struct {
	ID      string
	Label   string
	Created string
	// Current marks the passkey THIS browser registered or last used.
	Current bool
}

// showProfile renders the logged-in user's profile (data plane). A pending login
// step must be finished first.
func (h *Handler) showProfile(w http.ResponseWriter, r *http.Request) {
	sess, err := h.sm.Resolve(r.Context(), r)
	if err != nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.String()), http.StatusSeeOther)
		return
	}
	if sess.Pending != "" {
		http.Redirect(w, r, "/"+sess.Pending, http.StatusSeeOther)
		return
	}
	h.renderProfile(w, r, sess, "", http.StatusOK)
}

// profilePasswordData drives the dedicated self-service change-password page.
type profilePasswordData struct {
	flowChrome
	Error string
}

// showProfilePassword renders the dedicated change-password page (reached by a
// link from the profile — the same pattern as /profile/mfa).
func (h *Handler) showProfilePassword(w http.ResponseWriter, r *http.Request) {
	sess, err := h.sm.Resolve(r.Context(), r)
	if err != nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.String()), http.StatusSeeOther)
		return
	}
	if sess.Pending != "" {
		http.Redirect(w, r, "/"+sess.Pending, http.StatusSeeOther)
		return
	}
	h.renderProfilePassword(w, r, "", http.StatusOK)
}

func (h *Handler) renderProfilePassword(w http.ResponseWriter, r *http.Request, errMsg string, status int) {
	writeFlow(w, profilePasswordPage, profilePasswordData{
		flowChrome: h.flowData(r, "titleChangePassword"), Error: errMsg}, status)
}

// doProfilePassword is the SELF-SERVICE password change: it requires the current
// password (unlike the forced /update-password step). Errors re-render the
// dedicated page; success returns to the profile.
func (h *Handler) doProfilePassword(w http.ResponseWriter, r *http.Request) {
	sess, err := h.sm.Resolve(r.Context(), r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if sess.Pending != "" {
		http.Redirect(w, r, "/"+sess.Pending, http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	u, err := h.st.GetUserByID(r.Context(), sess.UserID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	current := r.PostFormValue("current")
	password := r.PostFormValue("password")
	confirm := r.PostFormValue("confirm")
	switch {
	case bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(current)) != nil:
		h.renderProfilePassword(w, r, h.tr(r, "errPwCurrentWrong"), http.StatusUnprocessableEntity)
		return
	case len(password) < 8:
		h.renderProfilePassword(w, r, h.tr(r, "errPwTooShort"), http.StatusUnprocessableEntity)
		return
	case password != confirm:
		h.renderProfilePassword(w, r, h.tr(r, "errPwMismatch"), http.StatusUnprocessableEntity)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := h.st.SetUserPassword(r.Context(), sess.UserID, string(hash), false); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/profile", http.StatusSeeOther)
}

// doProfileAvatar uploads (or clears) the user's profile photo: read, type-
// sniffed, size-bounded, stored as a data URI (offline-first — served back
// inline, no file storage, no external request).
func (h *Handler) doProfileAvatar(w http.ResponseWriter, r *http.Request) {
	sess, err := h.sm.Resolve(r.Context(), r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if sess.Pending != "" {
		http.Redirect(w, r, "/"+sess.Pending, http.StatusSeeOther)
		return
	}
	if err := r.ParseMultipartForm(512 << 10); err != nil {
		h.renderProfile(w, r, sess, h.tr(r, "errAvatarSize"), http.StatusRequestEntityTooLarge)
		return
	}
	if r.PostFormValue("step") == "clear" {
		if err := h.st.SetUserAvatar(r.Context(), sess.UserID, ""); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}
	file, _, err := r.FormFile("avatar")
	if err != nil {
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}
	defer func() { _ = file.Close() }()
	raw, err := io.ReadAll(io.LimitReader(file, 220_000+1))
	if err != nil || len(raw) > 220_000 {
		h.renderProfile(w, r, sess, h.tr(r, "errAvatarSize"), http.StatusRequestEntityTooLarge)
		return
	}
	var prefix string
	switch http.DetectContentType(raw) {
	case "image/png":
		prefix = "data:image/png;base64,"
	case "image/jpeg":
		prefix = "data:image/jpeg;base64,"
	case "image/webp":
		prefix = "data:image/webp;base64,"
	default:
		h.renderProfile(w, r, sess, h.tr(r, "errAvatarType"), http.StatusUnprocessableEntity)
		return
	}
	if err := h.st.SetUserAvatar(r.Context(), sess.UserID, prefix+base64.StdEncoding.EncodeToString(raw)); err != nil {
		h.renderProfile(w, r, sess, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	http.Redirect(w, r, "/profile", http.StatusSeeOther)
}

// doProfileDevCert stores or clears a DEVELOPER's public certificate — the
// credential their plugged service will authenticate with (dev plug
// matching). Devs only; the store validates the PEM.
func (h *Handler) doProfileDevCert(w http.ResponseWriter, r *http.Request) {
	sess, err := h.sm.Resolve(r.Context(), r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if sess.Pending != "" {
		http.Redirect(w, r, "/"+sess.Pending, http.StatusSeeOther)
		return
	}
	u, err := h.st.GetUserByID(r.Context(), sess.UserID)
	if err != nil || !u.Dev {
		http.Error(w, "developer capability required", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	cert := ""
	if r.PostFormValue("action") != "clear" {
		cert = strings.TrimSpace(r.PostFormValue("cert"))
	}
	if err := h.st.SetUserDevCert(r.Context(), sess.UserID, cert); err != nil {
		h.renderProfileDevCert(w, r, sess, h.tr(r, "errBadCert"), http.StatusUnprocessableEntity)
		return
	}
	http.Redirect(w, r, "/profile/dev/cert", http.StatusSeeOther)
}

// devCertView summarizes a stored PEM certificate for the profile page.
func devCertView(pemText string) (subject, fingerprint, expires string) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return
	}
	sum := sha256.Sum256(cert.Raw)
	fingerprint = hex.EncodeToString(sum[:8]) // enough to recognize it
	subject = cert.Subject.CommonName
	if subject == "" {
		subject = cert.Subject.String()
	}
	expires = cert.NotAfter.Format("2006-01-02")
	return
}

func (h *Handler) renderProfile(w http.ResponseWriter, r *http.Request, sess store.Session, errMsg string, status int) {
	data := profileData{flowChrome: h.flowData(r, "titleProfile"), Error: errMsg}
	if avatar, err := h.st.GetUserAvatar(r.Context(), sess.UserID); err == nil {
		data.Avatar = template.URL(avatar) //nolint:gosec // SanitizeAvatar gates writes
	}
	if u, err := h.st.GetUserByID(r.Context(), sess.UserID); err == nil {
		data.Username = u.Username
		data.Fullname = u.Fullname
		data.Email = u.Email
		data.Initials = initials(u)
		data.IsDev = u.Dev
	}
	if sess.TenantID != "" {
		if t, err := h.st.GetTenant(r.Context(), sess.TenantID); err == nil {
			data.TenantName = t.Name
		}
	}
	data.Apps = h.reachableLinks(r.Context(), sess)
	writeFlow(w, profilePage, data, status)
}

// showProfileSecurity renders the Security page: MFA state, password link,
// passkeys.
func (h *Handler) showProfileSecurity(w http.ResponseWriter, r *http.Request) {
	sess, err := h.sm.Resolve(r.Context(), r)
	if err != nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.String()), http.StatusSeeOther)
		return
	}
	if sess.Pending != "" {
		http.Redirect(w, r, "/"+sess.Pending, http.StatusSeeOther)
		return
	}
	h.renderProfileSecurity(w, r, sess, "", http.StatusOK)
}

func (h *Handler) renderProfileSecurity(w http.ResponseWriter, r *http.Request, sess store.Session, errMsg string, status int) {
	data := profileSecurityData{flowChrome: h.flowData(r, "titleSecurity"), Error: errMsg}
	if totp, err := h.st.GetUserTOTP(r.Context(), sess.UserID); err == nil {
		data.MFAEnrolled = totp.Enrolled
	}
	data.MFARequired, _ = h.st.MFARequiredForUser(r.Context(), sess.UserID)
	data.PasskeysAllowed = h.st.PasskeysAllowed(r.Context())
	data.APITokens = h.st.APITokensAllowed(r.Context())
	current := ""
	if c, err := r.Cookie(passkeyCookie); err == nil {
		current = c.Value
	}
	if keys, err := h.st.ListPasskeys(r.Context(), sess.UserID); err == nil {
		for _, k := range keys {
			data.Passkeys = append(data.Passkeys, passkeyView{
				ID: k.ID, Label: k.Label,
				Created: time.Unix(k.CreatedAt, 0).Format("2006-01-02"),
				Current: k.ID == current,
			})
		}
	}
	writeFlow(w, profileSecurityPage, data, status)
}

// showProfileDev renders the Developer page — dev capability required.
func (h *Handler) showProfileDev(w http.ResponseWriter, r *http.Request) {
	sess, err := h.sm.Resolve(r.Context(), r)
	if err != nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.String()), http.StatusSeeOther)
		return
	}
	if sess.Pending != "" {
		http.Redirect(w, r, "/"+sess.Pending, http.StatusSeeOther)
		return
	}
	u, err := h.st.GetUserByID(r.Context(), sess.UserID)
	if err != nil || !u.Dev {
		http.Error(w, "developer capability required", http.StatusForbidden)
		return
	}
	data := profileDevData{flowChrome: h.flowData(r, "titleDeveloper")}
	if cert, err := h.st.GetUserDevCert(r.Context(), sess.UserID); err == nil && cert != "" {
		data.DevCertSubject, data.DevCertFingerprint, data.DevCertExpires = devCertView(cert)
	}
	writeFlow(w, profileDevPage, data, http.StatusOK)
}

// showProfileDevCert renders the certificate sub-page.
func (h *Handler) showProfileDevCert(w http.ResponseWriter, r *http.Request) {
	sess, err := h.sm.Resolve(r.Context(), r)
	if err != nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.String()), http.StatusSeeOther)
		return
	}
	if sess.Pending != "" {
		http.Redirect(w, r, "/"+sess.Pending, http.StatusSeeOther)
		return
	}
	u, err := h.st.GetUserByID(r.Context(), sess.UserID)
	if err != nil || !u.Dev {
		http.Error(w, "developer capability required", http.StatusForbidden)
		return
	}
	h.renderProfileDevCert(w, r, sess, "", http.StatusOK)
}

func (h *Handler) renderProfileDevCert(w http.ResponseWriter, r *http.Request, sess store.Session, errMsg string, status int) {
	data := profileDevData{flowChrome: h.flowData(r, "titleDeveloper"), Error: errMsg}
	if cert, err := h.st.GetUserDevCert(r.Context(), sess.UserID); err == nil && cert != "" {
		data.DevCertSubject, data.DevCertFingerprint, data.DevCertExpires = devCertView(cert)
	}
	writeFlow(w, profileDevCertPage, data, status)
}

// initials builds a 1–2 letter avatar seed from the user's name (offline — no
// Gravatar).
func initials(u store.User) string {
	src := strings.TrimSpace(u.Fullname)
	if src == "" {
		src = u.Username
	}
	var out []rune
	for _, field := range strings.Fields(src) {
		if rs := []rune(field); len(rs) > 0 {
			out = append(out, unicode.ToUpper(rs[0]))
		}
		if len(out) >= 2 {
			break
		}
	}
	if len(out) == 0 {
		return "?"
	}
	return string(out)
}

// activeMemberships lists the tenants a user can actually enter: membership
// enabled AND tenant enabled.
func (h *Handler) activeMemberships(ctx context.Context, userID string) ([]store.UserTenant, error) {
	all, err := h.st.ListUserTenants(ctx, userID)
	if err != nil {
		return nil, err
	}
	active := all[:0]
	for _, t := range all {
		if t.Enabled {
			active = append(active, t)
		}
	}
	return active, nil
}

// withinHours evaluates the resolved working-hours window (TENANT-04). A
// broken configuration (bad timezone) fails OPEN with a warning — a config
// mistake must not lock every user out.
func (h *Handler) withinHours(ctx context.Context, userID, tenantID string) bool {
	ba, err := h.st.ResolveBusinessAccess(ctx, userID, tenantID)
	if err != nil {
		slog.Warn("business access resolution failed, allowing", "err", err)
		return true
	}
	ok, err := store.WithinBusinessAccess(ba, time.Now())
	if err != nil {
		slog.Warn("business access misconfigured, allowing", "err", err)
		return true
	}
	return ok
}

type selectTenantData struct {
	flowChrome
	Tenants []store.UserTenant
	Error   string
}

// showSelectTenant lists the tenants the signed-in user may enter
// (TENANT-03). With one or none there is nothing to choose — pass through.
func (h *Handler) showSelectTenant(w http.ResponseWriter, r *http.Request) {
	sess, err := h.sm.Resolve(r.Context(), r)
	if err != nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.String()), http.StatusSeeOther)
		return
	}
	if sess.Pending != "" {
		http.Redirect(w, r, "/"+sess.Pending, http.StatusSeeOther)
		return
	}
	next := safeNext(sess.Next)
	memberships, err := h.activeMemberships(r.Context(), sess.UserID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	switch len(memberships) {
	case 0:
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	case 1:
		// Nothing to choose — stamp the only tenant (hours-checked) and go.
		if !h.withinHours(r.Context(), sess.UserID, memberships[0].TenantID) {
			h.render(w, r, next, h.tr(r, "errOutsideHours"), http.StatusForbidden)
			return
		}
		if err := h.sm.SetTenant(r.Context(), r, memberships[0].TenantID); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if h.applyGroupStep(r, sess.UserID, memberships[0].TenantID) {
			next = "/select-group"
		}
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	h.renderSelect(w, r, memberships, "", http.StatusOK)
}

// doSelectTenant records the choice on the session after checking the
// membership and the working-hours window of the chosen tenant.
func (h *Handler) doSelectTenant(w http.ResponseWriter, r *http.Request) {
	sess, err := h.sm.Resolve(r.Context(), r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if sess.Pending != "" {
		http.Redirect(w, r, "/"+sess.Pending, http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	choice := r.PostFormValue("tenant")
	next := safeNext(sess.Next)
	// An in-session switch (the user button) carries the CURRENT page.
	if f := r.PostFormValue("next"); f != "" {
		next = safeNext(f)
	}
	memberships, err := h.activeMemberships(r.Context(), sess.UserID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var chosen *store.UserTenant
	for i := range memberships {
		if memberships[i].TenantID == choice {
			chosen = &memberships[i]
			break
		}
	}
	if chosen == nil {
		h.renderSelect(w, r, memberships, h.tr(r, "errTenantForbidden"), http.StatusForbidden)
		return
	}
	if !h.withinHours(r.Context(), sess.UserID, chosen.TenantID) {
		h.renderSelect(w, r, memberships,
			fmt.Sprintf(h.tr(r, "errTenantRefused"), chosen.TenantName), http.StatusForbidden)
		return
	}
	if err := h.sm.SetTenant(r.Context(), r, chosen.TenantID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Groups are per tenant: the switch reset the active group; in exclusive
	// mode with several groups the user picks again for THIS tenant.
	if h.applyGroupStep(r, sess.UserID, chosen.TenantID) {
		http.Redirect(w, r, "/select-group?next="+url.QueryEscape(next), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (h *Handler) renderSelect(w http.ResponseWriter, r *http.Request, tenants []store.UserTenant, errMsg string, status int) {
	writeFlow(w, selectTenantPage, selectTenantData{
		flowChrome: h.flowData(r, "titleChooseTenant"), Tenants: tenants, Error: errMsg}, status)
}

func (h *Handler) doLogout(w http.ResponseWriter, r *http.Request) {
	if err := h.sm.Destroy(r.Context(), w, r); err != nil {
		slog.Error("logout failed", "err", err)
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *Handler) render(w http.ResponseWriter, r *http.Request, next, errMsg string, status int) {
	writeFlow(w, loginPage, struct {
		flowChrome
		Next     string
		Error    string
		Public   []publicLink
		Passkeys bool // the gateway-wide policy shows/hides the passkey sign-in
		Register bool // self-registration open (policy on + SMTP ready)
		Forgot   bool // password reset available (SMTP ready)
		// Providers are the redirect authorities (AUTH-19), one button each.
		// A directory needs no button: it answers the ordinary form.
		Providers []externalProvider
		// Credentials shows the username/password form. It serves TWO
		// mechanisms, which is why closing the local password does not always
		// close the form: a directory is asked through this very field.
		Credentials bool
		// Shut: nothing on this page can let anyone in. Said plainly and
		// WITHOUT saying why — which door is closed is nobody's business but
		// the administrator's.
		Shut bool
	}{flowChrome: h.flowData(r, "titleSignIn"), Next: next, Error: errMsg,
		Public: h.publicLinks(r.Context()),
		// A passkey is a shortcut to an authority: with every one of them off,
		// it opens nothing, so it is not offered.
		Passkeys: h.st.PasskeysAllowed(r.Context()) && h.anyAuthorityEnabled(r.Context()),
		Register: h.selfRegisterOpen(r.Context()), Forgot: h.forgotOpen(r),
		Providers:   h.redirectProviders(r.Context()),
		Credentials: h.credentialFormOpen(r.Context()),
		Shut:        !h.anyWayIn(r.Context())}, status)
}

// publicLink is one UI route reachable without signing in, offered on the
// login page under the form.
type publicLink struct {
	Name string
	Href string
}

// publicLinks lists the enabled, unauthenticated UI routes that expose a
// usable entry path. API routes are not navigation targets and stay out —
// and so does the ADMIN plane's login: application routes are a data-plane
// affair, the console offers nothing anonymous.
func (h *Handler) publicLinks(ctx context.Context) []publicLink {
	if h.adminPlane {
		return nil
	}
	routes, err := h.st.ListRoutes(ctx)
	if err != nil {
		return nil
	}
	var links []publicLink
	for _, rt := range routes {
		// Listed = a UI route that opted in with a menu Link, public (no gateway
		// gate: empty Access, delegated to the upstream), reachable without a
		// session. The Link is the displayed label.
		if !rt.Enabled || !rt.Access.Empty() || !rt.IsUI || rt.UI == nil || rt.UI.Link == "" {
			continue
		}
		if href := routeEntryPath(rt); href != "" {
			links = append(links, publicLink{Name: rt.UI.Link, Href: href})
		}
	}
	return links
}

// reachableLinks lists the UI routes THIS session may open: the public ones,
// the authenticated ones (the caller is signed in), and the role-gated ones
// whose role the active tenant actually grants. This feeds the profile hub
// and the user-button's Applications submenu — the way back into the apps.
func (h *Handler) reachableLinks(ctx context.Context, sess store.Session) []publicLink {
	if h.adminPlane {
		return nil
	}
	routes, err := h.st.ListRoutes(ctx)
	if err != nil {
		return nil
	}
	// The caller, to test each route's Access. Memberships are NOT filled in:
	// this list is what one can open right now, in the organisation currently
	// active — offering a link that would land on the tenant chooser would be
	// offering a detour, not an application.
	caller := store.Caller{Authenticated: true, TenantID: sess.TenantID}
	if u, err := h.st.GetUserByID(ctx, sess.UserID); err == nil {
		caller.Username = u.Username
	}
	if names, err := h.st.SessionRoleNames(ctx, sess.UserID, sess.TenantID, sess.GroupID); err == nil {
		caller.Roles = names
	}
	var links []publicLink
	for _, rt := range routes {
		// Only UI routes that opted into the apps menu with a Link, and only
		// when the caller's access grants them (an empty Access is public). The
		// Link is the displayed label.
		if !rt.Enabled || !rt.IsUI || rt.UI == nil || rt.UI.Link == "" {
			continue
		}
		if !rt.Access.Grants(caller) {
			continue
		}
		if href := routeEntryPath(rt); href != "" {
			links = append(links, publicLink{Name: rt.UI.Link, Href: href})
		}
	}
	return links
}

// routeEntryPath derives a clickable entry URL from the route's first path
// pattern: the literal prefix before any wildcard ("/demo/**" -> "/demo").
func routeEntryPath(rt store.Route) string {
	for _, p := range rt.Predicates {
		if p.Type != "path" {
			continue
		}
		patterns, _ := p.Args["patterns"].([]any)
		for _, raw := range patterns {
			s, _ := raw.(string)
			if i := strings.IndexAny(s, "*{"); i >= 0 {
				s = s[:i]
			}
			s = strings.TrimSuffix(s, "/")
			if s == "" {
				s = "/"
			}
			if strings.HasPrefix(s, "/") {
				return s
			}
		}
	}
	return ""
}

// dummyHash keeps the failure path constant-time-ish for unknown users.
var dummyHash = func() []byte {
	h, _ := bcrypt.GenerateFromPassword([]byte("meerkat-dummy"), bcrypt.DefaultCost)
	return h
}()

// safeNext only allows same-site relative redirects — never an absolute URL
// (open-redirect guard).
// safeNext validates a post-login redirect target against open-redirect abuse:
// only a clean SAME-ORIGIN path is allowed, anything else collapses to "/". It
// rejects protocol-relative ("//host"), backslash tricks ("/\\host" — browsers
// fold "\" into "/"), control characters (tab/newline get stripped and can
// smuggle "//"), and absolute URLs (scheme or host).
func safeNext(next string) string {
	if next == "" || next[0] != '/' || strings.HasPrefix(next, "//") {
		return "/"
	}
	for _, c := range next {
		if c == '\\' || c < 0x20 || c == 0x7f {
			return "/"
		}
	}
	if u, err := url.Parse(next); err != nil || u.IsAbs() || u.Host != "" || u.Scheme != "" {
		return "/"
	}
	return next
}

// SeedAdmin creates the first root account when no user exists. The password
// comes from MEERKAT_ADMIN_PASSWORD, or is generated and printed once — the
// proper first-start setup page (LIFE-01) will replace this.
func SeedAdmin(ctx context.Context, st *store.Store) error {
	n, err := st.CountUsers(ctx)
	if err != nil || n > 0 {
		return err
	}
	password := os.Getenv("MEERKAT_ADMIN_PASSWORD")
	generated := password == ""
	if generated {
		raw := make([]byte, 12)
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		password = base64.RawURLEncoding.EncodeToString(raw)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if err := st.CreateUser(ctx, store.User{
		ID: "admin", Username: "admin", PasswordHash: string(hash),
		Fullname: "Administrator", Enabled: true, Root: true, EmailVerified: true,
		// A generated password is printed once — force a change at first login.
		MustChangePassword: generated,
	}); err != nil {
		return err
	}
	if generated {
		slog.Warn("first start: admin account created — change this password",
			"username", "admin", "password", password)
	} else {
		slog.Info("first start: admin account created from MEERKAT_ADMIN_PASSWORD", "username", "admin")
	}
	return nil
}
