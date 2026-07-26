import { Component, computed, signal } from '@angular/core';

// The Test coverage page renders e2e/scenarios.json VERBATIM (wired as an
// asset at build time): the exact matrix the Playwright suite executes. One
// source of truth — if a scenario shows here, a test enforces it.

interface Profile {
  id: string;
  username: string;
  en: string;
  fr: string;
}

interface Scenario {
  id: string;
  domain: string;
  kind: 'api' | 'ui' | 'flow';
  probe?: { method: string; path: string };
  allowed: string[];
  title: Record<string, string>;
  description: Record<string, string>;
}

interface ScenariosFile {
  profiles: Profile[];
  scenarios: Scenario[];
}

const DOMAIN_LABELS: Record<string, Record<string, string>> = {
  gateway: { en: 'Gateway scope', fr: 'Périmètre gateway' },
  application: { en: 'Application scope', fr: 'Périmètre application' },
  tenant: { en: 'Tenant scope', fr: 'Périmètre tenant' },
  console: { en: 'Console navigation', fr: 'Navigation console' },
  auth: { en: 'Sign-in and profile flows', fr: 'Flux de connexion et profil' },
};

@Component({
  selector: 'app-tests',
  imports: [],
  styles: [
    `
      .lang {
        float: right;
        display: flex;
        gap: 4px;
      }
      .lang button {
        border: 1px solid var(--border-color);
        background: var(--bg-secondary);
        color: var(--text-primary);
        border-radius: 6px;
        padding: 3px 10px;
        cursor: pointer;
        font-size: 0.8em;
      }
      .lang button.on {
        border-color: var(--accent, #25c2e0);
        color: var(--accent, #25c2e0);
      }
      .profiles {
        display: grid;
        gap: 6px;
        margin: 12px 0 20px;
      }
      .profiles code {
        margin-right: 6px;
      }
      .scenario {
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 12px 16px;
        margin: 10px 0;
        background: var(--bg-secondary);
      }
      .scenario h4 {
        margin: 0;
        display: flex;
        align-items: center;
        gap: 8px;
      }
      .kind {
        font-size: 0.65em;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        border: 1px solid var(--border-color);
        border-radius: 999px;
        padding: 2px 8px;
        color: var(--text-secondary, var(--text-primary));
      }
      .scenario p {
        margin: 8px 0;
      }
      .probe {
        font-family: 'Courier New', Consolas, monospace;
        font-size: 0.82em;
        color: var(--text-secondary, var(--text-primary));
      }
      .chips {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
        margin-top: 8px;
      }
      .chip {
        font-size: 0.78em;
        border-radius: 999px;
        padding: 2px 10px;
        border: 1px solid transparent;
      }
      .chip.ok {
        color: #2e9e5b;
        border-color: color-mix(in srgb, #2e9e5b 45%, transparent);
        background: color-mix(in srgb, #2e9e5b 10%, transparent);
      }
      .chip.no {
        color: #c65454;
        border-color: color-mix(in srgb, #c65454 40%, transparent);
        background: color-mix(in srgb, #c65454 8%, transparent);
        text-decoration: line-through;
      }
    `,
  ],
  template: `
    <div class="lang">
      <button [class.on]="lang() === 'en'" (click)="lang.set('en')">EN</button>
      <button [class.on]="lang() === 'fr'" (click)="lang.set('fr')">FR</button>
    </div>
    <h2>{{ lang() === 'fr' ? 'Couverture de tests' : 'Test coverage' }}</h2>

    <p>
      {{
        lang() === 'fr'
          ? "Cette page rend le fichier exact que la suite d'intégration Playwright exécute (e2e/scenarios.json) : chaque scénario est joué avec chacun des profils ci-dessous, en vérifiant que les profils autorisés passent ET que tous les autres sont refusés."
          : 'This page renders the exact file the Playwright integration suite executes (e2e/scenarios.json): every scenario runs as each of the profiles below, checking both that allowed profiles succeed AND that every other profile is refused.'
      }}
    </p>

    @if (data(); as d) {
      <h3>{{ lang() === 'fr' ? 'Profils' : 'Profiles' }}</h3>
      <div class="profiles">
        @for (p of d.profiles; track p.id) {
          <div><code>{{ p.id }}</code> {{ lang() === 'fr' ? p.fr : p.en }}</div>
        }
      </div>

      @for (domain of domains(); track domain) {
        <h3>{{ domainLabel(domain) }}</h3>
        @for (sc of byDomain(domain); track sc.id) {
          <div class="scenario">
            <h4>
              {{ sc.title[lang()] }}
              <span class="kind">{{ sc.kind }}</span>
            </h4>
            @if (sc.probe) {
              <div class="probe">{{ sc.probe.method }} {{ sc.probe.path }}</div>
            }
            <p>{{ sc.description[lang()] }}</p>
            @if (sc.allowed.length) {
              <div class="chips">
                @for (p of d.profiles; track p.id) {
                  <span class="chip" [class.ok]="sc.allowed.includes(p.id)" [class.no]="!sc.allowed.includes(p.id)">
                    {{ p.id }}
                  </span>
                }
              </div>
            }
          </div>
        }
      }
    } @else {
      <p>…</p>
    }
  `,
})
export class TestsComponent {
  protected readonly lang = signal<'en' | 'fr'>('en');
  protected readonly data = signal<ScenariosFile | null>(null);

  protected readonly domains = computed(() => {
    const d = this.data();
    if (!d) return [];
    return [...new Set(d.scenarios.map((s) => s.domain))];
  });

  constructor() {
    fetch(new URL('assets/scenarios.json', document.baseURI))
      .then((r) => r.json())
      .then((d: ScenariosFile) => this.data.set(d))
      .catch(() => this.data.set({ profiles: [], scenarios: [] }));
  }

  protected byDomain(domain: string): Scenario[] {
    return this.data()?.scenarios.filter((s) => s.domain === domain) ?? [];
  }

  protected domainLabel(domain: string): string {
    return DOMAIN_LABELS[domain]?.[this.lang()] ?? domain;
  }
}
