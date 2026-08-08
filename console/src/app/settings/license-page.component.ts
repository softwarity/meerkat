import { Component, computed, inject, signal } from '@angular/core';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { LoadingIndicatorComponent } from '@softwarity/loading-indicator';
import { ApiService, Edition } from '../api.service';

// What this installation IS, in one place - and the only screen that talks
// about editions at all. Everywhere else, an Enterprise control simply carries
// its [Enterprise] cap and links here; repeating the pitch on ten screens
// would turn the console into an advert.
//
// Read-only on purpose. The mode is not switched from here either: it is
// switched where organisations are administered, because that is where someone
// can see what it costs them.
interface FeatureRow {
  key: string;
  label: string;
  what: string;
  on: boolean;
}

@Component({
  selector: 'app-license-page',
  imports: [MatCardModule, MatIconModule, MatTooltipModule, LoadingIndicatorComponent],
  template: `
    <div class="banner">
      <h1 i18n="@@License">License</h1>
    </div>

    @if (loading()) {
      <loading-indicator withContainer />
    } @else if (edition(); as e) {
      <div class="content">
        <mat-card appearance="outlined" class="edition">
          <div class="line">
            <mat-icon>{{ e.enterprise ? 'workspace_premium' : 'public' }}</mat-icon>
            <div class="grow">
              <div class="title">
                @if (e.enterprise) {
                  <ng-container i18n="@@Enterprise_edition">Enterprise edition</ng-container>
                } @else {
                  <ng-container i18n="@@Community_edition">Community edition</ng-container>
                }
              </div>
              <p class="hint" i18n="@@License_perpetual_hint">
                A license is perpetual: what it unlocks stays unlocked, and an elapsed term never
                switches anything off. It says how far updates are covered, nothing more.
              </p>
            </div>
          </div>
        </mat-card>

        @if (hidden() > 0) {
          <mat-card appearance="outlined" class="warn">
            <div class="line">
              <mat-icon>visibility_off</mat-icon>
              <div class="grow">
                <div class="title" i18n="@@Organisations_held_back">
                  {{ hidden() }} organisations are not being served
                </div>
                <p class="hint" i18n="@@Organisations_held_back_hint">
                  Single-organisation mode serves the first one. Nothing is deleted: the others come
                  back the moment the mode is switched, and the people in them regain access then.
                </p>
              </div>
            </div>
          </mat-card>
        }

        <mat-card appearance="outlined">
          <h3 i18n="@@Features">Features</h3>
          <div class="features">
            @for (f of rows(); track f.key) {
              <div class="feature" [class.on]="f.on">
                <mat-icon>{{ f.on ? 'check_circle' : 'lock' }}</mat-icon>
                <div class="grow">
                  <div class="name">{{ f.label }}</div>
                  <div class="what">{{ f.what }}</div>
                </div>
              </div>
            }
          </div>
        </mat-card>
      </div>
    }
  `,
  styles: [
    `
      :host {
        display: flex;
        flex-direction: column;
        height: 100%;
        min-height: 0;
      }
      .banner {
        display: flex;
        align-items: center;
        gap: 16px;
        padding: 12px 24px;
        flex: none;
      }
      .banner h1 {
        font-size: 1.15rem;
        font-weight: 500;
        margin: 0;
        flex: 1;
      }
      .content {
        flex: 1 1 auto;
        min-height: 0;
        overflow-y: auto;
        padding: 0 24px 24px;
        display: grid;
        gap: 16px;
        max-width: 860px;
      }
      mat-card {
        padding: 20px 24px;
      }
      .line {
        display: flex;
        align-items: flex-start;
        gap: 16px;
      }
      .line > mat-icon {
        flex-shrink: 0;
        color: var(--mat-sys-on-surface-variant);
      }
      .edition .line > mat-icon {
        color: var(--mat-sys-tertiary);
      }
      .warn {
        border-color: var(--mat-sys-error);
      }
      .warn .line > mat-icon {
        color: var(--mat-sys-error);
      }
      .grow {
        flex: 1;
        min-width: 0;
      }
      .title {
        font-weight: 500;
      }
      h3 {
        margin: 0 0 12px;
        font-size: 1rem;
        font-weight: 500;
      }
      .hint {
        margin: 4px 0 0;
        font-size: 0.85rem;
        color: var(--mat-sys-on-surface-variant);
      }
      .features {
        display: grid;
        gap: 10px;
      }
      .feature {
        display: flex;
        align-items: flex-start;
        gap: 12px;
        opacity: 0.6;
      }
      .feature.on {
        opacity: 1;
      }
      .feature mat-icon {
        flex-shrink: 0;
        font-size: 20px;
        width: 20px;
        height: 20px;
        color: var(--mat-sys-outline);
      }
      .feature.on mat-icon {
        color: var(--mk-signal);
      }
      .name {
        font-weight: 500;
        font-size: 0.9rem;
      }
      .what {
        font-size: 0.82rem;
        color: var(--mat-sys-on-surface-variant);
      }
    `,
  ],
})
export class LicensePageComponent {
  private readonly api = inject(ApiService);

  protected readonly loading = signal(true);
  protected readonly edition = signal<Edition | null>(null);
  protected readonly hidden = computed(() => this.edition()?.hiddenTenants ?? 0);

  // What each key BUYS, in one sentence. Written here rather than served by the
  // API because it is marketing copy in the console's language, and the server
  // has no business holding translated prose.
  private readonly copy: Record<string, { label: string; what: string }> = {
    'multi-tenant': {
      label: $localize`:@@Feature_multi_tenant:Several organisations`,
      what: $localize`:@@Feature_multi_tenant_what:Isolate tenants, each with its own groups, members and hours. Without it there is one, and the console never names it.`,
    },
    directories: {
      label: $localize`:@@Feature_directories:Directories`,
      what: $localize`:@@Feature_directories_what:Plug an LDAP directory, an Active Directory or Kerberos in straight, and map their groups onto yours.`,
    },
    saml: {
      label: $localize`:@@Feature_saml:SAML`,
      what: $localize`:@@Feature_saml_what:Federate with a SAML identity provider, for the estates that have one and nothing else.`,
    },
    scim: {
      label: $localize`:@@Feature_scim:SCIM provisioning`,
      what: $localize`:@@Feature_scim_what:Accounts created and, above all, deactivated automatically when someone leaves.`,
    },
    'business-hours': {
      label: $localize`:@@Feature_business_hours:Working hours`,
      what: $localize`:@@Feature_business_hours_what:Refuse access outside declared hours, gateway-wide, per organisation or per person.`,
    },
    cluster: {
      label: $localize`:@@Feature_cluster:High availability`,
      what: $localize`:@@Feature_cluster_what:Several instances behind the same database, with sessions shared between them.`,
    },
    'audit-export': {
      label: $localize`:@@Feature_audit_export:Audit export`,
      what: $localize`:@@Feature_audit_export_what:Continuous export to a SIEM and long retention. Reading the trail is free and stays free.`,
    },
    'white-label': {
      label: $localize`:@@Feature_white_label:White label`,
      what: $localize`:@@Feature_white_label_what:Remove the Meerkat mark from the sign-in pages your users see.`,
    },
  };

  protected readonly rows = computed<FeatureRow[]>(() => {
    const e = this.edition();
    if (!e) return [];
    return e.known.map((key) => ({
      key,
      label: this.copy[key]?.label ?? key,
      what: this.copy[key]?.what ?? '',
      on: e.features.includes(key),
    }));
  });

  constructor() {
    this.api.edition().subscribe({
      next: (e) => {
        this.edition.set(e);
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }
}
