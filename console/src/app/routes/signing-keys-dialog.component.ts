import { Component, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatDialogModule } from '@angular/material/dialog';
import { MatExpansionModule } from '@angular/material/expansion';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatTooltipModule } from '@angular/material/tooltip';
import { ApiService, SigningKeys } from '../api.service';

// The identity JWT signing keys (signed-jwt): the JWKS the backends should
// verify against (the recommended path), plus each algorithm's PUBLIC key as a
// collapsed static fallback, and a rotate button. Reached from the Routes page.
// Private keys stay on the server — only public halves are shown.
@Component({
  selector: 'app-signing-keys-dialog',
  imports: [
    MatButtonModule,
    MatDialogModule,
    MatExpansionModule,
    MatIconModule,
    MatProgressBarModule,
    MatTooltipModule,
  ],
  styles: [
    `
      :host {
        display: block;
        max-width: 640px;
      }
      .workflow {
        margin: 0 0 16px;
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.85rem;
        line-height: 1.45;
      }
      .jwks {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 12px 14px;
        border-radius: var(--mk-radius);
        border: 1px solid color-mix(in srgb, var(--mk-signal) 45%, transparent);
        background: color-mix(in srgb, var(--mk-signal) 8%, var(--mat-sys-surface-container));
      }
      .jwks .col {
        display: flex;
        flex-direction: column;
        min-width: 0;
      }
      .jwks .lbl {
        display: flex;
        align-items: center;
        gap: 6px;
        font-size: 0.72rem;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        color: var(--mat-sys-on-surface-variant);
      }
      .jwks .badge {
        text-transform: none;
        letter-spacing: 0;
        padding: 0 6px;
        border-radius: 999px;
        background: var(--mk-signal);
        color: var(--mat-sys-on-secondary, #003);
        font-weight: 600;
      }
      .jwks .path {
        font-family: var(--mk-mono);
        font-size: 0.85rem;
        word-break: break-all;
      }
      .spacer {
        flex: 1;
      }
      .fallback {
        margin: 18px 0 8px;
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.8rem;
      }
      .key .alg {
        font-family: var(--mk-mono);
        font-weight: 600;
      }
      .key .kid {
        font-family: var(--mk-mono);
        font-size: 0.72rem;
        color: var(--mat-sys-on-surface-variant);
        margin-right: 10px;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      /* The PEM WRAPS (no horizontal scrollbar): newlines kept, the long base64
         lines break within the box. */
      pre.pem {
        margin: 4px 0 0;
        padding: 8px 10px;
        border-radius: 8px;
        background: var(--mat-sys-surface-container-low);
        font-family: var(--mk-mono);
        font-size: 0.72rem;
        line-height: 1.35;
        white-space: pre-wrap;
        word-break: break-all;
        overflow-x: hidden;
      }
      .warn {
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.82rem;
        margin-right: auto;
      }
    `,
  ],
  template: `
    <h2 mat-dialog-title i18n="@@JWT_signing_keys">JWT signing keys</h2>
    @if (loading()) {
      <mat-progress-bar mode="indeterminate" />
    }
    <mat-dialog-content>
      <p class="workflow" i18n="@@Signing_keys_workflow">
        The gateway signs each identity token with its private key (which never leaves the server).
        Backends fetch this JWKS once, cache it, and verify each token by its key id. Rotation is then
        picked up on its own.
      </p>
      @if (data(); as d) {
        <div class="jwks">
          <div class="col">
            <span class="lbl">
              <ng-container i18n="@@JWKS_endpoint">JWKS (data plane)</ng-container>
              <span class="badge" i18n="@@Recommended">Recommended</span>
            </span>
            <code class="path">{{ d.jwksPath }}</code>
          </div>
          <span class="spacer"></span>
          <button matIconButton (click)="copy(d.jwksPath)" i18n-matTooltip="@@Copy" matTooltip="Copy">
            <mat-icon>content_copy</mat-icon>
          </button>
        </div>

        <p class="fallback" i18n="@@Static_fallback">
          Static fallback: paste the PEM of your route's algorithm into that backend.
        </p>
        @for (k of d.keys; track k.algorithm) {
          <mat-expansion-panel class="key">
            <mat-expansion-panel-header>
              <mat-panel-title><span class="alg">{{ k.algorithm }}</span></mat-panel-title>
              <mat-panel-description>
                <span class="kid">kid {{ k.kid }}</span>
                <span class="spacer"></span>
                <button matButton (click)="$event.stopPropagation(); copy(k.publicPem)">
                  <mat-icon>content_copy</mat-icon>
                  <span i18n="@@Copy_PEM">Copy PEM</span>
                </button>
              </mat-panel-description>
            </mat-expansion-panel-header>
            <pre class="pem">{{ k.publicPem }}</pre>
          </mat-expansion-panel>
        }
      }
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      @if (confirming()) {
        <span class="warn" i18n="@@Rotate_confirm">Rotate now? Old keys stay valid briefly (grace window).</span>
        <button matButton (click)="confirming.set(false)" i18n="@@Cancel">Cancel</button>
        <button matButton="filled" [disabled]="renewing()" (click)="renew()" i18n="@@Rotate">Rotate</button>
      } @else {
        <button matButton (click)="confirming.set(true)" [disabled]="renewing() || loading()">
          <mat-icon>autorenew</mat-icon>
          <span i18n="@@Renew_keys">Renew keys</span>
        </button>
        <span class="spacer"></span>
        <button matButton mat-dialog-close i18n="@@Close">Close</button>
      }
    </mat-dialog-actions>
  `,
})
export class SigningKeysDialogComponent {
  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);

  protected readonly loading = signal(true);
  protected readonly renewing = signal(false);
  protected readonly confirming = signal(false);
  protected readonly data = signal<SigningKeys | null>(null);

  constructor() {
    this.reload();
  }

  private reload(): void {
    this.loading.set(true);
    this.api.getSigningKeys().subscribe({
      next: (d) => {
        this.data.set(d);
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  protected copy(text: string): void {
    void navigator.clipboard?.writeText(text);
    this.snack.open($localize`:@@Copied:Copied`, undefined, { duration: 1500 });
  }

  protected renew(): void {
    this.renewing.set(true);
    this.confirming.set(false);
    this.api.renewSigningKeys().subscribe({
      next: (d) => {
        this.data.set(d);
        this.renewing.set(false);
        this.snack.open($localize`:@@Signing_keys_rotated:Signing keys rotated`, undefined, { duration: 2500 });
      },
      error: () => {
        this.renewing.set(false);
        this.snack.open($localize`:@@Request_failed:Request failed`, undefined, { duration: 3000 });
      },
    });
  }
}
