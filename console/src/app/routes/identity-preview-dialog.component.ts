import { Component, computed, inject, signal } from '@angular/core';
import { MAT_DIALOG_DATA, MatDialogModule } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatExpansionModule } from '@angular/material/expansion';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatTooltipModule } from '@angular/material/tooltip';
import { ApiService, IdentityForward, IdentityPreview } from '../api.service';

// What the route's identity forwarding actually sends upstream, for a FICTIONAL
// caller the server picks (never the real session, and never values chosen by
// the console: a signed preview is a real token). Opened from the Identity
// section, it previews the DRAFT config — no save needed.
export interface IdentityPreviewData {
  routeName: string;
  identity: IdentityForward;
}

@Component({
  selector: 'app-identity-preview-dialog',
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
        max-width: 660px;
      }
      .hint {
        margin: 0 0 14px;
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.85rem;
      }
      .err {
        color: var(--mat-sys-error);
        white-space: pre-wrap;
      }
      table.hdrs {
        width: 100%;
        border-collapse: collapse;
      }
      table.hdrs td {
        padding: 6px 8px;
        border-bottom: 1px solid var(--mat-sys-outline-variant);
        font-family: var(--mk-mono);
        font-size: 0.8rem;
        vertical-align: top;
      }
      table.hdrs td.k {
        color: var(--mat-sys-secondary);
        white-space: nowrap;
        width: 1%;
      }
      table.hdrs td.v {
        word-break: break-all;
      }
      .block {
        display: flex;
        align-items: center;
        gap: 8px;
        margin-top: 6px;
      }
      .block .lbl {
        font-size: 0.72rem;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        color: var(--mat-sys-on-surface-variant);
      }
      .spacer {
        flex: 1;
      }
      pre {
        margin: 4px 0 0;
        padding: 8px 10px;
        border-radius: 8px;
        background: var(--mat-sys-surface-container-low);
        font-family: var(--mk-mono);
        font-size: 0.72rem;
        line-height: 1.4;
        white-space: pre-wrap;
        word-break: break-all;
        overflow-x: hidden;
      }
      .meta {
        font-family: var(--mk-mono);
        font-size: 0.75rem;
        color: var(--mat-sys-on-surface-variant);
      }
    `,
  ],
  template: `
    <h2 mat-dialog-title i18n="@@Identity_preview">Identity preview</h2>
    @if (loading()) {
      <mat-progress-bar mode="indeterminate" />
    }
    <mat-dialog-content>
      <p class="hint" i18n="@@Identity_preview_hint">
        What the upstream receives on every request of this route, for a sample caller. Values are
        fictional; the shape, the names and the signature are the real ones.
      </p>

      @if (error(); as e) {
        <p class="err">{{ e }}</p>
      } @else if (data(); as d) {
        @if (d.headers?.length) {
          <table class="hdrs">
            @for (h of d.headers; track h.name) {
              <tr>
                <td class="k">{{ h.name }}</td>
                <td class="v">{{ h.value }}</td>
              </tr>
            }
          </table>
        }

        @if (d.token) {
          <div class="block">
            <span class="lbl">Authorization</span>
            <span class="spacer"></span>
            <button matButton (click)="copy('Bearer ' + d.token)">
              <mat-icon>content_copy</mat-icon>
              <span i18n="@@Copy">Copy</span>
            </button>
          </div>
          <pre>Bearer {{ d.token }}</pre>

          @if (d.algorithm) {
            <p class="meta">{{ d.algorithm }} · kid {{ d.kid }}</p>
          }

          <mat-expansion-panel>
            <mat-expansion-panel-header>
              <mat-panel-title i18n="@@Decoded_claims">Decoded claims</mat-panel-title>
            </mat-expansion-panel-header>
            <pre>{{ claimsJson() }}</pre>
          </mat-expansion-panel>

          @if (d.publicPem) {
            <mat-expansion-panel>
              <mat-expansion-panel-header>
                <mat-panel-title i18n="@@Public_key">Public key</mat-panel-title>
                <mat-panel-description>
                  <span class="spacer"></span>
                  <button matButton (click)="$event.stopPropagation(); copy(d.publicPem!)">
                    <mat-icon>content_copy</mat-icon>
                    <span i18n="@@Copy_PEM">Copy PEM</span>
                  </button>
                </mat-panel-description>
              </mat-expansion-panel-header>
              <pre>{{ d.publicPem }}</pre>
            </mat-expansion-panel>
          }
        }
      }
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      @if (data()?.token) {
        <a matButton href="https://www.jwt.io/" target="_blank" rel="noopener noreferrer">
          <mat-icon svgIcon="jwt" />
          <span i18n="@@Check_on_jwt_io">Check on jwt.io</span>
        </a>
      }
      <span class="spacer"></span>
      <button matButton mat-dialog-close i18n="@@Close">Close</button>
    </mat-dialog-actions>
  `,
})
export class IdentityPreviewDialogComponent {
  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);
  private readonly input = inject<IdentityPreviewData>(MAT_DIALOG_DATA);

  protected readonly loading = signal(true);
  protected readonly error = signal('');
  protected readonly data = signal<IdentityPreview | null>(null);
  protected readonly claimsJson = computed(() => JSON.stringify(this.data()?.claims ?? {}, null, 2));

  constructor() {
    this.api.previewIdentity(this.input.routeName, this.input.identity).subscribe({
      next: (d) => {
        this.data.set(d);
        this.loading.set(false);
      },
      error: (err: unknown) => {
        const e = err as { error?: { error?: string } };
        this.error.set(
          typeof e?.error?.error === 'string' ? e.error.error : $localize`:@@Request_failed:Request failed`,
        );
        this.loading.set(false);
      },
    });
  }

  protected copy(text: string): void {
    void navigator.clipboard?.writeText(text);
    this.snack.open($localize`:@@Copied:Copied`, undefined, { duration: 1500 });
  }
}
