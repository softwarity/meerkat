import { Component, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatSnackBar } from '@angular/material/snack-bar';
import { ApiService } from '../api.service';

// API docs — the swagger-ui page the gateway serves at /apidocs/ (assets
// embedded in the binary, Sentinel's Watch skin), shown full-bleed in an
// iframe: swagger's invasive CSS stays fully isolated from Material, and the
// very same URL opens standalone in a tab (the page offers the pop-out).
//
// The bar ABOVE the iframe mints ephemeral test tokens: an identity to
// impersonate (user + roles), a bounded lifetime, and a copy button that
// yields `Bearer mksim_…` ready to paste into swagger's Authorize — checking
// that a route is properly protected without creating any account.
@Component({
  selector: 'app-api-docs-page',
  imports: [MatButtonModule, MatFormFieldModule, MatIconModule, MatInputModule, MatSelectModule],
  styles: [
    `
      :host {
        display: flex;
        flex-direction: column;
        height: 100%;
      }
      .bar {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 8px 16px 0;
        flex: none;
      }
      .bar mat-form-field {
        max-width: 200px;
      }
      .token {
        flex: 1;
        min-width: 0;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        font-family: var(--mono, ui-monospace, monospace);
        font-size: 0.8rem;
        color: var(--mat-sys-on-surface-variant);
      }
      iframe {
        display: block;
        width: 100%;
        border: 0;
        flex: 1;
      }
    `,
  ],
  template: `
    <div class="bar">
      <mat-form-field subscriptSizing="dynamic">
        <mat-label i18n="@@Test_as_user">Test as user</mat-label>
        <input matInput [value]="user()" (input)="user.set(asValue($event))" placeholder="alice" />
      </mat-form-field>
      <mat-form-field subscriptSizing="dynamic">
        <mat-label i18n="@@Roles">Roles</mat-label>
        <input matInput [value]="roles()" (input)="roles.set(asValue($event))" placeholder="auditor,sales" />
      </mat-form-field>
      <mat-form-field subscriptSizing="dynamic">
        <mat-label i18n="@@Validity">Validity</mat-label>
        <mat-select [value]="minutes()" (selectionChange)="minutes.set($event.value)">
          <mat-option [value]="15">15 min</mat-option>
          <mat-option [value]="30">30 min</mat-option>
          <mat-option [value]="60">60 min</mat-option>
        </mat-select>
      </mat-form-field>
      <button matButton="tonal" (click)="mint()" [disabled]="minting() || !user().trim()">
        <mat-icon>token</mat-icon>
        <ng-container i18n="@@Generate_test_token">Test token</ng-container>
      </button>
      @if (token()) {
        <span class="token" [title]="token()">{{ token() }}</span>
        <button
          matIconButton
          (click)="copy()"
          i18n-aria-label="@@Copy_for_authorize"
          aria-label="Copy for Authorize"
        >
          <mat-icon>content_copy</mat-icon>
        </button>
      }
    </div>
    <iframe src="/apidocs/" i18n-title="@@API_documentation" title="API documentation"></iframe>
  `,
})
export class ApiDocsPageComponent {
  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);

  protected readonly user = signal('');
  protected readonly roles = signal('');
  protected readonly minutes = signal(15);
  protected readonly minting = signal(false);
  protected readonly token = signal('');

  protected asValue(e: Event): string {
    return (e.target as HTMLInputElement).value;
  }

  protected mint(): void {
    this.minting.set(true);
    const roles = this.roles()
      .split(',')
      .map((r) => r.trim())
      .filter(Boolean);
    this.api.mintTestToken(this.user().trim(), roles, this.minutes()).subscribe({
      next: (r) => {
        this.minting.set(false);
        this.token.set(r.token);
      },
      error: () => {
        this.minting.set(false);
        this.snack.open($localize`:@@Test_token_failed:Could not mint the test token`, undefined, {
          duration: 3000,
        });
      },
    });
  }

  // What Authorize expects, verbatim: the header value with its Bearer prefix.
  protected async copy(): Promise<void> {
    await navigator.clipboard.writeText('Bearer ' + this.token());
    this.snack.open(
      $localize`:@@Test_token_copied:Copied — paste it into Authorize (MeerkatTestToken)`,
      undefined,
      { duration: 3500 },
    );
  }
}
