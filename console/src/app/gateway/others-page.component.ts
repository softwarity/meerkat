import { Component, inject, signal } from '@angular/core';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatSnackBar } from '@angular/material/snack-bar';
import { LoadingIndicatorComponent } from '@softwarity/loading-indicator';
import { ApiService } from '../api.service';

// Others - INFRA plane: the switches that fit no dedicated screen. Exposing
// the embedded API docs (swagger-ui), and the embedded issue tracker. Both
// ship OFF; while off their whole surface answers 404.
@Component({
  selector: 'app-others-page',
  imports: [MatCardModule, MatIconModule, MatSlideToggleModule, LoadingIndicatorComponent],
  styles: [
    `
      :host {
        display: block;
        padding: 24px;
        max-width: 720px;
      }
      mat-card {
        padding: 20px 24px;
      }
      .line {
        display: flex;
        align-items: center;
        gap: 16px;
      }
      .line mat-icon {
        flex-shrink: 0;
        color: var(--mat-sys-on-surface-variant);
      }
      .grow {
        flex: 1;
        min-width: 0;
      }
      .hint {
        margin: 4px 0 0;
        font-size: 0.85rem;
        color: var(--mat-sys-on-surface-variant);
      }
    `,
  ],
  template: `
    <h1 i18n="@@Others">Others</h1>
    @if (loading()) {
      <loading-indicator />
    } @else {
      <mat-card appearance="outlined">
        <div class="line">
          <mat-icon>api</mat-icon>
          <div class="grow">
            <div i18n="@@Expose_API_docs">Developer API docs on the data plane</div>
            <p class="hint" i18n="@@Expose_API_docs_hint">
              Opens /meerkat/apidocs on the application port: every route's OpenAPI spec, for
              signed-in users with the developer capability. Off, the page answers 404. The
              console's own API screen (Meerkat's contract) is not concerned.
            </p>
          </div>
          <mat-slide-toggle [checked]="exposed()" [disabled]="saving()" (change)="save($event.checked)" />
        </div>
      </mat-card>
      <mat-card appearance="outlined">
        <div class="line">
          <mat-icon>bug_report</mat-icon>
          <div class="grow">
            <div i18n="@@Enable_issue_reports">Issue reports from the applications</div>
            <p class="hint" i18n="@@Enable_issue_reports_hint">
              Adds a "Report an issue" entry to the user button of proxied applications: signed-in
              users file a description, a screenshot and the page context. Reports land in the
              console's Issues section. Off, the entry disappears and the endpoint answers 404.
            </p>
          </div>
          <mat-slide-toggle [checked]="issuesOn()" [disabled]="savingIssues()" (change)="saveIssues($event.checked)" />
        </div>
      </mat-card>
    }
  `,
})
export class OthersPageComponent {
  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);

  protected readonly loading = signal(true);
  protected readonly saving = signal(false);
  protected readonly exposed = signal(false);
  protected readonly savingIssues = signal(false);
  protected readonly issuesOn = signal(false);

  constructor() {
    this.api.apiDocsSetting().subscribe({
      next: (s) => {
        this.exposed.set(s.exposed);
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
    this.api.issuesSetting().subscribe({
      next: (s) => this.issuesOn.set(s.enabled),
      error: () => {},
    });
  }

  protected save(exposed: boolean): void {
    this.saving.set(true);
    this.api.saveApiDocsSetting(exposed).subscribe({
      next: (s) => {
        this.exposed.set(s.exposed);
        this.saving.set(false);
        this.snack.open(
          s.exposed
            ? $localize`:@@API_docs_exposed:API documentation exposed`
            : $localize`:@@API_docs_hidden:API documentation hidden`,
          undefined,
          { duration: 2500 },
        );
      },
      error: () => {
        this.saving.set(false);
        this.snack.open($localize`:@@Save_failed:Save failed`, undefined, { duration: 3000 });
      },
    });
  }

  protected saveIssues(enabled: boolean): void {
    this.savingIssues.set(true);
    this.api.saveIssuesSetting(enabled).subscribe({
      next: (s) => {
        this.issuesOn.set(s.enabled);
        this.savingIssues.set(false);
        this.snack.open(
          s.enabled
            ? $localize`:@@Issue_reports_enabled:Issue reports enabled`
            : $localize`:@@Issue_reports_disabled:Issue reports disabled`,
          undefined,
          { duration: 2500 },
        );
      },
      error: () => {
        this.savingIssues.set(false);
        this.snack.open($localize`:@@Save_failed:Save failed`, undefined, { duration: 3000 });
      },
    });
  }
}
