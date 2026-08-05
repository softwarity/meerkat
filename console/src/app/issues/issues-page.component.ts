import { Component, computed, effect, inject, LOCALE_ID, signal } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatSidenavModule } from '@angular/material/sidenav';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatTooltipModule } from '@angular/material/tooltip';
import { ActivatedRoute, Router } from '@angular/router';
import { LoadingIndicatorComponent } from '@softwarity/loading-indicator';
import { sessionStored } from '@softwarity/store';
import { DateTime } from 'luxon';
import { ApiService, Issue, IssueStatus } from '../api.service';
import { MeService } from '../me.service';
import { DialogsService } from '../shared/dialogs.service';

// The embedded issue tracker (ISSUE-03): the reports users file from the
// injected user-button panel, with their screenshot and captured context.
// A transverse section like Audit - the API scopes the content (root and
// infra/app admins see everything, a tenant admin their tenants' reports).
// The list stays light; opening a report fetches its detail into the drawer,
// driven by the URL (/issues/:id) so a refresh lands back on it.
//
// The collection switch (ISSUE-04) lives HERE rather than on a screen of
// miscellaneous toggles: an empty list means nothing until one knows whether
// anything is being collected, and this is where someone asks the question.
// Only infra admins see it - the endpoint is theirs, and a tenant admin
// reading the reports has no say over the gateway-wide feature.
@Component({
  selector: 'app-issues-page',
  imports: [
    MatButtonModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatSelectModule,
    MatSidenavModule,
    MatSlideToggleModule,
    MatTooltipModule,
    LoadingIndicatorComponent,
  ],
  styleUrl: './issues-page.component.scss',
  templateUrl: './issues-page.component.html',
})
export class IssuesPageComponent {
  private readonly api = inject(ApiService);
  private readonly router = inject(Router);
  private readonly snack = inject(MatSnackBar);
  private readonly dialogs = inject(DialogsService);
  private readonly locale = inject(LOCALE_ID);
  private readonly params = toSignal(inject(ActivatedRoute).paramMap);

  protected readonly statuses: IssueStatus[] = ['open', 'in-progress', 'closed'];

  protected readonly loading = signal(true);
  protected readonly issues = signal<Issue[]>([]);
  protected readonly search = signal('');
  // The collection switch: only an infra admin may read or flip it, so only
  // one sees it at all.
  protected readonly canSwitch = inject(MeService).isInfraAdmin;
  protected readonly collecting = signal(false);
  protected readonly savingCollect = signal(false);
  // The status filter survives a refresh (not the browser session).
  protected readonly view = sessionStored({ status: '' as IssueStatus | '' }, { storageKey: 'issues-view.v1' });

  protected readonly filtered = computed(() => {
    const q = this.search().trim().toLowerCase();
    if (!q) return this.issues();
    return this.issues().filter((i) =>
      [i.description, i.reporterName, i.tenantName, i.url].some((v) => (v ?? '').toLowerCase().includes(q)),
    );
  });

  // The open report, fetched whenever the URL carries an id.
  protected readonly detail = signal<Issue | null>(null);
  protected readonly detailLoading = signal(false);
  protected readonly shotBroken = signal(false);
  protected readonly comment = signal('');
  protected readonly sending = signal(false);
  protected readonly openedId = computed(() => this.params()?.get('id') ?? null);

  constructor() {
    this.reload();
    if (this.canSwitch()) {
      this.api.issuesSetting().subscribe({ next: (s) => this.collecting.set(s.enabled), error: () => {} });
    }
    effect(() => {
      const id = this.openedId();
      if (!id) {
        this.detail.set(null);
        return;
      }
      this.detailLoading.set(true);
      this.shotBroken.set(false);
      this.comment.set('');
      this.api.getIssue(id).subscribe({
        next: (is) => {
          this.detail.set(is);
          this.detailLoading.set(false);
        },
        error: () => {
          this.detailLoading.set(false);
          this.onClose();
        },
      });
    });
  }

  protected reload(): void {
    this.loading.set(true);
    this.api.listIssues(this.view.$status()).subscribe({
      next: (issues) => {
        this.issues.set(issues);
        this.loading.set(false);
      },
      error: () => {
        this.issues.set([]);
        this.loading.set(false);
      },
    });
  }

  // Flipping collection on or off. The list is not reloaded: what was already
  // filed stays readable either way - switching off stops the intake, it does
  // not hide the history.
  protected setCollecting(enabled: boolean): void {
    this.savingCollect.set(true);
    this.api.saveIssuesSetting(enabled).subscribe({
      next: (s) => {
        this.collecting.set(s.enabled);
        this.savingCollect.set(false);
        this.snack.open(
          s.enabled
            ? $localize`:@@Issue_reports_enabled:Issue reports enabled`
            : $localize`:@@Issue_reports_disabled:Issue reports disabled`,
          undefined,
          { duration: 2500 },
        );
      },
      error: () => {
        this.savingCollect.set(false);
        this.snack.open($localize`:@@Save_failed:Save failed`, undefined, { duration: 3000 });
      },
    });
  }

  protected open(i: Issue): void {
    void this.router.navigate(['/issues', i.id]);
  }

  protected onClose(): void {
    if (this.openedId()) void this.router.navigate(['/issues']);
  }

  protected setStatus(status: IssueStatus): void {
    const d = this.detail();
    if (!d || d.status === status) return;
    this.api.setIssueStatus(d.id, status).subscribe({
      next: (is) => {
        this.detail.set(is);
        this.patchRow(is);
      },
      error: (err) => this.fail(err),
    });
  }

  protected addComment(): void {
    const d = this.detail();
    const text = this.comment().trim();
    if (!d || !text || this.sending()) return;
    this.sending.set(true);
    this.api.addIssueComment(d.id, text).subscribe({
      next: (is) => {
        this.detail.set(is);
        this.comment.set('');
        this.sending.set(false);
      },
      error: (err) => {
        this.sending.set(false);
        this.fail(err);
      },
    });
  }

  protected async remove(): Promise<void> {
    const d = this.detail();
    if (!d) return;
    const ok = await this.dialogs.confirm({
      title: $localize`:@@Delete_this_report:Delete this report?`,
      message: $localize`:@@Delete_report_message:The report, its screenshot and its comments will be permanently removed.`,
      confirmLabel: $localize`:@@Delete:Delete`,
      danger: true,
    });
    if (!ok) return;
    this.api.deleteIssue(d.id).subscribe({
      next: () => {
        this.issues.set(this.issues().filter((i) => i.id !== d.id));
        this.onClose();
        this.snack.open($localize`:@@Report_deleted:Report deleted`, undefined, { duration: 2500 });
      },
      error: (err) => this.fail(err),
    });
  }

  // Keeps the list row in step with a drawer mutation, without a full reload.
  private patchRow(is: Issue): void {
    this.issues.set(this.issues().map((i) => (i.id === is.id ? { ...i, status: is.status, updatedAt: is.updatedAt } : i)));
  }

  private fail(err: unknown): void {
    const e = err as { error?: { error?: string } };
    this.snack.open(
      typeof e?.error?.error === 'string' ? e.error.error : $localize`:@@Request_failed:Request failed`,
      undefined,
      { duration: 4000 },
    );
  }

  protected statusLabel(s: IssueStatus): string {
    switch (s) {
      case 'open':
        return $localize`:@@Issue_open:Open`;
      case 'in-progress':
        return $localize`:@@Issue_in_progress:In progress`;
      default:
        return $localize`:@@Issue_closed:Closed`;
    }
  }

  protected firstLine(text: string): string {
    return text.split('\n', 1)[0];
  }

  protected relWhen(at: number): string {
    return DateTime.fromSeconds(at).reconfigure({ locale: this.locale }).toRelative() ?? '';
  }

  protected fullWhen(at: number): string {
    return DateTime.fromSeconds(at).reconfigure({ locale: this.locale }).toLocaleString(DateTime.DATETIME_MED);
  }
}
