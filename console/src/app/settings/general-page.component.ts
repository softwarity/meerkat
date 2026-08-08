import { HttpErrorResponse } from '@angular/common/http';
import { Component, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatSnackBar } from '@angular/material/snack-bar';
import { LoadingIndicatorComponent } from '@softwarity/loading-indicator';
import { ApiService, BusinessAccess, Settings } from '../api.service';
import { MatIconModule } from '@angular/material/icon';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MeService } from '../me.service';
import { DialogsService } from '../shared/dialogs.service';
import { EeLockComponent } from '../shared/ee-lock.component';
import { BusinessAccessFormComponent } from '../identity/business-access-form.component';

// Application-level General settings (root only): the GLOBAL working hours, the
// value every tenant inherits unless it overrides. A full PUT of /api/settings —
// the other fields ride along. Two things are deliberately NOT here: the group
// mode (RBAC-03), a per-tenant call, and the session TTL, which is a security
// policy and lives on the Security page.
@Component({
  selector: 'app-general-page',
  imports: [
    MatButtonModule,
    MatCardModule,
    LoadingIndicatorComponent,
    BusinessAccessFormComponent,
    EeLockComponent,
    MatIconModule,
    MatSlideToggleModule,
  ],
  styleUrl: './general-page.component.scss',
  templateUrl: './general-page.component.html',
})
export class GeneralPageComponent {
  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);

  private readonly me = inject(MeService);
  private readonly dialogs = inject(DialogsService);

  protected readonly loading = signal(true);
  protected readonly saving = signal(false);
  protected readonly switching = signal(false);
  protected readonly multiTenant = this.me.multiTenant;
  private readonly settings = signal<Settings | null>(null);

  protected readonly businessAccess = signal<BusinessAccess>({ inherited: false });

  constructor() {
    this.api.settings().subscribe({
      next: (s) => {
        this.settings.set(s);
        this.businessAccess.set(s.businessAccess ?? { inherited: false });
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  protected save(): void {
    const s = this.settings();
    if (!s) return;
    this.saving.set(true);
    this.api
      .saveSettings({
        ...s,
        businessAccess: { ...this.businessAccess(), inherited: false },
      })
      .subscribe({
        next: (saved) => {
          this.settings.set(saved);
          this.saving.set(false);
          this.snack.open($localize`:@@Settings_saved:Settings saved`, undefined, { duration: 2500 });
        },
        error: (err: unknown) => {
          this.saving.set(false);
          const e = err as { error?: { error?: string } };
          this.snack.open(
            typeof e?.error?.error === 'string' ? e.error.error : $localize`:@@Save_failed:Save failed`,
            undefined,
            { duration: 4000 },
          );
        },
      });
  }

  // Switching the shape of the installation. Going DOWN is the dangerous
  // direction and the only one that asks: organisations stop being served,
  // which cuts access for everyone in them - so the confirmation counts them
  // rather than saying "are you sure".
  //
  // The classes on <body> are refreshed rather than the page reloaded: the
  // mode is read per request server-side, so the switch is already in force by
  // the time this returns.
  protected async setTenancy(multi: boolean): Promise<void> {
    if (!multi) {
      const ok = await this.dialogs.confirm({
        title: $localize`:@@Serve_one_organisation:Serve a single organisation?`,
        message: $localize`:@@Serve_one_organisation_message:The other organisations stop being served and the people in them lose access to whatever asks for one. Nothing is deleted: switching back brings them and their access straight back.`,
        confirmLabel: $localize`:@@Switch:Switch`,
        danger: true,
      });
      if (!ok) return;
    }
    this.switching.set(true);
    this.api.setTenancy(multi ? 'multi' : 'single').subscribe({
      next: () => {
        void this.me.refreshEdition().then(() => this.switching.set(false));
        this.snack.open($localize`:@@Saved:Saved`, undefined, { duration: 2000 });
      },
      error: (e: HttpErrorResponse) => {
        this.switching.set(false);
        this.snack.open(e.error?.error ?? $localize`:@@Save_failed:Save failed`, undefined, { duration: 4000 });
      },
    });
  }
}
