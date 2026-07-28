import { DatePipe } from '@angular/common';
import { Component, computed, effect, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatSnackBar } from '@angular/material/snack-bar';
import { ApiService, BusinessAccess, Settings } from '../../api.service';
import { FormFieldComponent } from '../../shared/form-field.component';
import { BusinessAccessFormComponent } from '../business-access-form.component';
import { TenantScope } from '../tenant-scope';

// The tenant's General section (a child route of the tenant layout): identity
// and working hours, committed together with Save. The layout owns the tenant
// signal — a save pushes the fresh copy back so the left nav's name follows.
@Component({
  selector: 'app-tenant-general',
  imports: [
    DatePipe,
    MatButtonModule,
    MatFormFieldModule,
    MatInputModule,
    MatSelectModule,
    MatSlideToggleModule,
    FormFieldComponent,
    BusinessAccessFormComponent,
  ],
  styleUrl: './tenant-general.component.scss',
  templateUrl: './tenant-general.component.html',
})
export class TenantGeneralComponent {
  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);
  protected readonly scope = inject(TenantScope);

  protected readonly saving = signal(false);
  private readonly settings = signal<Settings | null>(null);

  // Editable copies, re-seeded whenever the layout loads another tenant.
  protected readonly name = signal('');
  protected readonly enabled = signal(true);
  protected readonly description = signal('');
  protected readonly businessAccess = signal<BusinessAccess>({ inherited: true });
  // '' in the store means "default cumulative"; the select surfaces it as MULTIPLE.
  protected readonly groupMode = signal('MULTIPLE');

  protected readonly globalBusinessAccess = computed<BusinessAccess>(
    () => this.settings()?.businessAccess ?? { inherited: false },
  );

  protected readonly dirty = computed(() => {
    const t = this.scope.tenant();
    if (!t) return false;
    return (
      this.name().trim() !== t.name ||
      this.enabled() !== t.enabled ||
      this.description().trim() !== t.description ||
      this.groupMode() !== (t.groupMode || 'MULTIPLE') ||
      JSON.stringify(this.businessAccess()) !== JSON.stringify(t.businessAccess)
    );
  });

  constructor() {
    effect(() => {
      const t = this.scope.tenant();
      if (!t) return;
      this.name.set(t.name);
      this.enabled.set(t.enabled);
      this.description.set(t.description);
      this.groupMode.set(t.groupMode || 'MULTIPLE');
      this.businessAccess.set(t.businessAccess);
    });
    this.api.settings().subscribe({ next: (s) => this.settings.set(s) });
  }

  protected save(): void {
    const t = this.scope.tenant();
    if (!t) return;
    this.saving.set(true);
    this.api
      .updateTenant({
        ...t,
        name: this.name().trim(),
        enabled: this.enabled(),
        description: this.description().trim(),
        groupMode: this.groupMode(),
        businessAccess: this.businessAccess(),
      })
      .subscribe({
        next: (saved) => {
          this.saving.set(false);
          this.scope.tenant.set(saved);
          this.snack.open($localize`:@@Tenant_NAME_saved:Tenant "${saved.name}:NAME:" saved`, undefined, { duration: 2500 });
        },
        error: (err) => {
          this.saving.set(false);
          const e = err as { error?: { error?: string } };
          this.snack.open(
            typeof e?.error?.error === 'string' ? e.error.error : $localize`:@@Request_failed:Request failed`,
            undefined,
            { duration: 4000 },
          );
        },
      });
  }
}
