import { HttpErrorResponse } from '@angular/common/http';
import { Component, inject, signal } from '@angular/core';
import { FormField, form, required } from '@angular/forms/signals';
import { MatButtonModule } from '@angular/material/button';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { ApiService, CatalogEntry, Route } from '../api.service';
import { BrickForm, formToSpec, specToForm } from './brick';
import { BrickListComponent } from './brick-list.component';

interface DialogData {
  route: Route | null;
  catalog: CatalogEntry[];
}

// Route editor: signal form for the scalar fields, brick lists (generated
// from the catalog) for predicates and filters. Saving PUTs to the admin API,
// which validates by compiling — its 422 message is surfaced verbatim.
@Component({
  selector: 'app-route-dialog',
  imports: [
    FormField,
    MatButtonModule,
    MatCheckboxModule,
    MatDialogModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    BrickListComponent,
  ],
  styles: [
    `
      .grid {
        display: grid;
        grid-template-columns: 2fr 1fr;
        gap: 0 16px;
      }
      .flags {
        display: flex;
        gap: 24px;
        margin: 4px 0 12px;
      }
      .error {
        color: var(--mat-sys-error);
        background: color-mix(in srgb, var(--mat-sys-error) 12%, transparent);
        border-radius: 6px;
        padding: 10px 14px;
        margin-top: 8px;
        white-space: pre-wrap;
      }
      mat-form-field {
        width: 100%;
      }
    `,
  ],
  template: `
    @if (data.route) {
      <h2 mat-dialog-title i18n="@@Edit_route">Edit route</h2>
    } @else {
      <h2 mat-dialog-title i18n="@@New_route">New route</h2>
    }
    <mat-dialog-content>
      <div class="grid">
        <mat-form-field>
          <mat-label i18n="@@Name">Name</mat-label>
          <input matInput [formField]="f.name" />
        </mat-form-field>
        <mat-form-field>
          <mat-label i18n="@@Order">Order</mat-label>
          <input matInput type="number" [formField]="f.order" />
        </mat-form-field>
      </div>

      <mat-form-field>
        <mat-label i18n="@@Upstream">Upstream</mat-label>
        <input matInput [formField]="f.upstream" placeholder="http://service:8080" />
        <mat-hint i18n="@@Not_used_when_a_terminal_filter_redirect_is_present">Not used when a terminal filter (redirect) is present</mat-hint>
      </mat-form-field>

      <div class="flags">
        <mat-checkbox [checked]="scalars().enabled" (change)="setFlag('enabled', $event.checked)">
          <ng-container i18n="@@Enabled">Enabled</ng-container>
        </mat-checkbox>
        <mat-checkbox
          [checked]="scalars().authenticated"
          (change)="setFlag('authenticated', $event.checked)"
        >
          <ng-container i18n="@@Authenticated">Authenticated</ng-container>
        </mat-checkbox>
      </div>

      <app-brick-list
        i18n-title="@@Predicates_all_must_match"
        title="Predicates — all must match"
        i18n-addLabel="@@Add_predicate"
        addLabel="Add predicate"
        [entries]="predicateEntries"
        [(bricks)]="predicates"
      />
      <app-brick-list
        i18n-title="@@Filters_applied_in_order"
        title="Filters — applied in order"
        i18n-addLabel="@@Add_filter"
        addLabel="Add filter"
        [entries]="filterEntries"
        [(bricks)]="filters"
      />

      @if (error()) {
        <div class="error">{{ error() }}</div>
      }
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button matButton mat-dialog-close i18n="@@Cancel">Cancel</button>
      <button matButton="filled" (click)="save()" [disabled]="saving() || !f().valid()" i18n="@@Save_apply">
        Save & apply
      </button>
    </mat-dialog-actions>
  `,
})
export class RouteDialogComponent {
  protected readonly data = inject<DialogData>(MAT_DIALOG_DATA);
  private readonly ref = inject(MatDialogRef<RouteDialogComponent>);
  private readonly api = inject(ApiService);

  protected readonly predicateEntries = this.data.catalog.filter((e) => e.kind === 'predicate');
  protected readonly filterEntries = this.data.catalog.filter((e) => e.kind === 'filter');

  protected readonly scalars = signal({
    name: this.data.route?.name ?? '',
    order: this.data.route?.order ?? 0,
    upstream: this.data.route?.upstream ?? '',
    enabled: this.data.route?.enabled ?? true,
    authenticated: this.data.route?.authenticated ?? false,
  });
  protected readonly f = form(this.scalars, (p) => {
    required(p.name);
  });

  protected readonly predicates = signal<BrickForm[]>(
    (this.data.route?.predicates ?? []).map((s) => specToForm(s, this.predicateEntries)),
  );
  protected readonly filters = signal<BrickForm[]>(
    (this.data.route?.filters ?? []).map((s) => specToForm(s, this.filterEntries)),
  );

  protected readonly error = signal('');
  protected readonly saving = signal(false);

  protected setFlag(flag: 'enabled' | 'authenticated', value: boolean): void {
    this.scalars.update((s) => ({ ...s, [flag]: value }));
  }

  protected save(): void {
    this.error.set('');
    this.saving.set(true);
    const s = this.scalars();
    const route: Route = {
      id: this.data.route?.id ?? crypto.randomUUID(),
      name: s.name.trim(),
      order: Number(s.order) || 0,
      enabled: s.enabled,
      authenticated: s.authenticated,
      upstream: s.upstream.trim(),
      predicates: this.predicates().map((b) => formToSpec(b, this.predicateEntries)),
      filters: this.filters().map((b) => formToSpec(b, this.filterEntries)),
    };
    this.api.putRoute(route).subscribe({
      next: (saved) => this.ref.close(saved),
      error: (err: unknown) => {
        this.saving.set(false);
        const msg =
          err instanceof HttpErrorResponse && typeof err.error?.error === 'string'
            ? err.error.error
            : $localize`:@@Save_failed:Save failed`;
        this.error.set(msg);
      },
    });
  }
}
