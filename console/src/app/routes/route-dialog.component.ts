import { NgTemplateOutlet } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { HttpErrorResponse } from '@angular/common/http';
import { ApiService, CatalogEntry, Param, Route, Spec } from '../api.service';

// The editor is GENERATED from the catalog: brick types come from
// /api/catalog and each brick's fields are rendered from its param schemas.
// Adding a predicate or filter in the Go registry lights it up here with
// zero console change.

interface BrickForm {
  type: string;
  // UI representation of args: stringList is edited as a comma-separated
  // string, converted back on save.
  values: Record<string, string | number | boolean>;
}

interface DialogData {
  route: Route | null;
  catalog: CatalogEntry[];
}

@Component({
  selector: 'app-route-dialog',
  imports: [
    NgTemplateOutlet,
    FormsModule,
    MatButtonModule,
    MatCheckboxModule,
    MatDialogModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatSelectModule,
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
      h3 {
        margin: 12px 0 8px;
        font-size: 0.95rem;
        font-weight: 500;
        color: var(--mat-sys-on-surface-variant);
      }
      .brick {
        display: grid;
        grid-template-columns: 180px 1fr auto;
        gap: 0 12px;
        align-items: start;
        padding: 8px 12px;
        margin-bottom: 8px;
        border: 1px solid var(--mat-sys-outline-variant);
        border-radius: 8px;
      }
      .brick .fields {
        display: grid;
        gap: 0 12px;
        grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      }
      .brick .bool-field {
        padding-top: 14px;
      }
      .error {
        color: var(--mat-sys-error);
        background: color-mix(in srgb, var(--mat-sys-error) 12%, transparent);
        border-radius: 6px;
        padding: 10px 14px;
        margin-top: 8px;
        font-size: 0.9em;
        white-space: pre-wrap;
      }
      mat-form-field {
        width: 100%;
      }
    `,
  ],
  template: `
    <h2 mat-dialog-title>{{ data.route ? 'Edit route' : 'New route' }}</h2>
    <mat-dialog-content>
      <div class="grid">
        <mat-form-field>
          <mat-label>Name</mat-label>
          <input matInput [(ngModel)]="name" required />
        </mat-form-field>
        <mat-form-field>
          <mat-label>Order</mat-label>
          <input matInput type="number" [(ngModel)]="order" />
        </mat-form-field>
      </div>

      <mat-form-field>
        <mat-label>Upstream</mat-label>
        <input matInput [(ngModel)]="upstream" placeholder="http://service:8080" />
        <mat-hint>Not used when a terminal filter (redirect) is present</mat-hint>
      </mat-form-field>

      <div class="flags">
        <mat-checkbox [(ngModel)]="enabled">Enabled</mat-checkbox>
        <mat-checkbox [(ngModel)]="authenticated">Authenticated</mat-checkbox>
      </div>

      <h3>Predicates — all must match</h3>
      @for (brick of predicates; track $index) {
        <ng-container
          *ngTemplateOutlet="brickTpl; context: { brick, list: predicates, entries: predicateEntries }"
        />
      }
      <button matButton (click)="add(predicates, predicateEntries[0])">
        <mat-icon>add</mat-icon>
        Add predicate
      </button>

      <h3>Filters — applied in order</h3>
      @for (brick of filters; track $index) {
        <ng-container
          *ngTemplateOutlet="brickTpl; context: { brick, list: filters, entries: filterEntries }"
        />
      }
      <button matButton (click)="add(filters, filterEntries[0])">
        <mat-icon>add</mat-icon>
        Add filter
      </button>

      @if (error()) {
        <div class="error">{{ error() }}</div>
      }
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button matButton mat-dialog-close>Cancel</button>
      <button matButton="filled" (click)="save()" [disabled]="saving()">Save & apply</button>
    </mat-dialog-actions>

    <ng-template #brickTpl let-brick="brick" let-list="list" let-entries="entries">
      <div class="brick">
        <mat-form-field>
          <mat-label>Type</mat-label>
          <mat-select
            [ngModel]="brick.type"
            (ngModelChange)="retype(brick, $event, entries)"
          >
            @for (e of entries; track e.type) {
              <mat-option [value]="e.type">{{ e.type }}</mat-option>
            }
          </mat-select>
          <mat-hint>{{ doc(brick.type, entries) }}</mat-hint>
        </mat-form-field>
        <div class="fields">
          @for (p of params(brick.type, entries); track p.name) {
            @if (p.kind === 'bool') {
              <mat-checkbox class="bool-field" [(ngModel)]="brick.values[p.name]">
                {{ p.name }}
              </mat-checkbox>
            } @else {
              <mat-form-field>
                <mat-label>{{ p.name }}{{ p.required ? ' *' : '' }}</mat-label>
                <input
                  matInput
                  [type]="p.kind === 'int' ? 'number' : 'text'"
                  [(ngModel)]="brick.values[p.name]"
                  [placeholder]="p.kind === 'stringList' ? 'comma, separated' : ''"
                />
                <mat-hint>{{ p.doc }}</mat-hint>
              </mat-form-field>
            }
          }
        </div>
        <button matIconButton (click)="removeBrick(list, brick)" aria-label="Remove">
          <mat-icon>close</mat-icon>
        </button>
      </div>
    </ng-template>
  `,
})
export class RouteDialogComponent {
  protected readonly data = inject<DialogData>(MAT_DIALOG_DATA);
  private readonly ref = inject(MatDialogRef<RouteDialogComponent>);
  private readonly api = inject(ApiService);

  protected readonly predicateEntries = this.data.catalog.filter((e) => e.kind === 'predicate');
  protected readonly filterEntries = this.data.catalog.filter((e) => e.kind === 'filter');

  protected name = this.data.route?.name ?? '';
  protected order = this.data.route?.order ?? 0;
  protected upstream = this.data.route?.upstream ?? '';
  protected enabled = this.data.route?.enabled ?? true;
  protected authenticated = this.data.route?.authenticated ?? false;
  protected predicates: BrickForm[] = (this.data.route?.predicates ?? []).map((s) =>
    this.toForm(s, this.predicateEntries),
  );
  protected filters: BrickForm[] = (this.data.route?.filters ?? []).map((s) =>
    this.toForm(s, this.filterEntries),
  );

  protected readonly error = signal('');
  protected readonly saving = signal(false);

  protected params(type: string, entries: CatalogEntry[]): Param[] {
    return entries.find((e) => e.type === type)?.params ?? [];
  }

  protected doc(type: string, entries: CatalogEntry[]): string {
    return entries.find((e) => e.type === type)?.doc ?? '';
  }

  protected add(list: BrickForm[], entry: CatalogEntry): void {
    list.push(this.toForm({ type: entry.type }, [entry]));
  }

  protected removeBrick(list: BrickForm[], brick: BrickForm): void {
    list.splice(list.indexOf(brick), 1);
  }

  protected retype(brick: BrickForm, type: string, entries: CatalogEntry[]): void {
    brick.type = type;
    brick.values = this.defaults(this.params(type, entries));
  }

  protected save(): void {
    this.error.set('');
    this.saving.set(true);
    const route: Route = {
      id: this.data.route?.id ?? crypto.randomUUID(),
      name: this.name.trim(),
      order: Number(this.order) || 0,
      enabled: this.enabled,
      authenticated: this.authenticated,
      upstream: this.upstream.trim(),
      predicates: this.predicates.map((b) => this.toSpec(b, this.predicateEntries)),
      filters: this.filters.map((b) => this.toSpec(b, this.filterEntries)),
    };
    this.api.putRoute(route).subscribe({
      next: (saved) => this.ref.close(saved),
      error: (err: unknown) => {
        this.saving.set(false);
        const msg =
          err instanceof HttpErrorResponse && typeof err.error?.error === 'string'
            ? err.error.error
            : 'Save failed';
        this.error.set(msg);
      },
    });
  }

  // ---- Spec <-> form conversion -------------------------------------------

  private toForm(spec: Spec, entries: CatalogEntry[]): BrickForm {
    const values = this.defaults(this.params(spec.type, entries));
    for (const [key, raw] of Object.entries(spec.args ?? {})) {
      values[key] = Array.isArray(raw) ? raw.join(', ') : (raw as string | number | boolean);
    }
    return { type: spec.type, values };
  }

  private defaults(params: Param[]): Record<string, string | number | boolean> {
    const values: Record<string, string | number | boolean> = {};
    for (const p of params) {
      if (p.kind === 'bool') {
        values[p.name] = (p.default as boolean) ?? false;
      } else if (p.default !== undefined && p.default !== null) {
        values[p.name] = Array.isArray(p.default)
          ? p.default.join(', ')
          : (p.default as string | number);
      }
    }
    return values;
  }

  private toSpec(brick: BrickForm, entries: CatalogEntry[]): Spec {
    const args: Record<string, unknown> = {};
    for (const p of this.params(brick.type, entries)) {
      const v = brick.values[p.name];
      if (v === undefined || v === '' || v === null) {
        continue; // omitted → server applies defaults / flags missing required
      }
      switch (p.kind) {
        case 'stringList':
          args[p.name] = String(v)
            .split(',')
            .map((s) => s.trim())
            .filter((s) => s !== '');
          break;
        case 'int':
          args[p.name] = Number(v);
          break;
        case 'bool':
          args[p.name] = Boolean(v);
          break;
        default:
          args[p.name] = String(v);
      }
    }
    return Object.keys(args).length ? { type: brick.type, args } : { type: brick.type };
  }
}
