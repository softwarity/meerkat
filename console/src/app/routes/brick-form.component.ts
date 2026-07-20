import { Component, computed, input, model, output } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { CatalogEntry } from '../api.service';
import { BrickForm, defaultsFor, docOf, paramsOf } from './brick';

// One predicate/filter brick: a type picker plus fields generated from the
// catalog's param schemas. Pure signal component — the brick travels through
// a model() signal, immutably updated.
@Component({
  selector: 'app-brick-form',
  imports: [
    MatButtonModule,
    MatCheckboxModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatSelectModule,
  ],
  styles: [
    `
      :host {
        display: grid;
        grid-template-columns: 180px 1fr auto;
        gap: 0 12px;
        align-items: start;
        padding: 8px 12px;
        margin-bottom: 8px;
        border: 1px solid var(--mat-sys-outline-variant);
        border-radius: 8px;
      }
      .fields {
        display: grid;
        gap: 0 12px;
        grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      }
      mat-checkbox {
        padding-top: 14px;
      }
      mat-form-field {
        width: 100%;
      }
    `,
  ],
  template: `
    <mat-form-field>
      <mat-label>Type</mat-label>
      <mat-select [value]="brick().type" (selectionChange)="retype($event.value)">
        @for (e of entries(); track e.type) {
          <mat-option [value]="e.type">{{ e.type }}</mat-option>
        }
      </mat-select>
      <mat-hint>{{ doc() }}</mat-hint>
    </mat-form-field>

    <div class="fields">
      @for (p of params(); track p.name) {
        @if (p.kind === 'bool') {
          <mat-checkbox [checked]="!!brick().values[p.name]" (change)="set(p.name, $event.checked)">
            {{ p.name }}
          </mat-checkbox>
        } @else {
          <mat-form-field>
            <mat-label>{{ p.name }}{{ p.required ? ' *' : '' }}</mat-label>
            <input
              matInput
              [type]="p.kind === 'int' ? 'number' : 'text'"
              [value]="text(p.name)"
              [placeholder]="p.kind === 'stringList' ? 'comma, separated' : ''"
              (input)="set(p.name, $any($event.target).value)"
            />
            <mat-hint>{{ p.doc }}</mat-hint>
          </mat-form-field>
        }
      }
    </div>

    <button matIconButton (click)="removed.emit()" aria-label="Remove">
      <mat-icon>close</mat-icon>
    </button>
  `,
})
export class BrickFormComponent {
  readonly brick = model.required<BrickForm>();
  readonly entries = input.required<CatalogEntry[]>();
  readonly removed = output<void>();

  protected readonly params = computed(() => paramsOf(this.brick().type, this.entries()));
  protected readonly doc = computed(() => docOf(this.brick().type, this.entries()));

  protected retype(type: string): void {
    this.brick.set({ type, values: defaultsFor(paramsOf(type, this.entries())) });
  }

  protected set(name: string, value: string | boolean): void {
    this.brick.update((b) => ({ ...b, values: { ...b.values, [name]: value } }));
  }

  // The values record only holds keys that were touched or have defaults —
  // an absent key must render as an empty input, never as "undefined".
  protected text(name: string): string {
    const v = this.brick().values[name] as string | number | boolean | undefined;
    return v === undefined ? '' : String(v);
  }
}
