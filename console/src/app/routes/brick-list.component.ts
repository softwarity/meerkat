import { Component, input, model } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { CatalogEntry } from '../api.service';
import { BrickForm, defaultsFor } from './brick';
import { BrickFormComponent } from './brick-form.component';

// An editable list of bricks (the predicates or the filters of a route).
@Component({
  selector: 'app-brick-list',
  imports: [MatButtonModule, MatIconModule, BrickFormComponent],
  styles: [
    `
      h3 {
        margin: 12px 0 8px;
        font-size: 0.95rem;
        font-weight: 500;
        color: var(--mat-sys-on-surface-variant);
      }
    `,
  ],
  template: `
    <h3>{{ title() }}</h3>
    @for (b of bricks(); track $index; let i = $index) {
      <app-brick-form
        [brick]="b"
        (brickChange)="updateAt(i, $event)"
        [entries]="entries()"
        (removed)="removeAt(i)"
      />
    }
    <button matButton (click)="add()">
      <mat-icon>add</mat-icon>
      {{ addLabel() }}
    </button>
  `,
})
export class BrickListComponent {
  readonly bricks = model.required<BrickForm[]>();
  readonly entries = input.required<CatalogEntry[]>();
  readonly title = input('');
  readonly addLabel = input('Add');

  protected add(): void {
    const first = this.entries()[0];
    this.bricks.update((list) => [
      ...list,
      { type: first.type, values: defaultsFor(first.params) },
    ]);
  }

  protected updateAt(index: number, brick: BrickForm): void {
    this.bricks.update((list) => list.map((b, i) => (i === index ? brick : b)));
  }

  protected removeAt(index: number): void {
    this.bricks.update((list) => list.filter((_, i) => i !== index));
  }
}
