import { Component, input, model } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';

// A reusable editor for a list of strings (path patterns, hosts, CIDRs…): one
// text field per entry with a remove button, plus an add button. The list is a
// model(): every edit sets a fresh array — no local state.
@Component({
  selector: 'app-string-list',
  imports: [MatButtonModule, MatFormFieldModule, MatIconModule, MatInputModule],
  styles: [
    `
      .row {
        display: flex;
        align-items: center;
        gap: 8px;
      }
      mat-form-field {
        flex: 1;
      }
    `,
  ],
  template: `
    @for (v of values(); track $index; let i = $index) {
      <div class="row">
        <mat-form-field>
          <input
            matInput
            [value]="v"
            [placeholder]="placeholder()"
            (input)="setAt(i, $any($event.target).value)"
          />
        </mat-form-field>
        <button matIconButton (click)="removeAt(i)" i18n-aria-label="@@Remove" aria-label="Remove">
          <mat-icon>close</mat-icon>
        </button>
      </div>
    }
    <button matButton (click)="add()">
      <mat-icon>add</mat-icon>
      {{ addLabel() }}
    </button>
  `,
})
export class StringListComponent {
  readonly values = model.required<string[]>();
  readonly placeholder = input('');
  readonly addLabel = input($localize`:@@Add:Add`);

  protected setAt(index: number, value: string): void {
    this.values.update((list) => list.map((v, i) => (i === index ? value : v)));
  }

  protected removeAt(index: number): void {
    this.values.update((list) => list.filter((_, i) => i !== index));
  }

  protected add(): void {
    this.values.update((list) => [...list, '']);
  }
}
