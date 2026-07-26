import {
  booleanAttribute,
  Component,
  contentChild,
  effect,
  ElementRef,
  forwardRef,
  input,
  signal,
  viewChild,
} from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MAT_FORM_FIELD, MatFormField, MatFormFieldModule, SubscriptSizing } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInput } from '@angular/material/input';

// A mat-form-field wrapper that projects a matInput input or textarea and adds
// the recurring suffix tools: a clear cross (default on), a copy-to-clipboard
// button and a visibility toggle that flips password ↔ text. The label is an
// input (not projected): content projected through ng-content is invisible to
// mat-form-field's own content queries, which is also why the projected control
// is registered explicitly below.
//
//   <app-form-field i18n-label="@@Name" label="Name" copyable>
//     <input matInput [value]="name()" (input)="name.set($any($event.target).value)" />
//   </app-form-field>
@Component({
  selector: 'app-form-field',
  imports: [MatButtonModule, MatFormFieldModule, MatIconModule],
  // The projected matInput resolves MAT_FORM_FIELD through its DECLARATION
  // injector (the calling template), where the inner mat-form-field is
  // invisible — without this provider it believes it is outside any form
  // field and keeps the browser's native input styling.
  providers: [{ provide: MAT_FORM_FIELD, useExisting: forwardRef(() => FormFieldComponent) }],
  host: { '(input)': 'syncEmpty()' },
  styles: [
    `
      :host {
        display: inline-block;
      }
      mat-form-field {
        width: 100%;
      }
    `,
  ],
  // The @if blocks are written without surrounding whitespace on purpose: the
  // app compiles with preserveWhitespaces (i18n), so a stray text node would
  // stop the single root from being projected into mat-form-field's slots.
  template: `
    <mat-form-field [subscriptSizing]="subscriptSizing()">
      @if (label()) {<mat-label>{{ label() }}</mat-label>}
      @if (icon()) {<mat-icon matPrefix>{{ icon() }}</mat-icon>}
      <ng-content />
      @if (revealable()) {<button
          matSuffix
          matIconButton
          type="button"
          (click)="toggleReveal()"
          i18n-aria-label="@@Toggle_visibility"
          aria-label="Toggle visibility"
        ><mat-icon>{{ revealed() ? 'visibility_off' : 'visibility' }}</mat-icon></button>}
      @if (copyable()) {<button
          matSuffix
          matIconButton
          type="button"
          (click)="copy()"
          i18n-aria-label="@@Copy"
          aria-label="Copy"
        ><mat-icon>{{ copied() ? 'check' : 'content_copy' }}</mat-icon></button>}
      @if (clearable() && !empty()) {<button
          matSuffix
          matIconButton
          type="button"
          (click)="clear()"
          i18n-aria-label="@@Clear"
          aria-label="Clear"
        ><mat-icon>close</mat-icon></button>}
    </mat-form-field>
  `,
})
export class FormFieldComponent {
  readonly label = input('');
  // Optional leading icon (a Material symbol name, e.g. "search").
  readonly icon = input('');
  readonly clearable = input(true, { transform: booleanAttribute });
  readonly copyable = input(false, { transform: booleanAttribute });
  readonly revealable = input(false, { transform: booleanAttribute });
  readonly subscriptSizing = input<SubscriptSizing>('fixed');

  private readonly formField = viewChild.required(MatFormField);
  private readonly control = contentChild(MatInput);
  private readonly controlRef = contentChild(MatInput, { read: ElementRef });

  protected readonly revealed = signal(false);
  protected readonly copied = signal(false);
  protected readonly empty = signal(true);

  constructor() {
    effect(() => {
      const control = this.control();
      if (control) this.formField()._control = control;
    });
    // stateChanges covers programmatic writes; the host input listener covers
    // typing (matInput does not emit stateChanges on keystrokes).
    effect((onCleanup) => {
      const control = this.control();
      if (!control) return;
      this.empty.set(control.empty);
      const sub = control.stateChanges.subscribe(() => this.empty.set(control.empty));
      onCleanup(() => sub.unsubscribe());
    });
  }

  // For controls that anchor an overlay on their form field (autocomplete,
  // datepicker) — delegate to the real mat-form-field.
  getConnectedOverlayOrigin(): ElementRef {
    return this.formField().getConnectedOverlayOrigin();
  }

  private get native(): HTMLInputElement | HTMLTextAreaElement | undefined {
    return this.controlRef()?.nativeElement;
  }

  protected syncEmpty(): void {
    this.empty.set(!this.native?.value);
  }

  protected clear(): void {
    const el = this.native;
    if (!el) return;
    el.value = '';
    // Dispatch so whatever binding listens on the projected input reacts.
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.focus();
    this.empty.set(true);
  }

  protected async copy(): Promise<void> {
    const el = this.native;
    if (!el?.value) return;
    await navigator.clipboard.writeText(el.value);
    this.copied.set(true);
    setTimeout(() => this.copied.set(false), 1500);
  }

  protected toggleReveal(): void {
    const el = this.native;
    if (!el || !(el instanceof HTMLInputElement)) return;
    const revealed = !this.revealed();
    this.revealed.set(revealed);
    el.type = revealed ? 'text' : 'password';
  }
}
