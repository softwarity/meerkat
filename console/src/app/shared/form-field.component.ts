import {
  booleanAttribute,
  Component,
  computed,
  contentChild,
  effect,
  ElementRef,
  forwardRef,
  inject,
  input,
  signal,
  viewChild,
} from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatDialog } from '@angular/material/dialog';
import { MatDividerModule } from '@angular/material/divider';
import { MAT_FORM_FIELD, MatFormField, MatFormFieldModule, SubscriptSizing } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInput } from '@angular/material/input';
import { MatMenuModule } from '@angular/material/menu';
import { MatTooltipModule } from '@angular/material/tooltip';
import { VaultEntry } from '../api.service';
import { VaultEntryDialogComponent, VaultEntryDialogData } from './vault-entry-dialog.component';
import { VaultService } from './vault.service';

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
//
// allowVault adds the vault picker (VAULT-01): a key button listing the entries
// of the accepted kinds, inserting the chosen one as $name at the caret, and
// offering to declare a new entry without leaving the screen.
//
//   <app-form-field label="Upstream" allowVault="secret/values">
@Component({
  selector: 'app-form-field',
  imports: [
    MatButtonModule,
    MatDividerModule,
    MatFormFieldModule,
    MatIconModule,
    MatMenuModule,
    MatTooltipModule,
  ],
  // The projected matInput resolves MAT_FORM_FIELD through its DECLARATION
  // injector (the calling template), where the inner mat-form-field is
  // invisible — without this provider it believes it is outside any form
  // field and keeps the browser's native input styling.
  providers: [{ provide: MAT_FORM_FIELD, useExisting: forwardRef(() => FormFieldComponent) }],
  host: { '(input)': 'syncEmpty()' },
  styleUrl: './form-field.component.scss',
  // The @if blocks are written without surrounding whitespace on purpose: the
  // app compiles with preserveWhitespaces (i18n), so a stray text node would
  // stop the single root from being projected into mat-form-field's slots.
  templateUrl: './form-field.component.html',
})
export class FormFieldComponent {
  readonly label = input('');
  // Optional leading icon (a Material symbol name, e.g. "search").
  readonly icon = input('');
  // Hint under the field. An input, not projected content: a <mat-hint> passed
  // through ng-content is invisible to mat-form-field's content queries (same
  // reason the label is an input).
  readonly hint = input('');
  readonly clearable = input(true, { transform: booleanAttribute });
  readonly copyable = input(false, { transform: booleanAttribute });
  readonly revealable = input(false, { transform: booleanAttribute });
  // Masks the projected control WITHOUT relying on input[type=password] — the
  // only way to hide a textarea, and the reason we can use one at all: browsers
  // never offer credential autofill on a textarea, only on inputs.
  readonly masked = input(false, { transform: booleanAttribute });
  readonly subscriptSizing = input<SubscriptSizing>('fixed');
  // Which vault kinds this field accepts: "secret", "values", or both
  // ("secret/values"). Empty (the default) hides the picker entirely.
  readonly allowVault = input('');
  // Which plane this field's value is resolved in (RBAC-05): a route field is
  // "gateway", an application setting is "app". The picker only offers entries
  // of that plane, because only those will actually resolve.
  readonly vaultScope = input<string>('infra');

  private readonly vault = inject(VaultService);
  private readonly dialog = inject(MatDialog);

  // The accepted kinds, parsed from allowVault ("secret/values", "values"…).
  protected readonly vaultKinds = computed<('value' | 'secret')[]>(() => {
    const spec = this.allowVault().toLowerCase();
    const kinds: ('value' | 'secret')[] = [];
    if (spec.includes('value')) kinds.push('value');
    if (spec.includes('secret')) kinds.push('secret');
    return kinds;
  });

  protected readonly vaultChoices = computed(() => {
    const kinds = this.vaultKinds();
    const scope = this.vaultScope();
    return this.vault.entries().filter((e) => kinds.includes(e.kind) && e.scope === scope);
  });

  protected loadVault(): void {
    void this.vault.ensureLoaded();
  }

  // Insert the reference AT THE CARET rather than replacing: an upstream reads
  // "http://${api-host}:8080", so the value is usually built around it.
  protected insertRef(entry: VaultEntry): void {
    const el = this.native;
    if (!el) return;
    // ${name} when the name could run into what follows, $name otherwise.
    const ref = `\${${entry.name}}`;
    const start = el.selectionStart ?? el.value.length;
    const end = el.selectionEnd ?? start;
    el.value = el.value.slice(0, start) + ref + el.value.slice(end);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.focus();
    el.setSelectionRange(start + ref.length, start + ref.length);
    this.empty.set(!el.value);
  }

  // Declare a new entry without leaving the screen being configured, then use
  // it right away.
  protected createEntry(): void {
    const data: VaultEntryDialogData = {
      kinds: this.vaultKinds(),
      scopes: [this.vaultScope()],
      suggestedName: '',
    };
    this.dialog
      .open<VaultEntryDialogComponent, VaultEntryDialogData, VaultEntry>(VaultEntryDialogComponent, {
        data,
        disableClose: true,
      })
      .afterClosed()
      .subscribe((created) => {
        if (created) this.insertRef(created);
      });
  }

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
    effect(() => {
      this.masked();
      this.control(); // re-run once the projected control exists
      this.applyMask();
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
    this.revealed.set(!this.revealed());
    this.applyMask();
  }

  // A password INPUT keeps flipping its type (native, best behaviour); anything
  // else (a textarea, a plain input) is masked in CSS.
  private applyMask(): void {
    const el = this.native;
    if (!el) return;
    if (el instanceof HTMLInputElement && (el.type === 'password' || el.dataset['mkPwd'])) {
      el.dataset['mkPwd'] = '1';
      el.type = this.revealed() ? 'text' : 'password';
      return;
    }
    const hide = this.masked() && !this.revealed();
    el.style.setProperty('-webkit-text-security', hide ? 'disc' : 'none');
    el.style.setProperty('text-security', hide ? 'disc' : 'none');
  }
}
