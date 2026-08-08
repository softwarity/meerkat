import { COMMA, ENTER } from '@angular/cdk/keycodes';
import { Component, computed, effect, inject, input, output, signal, viewChild } from '@angular/core';
import {
  MatAutocompleteModule,
  MatAutocompleteSelectedEvent,
  MatAutocompleteTrigger,
} from '@angular/material/autocomplete';
import { MatButtonModule } from '@angular/material/button';
import { MatChipInputEvent, MatChipsModule } from '@angular/material/chips';
import { MatDividerModule } from '@angular/material/divider';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatSnackBar } from '@angular/material/snack-bar';
import { ApiService, Role } from '../../api.service';
import { DialogsService } from '../../shared/dialogs.service';
import { FormFieldComponent } from '../../shared/form-field.component';

// One catalogue role, hosted in the roles-page right drawer (opened by clicking
// a row, like a route or a user). Its technical name, the human description the
// tenant screens put forward, the tags the groups matrix filters on, and the
// deletion - the table itself carries no action anymore.
//
// The PARENT is not edited here: MOVING a role is what drag and drop is for,
// and having two ways to move one would only invite them to disagree. A
// creation may still be born under a parent - the + on a row hands it over.
@Component({
  selector: 'app-role-editor',
  imports: [
    MatAutocompleteModule,
    MatButtonModule,
    MatChipsModule,
    MatDividerModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    FormFieldComponent,
  ],
  templateUrl: './role-editor.component.html',
  styleUrl: './role-editor.component.scss',
})
export class RoleEditorComponent {
  // null creates one.
  readonly role = input<Role | null>(null);
  // The role the creation hangs under, when it was opened by the + of a row.
  // Read at creation time only: an existing role moves by drag and drop.
  readonly parent = input<Role | null>(null);
  // Every tag already worn by a role of the catalogue: a tag is only useful to
  // the groups matrix if several roles spell it the SAME way, so the input
  // proposes what exists before letting a second spelling in.
  readonly knownTags = input<string[]>([]);

  readonly saved = output<Role>();
  readonly deleted = output<Role>();
  readonly closed = output<void>();

  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);
  private readonly dialogs = inject(DialogsService);

  private readonly tagTrigger = viewChild(MatAutocompleteTrigger);

  protected readonly name = signal('');
  protected readonly description = signal('');
  protected readonly tags = signal<string[]>([]);
  protected readonly tagQuery = signal('');
  protected readonly saving = signal(false);
  protected readonly separators = [ENTER, COMMA];

  // The suggestions: the catalogue's tags this role does not carry yet,
  // narrowed by what is being typed.
  protected readonly tagOptions = computed(() => {
    const q = this.tagQuery().trim().toLowerCase();
    const taken = new Set(this.tags());
    return this.knownTags()
      .filter((t) => !taken.has(t) && (!q || t.toLowerCase().includes(q)))
      .slice(0, 12);
  });

  protected readonly creating = computed(() => this.role() === null);
  // A system role's name is the contract the code checks against: describe it,
  // tag it, but never rename or delete it.
  protected readonly locked = computed(() => this.role()?.system ?? false);
  protected readonly canSave = computed(() => this.name().trim().length > 0 && !this.saving());

  constructor() {
    // Rebind whenever the drawer switches role (the URL drives it, the page
    // keeps the same component instance).
    effect(() => {
      const r = this.role();
      this.name.set(r?.name ?? '');
      this.description.set(r?.description ?? '');
      this.tags.set([...(r?.tags ?? [])]);
      this.tagQuery.set('');
    });
  }

  protected addTag(event: MatChipInputEvent): void {
    // Enter on a highlighted suggestion reaches BOTH the autocomplete and the
    // chip input: that key belongs to pickTag(), which adds the whole tag and
    // not the few letters typed under it.
    if (this.tagTrigger()?.panelOpen && this.tagTrigger()?.activeOption) return;
    this.pushTag(event.value);
    event.chipInput.clear();
    this.tagQuery.set('');
  }

  // Picking a suggestion: the autocomplete swallows the Enter key, so the chip
  // is added here and the option released for the next open.
  protected pickTag(event: MatAutocompleteSelectedEvent, input: HTMLInputElement): void {
    this.pushTag(event.option.value as string);
    input.value = '';
    this.tagQuery.set('');
    event.option.deselect();
  }

  private pushTag(raw: string): void {
    const tag = raw.trim();
    if (tag && !this.tags().includes(tag)) this.tags.update((t) => [...t, tag]);
  }

  protected removeTag(tag: string): void {
    this.tags.update((t) => t.filter((x) => x !== tag));
  }

  protected save(): void {
    if (!this.canSave()) return;
    this.saving.set(true);
    const current = this.role();
    const payload = {
      name: this.name().trim(),
      description: this.description().trim(),
      tags: this.tags(),
    };
    const call = current
      ? this.api.updateRole({ ...current, ...payload })
      : this.api.createRole({ ...payload, parentId: this.parent()?.id ?? '' });
    call.subscribe({
      next: (r) => {
        this.saving.set(false);
        this.saved.emit(r);
        // An update stays on the role it just wrote; a creation empties the
        // form for the next one (see resetForm).
        if (!current) this.resetForm();
      },
      error: (err: unknown) => {
        this.saving.set(false);
        this.fail(err);
      },
    });
  }

  // A catalogue is rarely filled one role at a time: a creation leaves the
  // drawer open on an empty form, ready for the next role. Closing is one
  // click away and staying on the role just created serves nobody.
  private resetForm(): void {
    this.name.set('');
    this.description.set('');
    this.tags.set([]);
    this.tagQuery.set('');
  }

  protected async remove(): Promise<void> {
    const current = this.role();
    if (!current) return;
    const ok = await this.dialogs.confirm({
      title: $localize`:@@Delete_role_NAME:Delete role "${current.name}:NAME:"?`,
      confirmLabel: $localize`:@@Delete:Delete`,
      danger: true,
    });
    if (!ok) return;
    this.api.deleteRole(current.id).subscribe({
      next: () => this.deleted.emit(current),
      error: (err: unknown) => this.fail(err),
    });
  }

  private fail(err: unknown): void {
    const e = err as { error?: { error?: string } };
    this.snack.open(
      typeof e?.error?.error === 'string' ? e.error.error : $localize`:@@Request_failed:Request failed`,
      undefined,
      { duration: 4000 },
    );
  }
}
