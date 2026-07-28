import { COMMA, ENTER } from '@angular/cdk/keycodes';
import { Component, computed, effect, inject, input, output, signal } from '@angular/core';
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
// deletion — the table itself carries no action anymore.
//
// The PARENT is not edited here: the hierarchy is what drag and drop is for,
// and having two ways to move a role would only invite them to disagree.
@Component({
  selector: 'app-role-editor',
  imports: [
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

  readonly saved = output<Role>();
  readonly deleted = output<Role>();
  readonly closed = output<void>();

  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);
  private readonly dialogs = inject(DialogsService);

  protected readonly name = signal('');
  protected readonly description = signal('');
  protected readonly tags = signal<string[]>([]);
  protected readonly saving = signal(false);
  protected readonly separators = [ENTER, COMMA];

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
    });
  }

  protected addTag(event: MatChipInputEvent): void {
    const tag = event.value.trim();
    if (tag && !this.tags().includes(tag)) this.tags.update((t) => [...t, tag]);
    event.chipInput.clear();
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
      : this.api.createRole(payload);
    call.subscribe({
      next: (r) => {
        this.saving.set(false);
        this.saved.emit(r);
      },
      error: (err: unknown) => {
        this.saving.set(false);
        this.fail(err);
      },
    });
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
