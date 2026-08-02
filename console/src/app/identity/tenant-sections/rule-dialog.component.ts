import { Component, computed, inject, signal } from '@angular/core';
import { MatAutocompleteModule } from '@angular/material/autocomplete';
import { MatButtonModule } from '@angular/material/button';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { AuthProvider, Group, GroupRule } from '../../api.service';
import { FormFieldComponent } from '../../shared/form-field.component';

export interface RuleDialogData {
  rule?: GroupRule;
  tenantName: string;
  groups: Group[];
  authorities: AuthProvider[];
  // The group names the authorities have actually been heard to say.
  reported: string[];
}

// One group rule, written as a sentence. The dialog exists mostly to keep the
// two halves apart in the reader's head: what has to be true upstream, and
// what it grants here.
@Component({
  selector: 'app-rule-dialog',
  imports: [
    MatAutocompleteModule,
    MatButtonModule,
    MatDialogModule,
    MatInputModule,
    MatSelectModule,
    FormFieldComponent,
  ],
  styleUrl: './rule-dialog.component.scss',
  templateUrl: './rule-dialog.component.html',
})
export class RuleDialogComponent {
  protected readonly data = inject<RuleDialogData>(MAT_DIALOG_DATA);
  protected readonly ref = inject(MatDialogRef<RuleDialogComponent, Partial<GroupRule> | undefined>);

  protected readonly providerId = signal(this.data.rule?.providerId ?? '');
  protected readonly external = signal(this.data.rule?.external ?? '');
  protected readonly groupId = signal(this.data.rule?.groupId ?? '');

  // What the field offers as you type: the names really reported, filtered.
  protected readonly suggestions = computed(() => {
    const typed = this.external().trim().toLowerCase();
    const all = this.data.reported;
    return typed ? all.filter((n) => n.toLowerCase().includes(typed)) : all;
  });

  // A rule matching every authority AND every group would admit anyone the
  // gateway ever authenticates, so the server refuses it. Say so here rather
  // than letting someone hit Save to find out.
  protected readonly canSave = computed(
    () => this.providerId().trim() !== '' || this.external().trim() !== '',
  );

  protected apply(): void {
    this.ref.close({
      providerId: this.providerId().trim(),
      external: this.external().trim(),
      groupId: this.groupId(),
    });
  }
}
