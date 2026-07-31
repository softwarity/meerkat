import { booleanAttribute, Component, computed, inject, input, model, output } from '@angular/core';
import { MatDialog } from '@angular/material/dialog';
import { MatInputModule } from '@angular/material/input';
import { SecretLocation, VaultEntry } from '../api.service';
import { FormFieldComponent } from './form-field.component';
import { VaultEntryDialogComponent, VaultEntryDialogData } from './vault-entry-dialog.component';
import { refName, suggestEntryName, vaultRef } from './vault-ref';

// The four states a secret field can be in. What separates them is not the
// text: it is WHO HOLDS the value.
export type SecretState = 'empty' | 'reference' | 'typed' | 'held';

// A field for a secret (VAULT-05). A secret is typed here at most once, on its
// way to the vault: what stays in the configuration is ${name}.
//
// Typing is allowed on purpose. A client secret is generated at the provider,
// lands in the clipboard and is never shown again — sending the admin to the
// vault first to create an entry, then back here to pick it, loses exactly that
// clipboard. So: paste, then move it in. One gesture.
//
// The validator is what makes it stick, and it applies to WHAT THE ADMIN
// TYPED, never to what they inherited:
//
//   empty      nothing set               — ordinary field
//   reference  ${name}                   — valid, shows WHICH entry
//   typed      a literal, just entered   — BLOCKING: they hold it, they can
//                                          move it, and the action is in the
//                                          error itself
//   held       a literal stored server-side, never received here — a warning,
//              not an error: blocking it would strand someone on a field they
//              cannot fill, for an edit that has nothing to do with it. One
//              click moves it, server-side.
@Component({
  selector: 'app-secret-field',
  imports: [MatInputModule, FormFieldComponent],
  styleUrl: './secret-field.component.scss',
  templateUrl: './secret-field.component.html',
})
export class SecretFieldComponent {
  private readonly dialog = inject(MatDialog);

  readonly label = input('');
  readonly hint = input('');
  readonly placeholder = input('');
  // The field's value: a ${name} reference, a literal being typed, or ''.
  readonly value = model('');
  // A LITERAL is stored server-side and was not sent here. Without this the
  // field would look unset, and an empty-looking password invites a reset.
  readonly held = input(false, { transform: booleanAttribute });
  // Where the server can find that literal, so it can move it in on its own.
  // Absent, an inherited literal can only be replaced, not moved.
  readonly at = input<SecretLocation>();
  readonly scope = input('infra');
  // Raised after a SERVER-SIDE move: the server rewrote the object, so the
  // screen's copy of it is stale and has to be reloaded.
  readonly moved = output<void>();

  protected readonly entry = computed(() => refName(this.value()));

  readonly state = computed<SecretState>(() => {
    if (this.entry()) return 'reference';
    if (this.value().trim()) return 'typed';
    return this.held() ? 'held' : 'empty';
  });

  // What a screen binds its Save button to. Only a typed literal blocks: it is
  // the one case where the admin has the value in hand.
  readonly invalid = computed(() => this.state() === 'typed');

  protected readonly moveLabel = $localize`:@@Move_into_the_vault:Move into the vault`;

  // What the field says about itself, and whether it can be acted on. A
  // blocking state that offers no way out is a dead end, so the action rides
  // in the field's own suffix row rather than somewhere else on the screen.
  protected readonly issue = computed(() => {
    switch (this.state()) {
      case 'typed':
        return {
          blocking: true,
          text: $localize`:@@Secret_must_go_to_the_vault:A secret is not saved in clear. Move it into the vault to continue.`,
          canMove: true,
        };
      case 'held':
        return {
          blocking: false,
          text: this.at()
            ? $localize`:@@Secret_stored_in_clear:A secret is stored in clear in the configuration.`
            : $localize`:@@Secret_stored_leave_empty_to_keep:A secret is stored. Leave empty to keep it.`,
          canMove: !!this.at(),
        };
      default:
        return null;
    }
  });

  // Server-side derivation, mirrored: the same field always suggests the same
  // entry, so moving one twice cannot scatter near-duplicates.
  private suggestedName(): string {
    const at = this.at();
    return at ? suggestEntryName(at.id || at.holder, at.field) : '';
  }

  protected move(): void {
    const typed = this.state() === 'typed' ? this.value().trim() : '';
    const data: VaultEntryDialogData = {
      kinds: ['secret'],
      scopes: [this.scope()],
      suggestedName: this.suggestedName(),
      // A literal that was just typed is handed over here; one that only the
      // server holds is fetched by the server itself.
      stash: typed ? { value: typed } : { from: this.at() },
    };
    this.dialog
      .open<VaultEntryDialogComponent, VaultEntryDialogData, VaultEntry>(VaultEntryDialogComponent, {
        data,
        disableClose: true,
      })
      .afterClosed()
      .subscribe((entry) => {
        if (!entry) return;
        this.value.set(vaultRef(entry.name));
        // The server rewrote the object behind this screen's back.
        if (!typed) this.moved.emit();
      });
  }
}
