import { DatePipe } from '@angular/common';
import { Component, effect, inject, input, signal, untracked } from '@angular/core';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { LoadingIndicatorComponent } from '@softwarity/loading-indicator';
import { catchError, of } from 'rxjs';
import { ApiService, ExternalIdentity } from '../api.service';

// The authorities a person can sign in through (AUTH-19), and what each one
// last said about them. Read-only, and deliberately raw.
//
// The GROUPS are the point. An authority reports its own group names on every
// sign-in; nothing of Meerkat's is derived from them yet, so this is the only
// place an admin can find out what upstream actually sends - "staff",
// "cn=devs,ou=groups,dc=acme,dc=io", "softwarity/gateway" - before writing any
// rule against those names. Showing them translated or tidied would defeat
// that: what is displayed has to be exactly what a mapping would match.
@Component({
  selector: 'app-external-identities',
  imports: [DatePipe, MatIconModule, MatTooltipModule, LoadingIndicatorComponent],
  styleUrl: './external-identities.component.scss',
  templateUrl: './external-identities.component.html',
})
export class ExternalIdentitiesComponent {
  readonly userId = input.required<string>();
  // Whether the account holds a LOCAL password, so an empty list can tell an
  // ordinary local account from one that cannot sign in at all.
  readonly hasPassword = input<boolean | undefined>(undefined);

  private readonly api = inject(ApiService);
  protected readonly identities = signal<ExternalIdentity[] | null>(null);

  constructor() {
    effect(() => {
      const userId = this.userId();
      untracked(() => this.load(userId));
    });
  }

  private load(userId: string): void {
    this.identities.set(null);
    this.api
      .userIdentities(userId)
      .pipe(catchError(() => of<ExternalIdentity[]>([])))
      .subscribe((list) => this.identities.set(list));
  }

  // The icon says at a glance which kind of authority answered.
  protected icon(kind: string): string {
    switch (kind) {
      case 'ldap':
        return 'account_tree';
      case 'github':
        return 'code';
      default:
        return 'shield_person';
    }
  }
}
