import { Component, computed, effect, inject, input, LOCALE_ID, output, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatDialog } from '@angular/material/dialog';
import { MatIconModule } from '@angular/material/icon';
import { MatMenuModule } from '@angular/material/menu';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';
import { MatTooltipModule } from '@angular/material/tooltip';
import { LoadingIndicatorComponent } from '@softwarity/loading-indicator';
import { RowActionsDirective } from '@softwarity/row-actions';
import { DateTime } from 'luxon';
import { catchError, firstValueFrom, forkJoin, Observable, of } from 'rxjs';
import { ApiService, Group, Member, User } from '../../api.service';
import { DialogsService } from '../../shared/dialogs.service';
import {
  GroupDialogComponent,
  GroupDialogData,
  GroupDialogResult,
} from '../group-dialog.component';
import { LoginHistoryDialogComponent } from '../login-history-dialog.component';
import { PasswordDialogComponent } from '../password-dialog.component';

interface UserRow {
  id: string;
  username: string;
  fullname: string;
  lastConnectionAt: number;
}

// The per-tenant members matrix (RBAC-02): rows are the available users, a
// first column marks membership OF this tenant — the checkbox joins/leaves,
// the "admin" badge beside it promotes a member to ADMIN (tenant
// administration is the membership type, TENANT-02). The tenant's owner
// (ownerId, transferred in the Danger zone) shows a read-only "owner" badge
// there instead. Then this tenant's groups are columns — a member is
// ticked into the groups they belong to; group columns are disabled for
// non-members. The last column shows the user's last connection and carries
// the tenant-scoped password reset. Everything persists immediately. Same
// mat-table pattern as the groups matrix.
@Component({
  selector: 'app-members-matrix',
  imports: [
    MatButtonModule,
    MatCheckboxModule,
    MatIconModule,
    MatMenuModule,
    MatTableModule,
    MatTooltipModule,
    LoadingIndicatorComponent,
    RowActionsDirective,
  ],
  templateUrl: './members-matrix.component.html',
  styleUrl: './members-matrix.component.scss',
})
export class MembersMatrixComponent {
  readonly tenantId = input.required<string>();
  // The tenant's owner (ownerId): shown as a read-only badge, may be a
  // non-member. Ownership is transferred in the Danger zone, not here.
  readonly ownerId = input('');
  // Username/fullname search — typed in the drawer's right-zone header.
  readonly filter = input('');
  readonly changed = output<void>();

  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);
  private readonly dialogs = inject(DialogsService);
  private readonly dialog = inject(MatDialog);
  private readonly locale = inject(LOCALE_ID);

  protected readonly loading = signal(true);
  protected readonly rows = signal<UserRow[]>([]);
  protected readonly groups = signal<Group[]>([]);
  // userId → their full membership (type, overrides) when a member.
  protected readonly memberships = signal<Map<string, Member>>(new Map());
  // userId → the group ids they are assigned.
  protected readonly memberGroups = signal<Record<string, string[]>>({});

  protected readonly filteredRows = computed(() => {
    const q = this.filter().trim().toLowerCase();
    if (!q) return this.rows();
    return this.rows().filter((u) => u.username.toLowerCase().includes(q) || u.fullname.toLowerCase().includes(q));
  });

  protected readonly displayedColumns = computed(() => [
    'user',
    'member',
    'spacer',
    ...this.groups().map((g) => g.id),
    'lastConn',
  ]);

  constructor() {
    effect(() => {
      this.tenantId();
      this.load();
    });
  }

  private load(): void {
    this.loading.set(true);
    forkJoin({
      // listUsers is root-only; a tenant admin falls back to the members list.
      users: this.api.listUsers().pipe(catchError(() => of<User[]>([]))),
      members: this.api.listMembers(this.tenantId()),
      groups: this.api.listGroups(this.tenantId()),
    }).subscribe({
      next: ({ users, members, groups }) => {
        const rows: UserRow[] = users.length
          ? users.map((u) => ({
              id: u.id,
              username: u.username,
              fullname: u.fullname,
              lastConnectionAt: u.lastConnectionAt,
            }))
          : members.map((m) => ({
              id: m.userId,
              username: m.username,
              fullname: m.fullname,
              lastConnectionAt: m.lastConnectionAt,
            }));
        this.rows.set(rows);
        this.groups.set(groups);
        this.memberships.set(new Map(members.map((m) => [m.userId, m])));
        this.loadMemberGroups(members.map((m) => m.userId));
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  private loadMemberGroups(memberIds: string[]): void {
    if (!memberIds.length) {
      this.memberGroups.set({});
      return;
    }
    const calls = Object.fromEntries(memberIds.map((id) => [id, this.api.memberGroups(this.tenantId(), id)]));
    forkJoin(calls).subscribe({ next: (map) => this.memberGroups.set(map) });
  }

  protected isMember(userId: string): boolean {
    return this.memberships().has(userId);
  }

  protected memberType(userId: string): string {
    return this.memberships().get(userId)?.type ?? '';
  }

  protected isOwner(userId: string): boolean {
    return userId === this.ownerId();
  }

  protected toggleMember(u: UserRow, checked: boolean): void {
    const req: Observable<unknown> = checked
      ? this.api.putMember({
          userId: u.id,
          tenantId: this.tenantId(),
          type: 'USER',
          enabled: true,
          businessAccess: { inherited: true },
          sessionTTL: '',
        })
      : this.api.deleteMember(this.tenantId(), u.id);
    req.subscribe({
      next: () => {
        this.load(); // membership map, groups and types all move together
        this.changed.emit();
      },
      error: (err) => this.snack.open(errMsg(err), undefined, { duration: 4000 }),
    });
  }

  // Tenant administration IS the membership type (TENANT-02): the badge flips
  // USER ↔ ADMIN. The owner has no toggle here — ownership is a tenant field,
  // transferred in the Danger zone.
  protected toggleAdmin(u: UserRow): void {
    const m = this.memberships().get(u.id);
    if (!m) return;
    const { username, fullname, email, lastConnectionAt, ...membership } = m;
    this.api.putMember({ ...membership, type: m.type === 'ADMIN' ? 'USER' : 'ADMIN' }).subscribe({
      next: (saved) =>
        this.memberships.update((map) => {
          const next = new Map(map);
          next.set(u.id, { ...m, type: saved.type });
          return next;
        }),
      error: (err) => this.snack.open(errMsg(err), undefined, { duration: 4000 }),
    });
  }

  protected memberInGroup(userId: string, groupId: string): boolean {
    return (this.memberGroups()[userId] ?? []).includes(groupId);
  }

  protected toggleMemberGroup(userId: string, groupId: string, checked: boolean): void {
    const current = this.memberGroups()[userId] ?? [];
    const ids = checked ? [...current, groupId] : current.filter((g) => g !== groupId);
    this.api.setMemberGroups(this.tenantId(), userId, ids).subscribe({
      next: (saved) => this.memberGroups.update((m) => ({ ...m, [userId]: saved })),
      error: (err) => {
        this.snack.open(errMsg(err), undefined, { duration: 4000 });
        this.load();
      },
    });
  }

  // ── last connection + tenant-scoped password reset ────────────────────────

  protected lastSeen(ts: number): string {
    if (!ts) return '—';
    return DateTime.fromSeconds(ts).reconfigure({ locale: this.locale }).toRelative() ?? '—';
  }

  protected lastSeenFull(ts: number): string {
    if (!ts) return '';
    return DateTime.fromSeconds(ts).reconfigure({ locale: this.locale }).toLocaleString(DateTime.DATETIME_MED);
  }

  protected showLogins(u: UserRow): void {
    this.dialog.open(LoginHistoryDialogComponent, {
      width: '520px',
      data: { tenantId: this.tenantId(), userId: u.id, username: u.username },
    });
  }

  protected async resetPassword(u: UserRow): Promise<void> {
    const ok = await this.dialogs.confirm({
      title: $localize`:@@Reset_password_USERNAME:Reset password for "${u.username}:USERNAME:"?`,
      confirmLabel: $localize`:@@Reset_password:Reset password`,
    });
    if (!ok) return;
    this.api.resetMemberPassword(this.tenantId(), u.id).subscribe({
      next: ({ password }) =>
        this.dialog.open(PasswordDialogComponent, { data: { username: u.username, password } }),
      error: (err) => this.snack.open(errMsg(err), undefined, { duration: 4000 }),
    });
  }

  // ── group columns (shared behaviour with the groups matrix) ───────────────

  protected async addGroup(): Promise<void> {
    const res = await firstValueFrom(
      this.dialog
        .open<GroupDialogComponent, GroupDialogData, GroupDialogResult | undefined>(GroupDialogComponent, {
          width: '440px',
          data: { title: $localize`:@@New_group:New group`, confirmLabel: $localize`:@@Create:Create` },
        })
        .afterClosed(),
    );
    if (!res) return;
    this.api.createGroup(this.tenantId(), { name: res.name, description: res.description, roleIds: [] }).subscribe({
      next: (g) => {
        this.groups.update((list) => [...list, g]);
        this.changed.emit();
      },
      error: (err) => this.snack.open(errMsg(err), undefined, { duration: 4000 }),
    });
  }

  protected async editGroup(g: Group): Promise<void> {
    const res = await firstValueFrom(
      this.dialog
        .open<GroupDialogComponent, GroupDialogData, GroupDialogResult | undefined>(GroupDialogComponent, {
          width: '440px',
          data: {
            title: $localize`:@@Edit_group:Edit group`,
            confirmLabel: $localize`:@@Save:Save`,
            name: g.name,
            description: g.description,
          },
        })
        .afterClosed(),
    );
    if (!res || (res.name === g.name && res.description === (g.description ?? ''))) return;
    this.api
      .updateGroup({ ...g, name: res.name, description: res.description, roleIds: g.roleIds ?? [] })
      .subscribe({
        next: (saved) => {
          this.groups.update((list) => list.map((x) => (x.id === saved.id ? saved : x)));
          this.changed.emit();
        },
        error: (err) => this.snack.open(errMsg(err), undefined, { duration: 4000 }),
      });
  }

  protected async removeGroup(g: Group): Promise<void> {
    const ok = await this.dialogs.confirm({
      title: $localize`:@@Delete_group_NAME:Delete group "${g.name}:NAME:"?`,
      confirmLabel: $localize`:@@Delete:Delete`,
      danger: true,
    });
    if (!ok) return;
    this.api.deleteGroup(this.tenantId(), g.id).subscribe({
      next: () => {
        this.groups.update((list) => list.filter((x) => x.id !== g.id));
        this.changed.emit();
      },
      error: (err) => this.snack.open(errMsg(err), undefined, { duration: 4000 }),
    });
  }
}

function errMsg(err: unknown): string {
  const e = err as { error?: { error?: string } };
  return typeof e?.error?.error === 'string' ? e.error.error : $localize`:@@Request_failed:Request failed`;
}
