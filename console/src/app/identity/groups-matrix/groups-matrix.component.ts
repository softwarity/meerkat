import { Component, computed, effect, inject, input, output, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatDialog } from '@angular/material/dialog';
import { MatIconModule } from '@angular/material/icon';
import { MatMenuModule } from '@angular/material/menu';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';
import { MatTooltipModule } from '@angular/material/tooltip';
import { LoadingIndicatorComponent } from '@softwarity/loading-indicator';
import { firstValueFrom, forkJoin } from 'rxjs';
import { ApiService, Group, Role } from '../../api.service';
import { RoleTreeRow, flattenRoles } from '../../shared/role-tree';
import { TreePrefixComponent } from '../../shared/tree-prefix.component';
import {
  GroupDialogComponent,
  GroupDialogData,
  GroupDialogResult,
} from '../group-dialog.component';
import { DialogsService } from '../../shared/dialogs.service';

// The per-tenant groups matrix (RBAC-02): rows are the GLOBAL role catalogue,
// columns are this tenant's groups, a cell checkbox = the role belongs to the
// group. Checking a role also checks its hierarchical children (a parent role
// implies its children). Rows filter by tag and search by name/description.
// A group column's kebab menu renames or deletes it. mat-table with a sticky
// role column and header; columns scroll horizontally when they overflow.
// One line of the matrix: a row of the flattened catalogue, plus whether it
// matched the filter itself or was pulled in to keep the chain readable.
interface RoleRow extends RoleTreeRow {
  context: boolean;
}

@Component({
  selector: 'app-groups-matrix',
  imports: [
    MatButtonModule,
    MatCheckboxModule,
    MatIconModule,
    MatMenuModule,
    MatTableModule,
    MatTooltipModule,
    LoadingIndicatorComponent,
    TreePrefixComponent,
  ],
  templateUrl: './groups-matrix.component.html',
  styleUrl: './groups-matrix.component.scss',
})
export class GroupsMatrixComponent {
  readonly tenantId = input.required<string>();
  // Name/description search and the single-tag filter — both live in the
  // layout's right-zone header.
  readonly filter = input('');
  readonly tagFilter = input('');
  // The role tags available, for the header's tag select.
  readonly availableTags = output<string[]>();
  // Emitted when the set of groups changes, so the host can refresh anything
  // else that lists them (the members matrix).
  readonly changed = output<void>();

  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);
  private readonly dialogs = inject(DialogsService);
  private readonly dialog = inject(MatDialog);

  protected readonly loading = signal(true);
  protected readonly roles = signal<Role[]>([]);
  protected readonly groups = signal<Group[]>([]);

  // roleId → its parent, to walk the ancestor chain: a role implied by an
  // ancestor already in the group is checked AND locked (you cannot uncheck a
  // child while its parent grants it).
  private readonly parentOf = computed(() => {
    const map = new Map<string, string>();
    for (const r of this.roles()) if (r.parentId) map.set(r.id, r.parentId);
    return map;
  });

  private readonly allTags = computed(() =>
    [...new Set(this.roles().flatMap((r) => r.tags))].sort(),
  );

  // The catalogue as the TREE it already behaves like, drawn with the same
  // guides as the roles page (shared/role-tree.ts): two screens picturing one
  // hierarchy differently is how a reader learns to distrust both.
  //
  // The hierarchy is not decoration here: a role implies its descendants, which
  // is why a box can be checked and locked because an ancestor grants it. The
  // branch is what makes that lock legible.
  protected readonly rows = computed<RoleRow[]>(() => {
    const roles = this.roles();
    const q = this.filter().trim().toLowerCase();
    const tag = this.tagFilter();
    if (!q && !tag) {
      return flattenRoles(roles).map((row) => ({ ...row, context: false }));
    }
    const matches = new Set<string>();
    for (const r of roles) {
      const desc = (r.description ?? '').toLowerCase();
      const matchQ = !q || r.name.toLowerCase().includes(q) || desc.includes(q);
      const matchTag = !tag || (r.tags ?? []).includes(tag);
      if (matchQ && matchTag) matches.add(r.id);
    }
    // Ancestors of a match come along, or the branch would lie: a row drawn
    // under nothing reads as a root, at the very moment someone filtered in
    // order to understand. Dimmed, not hidden, and still clickable since they
    // are real roles.
    const visible = new Set(matches);
    for (const id of matches) for (const a of this.ancestorsOf(id)) visible.add(a);
    return flattenRoles(roles.filter((r) => visible.has(r.id))).map((row) => ({
      ...row,
      context: !matches.has(row.role.id),
    }));
  });

  protected readonly displayedColumns = computed(() => ['role', 'spacer', ...this.groups().map((g) => g.id)]);


  constructor() {
    effect(() => {
      this.tenantId(); // re-run when the tenant changes
      this.load();
    });
    // Publish the tag list for the layout header's select.
    effect(() => this.availableTags.emit(this.allTags()));
  }

  private load(): void {
    this.loading.set(true);
    forkJoin({ roles: this.api.listRoles(), groups: this.api.listGroups(this.tenantId()) }).subscribe({
      next: ({ roles, groups }) => {
        this.roles.set(roles);
        this.groups.set(groups);
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  private ancestorsOf(id: string): string[] {
    const out: string[] = [];
    const seen = new Set<string>();
    let cur = this.parentOf().get(id);
    while (cur && !seen.has(cur)) {
      seen.add(cur);
      out.push(cur);
      cur = this.parentOf().get(cur);
    }
    return out;
  }

  // Look the group up fresh from the signal (NOT the column-loop closure) so a
  // cell re-evaluates when groups() changes — otherwise the checkbox is stale.
  private groupById(id: string): Group | undefined {
    return this.groups().find((g) => g.id === id);
  }

  // A group's role set, null-safe: an older gateway serialises no-roles as null.
  private roleIdsOf(groupId: string): string[] {
    return this.groupById(groupId)?.roleIds ?? [];
  }

  // Checked = the role is in the group directly OR granted by an ancestor.
  protected roleChecked(role: Role, groupId: string): boolean {
    const ids = this.roleIdsOf(groupId);
    return ids.includes(role.id) || this.ancestorsOf(role.id).some((a) => ids.includes(a));
  }

  // Locked = an ancestor already grants it, so it cannot be toggled on its own.
  protected roleImplied(role: Role, groupId: string): boolean {
    const ids = this.roleIdsOf(groupId);
    return this.ancestorsOf(role.id).some((a) => ids.includes(a));
  }

  protected toggle(role: Role, groupId: string, checked: boolean): void {
    const g = this.groupById(groupId);
    if (!g) return;
    const current = g.roleIds ?? [];
    const roleIds = checked ? [...current, role.id] : current.filter((r) => r !== role.id);
    this.api.updateGroup({ ...g, roleIds }).subscribe({
      next: (saved) => this.groups.update((list) => list.map((x) => (x.id === saved.id ? saved : x))),
      error: (err) => {
        this.snack.open(errMsg(err), undefined, { duration: 4000 });
        this.load();
      },
    });
  }

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
