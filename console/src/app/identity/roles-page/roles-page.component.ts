import { CdkDragDrop, DragDropModule } from '@angular/cdk/drag-drop';
import { Component, computed, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatDialog } from '@angular/material/dialog';
import { MatIconModule } from '@angular/material/icon';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';
import { MatTooltipModule } from '@angular/material/tooltip';
import { LoadingIndicatorComponent } from '@softwarity/loading-indicator';
import { RowActionsDirective } from '@softwarity/row-actions';
import { firstValueFrom } from 'rxjs';
import { ApiService, Role } from '../../api.service';
import { DialogsService } from '../../shared/dialogs.service';
import { RoleDialogComponent, RoleDialogResult } from '../role-dialog.component';
import { TreeGuide, TreePrefixComponent } from '../../shared/tree-prefix.component';

// One row of the flattened tree: the role plus the guide glyphs materializing
// its position in the hierarchy.
interface RoleNode {
  role: Role;
  guides: TreeGuide[];
}

// The GLOBAL role catalogue (RBAC-01), root only — archway's roles tree: a
// flat mat-table ordered as a depth-first walk of the parentId hierarchy,
// with SVG guide lines materializing the branches. The hierarchy is edited by
// DRAG AND DROP: drag a row onto another row to make it that role's child,
// or onto the drop zone above the table to make it top-level. Dropping a role
// onto itself, its current parent or one of its descendants is refused.
// Per-tenant GROUPS assemble subsets of this catalogue (in the tenant drawer).
// System roles are protected from deletion.
@Component({
  selector: 'app-roles-page',
  imports: [
    DragDropModule,
    MatButtonModule,
    MatIconModule,
    MatTableModule,
    MatTooltipModule,
    LoadingIndicatorComponent,
    RowActionsDirective,
    TreePrefixComponent,
  ],
  templateUrl: './roles-page.component.html',
  styleUrl: './roles-page.component.scss',
})
export class RolesPageComponent {
  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);
  private readonly dialogs = inject(DialogsService);
  private readonly dialog = inject(MatDialog);

  protected readonly loading = signal(true);
  protected readonly roles = signal<Role[]>([]);
  protected readonly columns = ['role', 'description', 'tags'];

  // Depth-first walk of the parentId hierarchy — the table shows the TREE.
  protected readonly nodes = computed(() => flattenTree(this.roles()));

  // Drag state: the role in flight, and the currently valid drop target
  // (a role = becomes its child; 'root' = becomes top-level).
  protected readonly dragged = signal<Role | null>(null);
  protected readonly target = signal<Role | 'root' | null>(null);
  protected readonly targetRoleId = computed(() => {
    const t = this.target();
    return t && t !== 'root' ? t.id : null;
  });

  private readonly parentOf = computed(() => {
    const map = new Map<string, string>();
    for (const r of this.roles()) if (r.parentId) map.set(r.id, r.parentId);
    return map;
  });

  constructor() {
    this.load();
  }

  load(): void {
    this.loading.set(true);
    this.api.listRoles().subscribe({
      next: (roles) => {
        this.roles.set(roles);
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  // ── drag & drop re-parenting ──────────────────────────────────────────────

  protected dragStarted(role: Role): void {
    this.dragged.set(role);
    this.target.set(null);
  }

  protected dragEnded(): void {
    this.dragged.set(null);
    this.target.set(null);
  }

  // The CDK preview under the pointer is pointer-events:none, so the row under
  // the cursor receives mouseover — that row is the drop candidate.
  protected hoverRow(role: Role): void {
    const d = this.dragged();
    if (!d) return;
    this.target.set(this.validTarget(d, role) ? role : null);
  }

  protected hoverRoot(): void {
    const d = this.dragged();
    if (d?.parentId) this.target.set('root');
  }

  // A role cannot become a child of itself, of its current parent (no-op) or
  // of one of its own descendants (cycle).
  private validTarget(dragged: Role, over: Role): boolean {
    if (over.id === dragged.parentId) return false;
    let cur: string | undefined = over.id;
    const seen = new Set<string>();
    while (cur && !seen.has(cur)) {
      if (cur === dragged.id) return false; // over IS dragged or sits in its subtree
      seen.add(cur);
      cur = this.parentOf().get(cur);
    }
    return true;
  }

  protected drop(): void {
    const dragged = this.dragged();
    const target = this.target();
    this.dragEnded();
    if (!dragged || !target) return;
    const parentId = target === 'root' ? '' : target.id;
    this.api.updateRole({ ...dragged, parentId }).subscribe({
      next: (saved) => this.roles.update((list) => list.map((r) => (r.id === saved.id ? saved : r))),
      error: (err) => {
        this.snack.open(errMsg(err), undefined, { duration: 4000 });
        this.load(); // a rejected cycle rolls the tree back to server truth
      },
    });
  }

  // ── CRUD ──────────────────────────────────────────────────────────────────

  protected async create(): Promise<void> {
    const res = await this.openRoleDialog({
      title: $localize`:@@New_role:New role`,
      confirmLabel: $localize`:@@Create:Create`,
    });
    if (!res) return;
    this.api.createRole({ name: res.name, description: res.description, tags: res.tags }).subscribe({
      next: (r) => this.roles.update((list) => [...list, r]),
      error: (err) => this.snack.open(errMsg(err), undefined, { duration: 4000 }),
    });
  }

  protected async edit(role: Role): Promise<void> {
    const res = await this.openRoleDialog({
      title: $localize`:@@Edit_role:Edit role`,
      confirmLabel: $localize`:@@Save:Save`,
      name: role.name,
      description: role.description,
      tags: role.tags,
    });
    if (!res) return;
    this.api.updateRole({ ...role, name: res.name, description: res.description, tags: res.tags }).subscribe({
      next: (saved) => this.roles.update((list) => list.map((r) => (r.id === saved.id ? saved : r))),
      error: (err) => this.snack.open(errMsg(err), undefined, { duration: 4000 }),
    });
  }

  private openRoleDialog(data: {
    title: string;
    confirmLabel: string;
    name?: string;
    description?: string;
    tags?: string[];
  }): Promise<RoleDialogResult | undefined> {
    return firstValueFrom(
      this.dialog.open(RoleDialogComponent, { data, width: '480px', restoreFocus: true }).afterClosed(),
    );
  }

  protected async remove(role: Role): Promise<void> {
    const ok = await this.dialogs.confirm({
      title: $localize`:@@Delete_role_NAME:Delete role "${role.name}:NAME:"?`,
      confirmLabel: $localize`:@@Delete:Delete`,
      danger: true,
    });
    if (!ok) return;
    this.api.deleteRole(role.id).subscribe({
      next: () => this.load(),
      error: (err) => this.snack.open(errMsg(err), undefined, { duration: 4000 }),
    });
  }
}

// Depth-first flatten of the parentId hierarchy, siblings in name order, with
// the guide glyphs for each row (see TreePrefixComponent). An orphaned
// parentId (mid-delete) degrades to top-level.
function flattenTree(roles: Role[]): RoleNode[] {
  const ids = new Set(roles.map((r) => r.id));
  const byParent = new Map<string, Role[]>();
  for (const r of roles) {
    const key = r.parentId && ids.has(r.parentId) ? r.parentId : '';
    byParent.set(key, [...(byParent.get(key) ?? []), r]);
  }
  for (const children of byParent.values()) children.sort((a, b) => a.name.localeCompare(b.name));

  const out: RoleNode[] = [];
  const walk = (parentId: string, prefix: TreeGuide[]): void => {
    const children = byParent.get(parentId) ?? [];
    children.forEach((r, i) => {
      const last = i === children.length - 1;
      const guides: TreeGuide[] = parentId === '' ? [] : [...prefix, last ? 'attach-end' : 'attach-continue'];
      out.push({ role: r, guides });
      walk(r.id, parentId === '' ? [] : [...prefix, last ? 'empty' : 'continue']);
    });
  };
  walk('', []);
  return out;
}

function errMsg(err: unknown): string {
  const e = err as { error?: { error?: string } };
  return typeof e?.error?.error === 'string' ? e.error.error : $localize`:@@Request_failed:Request failed`;
}
