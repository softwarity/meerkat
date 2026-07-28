import { DragDropModule } from '@angular/cdk/drag-drop';
import { Component, computed, inject, signal } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatSidenavModule } from '@angular/material/sidenav';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';
import { MatTooltipModule } from '@angular/material/tooltip';
import { ActivatedRoute, Router } from '@angular/router';
import { LoadingIndicatorComponent } from '@softwarity/loading-indicator';
import { ApiService, Role } from '../../api.service';
import { TreeGuide, TreePrefixComponent } from '../../shared/tree-prefix.component';
import { RoleEditorComponent } from '../role-editor/role-editor.component';

// One row of the flattened tree: the role plus the guide glyphs materializing
// its position in the hierarchy.
interface RoleNode {
  role: Role;
  guides: TreeGuide[];
}

// The GLOBAL role catalogue (RBAC-01), root only — archway's roles tree: a
// flat mat-table ordered as a depth-first walk of the parentId hierarchy,
// with SVG guide lines materializing the branches.
//
// TWO gestures, two meanings. Clicking a row opens it in the right drawer (the
// URL drives it: roles/new, roles/:id) where the name, description, tags and
// the deletion live — the table itself carries no action. Dragging a row BY
// ITS HANDLE onto another one re-parents it, or onto the drop zone above the
// table to make it top-level; dropping a role onto itself, its current parent
// or one of its descendants is refused. Per-tenant GROUPS assemble subsets of
// this catalogue. System roles are protected from renaming and deletion.
@Component({
  selector: 'app-roles-page',
  imports: [
    DragDropModule,
    MatButtonModule,
    MatIconModule,
    MatSidenavModule,
    MatTableModule,
    MatTooltipModule,
    LoadingIndicatorComponent,
    TreePrefixComponent,
    RoleEditorComponent,
  ],
  templateUrl: './roles-page.component.html',
  styleUrl: './roles-page.component.scss',
})
export class RolesPageComponent {
  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);
  private readonly router = inject(Router);
  private readonly ar = inject(ActivatedRoute);

  protected readonly loading = signal(true);
  protected readonly roles = signal<Role[]>([]);
  protected readonly columns = ['role', 'description', 'tags'];

  // Depth-first walk of the parentId hierarchy — the table shows the TREE.
  protected readonly nodes = computed(() => flattenTree(this.roles()));

  // The URL drives the drawer (F5-proof): roles/new = creating, roles/:id =
  // editing that role.
  private readonly params = toSignal(this.ar.paramMap);
  private readonly urlSegs = toSignal(this.ar.url);
  protected readonly editing = computed<Role | 'new' | null>(() => {
    if (this.urlSegs()?.some((s) => s.path === 'new')) return 'new';
    const id = this.params()?.get('id');
    if (!id) return null;
    return this.roles().find((r) => r.id === id) ?? null;
  });
  protected readonly editingRole = computed(() => {
    const e = this.editing();
    return e === null || e === 'new' ? null : e;
  });

  // Drag state: the role in flight, and the currently valid drop target
  // (a role = becomes its child; 'root' = becomes top-level).
  protected readonly dragged = signal<Role | null>(null);
  protected readonly target = signal<Role | 'root' | null>(null);
  protected readonly targetRoleId = computed(() => {
    const t = this.target();
    return t && t !== 'root' ? t.id : null;
  });
  // A drag ends with a click on the row underneath: swallow that one, or every
  // re-parenting would also open the drawer.
  private suppressClick = false;

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

  // ── the drawer ────────────────────────────────────────────────────────────

  protected openRole(role: Role): void {
    if (this.suppressClick) return;
    void this.router.navigate(['/application/roles', role.id]);
  }

  protected openNew(): void {
    void this.router.navigate(['/application/roles', 'new']);
  }

  protected closeEditor(): void {
    if (this.editing() !== null) void this.router.navigate(['/application/roles']);
  }

  // Save keeps the drawer open: the URL gains the fresh id after a creation,
  // and the reloaded list rebinds the fresh role into the editor.
  protected onSaved(saved: Role): void {
    this.snack.open($localize`:@@Role_NAME_saved:Role "${saved.name}:NAME:" saved`, undefined, {
      duration: 2500,
    });
    if (this.editing() === 'new') {
      void this.router.navigate(['/application/roles', saved.id], { replaceUrl: true });
    }
    this.load();
  }

  protected onDeleted(): void {
    void this.router.navigate(['/application/roles']);
    this.load();
  }

  // ── drag & drop re-parenting ──────────────────────────────────────────────

  protected dragStarted(role: Role): void {
    this.dragged.set(role);
    this.target.set(null);
  }

  // The CDK emits `ended` BEFORE the drop list's `dropped` (drag-ref.ts:
  // `ended.next(...)` then `container.drop(...)`), so clearing the drag state
  // here would wipe the target `drop()` is about to read, and the re-parenting
  // would silently do nothing. Defer it: a drag released with no valid target
  // still clears, one that lands lets drop() read the state first.
  protected dragEnded(): void {
    this.suppressClick = true;
    queueMicrotask(() => this.clearDrag());
    setTimeout(() => (this.suppressClick = false));
  }

  private clearDrag(): void {
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
    this.clearDrag();
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
