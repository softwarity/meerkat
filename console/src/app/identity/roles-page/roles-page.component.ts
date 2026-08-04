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
import { RowActionsDirective } from '@softwarity/row-actions';
import { ApiService, Role } from '../../api.service';
import { TreeGuide, TreePrefixComponent } from '../../shared/tree-prefix.component';
import { flattenRoles } from '../../shared/role-tree';
import { RoleEditorComponent } from '../role-editor/role-editor.component';

// One row of the flattened tree: the role plus the guide glyphs materializing
// its position in the hierarchy. A NULL role is the catalogue root, the one row
// that stands for no stored role — every top-level role hangs under it.
interface RoleNode {
  role: Role | null;
  guides: TreeGuide[];
}

// The GLOBAL role catalogue (RBAC-01), root only — archway's roles tree: a
// flat mat-table ordered as a depth-first walk of the parentId hierarchy,
// with SVG guide lines materializing the branches.
//
// The table opens on a ROOT row standing for the catalogue itself. It is not a
// stored role: it cannot be opened, dragged or deleted, it only receives what
// belongs at the top level. Every creation is therefore the same gesture — the
// + of the row one wants to hang under, the root row included.
//
// TWO gestures, two meanings. Clicking a row opens it in the right drawer (the
// URL drives it: roles/new, roles/:id) where the name, description, tags and
// the deletion live. Dragging a row BY ITS HANDLE onto another one re-parents
// it, onto the root row makes it top-level; dropping a role onto itself, its
// current parent or one of its descendants is refused. Per-tenant GROUPS
// assemble subsets of this catalogue. System roles are protected from renaming
// and deletion.
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
    RowActionsDirective,
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

  // Depth-first walk of the parentId hierarchy — the table shows the TREE,
  // the catalogue root included as its first row.
  // The catalogue root opens the list; the top-level roles branch off it like
  // any other children.
  protected readonly nodes = computed<RoleNode[]>(() => [
    { role: null, guides: [] },
    ...flattenRoles(this.roles()),
  ]);
  protected readonly isRoot = (_: number, n: RoleNode): boolean => n.role === null;

  // The tags already in use, offered as suggestions by the editor: a tag only
  // groups roles together if they all spell it the same way.
  protected readonly knownTags = computed(() =>
    [...new Set(this.roles().flatMap((r) => r.tags ?? []))].sort((a, b) => a.localeCompare(b)),
  );

  // The URL drives the drawer (F5-proof): roles/new = creating, roles/:id =
  // editing that role.
  private readonly params = toSignal(this.ar.paramMap);
  private readonly urlSegs = toSignal(this.ar.url);
  private readonly query = toSignal(this.ar.queryParamMap);
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
  // roles/new?parent=<id> — the + on a row creates UNDER that role, and the
  // query param survives an F5 like the rest of the drawer. An id that no
  // longer exists degrades to a top-level creation.
  protected readonly newParent = computed(() => {
    if (this.editing() !== 'new') return null;
    const id = this.query()?.get('parent');
    return (id && this.roles().find((r) => r.id === id)) || null;
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

  // The + on a row: same blank drawer, but the creation lands as a child of
  // that role. Chaining several children keeps the parent (the form empties,
  // the URL does not move).
  protected newChild(parent: Role): void {
    void this.router.navigate(['/application/roles', 'new'], { queryParams: { parent: parent.id } });
  }

  protected closeEditor(): void {
    if (this.editing() !== null) void this.router.navigate(['/application/roles']);
  }

  // Save keeps the drawer open on the role it just wrote. A CREATION stays on
  // roles/new with an emptied form, ready for the next role — the URL must NOT
  // switch to the fresh id, or rebinding that role under the empty form would
  // turn the next save into an edit. The snackbar is what says it landed.
  protected onSaved(saved: Role): void {
    const created = this.editing() === 'new';
    this.snack.open(
      created
        ? $localize`:@@Role_NAME_created:Role "${saved.name}:NAME:" created`
        : $localize`:@@Role_NAME_saved:Role "${saved.name}:NAME:" saved`,
      undefined,
      { duration: 2500 },
    );
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


function errMsg(err: unknown): string {
  const e = err as { error?: { error?: string } };
  return typeof e?.error?.error === 'string' ? e.error.error : $localize`:@@Request_failed:Request failed`;
}
