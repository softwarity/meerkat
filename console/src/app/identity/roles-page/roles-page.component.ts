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
  styles: [
    `
      :host {
        display: block;
      }
      .banner {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 12px 24px;
      }
      .banner h1 {
        font-size: 1.15rem;
        font-weight: 500;
        margin: 0;
        flex: 1;
      }
      .content {
        padding: 0 24px 24px;
      }
      .empty {
        padding: 48px;
        text-align: center;
        color: var(--mat-sys-on-surface-variant);
      }
      /* visible only while dragging a non-root role: drop here = top-level */
      .root-zone {
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 8px;
        padding: 10px 16px;
        border: 1px dashed var(--mat-sys-outline);
        border-radius: var(--mat-sys-corner-medium, 8px);
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.88rem;
      }
      .root-zone.drop-target {
        border-color: var(--mat-sys-secondary);
        color: var(--mat-sys-secondary);
        background: color-mix(in srgb, var(--mat-sys-secondary) 12%, transparent);
      }
      mat-row {
        cursor: grab;
      }
      mat-row.drop-target {
        background: color-mix(in srgb, var(--mat-sys-secondary) 14%, transparent);
      }
      mat-row.dragged {
        opacity: 0.35;
      }
      .handle {
        cursor: grab;
        color: var(--mat-sys-on-surface-variant);
        flex-shrink: 0;
      }
      .handle:active {
        cursor: grabbing;
      }
      .role-cell {
        display: flex;
        align-items: center;
        align-self: stretch;
        min-width: 0;
      }
      .role-label {
        display: flex;
        align-items: baseline;
        gap: 8px;
        padding: 6px 0 6px 6px;
        min-width: 0;
      }
      .name {
        font-weight: 500;
        font-family: var(--mk-mono);
        font-size: 0.88rem;
      }
      .sys {
        font-size: 0.66rem;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        color: var(--mat-sys-on-surface-variant);
      }
      .desc {
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.88rem;
      }
      .tags-inline {
        display: flex;
        gap: 4px;
        flex-wrap: wrap;
      }
      .tag {
        font-size: 0.66rem;
        letter-spacing: 0.04em;
        padding: 1px 8px;
        border-radius: 999px;
        background: var(--mat-sys-surface-container-highest);
        color: var(--mat-sys-on-surface-variant);
      }
      .mat-column-role {
        flex: 1 1 34%;
        justify-content: flex-start;
        padding-left: 16px;
      }
      .mat-column-description {
        flex: 1 1 42%;
      }
      /* read-only tag pills, roomy now that the table spans the full width */
      .mat-column-tags {
        flex: 1 1 24%;
        justify-content: flex-start;
      }
      /* the dragged row's origin collapses to a slim marker */
      .placeholder {
        height: 4px;
        background: var(--mat-sys-outline-variant);
      }
      .drag-preview {
        opacity: 0.6;
      }
    `,
  ],
  template: `
    <div class="banner">
      <h1 i18n="@@Roles">Roles</h1>
      <button matButton="filled" (click)="create()">
        <mat-icon>add</mat-icon>
        <ng-container i18n="@@New_role">New role</ng-container>
      </button>
    </div>

    <div class="content">
      @if (loading()) {
        <loading-indicator withContainer />
      } @else if (nodes().length === 0) {
        <div class="empty" i18n="@@No_role_yet">No role yet, create the first one.</div>
      } @else {
        @if (dragged(); as d) {
          @if (d.parentId) {
            <div class="root-zone" [class.drop-target]="target() === 'root'" (mouseover)="hoverRoot()">
              <mat-icon>upload</mat-icon>
              <ng-container i18n="@@Drop_here_for_top_level">Drop here to make it a top-level role</ng-container>
            </div>
          }
        }

        <mat-table
          [dataSource]="nodes()"
          cdkDropList
          cdkDropListSortingDisabled
          (cdkDropListDropped)="drop()"
          (mouseleave)="target.set(null)"
        >
          <ng-container matColumnDef="role">
            <mat-header-cell *matHeaderCellDef i18n="@@Roles">Roles</mat-header-cell>
            <mat-cell *matCellDef="let n">
              <div class="role-cell">
                <mat-icon cdkDragHandle class="handle" (click)="$event.stopPropagation()">drag_indicator</mat-icon>
                <app-tree-prefix [guides]="n.guides" />
                <span class="role-label">
                  <span class="name">{{ n.role.name }}</span>
                  @if (n.role.system) {
                    <span class="sys" i18n="@@System">system</span>
                  }
                </span>
              </div>
            </mat-cell>
          </ng-container>

          <ng-container matColumnDef="description">
            <mat-header-cell *matHeaderCellDef i18n="@@Description">Description</mat-header-cell>
            <mat-cell *matCellDef="let n">
              <span class="desc">{{ n.role.description }}</span>
            </mat-cell>
          </ng-container>

          <ng-container matColumnDef="tags">
            <mat-header-cell *matHeaderCellDef></mat-header-cell>
            <mat-cell *matCellDef="let n">
              @if (n.role.tags.length) {
                <span class="tags-inline">
                  @for (t of n.role.tags; track t) {
                    <span class="tag">{{ t }}</span>
                  }
                </span>
              }
              <span rowActions="tonal">
                <button
                  matIconButton
                  (click)="edit(n.role)"
                  i18n-matTooltip="@@Edit_role"
                  matTooltip="Edit role"
                  i18n-aria-label="@@Edit_role"
                  aria-label="Edit role"
                >
                  <mat-icon>edit</mat-icon>
                </button>
                <button
                  matIconButton
                  [disabled]="n.role.system"
                  (click)="remove(n.role)"
                  i18n-matTooltip="@@Delete_role"
                  matTooltip="Delete role"
                  i18n-aria-label="@@Delete_role"
                  aria-label="Delete role"
                >
                  <mat-icon>delete</mat-icon>
                </button>
              </span>
            </mat-cell>
          </ng-container>

          <mat-header-row *matHeaderRowDef="columns"></mat-header-row>
          <mat-row
            *matRowDef="let n; columns: columns"
            cdkDrag
            cdkDragLockAxis="y"
            cdkDragPreviewClass="drag-preview"
            [cdkDragData]="n.role"
            [class.drop-target]="targetRoleId() === n.role.id"
            [class.dragged]="dragged()?.id === n.role.id"
            (cdkDragStarted)="dragStarted(n.role)"
            (cdkDragEnded)="dragEnded()"
            (mouseover)="hoverRow(n.role)"
          >
            <div class="placeholder" *cdkDragPlaceholder></div>
          </mat-row>
        </mat-table>
      }
    </div>
  `,
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

  private load(): void {
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
