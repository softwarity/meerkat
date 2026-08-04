import { Role } from '../api.service';
import { TreeGuide } from './tree-prefix.component';

// One row of a flattened role hierarchy: the role and the guide glyphs that
// draw its branch (see TreePrefixComponent).
export interface RoleTreeRow {
  role: Role;
  guides: TreeGuide[];
}

// Depth-first flatten of the parentId hierarchy, siblings in name order, with
// the guides materializing each branch.
//
// Shared by the roles page and the groups matrix, because two screens drawing
// the same catalogue with two different pictures of it is how a reader learns
// to distrust both. Sorting inside a level rather than globally is what makes
// two loads give the same order.
//
// An orphaned parentId (a parent deleted mid-flight) degrades to top level: an
// orphan has to stay reachable, or nobody can fix it from the screen.
//
// The list is taken AS GIVEN: a caller that filters passes the surviving set,
// and the guides are computed over that set. Computing them over the whole
// catalogue would draw a branch to a sibling nobody can see.
export function flattenRoles(roles: Role[]): RoleTreeRow[] {
  const ids = new Set(roles.map((r) => r.id));
  const byParent = new Map<string, Role[]>();
  for (const r of roles) {
    const key = r.parentId && ids.has(r.parentId) ? r.parentId : '';
    byParent.set(key, [...(byParent.get(key) ?? []), r]);
  }
  for (const children of byParent.values()) children.sort((a, b) => a.name.localeCompare(b.name));

  const out: RoleTreeRow[] = [];
  const walk = (parentId: string, prefix: TreeGuide[]): void => {
    const children = byParent.get(parentId) ?? [];
    children.forEach((r, i) => {
      const last = i === children.length - 1;
      out.push({ role: r, guides: [...prefix, last ? 'attach-end' : 'attach-continue'] });
      walk(r.id, [...prefix, last ? 'empty' : 'continue']);
    });
  };
  walk('', []);
  return out;
}
