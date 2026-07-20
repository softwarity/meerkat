import { CatalogEntry, Param, Spec } from '../api.service';

// UI form state of one predicate/filter brick. stringList params are edited
// as a comma-separated string and converted back to arrays on save.
export interface BrickForm {
  type: string;
  values: Record<string, string | number | boolean>;
}

export function paramsOf(type: string, entries: CatalogEntry[]): Param[] {
  return entries.find((e) => e.type === type)?.params ?? [];
}

export function docOf(type: string, entries: CatalogEntry[]): string {
  return entries.find((e) => e.type === type)?.doc ?? '';
}

export function defaultsFor(params: Param[]): BrickForm['values'] {
  const values: BrickForm['values'] = {};
  for (const p of params) {
    if (p.kind === 'bool') {
      values[p.name] = (p.default as boolean) ?? false;
    } else if (p.default !== undefined && p.default !== null) {
      values[p.name] = Array.isArray(p.default)
        ? p.default.join(', ')
        : (p.default as string | number);
    }
  }
  return values;
}

export function specToForm(spec: Spec, entries: CatalogEntry[]): BrickForm {
  const values = defaultsFor(paramsOf(spec.type, entries));
  for (const [key, raw] of Object.entries(spec.args ?? {})) {
    values[key] = Array.isArray(raw) ? raw.join(', ') : (raw as string | number | boolean);
  }
  return { type: spec.type, values };
}

export function formToSpec(brick: BrickForm, entries: CatalogEntry[]): Spec {
  const args: Record<string, unknown> = {};
  for (const p of paramsOf(brick.type, entries)) {
    const v = brick.values[p.name];
    if (v === undefined || v === '' || v === null) {
      continue; // omitted → server applies defaults / flags missing required
    }
    switch (p.kind) {
      case 'stringList':
        args[p.name] = String(v)
          .split(',')
          .map((s) => s.trim())
          .filter((s) => s !== '');
        break;
      case 'int':
        args[p.name] = Number(v);
        break;
      case 'bool':
        args[p.name] = Boolean(v);
        break;
      default:
        args[p.name] = String(v);
    }
  }
  return Object.keys(args).length ? { type: brick.type, args } : { type: brick.type };
}
