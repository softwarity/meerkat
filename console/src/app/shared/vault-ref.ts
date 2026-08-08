// The reference grammar, kept in step with internal/vault (RefName/Ref/NameOK).
// It is duplicated here rather than fetched because a form has to judge what is
// being typed, keystroke by keystroke, with nothing to ask.

const NAME = '[A-Za-z][A-Za-z0-9_.-]*';
const WHOLE_REF = new RegExp(`^(?:\\$\\{(${NAME})\\}|\\$(${NAME}))$`);

// The name a value points at when the value is NOTHING BUT that reference,
// '' otherwise.
//
// The distinction only matters for secrets, and it is deliberately strict: an
// upstream is built around its references ('http://${host}:8080'), but a
// password either IS what the vault holds or is a literal sitting in the
// configuration. '${a}${b}' and a password that happens to start with '$'
// (bcrypt hashes do) are literals by this rule, which is the safe way round.
export function refName(value: string): string {
  const m = WHOLE_REF.exec(value.trim());
  return m ? (m[1] ?? m[2]) : '';
}

export function isRef(value: string): boolean {
  return refName(value) !== '';
}

// The form that survives anything written after it.
export function vaultRef(name: string): string {
  return `\${${name}}`;
}

export const VAULT_NAME_RE = new RegExp(`^${NAME}$`);

// The name a secret lands under by default: the object it belongs to, then the
// field. Mirrors SuggestEntryName in internal/admin/secrets.go - the server
// derives the same name when none is given, so the two must not drift.
export function suggestEntryName(id: string, field: string): string {
  const kebab = field.replace(/([a-z0-9])([A-Z])/g, '$1-$2').toLowerCase();
  const name = `${id.trim()}-${kebab}`
    .toLowerCase()
    .replace(/[^a-z0-9_.-]/g, '-')
    .replace(/^-+|-+$/g, '');
  return /^[a-z]/.test(name) ? name : `secret-${name}`;
}
