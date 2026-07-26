import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import scenariosFile from '../scenarios.json';

// scenarios.json is THE shared source of truth: the suites execute it, the
// doc site renders it. Keep this module dumb — read, type, resolve.

export interface Scenario {
  id: string;
  domain: string;
  kind: 'api' | 'ui' | 'flow';
  // allowedStatus: acceptable statuses for ALLOWED profiles when plain 2xx is
  // not guaranteed (e.g. 422 while a dependency is not configured) — the
  // point stays that it is NOT 401/403.
  probe?: { method: string; path: string; body?: unknown; allowedStatus?: number[] };
  check?: { railItem: string };
  spec?: string;
  allowed: string[];
  title: Record<string, string>;
  description: Record<string, string>;
}

export interface Profile {
  id: string;
  username: string;
}

export const profiles: Profile[] = scenariosFile.profiles;
export const scenarios: Scenario[] = scenariosFile.scenarios as Scenario[];

export const AUTH_DIR = join(__dirname, '..', '.auth');
// The two planes ISOLATE their sessions (MEERKAT_ADMIN_SESSION vs
// MEERKAT_SESSION): each profile carries one storage state per plane.
export const authFile = (profileId: string) => join(AUTH_DIR, `${profileId}.json`);
export const authDataFile = (profileId: string) => join(AUTH_DIR, `${profileId}.data.json`);

// Written by the setup project: ids and passwords of the seeded fixtures.
export interface Seeded {
  tenantId: string;
  users: Record<string, { id: string; username: string; password: string }>;
}

export function seeded(): Seeded {
  const p = join(AUTH_DIR, 'seeded.json');
  if (!existsSync(p)) throw new Error('run the setup project first (it seeds profiles and writes .auth/seeded.json)');
  return JSON.parse(readFileSync(p, 'utf8'));
}

// Resolves {tenantId} / {aliceId} placeholders against the seeded fixtures.
export function resolvePath(path: string): string {
  const s = seeded();
  return path.replaceAll('{tenantId}', s.tenantId).replaceAll('{aliceId}', s.users['user'].id);
}
