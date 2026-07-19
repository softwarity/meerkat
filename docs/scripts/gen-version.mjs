// Resolve the latest release tag at BUILD time and write it as a static resource
// served by GitHub Pages (src/assets/version.json → /meerkat/assets/version.json).
// The doc-site reads THAT file at runtime instead of the GitHub API, so there is
// no API rate limit. Runs on every build (local and CI). CI must check out with
// fetch-depth: 0 so the tags are present.
import { execSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Offline / no-tags fallback (e.g. `ng serve`, a shallow checkout). The runtime
// fetch normally overrides it; there is no release yet.
const FALLBACK = '0.0.0';

const out = resolve(dirname(fileURLToPath(import.meta.url)), '../src/assets/version.json');

function latestTag() {
  try {
    const t = execSync('git describe --tags --abbrev=0', { stdio: ['ignore', 'pipe', 'ignore'] })
      .toString()
      .trim()
      .replace(/^v/, '');
    if (t) return t;
  } catch {
    /* no git / no tags reachable → fall back */
  }
  return FALLBACK;
}

const version = latestTag();
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, JSON.stringify({ version }) + '\n');
console.log(`[gen-version] ${out} ← ${version}`);
