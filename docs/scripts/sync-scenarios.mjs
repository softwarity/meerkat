// Copies e2e/scenarios.json (the integration suite's single source of truth)
// into the doc-site assets at build time — Angular refuses assets outside the
// workspace root, and a copy keeps the doc build self-contained anyway.
import { copyFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const src = fileURLToPath(new URL('../../e2e/scenarios.json', import.meta.url));
const destDir = fileURLToPath(new URL('../src/assets', import.meta.url));
const dest = `${destDir}/scenarios.json`;

mkdirSync(destDir, { recursive: true });
copyFileSync(src, dest);
console.log(`[sync-scenarios] ${dest} ← e2e/scenarios.json`);
