// Builds the gateway from the working tree and runs it on the e2e ports with
// a DISPOSABLE database: every run starts from a clean slate, the setup
// project re-seeds the profiles through the real HTTP flows.
import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const repo = fileURLToPath(new URL('../..', import.meta.url));
const tmp = fileURLToPath(new URL('../.tmp', import.meta.url));
const bin = `${tmp}/meerkat`;

const build = spawnSync('go', ['build', '-o', bin, './cmd/meerkat'], { cwd: repo, stdio: 'inherit' });
if (build.status !== 0) process.exit(build.status ?? 1);

rmSync(`${tmp}/data`, { recursive: true, force: true });
mkdirSync(`${tmp}/data`, { recursive: true });

const child = spawn(
  bin,
  [
    '-addr', ':18082',
    '-admin-addr', ':19092',
    '-console-url', 'http://localhost:14200',
    '-data', `${tmp}/data`,
  ],
  {
    stdio: 'inherit',
    env: { ...process.env, MEERKAT_ADMIN_PASSWORD: 'e2e-Root-Password-1' },
  },
);
child.on('exit', (code) => process.exit(code ?? 1));
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => child.kill());
