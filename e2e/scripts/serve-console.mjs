// Static server for the console build (SPA fallback to index.html): the
// gateway's --console-url proxies to it and stamps identity on the body.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { existsSync, readdirSync, statSync } from 'node:fs';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const PORT = 14200;
const ROOT = fileURLToPath(new URL('../../console/dist/console/browser', import.meta.url));

// A localized build has no index.html of its own: it has one per locale, in a
// subdirectory named after it (en/, fr/, ar/...), which is exactly what the
// gateway serves. So the fallback below resolves inside the locale of the
// request rather than at the root, and the suite runs against the build that
// actually ships instead of a debug one.
const locales = existsSync(ROOT)
  ? readdirSync(ROOT, { withFileTypes: true })
      .filter((e) => e.isDirectory() && existsSync(join(ROOT, e.name, 'index.html')))
      .map((e) => e.name)
  : [];
if (locales.length === 0 && !existsSync(join(ROOT, 'index.html'))) {
  console.error(`console build missing at ${ROOT} — run: cd console && npm run build`);
  process.exit(1);
}

// The index that answers a path: the one of its locale when it names a known
// one, otherwise the first locale (or the root index of an unlocalized build).
function fallbackFor(path) {
  const first = path.split('/')[0];
  if (locales.includes(first)) return join(ROOT, first, 'index.html');
  return locales.length ? join(ROOT, locales[0], 'index.html') : join(ROOT, 'index.html');
}

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
};

createServer(async (req, res) => {
  const path = normalize(decodeURIComponent(new URL(req.url, 'http://x').pathname)).replace(/^([/\\])+/, '');
  let file = join(ROOT, path);
  if (!path || !file.startsWith(ROOT) || !existsSync(file) || statSync(file).isDirectory()) {
    file = fallbackFor(path);
  }
  try {
    const body = await readFile(file);
    res.writeHead(200, { 'Content-Type': TYPES[extname(file)] ?? 'application/octet-stream' });
    res.end(body);
  } catch {
    res.writeHead(500);
    res.end('read error');
  }
}).listen(PORT, () => console.log(`console static server on :${PORT} from ${ROOT}`));
