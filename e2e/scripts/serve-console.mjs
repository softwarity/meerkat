// Static server for the console build (SPA fallback to index.html): the
// gateway's --console-url proxies to it and stamps identity on the body.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const PORT = 14200;
const ROOT = fileURLToPath(new URL('../../console/dist/console/browser', import.meta.url));

if (!existsSync(join(ROOT, 'index.html'))) {
  console.error(`console build missing at ${ROOT} — run: cd console && npx ng build --configuration development`);
  process.exit(1);
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
  let file = join(ROOT, path || 'index.html');
  if (!file.startsWith(ROOT) || !existsSync(file)) file = join(ROOT, 'index.html');
  try {
    const body = await readFile(file);
    res.writeHead(200, { 'Content-Type': TYPES[extname(file)] ?? 'application/octet-stream' });
    res.end(body);
  } catch {
    res.writeHead(500);
    res.end('read error');
  }
}).listen(PORT, () => console.log(`console static server on :${PORT} from ${ROOT}`));
