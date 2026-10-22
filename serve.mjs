#!/usr/bin/env node
// Minimal, dependency-free static server for running rollavpn on your own machine.
// Usage: node serve.mjs [port]     (listens on 127.0.0.1 only)
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(fileURLToPath(new URL('.', import.meta.url)), 'web');
const PORT = Number(process.argv[2] || process.env.PORT || 8000);
const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.txt': 'text/plain; charset=utf-8',
};
// The same security headers Cloudflare serves: the "/*" block of web/_headers.
const SECURITY_HEADERS = {};
{
  let inAll = false;
  for (const line of readFileSync(join(ROOT, '_headers'), 'utf8').split('\n')) {
    if (/^\S/.test(line)) inAll = line.trim() === '/*';
    const m = inAll && line.match(/^\s+([\w-]+):\s*(.+)$/);
    if (m) SECURITY_HEADERS[m[1]] = m[2].trim();
  }
}
// Plain http on localhost: browsers ignore HSTS there anyway, and the page should never be cached.
delete SECURITY_HEADERS['Strict-Transport-Security'];
SECURITY_HEADERS['Cache-Control'] = 'no-store';

createServer(async (req, res) => {
  let path;
  try {
    path = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  } catch {
    res.writeHead(400).end();
    return;
  }
  const file = normalize(join(ROOT, path.endsWith('/') ? path + 'index.html' : path));
  if (!file.startsWith(ROOT + sep) || req.method !== 'GET' || file === join(ROOT, '_headers')) {
    res.writeHead(404).end();
    return;
  }
  try {
    const body = await readFile(file);
    res.writeHead(200, { 'Content-Type': TYPES[extname(file)] || 'application/octet-stream', ...SECURITY_HEADERS });
    res.end(body);
  } catch {
    res.writeHead(404, SECURITY_HEADERS).end('Not found');
  }
}).listen(PORT, '127.0.0.1', () => {
  console.log(`rollavpn running at http://localhost:${PORT}  (Ctrl+C to stop)`);
});
