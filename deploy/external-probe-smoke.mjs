// An actual Mihomo process traverses a local authenticated HTTP proxy.
// No external server, credential or internet access is needed for this smoke check.
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
const { probeExternalNode } = await import(pathToFileURL(path.resolve('apps/server/dist/core/external/probe.js')).href);
const { normalizeExternal } = await import(pathToFileURL(path.resolve('apps/server/dist/core/external/types.js')).href);
const { externalClash } = await import(pathToFileURL(path.resolve('apps/server/dist/core/external/format.js')).href);

// Validate the real shipped core accepts both QUIC protocols, including their authentication/TLS options.
const directory = await mkdtemp(path.join(tmpdir(), 'singray-quic-smoke-'));
try {
  const proxies = [
    normalizeExternal({ name: 'HY2', protocol: 'hysteria2', host: '127.0.0.1', port: 18443, password: 'test-password',
      security: 'tls', sni: 'test.example', obfs: 'salamander', obfsPassword: 'test-obfs' }),
    normalizeExternal({ name: 'TUIC', protocol: 'tuic', host: '127.0.0.1', port: 18444,
      uuid: 'c11c19a2-d901-4d32-9865-412d5c774f11', password: 'test-password', security: 'tls', sni: 'test.example', alpn: ['h3'], congestion: 'bbr' }),
  ].map(externalClash);
  const file = path.join(directory, 'config.json');
  await writeFile(file, JSON.stringify({ proxies, rules: ['MATCH,DIRECT'], 'geo-auto-update': false }), { mode: 0o600 });
  const core = process.env.PANEL_TEST_CORE_PATH ?? (process.platform === 'win32' ? 'mihomo.exe' : '/usr/local/bin/mihomo');
  const validation = spawnSync(core, ['-t', '-d', directory, '-f', file], { encoding: 'utf8', timeout: 15_000, windowsHide: true });
  assert.equal(validation.status, 0, `QUIC configuration rejected: ${validation.error?.message ?? validation.stderr}`);
  console.log('Actual Mihomo Hysteria2/TUIC configuration checks passed');
} finally {
  await rm(directory, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
}
const sockets = new Set();
let requests = 0, authenticated = 0;
const proxy = http.createServer((_req, res) => { requests++; res.writeHead(204); res.end(); });
proxy.on('connect', (req, socket) => {
  sockets.add(socket); socket.once('close', () => sockets.delete(socket));
  if (req.headers['proxy-authorization'] !== 'Basic ' + Buffer.from('test-user:test-password').toString('base64')) {
    socket.end('HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n'); return;
  }
  authenticated++;
  socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
  let buffer = '';
  socket.on('data', chunk => {
    buffer += chunk.toString();
    if (buffer.includes('\r\n\r\n')) { requests++; socket.end('HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n'); }
  });
});
await new Promise(resolve => proxy.listen(0, '127.0.0.1', resolve));
try {
  const n = normalizeExternal({ name: 'smoke', protocol: 'http', host: '127.0.0.1', port: proxy.address().port,
    username: 'test-user', password: 'test-password' });
  const options = { testUrl: 'http://probe.invalid/generate_204' };
  const ok = await probeExternalNode(n, options);
  assert.equal(ok.status, 'ok', ok.detail); assert.ok(ok.latencyMs >= 0);
  assert.ok(requests > 0); assert.ok(authenticated > 0);
  const bad = await probeExternalNode({ ...n, password: 'wrong-password' }, options);
  assert.equal(bad.status, 'failed'); assert.equal(bad.latencyMs, null);
  // A TCP listener without a working proxy must not produce a successful latency.
  const blackhole = net.createServer(socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  await new Promise(resolve => blackhole.listen(0, '127.0.0.1', resolve));
  const failed = await probeExternalNode({ ...n, port: blackhole.address().port }, { ...options, timeoutMs: 2500 });
  assert.equal(failed.status, 'failed');
  for (const socket of sockets) socket.destroy();
  await new Promise(resolve => blackhole.close(resolve));
  console.log('Actual Mihomo authenticated proxy access, wrong-password rejection and timeout checks passed');
} finally {
  for (const socket of sockets) socket.destroy();
  await new Promise(resolve => proxy.close(resolve));
}
