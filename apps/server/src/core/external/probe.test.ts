import { describe, it, expect } from 'vitest';
import { mkdtemp, writeFile, readFile, access, rm } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { probeExternalNode } from './probe.js';
import { normalizeExternal } from './types.js';

const node = normalizeExternal({ name: 'HY', protocol: 'hysteria2', host: 'example.com', port: 443, password: 'super-secret', security: 'tls' });
describe('isolated real proxy latency test', () => {
  it('reports a missing core without exposing credentials', async () => {
    const r = await probeExternalNode(node, { corePath: path.join(tmpdir(), 'singray-core-does-not-exist') });
    expect(r.status).toBe('unavailable'); expect(JSON.stringify(r)).not.toContain(node.password);
  });
  it('reports unsupported transport instead of faking TCP success', async () => {
    const r = await probeExternalNode(normalizeExternal({ ...node, protocol: 'vless', uuid: 'uuid', transport: 'xhttp' }));
    expect(r.status).toBe('unsupported'); expect(r.latencyMs).toBeNull();
  });
  it('uses the authenticated local controller, keeps QUIC config, and cleans all files', async () => {
    // A real child process verifies runner lifecycle and controller handling, without outbound internet.
    const dir = await mkdtemp(path.join(tmpdir(), 'singray-core-test-'));
    const script = path.join(dir, 'fake-core.cjs');
    const seen = path.join(dir, 'seen');
    await writeFile(script, `const fs=require('fs'),http=require('http'); const file=process.argv[process.argv.indexOf('-f')+1];
      const c=JSON.parse(fs.readFileSync(file)); if(c.proxies[0].type!=='hysteria2'||c.port||c['mixed-port'])process.exit(1);
      fs.writeFileSync(${JSON.stringify(seen)}, file);
      const port=Number(c['external-controller'].split(':').pop());
      http.createServer((req,res)=>{res.setHeader('Content-Type','application/json'); if(req.headers.authorization!=='Bearer '+c.secret){res.writeHead(403);return res.end('{}')}
      res.end(req.url==='/version'?'{}':JSON.stringify({delay:123}));}).listen(port,'127.0.0.1');`);
    try {
      expect(await probeExternalNode(node, { corePath: process.execPath, coreArgs: [script], timeoutMs: 5000 })).toMatchObject({ status: 'ok', latencyMs: 123 });
      await expect(access(await readFile(seen, 'utf8'))).rejects.toThrow();
    }
    finally { await rm(dir, { recursive: true, force: true }); }
  });
});
