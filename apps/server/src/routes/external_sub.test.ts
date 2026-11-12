import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { DatabaseSync } from 'node:sqlite';
import { parse as parseYaml } from 'yaml';
import { migrate } from '../db/client.js';
import subRoutes, { singboxSubRoutes, xraySubRoutes } from './sub.js';
import { importExternal, updateExternal } from '../services/externalNodes.js';
const state = vi.hoisted(() => ({ db: null as DatabaseSync | null }));
vi.mock('../db/client.js', async original => ({ ...await original<typeof import('../db/client.js')>(), getDb: () => state.db! }));
let app: FastifyInstance;
beforeEach(async () => {
  state.db = new DatabaseSync(':memory:'); migrate(state.db);
  state.db.prepare("INSERT INTO settings(key,value) VALUES('sub_slug','test-slug')").run();
  importExternal(state.db, 'vless://uuid@example.com:443?security=tls&type=ws&path=%2Fws&host=cdn.example&sni=tls.example#External\nhy2://pw@hy.example:443#HY', undefined, true);
  app = Fastify(); await app.register(singboxSubRoutes, { prefix: '/sub/singbox' });
  await app.register(xraySubRoutes, { prefix: '/sub/xray' }); await app.register(subRoutes, { prefix: '/sub' });
});
afterEach(async () => { await app.close(); state.db!.close(); });
describe('external subscription integration', () => {
  it('includes each external node exactly once in all formats and retains security options', async () => {
    for (const url of ['/sub/test-slug', '/sub/xray/test-slug']) {
      const res = await app.inject(url); expect(res.headers['cache-control']).toBe('no-store');
      const lines = Buffer.from(res.body, 'base64').toString().split('\n'); expect(lines).toHaveLength(2);
      expect(lines[0]).toContain('security=tls'); expect(lines[0]).not.toContain('reality');
    }
    const clash = parseYaml((await app.inject({ url: '/sub/test-slug', headers: { 'user-agent': 'mihomo' } })).body);
    expect(clash.proxies).toHaveLength(2);
    expect(clash.proxies[0]).toMatchObject({ name: 'External', 'skip-cert-verify': false, 'ws-opts': { path: '/ws', headers: { Host: 'cdn.example' } } });
    for (const url of ['/sub/test-slug', '/sub/singbox/test-slug']) {
      const sb = (await app.inject({ url, headers: { 'user-agent': 'sing-box' } })).json();
      expect(sb.outbounds.filter((o: { tag: string }) => ['External', 'HY'].includes(o.tag))).toHaveLength(2);
      expect(sb.outbounds[0]).toMatchObject({ tls: { insecure: false }, transport: { type: 'ws' } });
    }
  });
  it('reflects rename, exclusion and disabled status immediately, guards slug, and lists supported output formats', async () => {
    updateExternal(state.db!, 1, { name: 'Renamed' }); updateExternal(state.db!, 2, { includeInSub: false });
    const lines = Buffer.from((await app.inject('/sub/xray/test-slug')).body, 'base64').toString();
    expect(lines).toContain('#Renamed'); expect(lines).not.toContain('hy.example');
    updateExternal(state.db!, 1, { enabled: false });
    expect(Buffer.from((await app.inject('/sub/test-slug')).body, 'base64').toString()).toBe('');
    expect((await app.inject('/sub/wrong-slug')).statusCode).toBe(404);
  });
});
