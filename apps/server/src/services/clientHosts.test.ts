import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { migrate } from '../db/client.js';
import { createServer, getServer, updateServer } from './servers.js';
import { createNode, getNode } from './nodes.js';
import { createXrayNode, getXrayNode, updateXrayNode } from './xray_nodes.js';
import { collectSingboxNodes, collectXrayNodes } from './subs.js';
import { normalizeHosts } from './clientHosts.js';
import { resetTopologyTrigger } from '../core/topology/trigger.js';
import { MIGRATIONS, ensureMigrationsTable } from '../db/migrations.js';

let db: DatabaseSync;
beforeEach(() => { db = new DatabaseSync(':memory:'); migrate(db); });
afterEach(() => { resetTopologyTrigger(); db.close(); });
const base = { name: 'multi', role: 'relay' as const, host: '10.0.0.1', sshAuthSecret: 'test-key' };

describe('multiple client addresses share one proxy', () => {
  it('upgrades the old schema and preserves a single public address', () => {
    const old = new DatabaseSync(':memory:');
    try {
      ensureMigrationsTable(old);
      for (const migration of MIGRATIONS.filter((m) => !m.name.startsWith('0016_'))) {
        old.exec(migration.sql);
        old.prepare('INSERT INTO schema_migrations (name) VALUES (?)').run(migration.name);
      }
      old.prepare("INSERT INTO servers (name, role, host, client_host) VALUES ('old', 'relay', '1.2.3.4', 'old.example.com')").run();
      migrate(old);
      migrate(old); // 重启重复执行应幂等
      expect(getServer(old, 1).clientHosts).toEqual(['old.example.com']);
    } finally { old.close(); }
  });

  it('updates automatic TLS SNI after changing machine domains, while preserving a custom SNI', () => {
    const server = createServer(db, { ...base, clientHosts: ['a.example.com', 'b.example.com'] });
    const auto = createXrayNode(db, { template: 'xray-trojan-tls', name: 'Auto', serverId: server.id });
    createXrayNode(db, { template: 'xray-trojan-tls', name: 'Custom', serverId: server.id, sni: 'cert.other.com' });
    updateServer(db, server.id, { clientHosts: ['c.example.com', 'd.example.com'] });
    const views = collectXrayNodes(db);
    expect(views.filter((v) => v.id === auto.id).map((v) => v.sni)).toEqual(['c.example.com', 'd.example.com']);
    expect(views.filter((v) => v.id !== auto.id).every((v) => v.sni === 'cert.other.com')).toBe(true);
    expect(getXrayNode(db, auto.id).share_links.map((l) => new URL(l.link).searchParams.get('sni'))).toEqual(['c.example.com', 'd.example.com']);
  });
  it('normalizes domains and rejects URLs, ports and shell/path characters', () => {
    expect(normalizeHosts([' A.example.COM. ', 'a.example.com', 'b.example.com'])).toEqual(['a.example.com', 'b.example.com']);
    for (const bad of ['https://a.com', 'a.com:443', 'a.com/x', 'x;id', '../a', '*.a.com', '']) {
      expect(() => normalizeHosts([bad])).toThrow();
    }
  });

  it('legacy addresses remain usable and omitted updates preserve multiple addresses', () => {
    const legacy = createServer(db, { ...base, clientHost: 'old.example.com' });
    expect(collectXrayNodes(db)).toEqual([]);
    updateServer(db, legacy.id, { clientHosts: ['a.example.com', 'b.example.com'] } as never);
    updateServer(db, legacy.id, { region: 'HK' });
    expect(getServer(db, legacy.id)).toMatchObject({ client_host: 'a.example.com', clientHosts: ['a.example.com', 'b.example.com'] });
  });

  it('both cores inherit addresses, export separate entries and keep a single stored node', () => {
    const server = createServer(db, { ...base, clientHosts: ['a.example.com', 'b.example.com'] } as never);
    const sb = createNode(db, { template: 'vmess-ws-tls', name: 'SB', serverId: server.id });
    const xr = createXrayNode(db, { template: 'xray-trojan-tls', name: 'XR', serverId: server.id });
    for (const [views, port] of [[collectSingboxNodes(db), sb.listen_port], [collectXrayNodes(db), xr.listen_port]] as const) {
      expect(views.map((v) => v.host)).toEqual(['a.example.com', 'b.example.com']);
      expect(new Set(views.map((v) => v.name)).size).toBe(2);
      expect(views[0].creds).toEqual(views[1].creds);
      expect(views.every((v) => v.port === port)).toBe(true);
      expect(views.map((v) => v.sni)).toEqual(['a.example.com', 'b.example.com']);
    }
    expect(db.prepare('SELECT COUNT(*) c FROM xray_nodes').get()).toMatchObject({ c: 1 });
    expect(getNode(db, sb.id)).toHaveProperty('share_links', expect.any(Array));
    expect(getXrayNode(db, xr.id)).toHaveProperty('share_links', expect.any(Array));
  });

  it('nodes select a subset, reject unrelated domains, and can return to inheritance', () => {
    const server = createServer(db, { ...base, clientHosts: ['a.example.com', 'b.example.com'] } as never);
    const node = createXrayNode(db, { template: 'xray-trojan-tls', name: 'XR', serverId: server.id, clientHosts: ['b.example.com'] } as never);
    expect(collectXrayNodes(db).map((v) => v.host)).toEqual(['b.example.com']);
    expect(() => updateXrayNode(db, node.id, { clientHosts: ['other.example.com'] } as never)).toThrow();
    updateXrayNode(db, node.id, { clientHosts: [] } as never);
    expect(collectXrayNodes(db)).toHaveLength(2);
    updateServer(db, server.id, { clientHosts: ['a.example.com'] } as never);
    expect(collectXrayNodes(db).map((v) => v.host)).toEqual(['a.example.com']);
  });

  it('multiple Reality addresses keep the borrowing SNI and override the default IP preference', () => {
    const server = createServer(db, { ...base, clientHosts: ['a.example.com', 'b.example.com'] } as never);
    createXrayNode(db, { template: 'xray-vless-reality', name: 'Reality', serverId: server.id, sni: 'www.microsoft.com' });
    const views = collectXrayNodes(db);
    expect(views.map((v) => v.host)).toEqual(['a.example.com', 'b.example.com']);
    expect(views.every((v) => v.sni === 'www.microsoft.com')).toBe(true);
  });
});
