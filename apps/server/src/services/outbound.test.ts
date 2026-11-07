import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { migrate } from '../db/client.js';
import { resetTopologyTrigger } from '../core/topology/trigger.js';
import { createServer } from './servers.js';
import { createNode, getNode, updateNode } from './nodes.js';
import { createXrayNode, getXrayNode, updateXrayNode } from './xray_nodes.js';
import { decryptSecret } from './creds.js';
import { listPendingDeploys } from './deployState.js';

let db: DatabaseSync;
beforeEach(() => {
  db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON');
  migrate(db);
  createServer(db, { name: 'entry', host: '10.0.0.1', role: 'relay', sshAuthSecret: 'key' });
  createServer(db, { name: 'landing', host: '10.0.0.2', role: 'landing', sshAuthSecret: 'key' });
});
afterEach(() => { resetTopologyTrigger(); db.close(); });

const cores = [
  { core: 'singbox', table: 'nodes', template: 'vmess-ws-tls', create: createNode, update: updateNode, get: getNode },
  { core: 'xray', table: 'xray_nodes', template: 'xray-trojan-tls', create: createXrayNode, update: updateXrayNode, get: getXrayNode },
] as const;

for (const core of cores) {
  describe(`${core.core} proxy outbound persistence`, () => {
    const proxyUrl = 'socks5://user:p%40ss@1.2.3.4:5678';
    const create = (extra = {}) => core.create(db, { name: 'proxy-node', serverId: 1, template: core.template, outboundType: 'proxy', proxyUrl, ...extra });

    it('encrypts the URL, echoes it for editing, preserves partial updates and marks deployment pending', () => {
      const node = create();
      expect(node).toMatchObject({ outbound_type: 'proxy', proxy_url: proxyUrl });
      expect(node.landing_server_id).toBeUndefined();
      const row = db.prepare(`SELECT proxy_url_enc FROM ${core.table} WHERE id=?`).get(node.id) as { proxy_url_enc: string };
      expect(row.proxy_url_enc).not.toContain('p%40ss');
      expect(decryptSecret(row.proxy_url_enc)).toBe(proxyUrl);
      expect(core.update(db, node.id, { name: 'renamed' }).proxy_url).toBe(proxyUrl);
      expect(core.get(db, node.id).proxy_url).toBe(proxyUrl);
      expect(listPendingDeploys(db).find(s => s.serverId === 1)?.[core.core]).toBe(true);
      expect(node.share_link).not.toContain('1.2.3.4');
    });

    it('replaces the URL and clears incompatible fields when switching all three modes', () => {
      const node = create({ outboundType: 'relay', landingServerId: 2 });
      expect(core.update(db, node.id, { outboundType: 'proxy', proxyUrl })).toMatchObject({ outbound_type: 'proxy', proxy_url: proxyUrl, landing_server_id: undefined });
      expect(core.update(db, node.id, { proxyUrl: 'http://proxy.example.com:8080' }).proxy_url).toBe('http://proxy.example.com:8080');
      expect(core.update(db, node.id, { outboundType: 'relay', landingServerId: 2 })).toMatchObject({ outbound_type: 'relay', proxy_url: undefined, landing_server_id: 2 });
      expect(db.prepare(`SELECT proxy_url_enc FROM ${core.table} WHERE id=?`).get(node.id)).toMatchObject({ proxy_url_enc: '' });
      core.update(db, node.id, { outboundType: 'proxy', proxyUrl });
      expect(core.update(db, node.id, { outboundType: 'direct' })).toMatchObject({ outbound_type: 'direct', proxy_url: undefined, landing_server_id: undefined });
      expect(db.prepare(`SELECT proxy_url_enc FROM ${core.table} WHERE id=?`).get(node.id)).toMatchObject({ proxy_url_enc: '' });
    });

    it('rejects missing or invalid URLs without altering the existing node', () => {
      expect(() => create({ proxyUrl: undefined })).toThrow(/代理链接/);
      const node = create();
      expect(() => core.update(db, node.id, { proxyUrl: 'https://user:secret@proxy.example.com:443' })).toThrow(/代理链接/);
      expect(core.get(db, node.id).proxy_url).toBe(proxyUrl);
      expect(() => core.update(db, node.id, { proxyUrl: '' })).toThrow(/代理链接/);
    });

    it('requires a landing when switching from proxy to relay', () => {
      const node = create();
      expect(() => core.update(db, node.id, { outboundType: 'relay' })).toThrow(/落地机/);
      expect(core.get(db, node.id).outbound_type).toBe('proxy');
    });
  });
}

it('keeps tunnel nodes outside proxy mode', () => {
  expect(() => createNode(db, { name: 'tunnel', serverId: 1, template: 'tunnel', tunnelAddress: '10.0.0.9', tunnelPort: 443, outboundType: 'proxy', proxyUrl: 'http://proxy.example.com:8080' })).toThrow(/隧道/);
  const node = createNode(db, { name: 'change', serverId: 1, template: 'socks', outboundType: 'proxy', proxyUrl: 'http://proxy.example.com:8080' });
  expect(updateNode(db, node.id, { protocol: 'tunnel', tunnelAddress: '10.0.0.9', tunnelPort: 443 })).toMatchObject({ outbound_type: 'direct', proxy_url: undefined });
});
