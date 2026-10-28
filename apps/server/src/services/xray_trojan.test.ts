import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { migrate } from '../db/client.js';
import { createXrayNode, getXrayNode, updateXrayNode } from './xray_nodes.js';
import { createServer } from './servers.js';
import { decryptJson } from './creds.js';
import { collectXrayNodes } from './subs.js';
import { buildXrayInbound } from '../core/configgen/xray/index.js';
import { buildShareLink, toBase64, toSingboxConfig, type NodeView } from '../core/subscribe/index.js';
import { clashProxy } from '../core/subscribe/clash.js';
import { resetTopologyTrigger } from '../core/topology/trigger.js';

let db: DatabaseSync;
let serverId: number;

beforeEach(() => {
  db = new DatabaseSync(':memory:');
  migrate(db);
  serverId = createServer(db, {
    name: 'trojan-server', role: 'relay', host: '10.0.0.1', clientHost: 'proxy.example.com', sshAuthSecret: 'test-key',
  }).id;
});
afterEach(() => { resetTopologyTrigger(); db.close(); });

describe('Xray Trojan + TLS', () => {
  it('creates password-authenticated TLS nodes without flow or WebSocket settings', () => {
    const node = createXrayNode(db, { template: 'xray-trojan-tls', name: 'Trojan', serverId, port: 8443 });
    expect(node).toMatchObject({ protocol: 'trojan', tls_mode: 'tls', transport: 'raw', listen_port: 8443, sni: 'proxy.example.com' });
    expect(node.flow).toBeUndefined();
    expect(node.ws_path).toBeUndefined();
    const row = db.prepare('SELECT creds_enc FROM xray_nodes WHERE id = ?').get(node.id) as { creds_enc: string };
    const creds = decryptJson(row.creds_enc);
    expect(Object.keys(creds)).toEqual(['password']);
    expect(creds.password.length).toBeGreaterThanOrEqual(16);
    expect(row.creds_enc).not.toContain(creds.password);
    const link = new URL(node.share_link!);
    expect(link.protocol).toBe('trojan:');
    expect(decodeURIComponent(link.username)).toBe(creds.password);
    expect(link.searchParams.get('security')).toBe('tls');
    expect(link.searchParams.get('sni')).toBe('proxy.example.com');
    const inbound = buildXrayInbound({
      id: node.id, name: node.name, server_id: serverId, protocol: 'trojan', listen_port: 8443, enabled: 1,
      creds: { password: creds.password }, tls_mode: 'tls', transport: 'raw', sni: node.sni!, flow: '', ws_path: '',
      outbound_type: 'direct', landing_server_id: null, note: '',
    }, { id: serverId, name: 'trojan-server', host: 'proxy.example.com', role: 'relay', certPath: '/cert.pem', keyPath: '/key.pem' });
    expect(inbound).toMatchObject({
      protocol: 'trojan', settings: { clients: [{ password: creds.password }] },
      streamSettings: { network: 'tcp', security: 'tls', tlsSettings: { certificates: [{ certificateFile: '/cert.pem', keyFile: '/key.pem' }] } },
    });
    migrate(db);
    expect(getXrayNode(db, node.id).protocol).toBe('trojan');
  });

  it('preserves an explicit certificate SNI and supports changing password and SNI', () => {
    const node = createXrayNode(db, { template: 'xray-trojan-tls', name: 'Trojan', serverId, sni: 'cert.example.com' });
    expect(node.sni).toBe('cert.example.com');
    const saved = updateXrayNode(db, node.id, { sni: ' next.example.com ', authPassword: 'p@ss:/?#123456789' });
    expect(saved.sni).toBe('next.example.com');
    expect(saved.auth_password).toBe('p@ss:/?#123456789');
    const link = new URL(saved.share_link!);
    expect(decodeURIComponent(link.username)).toBe('p@ss:/?#123456789');
    expect(link.searchParams.get('sni')).toBe('next.example.com');
    expect(updateXrayNode(db, node.id, { authPassword: '' }).auth_password).toBe(saved.auth_password);
    const view = collectXrayNodes(db).find((v) => v.id === node.id)!;
    expect(view).toMatchObject({ protocol: 'trojan', sni: 'next.example.com', creds: { password: saved.auth_password } });
    expect(Buffer.from(toBase64([view]), 'base64').toString()).toBe(saved.share_link);
  });

  it('switching XHTTP to Trojan resets transport, path, flow and credentials', () => {
    const node = createXrayNode(db, { template: 'xray-vless-xhttp', name: 'switch', serverId });
    expect(node.ws_path).toMatch(/^\/xhttp-/);
    const saved = updateXrayNode(db, node.id, { protocol: 'trojan', sni: 'cert.example.com' });
    expect(saved).toMatchObject({ protocol: 'trojan', tls_mode: 'tls', transport: 'raw', sni: 'cert.example.com' });
    expect(saved.ws_path).toBeUndefined();
    expect(saved.flow).toBeUndefined();
    expect(saved.auth_password).toBeTruthy();
    expect(saved.share_link).not.toContain('flow=');
    expect(saved.share_link).not.toContain('path=');
  });

  it('share links and client subscriptions use the certificate SNI even when the address is an IP', () => {
    const view: NodeView = {
      id: 1, name: 'Trojan', protocol: 'trojan', host: '10.0.0.1', port: 8443, sni: 'cert.example.com',
      ws_path: '', realityPublicKey: null, shortId: null, creds: { password: 'password-123456789' },
    };
    const link = new URL(buildShareLink(view)!);
    expect(link.hostname).toBe('10.0.0.1');
    expect(link.searchParams.get('sni')).toBe('cert.example.com');
    expect(clashProxy(view)).toMatchObject({ type: 'trojan', server: '10.0.0.1', sni: 'cert.example.com', password: view.creds.password });
    const config = toSingboxConfig([view]) as { outbounds: Record<string, unknown>[] };
    expect(config.outbounds[0]).toMatchObject({ type: 'trojan', server: '10.0.0.1', tls: { server_name: 'cert.example.com' } });
  });
});
