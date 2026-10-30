import { describe, it, expect } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { migrate } from '../db/client.js';
import { deployAll, deployServerBothCores, planDeployments } from './deployAll.js';
import { encrypt } from '../core/crypto.js';
import { config } from '../config.js';
import { createXrayNode } from './xray_nodes.js';
import { resetTopologyTrigger } from '../core/topology/trigger.js';
import { X509Certificate } from 'node:crypto';
import { markDirty, listPendingDeploys } from './deployState.js';

function seedDb(): DatabaseSync {
  const db = new DatabaseSync(':memory:');
  migrate(db);
  const enc = (s: string) => encrypt(config.appSecret, s);
  db.prepare("INSERT INTO servers (id, name, role, host, ssh_sudo, control, ssh_auth_secret) VALUES (1, 'corenet', 'relay', '10.0.0.1', 0, 'ssh', ?)").run(enc('fake-key-1'));
  db.prepare("INSERT INTO servers (id, name, role, host, control, ssh_auth_secret) VALUES (2, 'landing', 'landing', '10.0.0.2', 'ssh', ?)").run(enc('fake-key-2'));
  db.prepare("INSERT INTO servers (id, name, role, host, control) VALUES (3, 'agentbox', 'relay', '10.0.0.3', 'agent')").run();
  db.prepare("INSERT INTO relay_settings (server_id, reality_public_key, reality_private_key, short_id, port_base) VALUES (1, 'pbk', ?, 'sid1', 31000)").run(enc('rpvk1'));
  db.prepare("INSERT INTO landing_settings (server_id, in_port, method, password) VALUES (2, 20408, '2022-blake3-aes-128-gcm', ?)").run(enc('landing-pass'));
  db.prepare("INSERT INTO nodes (server_id, name, protocol, listen_port, creds_enc, tls_mode, sni, outbound_type, landing_server_id) VALUES (1, 'vless-relay', 'vless', 31001, ?, 'reality', 'dl.google.com', 'relay', 2)").run(enc(JSON.stringify({ uuid: 'u-1' })));
  db.prepare("INSERT INTO nodes (server_id, name, protocol, listen_port, creds_enc, tls_mode) VALUES (2, 'ss-landing', 'shadowsocks', 31002, ?, 'tls')").run(enc(JSON.stringify({ method: '2022-blake3-aes-128-gcm', password: 'p1' })));
  db.prepare("INSERT INTO xray_nodes (server_id, name, protocol, listen_port, creds_enc, tls_mode, sni, flow) VALUES (1, 'xvless', 'vless', 41001, ?, 'reality', 'dl.google.com', 'xtls-rprx-vision')").run(enc(JSON.stringify({ uuid: 'x-1' })));
  return db;
}

/** fake exec: everything succeeds, is-active → active */
const okExec = async (_c: any, cmd: string) => ({ stdout: cmd.includes('is-active') ? 'active\n' : '', stderr: '' });
const okWrite = async () => {};

describe('deployAll orchestration', () => {
  it('plans both marked cores together, excludes agent machines, and snapshots the selection', () => {
    const db = seedDb();
    try {
      markDirty(db, 1, 'singbox');
      markDirty(db, 1, 'xray');
      markDirty(db, 3, 'singbox');
      const plan = planDeployments(db, 'pending');
      expect(plan).toEqual([{ serverId: 1, name: 'corenet', core: undefined }]);
      markDirty(db, 2, 'singbox');
      expect(plan).toHaveLength(1);
      expect(planDeployments(db, 'pending')).toHaveLength(2);
    } finally { db.close(); }
  });

  it('pending deployment touches only the marked machine and core', async () => {
    const db = seedDb();
    markDirty(db, 1, 'xray');
    const calls: { host?: string; cmd: string }[] = [];
    try {
      const results = await deployAll(db, {
        execFn: async (conn, cmd) => { calls.push({ host: conn.host, cmd }); return okExec(conn, cmd); },
        writeFileFn: okWrite,
      }, undefined, { scope: 'pending' });
      expect(results.map((r) => r.serverId)).toEqual([1]);
      expect(results[0].singbox.skipped).toBe(true);
      expect(results[0].xray.steps).toContain('health');
      expect(calls.every((c) => c.host === '10.0.0.1' && !c.cmd.includes('sing-box'))).toBe(true);
      expect(listPendingDeploys(db)).toEqual([]);
    } finally { db.close(); }
  });

  it('no pending changes means no SSH commands or deployments', async () => {
    const db = seedDb();
    let calls = 0;
    try {
      const results = await deployAll(db, { execFn: async (conn, cmd) => { calls++; return okExec(conn, cmd); }, writeFileFn: okWrite }, undefined, { scope: 'pending' });
      expect(results).toEqual([]);
      expect(calls).toBe(0);
    } finally { db.close(); }
  });

  it('execution uses the job snapshot and leaves later changes on other machines pending', async () => {
    const db = seedDb();
    markDirty(db, 1, 'xray');
    const targets = planDeployments(db, 'pending');
    markDirty(db, 2, 'singbox');
    try {
      const results = await deployAll(db, { execFn: okExec, writeFileFn: okWrite }, undefined, { targets });
      expect(results.map((r) => r.serverId)).toEqual([1]);
      expect(listPendingDeploys(db)).toEqual([{ serverId: 2, name: 'landing', singbox: true, xray: false }]);
    } finally { db.close(); }
  });

  it('a sing-box-only deployment skips Xray even when this machine is an Xray landing', async () => {
    const db = seedDb();
    db.prepare("UPDATE xray_nodes SET outbound_type = 'relay', landing_server_id = 2 WHERE server_id = 1").run();
    markDirty(db, 2, 'xray');
    const calls: string[] = [];
    try {
      const result = await deployServerBothCores(db, 2, { execFn: async (conn, cmd) => { calls.push(cmd); return okExec(conn, cmd); }, writeFileFn: okWrite }, 'singbox');
      expect(result.xray.skipped).toBe(true);
      expect(calls.some((cmd) => cmd.includes('xray'))).toBe(false);
      expect(db.prepare('SELECT * FROM xray_server_settings WHERE server_id = 2').get()).toBeUndefined();
      expect(listPendingDeploys(db)).toEqual([{ serverId: 2, name: 'landing', singbox: false, xray: true }]);
    } finally { db.close(); }
  });

  it('does not clear unrelated dirty flags or create sing-box keys during Xray deployment', async () => {
    const db = seedDb();
    db.prepare("UPDATE nodes SET protocol = 'vless', tls_mode = 'reality' WHERE server_id = 2").run();
    markDirty(db, 2, 'singbox');
    try {
      const result = await deployServerBothCores(db, 2, { execFn: okExec, writeFileFn: okWrite }, 'xray');
      expect(result.singbox.skipped).toBe(true);
      expect(db.prepare('SELECT * FROM relay_settings WHERE server_id = 2').get()).toBeUndefined();
      expect(listPendingDeploys(db)[0].singbox).toBe(true);
    } finally { db.close(); }
  });

  it('retains failed or newly edited pending changes for the next deployment', async () => {
    const db = seedDb();
    markDirty(db, 1, 'xray');
    try {
      const failed = await deployAll(db, { execFn: async () => { throw new Error('SSH unavailable'); }, writeFileFn: okWrite }, undefined, { scope: 'pending' });
      expect(failed[0].xray.ok).toBe(false);
      expect(listPendingDeploys(db)[0].xray).toBe(true);
      const results = await deployAll(db, { execFn: async (conn, cmd) => {
        if (cmd.includes('is-active')) db.prepare("UPDATE pending_deploys SET xray_marked_at = '2099-01-01T00:00:00.000Z' WHERE server_id = 1").run();
        return okExec(conn, cmd);
      }, writeFileFn: okWrite }, undefined, { scope: 'pending' });
      expect(results[0].xray.ok).toBe(true);
      expect(listPendingDeploys(db)[0].xray).toBe(true);
    } finally { db.close(); }
  });
  it('uses one inbound and a certificate containing all aliases', async () => {
    const db = seedDb();
    db.prepare('UPDATE servers SET client_host = ?, client_hosts = ? WHERE id = 1')
      .run('a.example.com', JSON.stringify(['a.example.com', 'b.example.com']));
    createXrayNode(db, { template: 'xray-trojan-tls', name: 'shared', serverId: 1, port: 8443 });
    const writes: { path: string; content: string }[] = [];
    try {
      const result = await deployServerBothCores(db, 1, { execFn: okExec as never,
        writeFileFn: async (_conn, path, content) => { writes.push({ path, content }); },
      }, 'xray');
      expect(result.xray.ok).toBe(true);
      const cert = new X509Certificate(writes.find((w) => w.path.endsWith('.crt'))!.content);
      expect(cert.checkHost('a.example.com')).toBeTruthy();
      expect(cert.checkHost('b.example.com')).toBeTruthy();
      const cfg = JSON.parse(writes.find((w) => w.path === '/tmp/singray-xray/config.json')!.content);
      expect(cfg.inbounds.filter((i: { protocol: string }) => i.protocol === 'trojan')).toHaveLength(1);
      const incomplete = await deployServerBothCores(db, 1, { execFn: async (_c, cmd) => ({
        stdout: cmd.includes('-checkhost') ? 'NO' : 'YES', stderr: '',
      }), writeFileFn: okWrite }, 'xray');
      expect(incomplete.xray.ok).toBe(false);
      expect(incomplete.xray.error).toContain('未覆盖全部');
    } finally { resetTopologyTrigger(); db.close(); }
  });
  it('deploys Trojan over TCP + TLS using the existing machine certificate', async () => {
    const db = seedDb();
    db.prepare("UPDATE servers SET client_host = 'proxy.example.com' WHERE id = 1").run();
    createXrayNode(db, { template: 'xray-trojan-tls', name: 'Trojan deploy', serverId: 1, port: 8443 });
    const writes: { path: string; content: string }[] = [];
    const execFn = async (_conn: unknown, command: string) => ({
      stdout: command.includes('/etc/singray/certs/') ? 'YES\n' : command.includes('is-active') ? 'active\n' : '', stderr: '',
    });
    try {
      const result = await deployServerBothCores(db, 1, {
        execFn: execFn as never,
        writeFileFn: async (_conn, path, content) => { writes.push({ path, content }); },
      }, 'xray');
      expect(result.xray.ok).toBe(true);
      expect(result.xray.steps).toContain('cert(acme)');
      const configFile = writes.find((w) => w.path === '/tmp/singray-xray/config.json');
      const rendered = JSON.parse(configFile!.content);
      const inbound = rendered.inbounds.find((i: { protocol: string }) => i.protocol === 'trojan');
      expect(inbound).toMatchObject({ port: 8443, streamSettings: {
        network: 'tcp', security: 'tls', tlsSettings: { certificates: [{
          certificateFile: '/etc/singray/certs/proxy.example.com/fullchain.pem',
          keyFile: '/etc/singray/certs/proxy.example.com/key.pem',
        }] },
      } });
      expect(inbound.settings.clients[0].password).toBeTruthy();
      expect(inbound.settings.clients[0]).not.toHaveProperty('flow');
    } finally { resetTopologyTrigger(); db.close(); }
  });

  it('deploys both cores per machine (agent machines excluded from deployAll)', async () => {
    const db = seedDb();
    const results = await deployAll(db, { execFn: okExec as any, writeFileFn: okWrite });
    expect(results).toHaveLength(2); // only control='ssh' machines

    const corenet = results.find((r) => r.serverName === 'corenet')!;
    expect(corenet.singbox.ok).toBe(true);
    expect(corenet.singbox.steps).toContain('render');
    expect(corenet.singbox.steps).toContain('health');
    // xray vless present → deployed, not skipped
    expect(corenet.xray.ok).toBe(true);
    expect(corenet.xray.steps).toContain('health');

    const landing = results.find((r) => r.serverName === 'landing')!;
    // landing machine: ss-landing node with tls → cert step must appear
    expect(landing.singbox.steps).toContain('cert(self-signed)');
    expect(landing.singbox.ok).toBe(true);

    // agent machine not part of deployAll (V1 SSH only)
    expect(results.some((r) => r.serverName === 'agentbox')).toBe(false);
  }, 60000);

  it('propagates deploy failure per machine without aborting others', async () => {
    const db = seedDb();
    const failingExec = async (_c: any, cmd: string) => {
      if (cmd.includes('sing-box check')) throw new Error('invalid config');
      return { stdout: cmd.includes('is-active') ? 'active\n' : '', stderr: '' };
    };
    const results = await deployAll(db, { execFn: failingExec as any, writeFileFn: okWrite });
    const corenet = results.find((r) => r.serverName === 'corenet')!;
    expect(corenet.singbox.ok).toBe(false);
    expect(corenet.singbox.error).toContain('invalid config');
    expect(corenet.singbox.steps.join(',')).toContain('verify');
    // xray core unaffected by sing-box check failure (per-core isolation)
    expect(corenet.xray.ok).toBe(true);
    // other machines still processed (no abort)
    const landing = results.find((r) => r.serverName === 'landing')!;
    expect(landing.singbox.ok).toBe(false); // also fails check, but result recorded
    expect(landing.xray.skipped).toBe(true); // nothing to deploy → clean skip
  }, 60000);

  it('direct call: deployServerBothCores returns per-core result shape', async () => {
    const db = seedDb();
    const r = await deployServerBothCores(db, 2, { execFn: okExec as any, writeFileFn: okWrite });
    expect(r.serverName).toBe('landing');
    expect(r.xray.skipped).toBe(true); // no xray nodes, no relay refs
    expect(r.singbox.ok).toBe(true);
  }, 60000);

  it('auto-installs missing core binary before deploy', async () => {
    const db = seedDb();
    const execFn = async (_c: unknown, cmd: string) => {
      if (cmd.startsWith('test -x ')) throw new Error('exit code 1'); // 二进制不存在
      return { stdout: cmd.includes('is-active') ? 'active\n' : '', stderr: '' };
    };
    const r = await deployServerBothCores(db, 1, { execFn: execFn as any, writeFileFn: okWrite });
    expect(r.singbox.ok).toBe(true);
    expect(r.singbox.steps).toContain('auto-install');
    expect(r.xray.steps).toContain('auto-install');
  }, 60000);
});
