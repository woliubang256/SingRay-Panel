// Deploy orchestration (design.md §3): collect machine data → render config
// (pure configgen) → ensure certs → transactional deployCore. deployAll runs
// machines with concurrency ≤3. Ported from singbox-panel deployServices.js +
// deployXrayServices.js semantics (lazy reality keypair / landing port / certs).

import type { DatabaseSync } from 'node:sqlite';
import { buildMachineConfig } from '../core/configgen/singbox/index.js';
import { buildXrayConfig } from '../core/configgen/xray/index.js';
import { genSelfSignedCert } from '../core/configgen/cert.js';
import type { MachineCtx } from '../core/configgen/types.js';
import { deployCore } from '../core/deploy/index.js';
import { exec, writeFile } from '../core/ssh/executor.js';
import { rowConn } from './conn.js';
import type { SshConn } from '../core/ssh/executor.js';
import { decrypt, encrypt, genRealityKeypair, genShortId, genSsPassword } from '../core/crypto.js';
import { serverLifecycle } from './lifecycle.js';
import { withServerLock } from './locks.js';
import { recordDeploy } from './deployAudit.js';
import { clearDirtyCore, dirtyStamp } from './deployState.js';
import { hasRealCert, certPaths } from '../core/certs/acme.js';
import { config } from '../config.js';
import { HttpError } from './errors.js';
import { certificateDomains, serverHosts, type HostServer } from './clientHosts.js';

const secret = () => config.appSecret; // 字段加密密钥(迁移须等于旧 APP_SECRET)

export interface MachineDeployResult {
  serverId: number;
  serverName: string;
  singbox: { ok: boolean; error?: string; steps: string[]; journal?: string; skipped?: boolean };
  xray: { ok: boolean; error?: string; steps: string[]; journal?: string; skipped?: boolean };
}

type Row = Record<string, any>;

export type DeployScope = 'all' | 'pending';
export interface DeployTarget {
  serverId: number;
  name: string;
  /** 缺省表示双核心。 */
  core?: 'singbox' | 'xray';
}

/** 任务创建和执行共用同一份机器/核心清单,不在执行时重新扩大范围。 */
export function planDeployments(db: DatabaseSync, scope: DeployScope = 'all'): DeployTarget[] {
  const rows = db.prepare(`
    SELECT s.id, s.name, p.singbox, p.xray FROM servers s
    LEFT JOIN pending_deploys p ON p.server_id = s.id
    WHERE s.control = 'ssh' ${scope === 'pending' ? 'AND (p.singbox = 1 OR p.xray = 1)' : ''}
    ORDER BY s.id
  `).all() as { id: number; name: string; singbox: number | null; xray: number | null }[];
  return rows.map((r) => ({ serverId: r.id, name: r.name,
    core: scope === 'all' || (r.singbox === 1 && r.xray === 1) ? undefined : r.singbox === 1 ? 'singbox' : 'xray',
  }));
}

const skipCore = () => ({ ok: true, steps: ['skip'], skipped: true });

function collectMachineData(db: DatabaseSync, machineId: number) {
  const row = db.prepare('SELECT * FROM servers WHERE id = ?').get(machineId) as Row | undefined;
  if (!row) throw new Error(`server ${machineId} not found`);

  let relaySettings: { realityPrivateKey: string; shortId: string } | null = null;
  let landingSettings: { in_port: number; method: string; password: string } | null = null;
  if (row.role === 'relay') {
    const rs = db.prepare('SELECT * FROM relay_settings WHERE server_id = ?').get(machineId) as Row | undefined;
    if (rs) relaySettings = { realityPrivateKey: decrypt(secret(), rs.reality_private_key), shortId: rs.short_id };
  } else if (row.role === 'landing') {
    const ls = db.prepare('SELECT * FROM landing_settings WHERE server_id = ?').get(machineId) as Row | undefined;
    if (ls) landingSettings = { in_port: ls.in_port, method: ls.method, password: decrypt(secret(), ls.password) };
  }

  // 落地机等也可能直连 vless-reality 节点 → 懒生成 Reality 密钥并持久化
  if (!relaySettings) {
    const hasReality = (db.prepare("SELECT COUNT(*) c FROM nodes WHERE server_id = ? AND protocol = 'vless' AND enabled = 1").get(machineId) as { c: number }).c;
    if (hasReality > 0) {
      const { publicKey, privateKey } = genRealityKeypair();
      const shortId = genShortId();
      db.prepare('INSERT OR REPLACE INTO relay_settings (server_id, reality_public_key, reality_private_key, short_id, port_base) VALUES (?,?,?,?,31000)').run(machineId, publicKey, encrypt(secret(), privateKey), shortId);
      relaySettings = { realityPrivateKey: privateKey, shortId };
    }
  }

  const nodes = (db.prepare('SELECT * FROM nodes WHERE server_id = ?').all(machineId) as Row[]).map((n) => ({
    id: n.id, name: n.name, server_id: n.server_id, protocol: n.protocol, listen_port: n.listen_port,
    enabled: n.enabled, creds: JSON.parse(decrypt(secret(), n.creds_enc)), tls_mode: n.tls_mode, sni: n.sni,
    transport: n.transport, ws_path: n.ws_path, outbound_type: n.outbound_type, landing_server_id: n.landing_server_id,
    tunnel_address: n.tunnel_address, tunnel_port: n.tunnel_port, note: n.note,
  }));

  const landings: Record<number, { host: string; in_port: number; method: string; password: string }> = {};
  const landingIds = [...new Set(nodes.map((n) => n.landing_server_id).filter(Boolean))];
  for (const id of landingIds) {
    const ls = db.prepare('SELECT * FROM landing_settings WHERE server_id = ?').get(id) as Row | undefined;
    const srv = db.prepare('SELECT host, client_host FROM servers WHERE id = ?').get(id) as Row | undefined;
    if (ls && srv) landings[id] = { host: srv.client_host || srv.host, in_port: ls.in_port, method: ls.method, password: decrypt(secret(), ls.password) };
  }

  const machine: MachineCtx & { id: number } = {
    id: row.id,
    name: row.name,
    host: row.client_host || row.host,
    certDomains: serverHosts(row as HostServer),
    role: row.role,
    certPath: `/etc/sing-box/tls/${row.name}.crt`,
    keyPath: `/etc/sing-box/tls/${row.name}.key`,
    realityPrivateKey: relaySettings?.realityPrivateKey,
    shortId: relaySettings?.shortId,
  };

  return { row, machine, landingSettings, nodes, landings };
}

function collectXrayMachineData(db: DatabaseSync, machineId: number) {
  const row = db.prepare('SELECT * FROM servers WHERE id = ?').get(machineId) as Row | undefined;
  if (!row) throw new Error(`server ${machineId} not found`);

  // Xray Reality 密钥(懒生成;已有记录则解密)
  let xs = db.prepare('SELECT * FROM xray_server_settings WHERE server_id = ?').get(machineId) as Row | undefined;
  if (!xs) {
    const hasReality = (db.prepare("SELECT COUNT(*) c FROM xray_nodes WHERE server_id = ? AND protocol = 'vless' AND enabled = 1").get(machineId) as { c: number }).c;
    if (hasReality > 0) {
      const { publicKey, privateKey } = genRealityKeypair();
      const shortId = genShortId();
      db.prepare('INSERT OR REPLACE INTO xray_server_settings (server_id, reality_public_key, reality_private_key, short_id, port_base) VALUES (?,?,?,?,41000)').run(machineId, publicKey, encrypt(secret(), privateKey), shortId);
      xs = { reality_private_key: privateKey, short_id: shortId };
    }
  } else if (xs.reality_private_key) {
    xs = { ...xs, reality_private_key: decrypt(secret(), xs.reality_private_key) };
  }

  const nodes = (db.prepare('SELECT * FROM xray_nodes WHERE server_id = ?').all(machineId) as Row[]).map((n) => ({
    id: n.id, name: n.name, server_id: n.server_id, protocol: n.protocol, listen_port: n.listen_port,
    enabled: n.enabled, creds: JSON.parse(decrypt(secret(), n.creds_enc)), tls_mode: n.tls_mode, sni: n.sni,
    transport: n.transport, ws_path: n.ws_path, flow: n.flow, outbound_type: n.outbound_type,
    landing_server_id: n.landing_server_id, note: n.note,
  }));

  const landings: Record<number, { host: string; in_port: number; method: string; password: string }> = {};
  const landingIds = [...new Set(nodes.map((n) => n.landing_server_id).filter(Boolean))];
  for (const id of landingIds) {
    const srv = db.prepare('SELECT host, client_host FROM servers WHERE id = ?').get(id) as Row | undefined;
    const xls = db.prepare('SELECT * FROM xray_server_settings WHERE server_id = ?').get(id) as Row | undefined;
    if (xls?.in_port && srv) {
      landings[id] = { host: srv.client_host || srv.host, in_port: xls.in_port, method: xls.in_method || 'aes-128-gcm', password: decrypt(secret(), xls.in_password_enc) };
    }
  }

  // Xray 落地机独立 ss 入站(与 sing-box 分开端口,懒生成)
  let xrayLandingSettings: { in_port: number; in_method: string; in_password: string } | null = null;
  if (row.role === 'landing') {
    const hasRelayRef = ((db.prepare("SELECT COUNT(*) c FROM xray_nodes WHERE landing_server_id = ? AND enabled = 1 AND outbound_type = 'relay'").get(machineId)) as { c: number }).c > 0;
    if (hasRelayRef) {
      if (xs?.in_port) {
        xrayLandingSettings = { in_port: xs.in_port, in_method: xs.in_method || 'aes-128-gcm', in_password: decrypt(secret(), xs.in_password_enc) };
      } else {
        const portBase = xs?.port_base || 41000;
        let port = portBase + machineId;
        const sbPort = db.prepare('SELECT in_port FROM landing_settings WHERE server_id = ?').get(machineId) as { in_port: number } | undefined;
        if (sbPort && sbPort.in_port === port) port += 100;
        const password = genSsPassword();
        const enc = encrypt(secret(), password);
        if (xs) {
          db.prepare('UPDATE xray_server_settings SET in_port=?, in_method=?, in_password_enc=? WHERE server_id=?').run(port, 'aes-128-gcm', enc, machineId);
        } else {
          db.prepare('INSERT OR REPLACE INTO xray_server_settings (server_id, reality_public_key, reality_private_key, short_id, port_base, in_port, in_method, in_password_enc) VALUES (?,?,?,?,?,?,?,?)').run(machineId, '', '', '', 41000, port, 'aes-128-gcm', enc);
        }
        xrayLandingSettings = { in_port: port, in_method: 'aes-128-gcm', in_password: password };
      }
    }
  }

  const machine: MachineCtx & { id: number } = {
    id: row.id,
    name: row.name,
    host: row.client_host || row.host,
    certDomains: serverHosts(row as HostServer),
    role: row.role,
    certPath: `/etc/sing-box/tls/${row.name}.crt`,
    keyPath: `/etc/sing-box/tls/${row.name}.key`,
    realityPrivateKey: (xs as Row | undefined)?.reality_private_key,
    shortId: (xs as Row | undefined)?.short_id,
  };

  return { row, machine, nodes, landings, xrayLandingSettings };
}

async function ensureCerts(
  conn: SshConn,
  machine: MachineCtx,
  nodes: { tls_mode: string }[],
  inject?: { execFn?: typeof exec; writeFileFn?: typeof writeFile },
): Promise<string[]> {
  if (!nodes.some((n) => n.tls_mode === 'tls')) return [];
  const execFn = inject?.execFn ?? exec;
  const writeFileFn = inject?.writeFileFn ?? writeFile;
  // 真证书(ACME)已装 → 直接用,不再生成自签(新版 Xray 已移除 allowInsecure,自签在客户端不可用)
  if (machine.certPath?.startsWith('/etc/singray/certs/')) return ['cert(acme)'];
  const { certPem, keyPem } = genSelfSignedCert({ commonName: machine.name, altNames: [...new Set([machine.name, machine.host, ...(machine.certDomains ?? [])])] });
  await execFn(conn, 'mkdir -p /etc/sing-box/tls', { timeoutClass: 'quick' });
  await writeFileFn(conn, machine.certPath!, certPem, execFn);
  await writeFileFn(conn, machine.keyPath!, keyPem, execFn);
  return ['cert(self-signed)'];
}

async function useMachineCert(conn: SshConn, row: Row, machine: MachineCtx, execFn: typeof exec) {
  const domains = certificateDomains(row as HostServer);
  const domain = domains[0];
  if (!domain || !await hasRealCert(conn, domain, execFn)) return;
  if (domains.length > 1 && !await hasRealCert(conn, domain, execFn, domains)) {
    throw new Error('现有证书未覆盖全部对外域名,请重新签发多域名证书后部署');
  }
  const paths = certPaths(domain);
  machine.certPath = paths.fullchain;
  machine.keyPath = paths.key;
}

/** 单机双核心下发。execFn/writeFileFn 可注入供测试。 */
export async function deployServerBothCores(
  db: DatabaseSync,
  serverId: number,
  inject?: { execFn?: typeof exec; writeFileFn?: typeof writeFile },
  /** 只部署其中一个核心(单机按核心下发);缺省两个都部署 */
  only?: 'singbox' | 'xray',
): Promise<MachineDeployResult> {
  // 按机器串行:并发部署会各自 render→swap,后一个覆盖前一个,而两个都报成功
  return withServerLock(serverId, () => deployBothCoresInner(db, serverId, inject, only));
}

async function deployBothCoresInner(
  db: DatabaseSync,
  serverId: number,
  inject?: { execFn?: typeof exec; writeFileFn?: typeof writeFile },
  only?: 'singbox' | 'xray',
): Promise<MachineDeployResult> {
  const sbRow = db.prepare('SELECT * FROM servers WHERE id = ?').get(serverId) as Row | undefined;
  if (!sbRow) throw new HttpError(404, '服务器不存在');
  // 部署前记下待部署标记时间:部署期间再发的变更不动它,成功后也不会被清零
  const dirty = { singbox: dirtyStamp(db, serverId, 'singbox'), xray: dirtyStamp(db, serverId, 'xray') };
  const base: MachineDeployResult = {
    serverId,
    serverName: sbRow.name,
    singbox: skipCore(),
    xray: skipCore(),
  };
  if (sbRow.control !== 'ssh') {
    if (only !== 'xray') base.singbox = { ok: false, error: 'agent 模式暂不支持下发(V1 仅 SSH)', steps: [] };
    if (only !== 'singbox') base.xray = { ok: false, error: 'agent 模式暂不支持下发', steps: [] };
    recordDeploy(db, base);
    return base;
  }
  const conn = rowConn(db, sbRow);

  // sing-box
  if (only !== 'xray') {
    const sbData = collectMachineData(db, serverId);
    if (sbData.nodes.some((n) => n.enabled === 1) || sbData.row.role === 'landing') {
      try {      // 部署前置:机器缺核心二进制时自动先安装(部署=配置下发,前提是核心已装)
        const sbExec = inject?.execFn ?? exec;
        // 真证书优先: 机器上有 ACME 证书(client_host 域名) → certPath 指向它
        if (sbData.nodes.some((n) => n.enabled && n.tls_mode === 'tls')) await useMachineCert(conn, sbData.row, sbData.machine, sbExec);
        let sbAutoInstall = false;
        try {
          await sbExec(conn, 'test -x /usr/local/bin/sing-box', { timeoutClass: 'quick' });
        } catch {
          await serverLifecycle(db, serverId, 'singbox', 'install', inject);
          sbAutoInstall = true;
        }
        const certSteps = await ensureCerts(conn, sbData.machine, sbData.nodes, inject);
        const cfg = buildMachineConfig({ machine: sbData.machine, landingSettings: sbData.landingSettings ?? undefined, nodes: sbData.nodes, landings: sbData.landings });
        const r = await deployCore(conn, { core: 'singbox', config: cfg, execFn: inject?.execFn, writeFileFn: inject?.writeFileFn });
        base.singbox = { ok: r.ok, error: r.error, steps: [...(sbAutoInstall ? ['auto-install'] : []), ...certSteps, ...r.steps.map((s) => s.step + (s.ok ? '' : '(fail)'))], journal: r.journal };
        if (r.ok) {
          clearDirtyCore(db, serverId, 'singbox', dirty.singbox);
          // 部署成功后查询核心版本并写库(否则版本信息只在 install 时更新)
          try {
            const v = await (inject?.execFn ?? exec)(conn, 'sing-box version 2>/dev/null | head -1', { timeoutClass: 'quick' });
            const ver = v.stdout.match(/\d+\.\d+\.\d+/)?.[0] ?? v.stdout.trim();
            db.prepare('UPDATE servers SET singbox_version = ? WHERE id = ?').run(ver, serverId);
          } catch { /* 版本查询失败不阻断 */ }
        }
      } catch (err) {
        base.singbox = { ok: false, error: (err as Error).message, steps: [] };
      }
    } else {
      // 无可下发的 sing-box 内容 → 该核心无待部署项
      clearDirtyCore(db, serverId, 'singbox', dirty.singbox);
    }
  }

  // xray
  if (only !== 'singbox') {
    const xrData = collectXrayMachineData(db, serverId);
    const hasXrayActive = xrData.nodes.some((n) => n.enabled === 1);
    const isLandingRef = ((db.prepare("SELECT COUNT(*) c FROM xray_nodes WHERE landing_server_id = ? AND enabled = 1 AND outbound_type = 'relay'").get(serverId)) as { c: number }).c > 0;
    if (hasXrayActive || isLandingRef) {
      try {
        const xrExec = inject?.execFn ?? exec;
        if (xrData.nodes.some((n) => n.enabled && n.tls_mode === 'tls')) await useMachineCert(conn, xrData.row, xrData.machine, xrExec);
        let xrAutoInstall = false;
        try {
          await xrExec(conn, 'test -x /usr/local/bin/xray', { timeoutClass: 'quick' });
        } catch {
          await serverLifecycle(db, serverId, 'xray', 'install', inject);
          xrAutoInstall = true;
        }
        const certSteps = await ensureCerts(conn, xrData.machine, xrData.nodes, inject);
        const cfg = buildXrayConfig({ machine: xrData.machine, nodes: xrData.nodes, landings: xrData.landings, xrayLandingSettings: xrData.xrayLandingSettings ?? undefined });
        const r = await deployCore(conn, { core: 'xray', config: cfg, execFn: inject?.execFn, writeFileFn: inject?.writeFileFn });
        base.xray = { ok: r.ok, error: r.error, steps: [...(xrAutoInstall ? ['auto-install'] : []), ...certSteps, ...r.steps.map((s) => s.step + (s.ok ? '' : '(fail)'))], journal: r.journal };
        if (r.ok) {
          clearDirtyCore(db, serverId, 'xray', dirty.xray);
          try {
            const v = await (inject?.execFn ?? exec)(conn, 'xray version 2>/dev/null | head -1', { timeoutClass: 'quick' });
            const ver = v.stdout.match(/\d+\.\d+\.\d+/)?.[0] ?? v.stdout.trim();
            db.prepare('UPDATE servers SET xray_version = ? WHERE id = ?').run(ver, serverId);
          } catch { /* 版本查询失败不阻断 */ }
        }
      } catch (err) {
        base.xray = { ok: false, error: (err as Error).message, steps: [] };
      }
    } else {
      clearDirtyCore(db, serverId, 'xray', dirty.xray);
    }
  }

  recordDeploy(db, base); // 审计:进程重启后还能查到上次部署的结果
  return base;
}

/** 全量或待变更部署,并发 ≤3;可传入任务创建时的清单保证进度与执行范围一致。 */
export async function deployAll(
  db: DatabaseSync,
  inject?: Parameters<typeof deployServerBothCores>[2],
  onProgress?: (result: MachineDeployResult) => void,
  options: { scope?: DeployScope; targets?: DeployTarget[] } = {},
): Promise<MachineDeployResult[]> {
  const servers = options.targets ?? planDeployments(db, options.scope);
  const results: MachineDeployResult[] = new Array(servers.length);
  let cursor = 0;
  async function worker() {
    while (cursor < servers.length) {
      const idx = cursor++;
      const s = servers[idx];
      try {
        results[idx] = await deployServerBothCores(db, s.serverId, inject, s.core);
      } catch (err) {
        results[idx] = {
          serverId: s.serverId, serverName: s.name,
          singbox: s.core === 'xray' ? skipCore() : { ok: false, error: (err as Error).message, steps: [] },
          xray: s.core === 'singbox' ? skipCore() : { ok: false, error: (err as Error).message, steps: [] },
        };
      }
      onProgress?.(results[idx]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(3, servers.length) }, worker));
  return results;
}
