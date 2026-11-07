// 节点连通性测试(面板本机,原生 net/tls,无 nc/openssl 依赖 — design.md §5)
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { getDb } from '../db/client.js';
import { HttpError } from '../services/errors.js';
import { probeNode } from '../core/probe/index.js';
import { listProbes, probeAllNodes } from '../services/autoProbe.js';
import type { Row } from '../services/row.js';
import { rowConn } from '../services/conn.js';
import { withServerLock } from '../services/locks.js';
import { nodeHosts, serverHosts } from '../services/clientHosts.js';
import { diagnoseXrayNode } from '../services/nodeDiagnostics.js';
import { readProxyUrl } from '../services/outbound.js';

const idParam = z.object({ id: z.coerce.number().int() });

/** TLS 类协议且配置了 SNI → 做握手;其余仅 TCP 端口探测 */
function probeMode(protocol: string, sni: string): 'tcp' | 'tls' {
  return ['vless', 'vmess', 'trojan'].includes(protocol) && !!sni ? 'tls' : 'tcp';
}

/** Match subscription expansion: a node can select a subset of machine domains. */
function nodeEndpoint(node: Row, server: Row, requestedHost?: string) {
  const machine = { host: server.host, client_host: server.client_host, client_hosts: server.client_hosts };
  const hosts = nodeHosts(node.client_hosts, machine);
  const host = requestedHost ?? hosts[0];
  if (!hosts.includes(host)) throw new HttpError(400, '诊断地址必须是该节点的订阅入口');
  const dynamicSni = node.tls_mode === 'tls' && (!node.sni || node.sni === server.host || serverHosts(machine).includes(node.sni));
  return { host, sni: dynamicSni ? host : node.sni };
}

export default async function testRoutes(app: FastifyInstance): Promise<void> {
  app.post('/xray-nodes/:id/diagnose', { config: { rateLimit: { max: 6, timeWindow: '1 minute' } } }, async req => {
    const { id } = z.object({ id: z.coerce.number().int().positive() }).parse(req.params);
    const { host: requestedHost } = z.object({ host: z.string().max(253).optional() }).parse(req.body ?? {});
    const db = getDb();
    const initial = db.prepare('SELECT server_id FROM xray_nodes WHERE id = ?').get(id) as Row | undefined;
    if (!initial) throw new HttpError(404, 'Xray 节点不存在');
    return withServerLock(initial.server_id, async () => {
      const node = db.prepare('SELECT * FROM xray_nodes WHERE id = ?').get(id) as Row | undefined;
      if (!node) throw new HttpError(404, 'Xray 节点不存在');
      const server = db.prepare('SELECT * FROM servers WHERE id = ?').get(node.server_id) as Row | undefined;
      if (!server) throw new HttpError(404, '服务器不存在');
      if (server.control !== 'ssh') throw new HttpError(400, '节点诊断目前仅支持 SSH 管理的机器');
      const endpoint = nodeEndpoint(node, server, requestedHost);
      const pending = db.prepare('SELECT xray FROM pending_deploys WHERE server_id = ?').get(node.server_id) as Row | undefined;
      let conn;
      try { conn = rowConn(db, server); }
      catch { throw new HttpError(400, '无法读取该机器的 SSH 凭据，请检查服务器设置'); }
      let proxyUrl: string | undefined;
      if (node.outbound_type === 'proxy') {
        try { proxyUrl = readProxyUrl(node.proxy_url_enc); }
        catch { /* The report marks missing/unreadable proxy credentials as an error. */ }
      }
      return diagnoseXrayNode(conn, { ...endpoint, nodeId: node.id, port: node.listen_port,
        protocol: node.protocol, tlsMode: node.tls_mode, transport: node.transport, wsPath: node.ws_path,
        enabled: node.enabled === 1, pending: pending?.xray === 1, outboundType: node.outbound_type, proxyUrl });
    }, { waitMs: 10_000 });
  });

  const probeFromRow = (node: Row) => {
    const db = getDb();
    const srv = db.prepare('SELECT host, client_host, client_hosts FROM servers WHERE id = ?').get(node.server_id) as Row | undefined;
    if (!srv) throw new HttpError(404, '服务器不存在');
    const endpoint = nodeEndpoint(node, srv);
    return probeNode({
      ...endpoint,
      port: node.listen_port,
      mode: probeMode(node.protocol, endpoint.sni),
    });
  };

  app.post('/nodes/:id', async (req) => {
    const { id } = idParam.parse(req.params);
    const node = getDb().prepare('SELECT * FROM nodes WHERE id = ?').get(id) as Row | undefined;
    if (!node) throw new HttpError(404, '节点不存在');
    return probeFromRow(node);
  });

  app.post('/xray-nodes/:id', async (req) => {
    const { id } = idParam.parse(req.params);
    const node = getDb().prepare('SELECT * FROM xray_nodes WHERE id = ?').get(id) as Row | undefined;
    if (!node) throw new HttpError(404, 'Xray 节点不存在');
    return probeFromRow(node);
  });

  /** 最近一次自动探测结果(所有节点) */
  app.get('/probes', async () => listProbes(getDb()));

  /** 立刻跑一轮自动探测(定时任务跑的也是这个) */
  app.post('/probe-all', async () => {
    const r = await probeAllNodes(getDb());
    return { checked: r.checked, ok: r.ok, failed: r.failed };
  });
}
