import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { DatabaseSync } from 'node:sqlite';
import { migrate } from '../db/client.js';
import { diagnoseXrayNode } from '../services/nodeDiagnostics.js';
import { holdsServerLock, resetServerLocks } from '../services/locks.js';
import { HttpError } from '../services/errors.js';
import routes from './test.js';
import { probeNode } from '../core/probe/index.js';
import { encryptSecret } from '../services/creds.js';

const state = vi.hoisted(() => ({ db: null as DatabaseSync | null }));
vi.mock('../db/client.js', async original => ({ ...await original<typeof import('../db/client.js')>(), getDb: () => state.db! }));
vi.mock('../services/conn.js', () => ({ rowConn: (_db: unknown, row: { id: number }) => ({ serverId: row.id, host: '10.0.0.1', sudo: false }) }));
vi.mock('../services/nodeDiagnostics.js', () => ({ diagnoseXrayNode: vi.fn() }));
vi.mock('../core/probe/index.js', () => ({ probeNode: vi.fn(async () => ({ ok: true, latency_ms: 1, detail: 'OK' })) }));
let app: FastifyInstance;
beforeEach(async () => {
  vi.resetAllMocks(); resetServerLocks();
  state.db = new DatabaseSync(':memory:'); migrate(state.db);
  state.db.exec(`INSERT INTO servers(id,name,role,host,client_host,client_hosts,control) VALUES
    (1,'HK','relay','10.0.0.1','hk.example.com','["hk.example.com","hk2.example.com"]','ssh');
    INSERT INTO xray_nodes(id,name,server_id,protocol,listen_port,creds_enc,tls_mode,sni,transport,client_hosts)
    VALUES (7,'Trojan',1,'trojan',31250,'ENCRYPTED-SECRET','tls','hk.example.com','raw','["hk2.example.com"]');`);
  vi.mocked(diagnoseXrayNode).mockImplementation(async conn => {
    expect(holdsServerLock(conn.serverId)).toBe(true);
    return { checkedAt: '', target: { host: 'hk2.example.com', port: 31250, sni: 'hk2.example.com' }, status: 'warning', summary: 'result', checks: [] };
  });
  app = Fastify();
  app.setErrorHandler((error, _req, reply) => reply.code(error instanceof HttpError ? error.status : 400).send({ error: error instanceof Error ? error.message : 'error' }));
  await app.register(routes, { prefix: '/api/test' });
});
afterEach(async () => { await app.close(); state.db!.close(); });
const request = (id = '7', body?: unknown) => app.inject({ method: 'POST', url: `/api/test/xray-nodes/${id}/diagnose`, ...(body ? { payload: body } : {}) });

describe('Xray single node diagnosis endpoint', () => {
  it('uses the same subscribed host and effective SNI for ordinary node tests', async () => {
    expect((await app.inject({ method: 'POST', url: '/api/test/xray-nodes/7' })).statusCode).toBe(200);
    expect(probeNode).toHaveBeenCalledWith(expect.objectContaining({ host: 'hk2.example.com', sni: 'hk2.example.com', port: 31250 }));
  });

  it('inspects only the requested machine under its lock and uses the subscribed host/SNI', async () => {
    const result = await request();
    expect(result.statusCode).toBe(200);
    expect(diagnoseXrayNode).toHaveBeenCalledWith(expect.objectContaining({ serverId: 1 }), expect.objectContaining({
      nodeId: 7, host: 'hk2.example.com', port: 31250, sni: 'hk2.example.com', protocol: 'trojan', tlsMode: 'tls', outboundType: 'direct',
    }));
    expect(JSON.stringify(result.json())).not.toContain('ENCRYPTED-SECRET');
  });

  it('rejects an address outside the node subscription entries', async () => {
    expect((await request('7', { host: '169.254.169.254' })).statusCode).toBe(400);
    expect(diagnoseXrayNode).not.toHaveBeenCalled();
  });

  it('rejects missing, invalid and agent-controlled nodes before SSH', async () => {
    expect((await request('999')).statusCode).toBe(404);
    expect((await request('-1')).statusCode).toBe(400);
    state.db!.exec("UPDATE servers SET control='agent' WHERE id=1");
    expect((await request()).statusCode).toBe(400);
    expect(diagnoseXrayNode).not.toHaveBeenCalled();
  });

  it('reports pending deployment state and preserves an explicit alternate SNI', async () => {
    state.db!.exec("UPDATE xray_nodes SET sni='alternate.example.com',enabled=0 WHERE id=7; INSERT INTO pending_deploys(server_id,xray) VALUES(1,1)");
    expect((await request()).statusCode).toBe(200);
    expect(diagnoseXrayNode).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ sni: 'alternate.example.com', pending: true, enabled: false }));
  });

  it('decrypts the saved upstream only for proxy diagnostics without returning it', async () => {
    const proxyUrl = 'socks5://proxy-user:PROXY-SECRET@proxy.example.com:1080';
    state.db!.prepare("UPDATE xray_nodes SET outbound_type='proxy',proxy_url_enc=? WHERE id=7").run(encryptSecret(proxyUrl));
    const result = await request();
    expect(result.statusCode).toBe(200);
    expect(diagnoseXrayNode).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ nodeId: 7, outboundType: 'proxy', proxyUrl }));
    expect(result.body).not.toMatch(/PROXY-SECRET|proxy-user/);
  });

  it('lets diagnostics report an unreadable proxy secret without returning decryption errors', async () => {
    state.db!.exec("UPDATE xray_nodes SET outbound_type='proxy',proxy_url_enc='BROKEN-PROXY-SECRET' WHERE id=7");
    const result = await request();
    expect(result.statusCode).toBe(200);
    expect(diagnoseXrayNode).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ outboundType: 'proxy', proxyUrl: undefined }));
    expect(result.body).not.toContain('BROKEN-PROXY-SECRET');
  });
});
