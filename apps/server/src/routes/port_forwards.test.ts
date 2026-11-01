import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { DatabaseSync } from 'node:sqlite';
import { migrate } from '../db/client.js';
import { applyForward, reconcile, removeIptablesLine } from '../core/forward/index.js';
import { holdsServerLock, resetServerLocks } from '../services/locks.js';
import routes from './port_forwards.js';

const state = vi.hoisted(() => ({ db: null as DatabaseSync | null }));
vi.mock('../db/client.js', async (original) => ({
  ...await original<typeof import('../db/client.js')>(), getDb: () => state.db!,
}));
vi.mock('../core/forward/index.js', async (original) => ({
  ...await original<typeof import('../core/forward/index.js')>(),
  reconcile: vi.fn(), applyForward: vi.fn(), removeIptablesLine: vi.fn(),
}));
vi.mock('../services/conn.js', () => ({ serverConn: (_db: unknown, id: number) => ({ serverId: id, host: '127.0.0.1', sudo: false }) }));
const empty = () => ({ actualIptables: [], actualSocatUnits: [], missingIptables: [], missingSocat: [], orphanIptables: [], orphanSocat: [], ruleIssues: [] });
const broken = () => ({ ...empty(), missingIptables: [2, 3, 4], ruleIssues: [2, 3, 4].map(id => ({ id, entryPort: 31219 + id, issues: ['源地址转换缺失'] })) });
let app: FastifyInstance;

beforeEach(async () => {
  vi.resetAllMocks();
  resetServerLocks();
  state.db = new DatabaseSync(':memory:');
  migrate(state.db);
  state.db.exec("INSERT INTO servers (id,name,role,host,client_host,control) VALUES (1,'HK','relay','10.0.0.1','','ssh'), (2,'landing','landing','10.0.0.2','landing.example.com','ssh'), (3,'other','relay','10.0.0.3','','ssh')");
  for (const id of [2, 3, 4]) state.db.prepare("INSERT INTO port_forwards (id,name,entry_server_id,landing_server_id,target_node_type,target_node_id,entry_port,target_port,mechanism) VALUES (?, ?,1,2,'xray',7,?,?,'iptables')").run(id, 'route-' + id, 31219 + id, 31932 + id);
  state.db.exec("INSERT INTO port_forwards (id,name,entry_server_id,landing_server_id,target_node_type,target_node_id,entry_port,target_port,mechanism,enabled) VALUES (8,'disabled',1,2,'xray',7,31228,31938,'iptables',0), (9,'another-entry',3,2,'xray',7,31229,31939,'iptables',1)");
  vi.mocked(reconcile).mockResolvedValue(broken());
  vi.mocked(applyForward).mockImplementation(async () => { expect(holdsServerLock(1)).toBe(true); });
  app = Fastify();
  await app.register(routes, { prefix: '/api/port-forwards' });
});
afterEach(async () => { await app.close(); state.db!.close(); });
const request = (fix = false) => app.inject({ method: 'POST', url: '/api/port-forwards/reconcile', payload: { entryServerId: 1, fix } });

describe('forward configuration inspection and repair', () => {
  it('passes the actual landing target and enabled rules to read-only inspection', async () => {
    const result = await request();
    expect(result.statusCode).toBe(200);
    expect(result.json().ruleIssues).toHaveLength(3);
    const inspected = vi.mocked(reconcile).mock.calls[0][1];
    expect(inspected).toHaveLength(3);
    expect(inspected[0]).toMatchObject({ id: 2, landingHost: 'landing.example.com', targetPort: 31934 });
    expect(applyForward).not.toHaveBeenCalled();
  });

  it('repairs all three routes over SSH and returns a fresh inspection', async () => {
    vi.mocked(reconcile).mockResolvedValueOnce(broken()).mockResolvedValueOnce(empty());
    const result = await request(true);
    expect(result.statusCode).toBe(200);
    expect(result.json()).toMatchObject({ missingIptables: [], ruleIssues: [], verified: true, repaired: { reapplied: [2, 3, 4], errors: [] } });
    expect(reconcile).toHaveBeenCalledTimes(2);
    expect(applyForward).toHaveBeenCalledTimes(3);
  });

  it('continues repairing other routes when one fails and retains its warning', async () => {
    vi.mocked(applyForward).mockRejectedValueOnce(new Error('permanent write failed'));
    vi.mocked(reconcile).mockResolvedValueOnce(broken()).mockResolvedValueOnce({ ...empty(), missingIptables: [2], ruleIssues: [broken().ruleIssues[0]] });
    const result = (await request(true)).json();
    expect(result.repaired.reapplied).toEqual([3, 4]);
    expect(result.repaired.errors[0]).toContain('permanent write failed');
    expect(result.missingIptables).toEqual([2]);
  });

  it('does not report success when the final inspection fails', async () => {
    vi.mocked(reconcile).mockResolvedValueOnce(broken()).mockRejectedValueOnce(new Error('SSH disconnected'));
    const result = (await request(true)).json();
    expect(result.verified).toBe(false);
    expect(result.repaired.errors.join(' ')).toContain('SSH disconnected');
    expect(result.missingIptables).toEqual([2, 3, 4]);
  });

  it('cleans orphan configuration without applying another entry or a disabled rule', async () => {
    const line = 'ipv4 nat -A PREROUTING -p tcp --dport 31228 -m comment --comment singray:8 -j DNAT --to-destination 10.0.0.2:31938';
    vi.mocked(reconcile).mockResolvedValueOnce({ ...empty(), orphanIptables: [line] }).mockResolvedValueOnce(empty());
    const result = (await request(true)).json();
    expect(removeIptablesLine).toHaveBeenCalledWith(expect.objectContaining({ serverId: 1 }), line);
    expect(applyForward).not.toHaveBeenCalled();
    expect(result.repaired.removed).toEqual([line]);
  });
});
