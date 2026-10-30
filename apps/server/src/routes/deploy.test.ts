import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { DatabaseSync } from 'node:sqlite';
import { migrate } from '../db/client.js';
import { markDirty } from '../services/deployState.js';
import { deployAll } from '../services/deployAll.js';
import deployRoutes from './deploy.js';

const state = vi.hoisted(() => ({ db: null as DatabaseSync | null }));
vi.mock('../db/client.js', async (original) => ({
  ...await original<typeof import('../db/client.js')>(), getDb: () => state.db!,
}));
vi.mock('../services/deployAll.js', async (original) => ({
  ...await original<typeof import('../services/deployAll.js')>(), deployAll: vi.fn(async () => []),
}));

let app: FastifyInstance;
beforeEach(async () => {
  vi.clearAllMocks();
  state.db = new DatabaseSync(':memory:');
  migrate(state.db);
  state.db.exec(`INSERT INTO servers (id, name, role, host, control) VALUES
    (1, 'one', 'relay', '10.0.0.1', 'ssh'), (2, 'two', 'relay', '10.0.0.2', 'ssh'), (3, 'agent', 'relay', '10.0.0.3', 'agent')`);
  app = Fastify();
  await app.register(deployRoutes, { prefix: '/api/deploy' });
});
afterEach(async () => { await app.close(); state.db!.close(); });

describe('deployment job scope', () => {
  it('pending jobs expose and execute the same marked machine/core list', async () => {
    markDirty(state.db!, 2, 'xray');
    markDirty(state.db!, 3, 'singbox');
    const response = await app.inject({ method: 'POST', url: '/api/deploy/pending' });
    expect(response.statusCode).toBe(200);
    const job = response.json();
    expect(job.scope).toBe('pending');
    expect(job.machines).toEqual([{ serverId: 2, name: 'two', core: 'xray', status: 'pending' }]);
    expect(deployAll).toHaveBeenCalledWith(state.db, undefined, expect.any(Function), { targets: [{ serverId: 2, name: 'two', core: 'xray' }] });
    const status = await app.inject({ method: 'GET', url: `/api/deploy/status/${job.jobId}` });
    expect(status.json()).toMatchObject({ scope: 'pending', machines: job.machines });
  });

  it('full deployment still includes all SSH machines and both cores', async () => {
    const response = await app.inject({ method: 'POST', url: '/api/deploy/all' });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ scope: 'all', machines: [{ serverId: 1 }, { serverId: 2 }] });
    expect(deployAll).toHaveBeenCalledWith(state.db, undefined, expect.any(Function), { targets: [
      { serverId: 1, name: 'one', core: undefined }, { serverId: 2, name: 'two', core: undefined },
    ] });
  });

  it('an empty pending list completes without falling back to all servers', async () => {
    const response = await app.inject({ method: 'POST', url: '/api/deploy/pending' });
    expect(response.json()).toMatchObject({ scope: 'pending', machines: [] });
    expect(deployAll).not.toHaveBeenCalled();
    const status = await app.inject({ method: 'GET', url: `/api/deploy/status/${response.json().jobId}` });
    expect(status.json().done).toBe(true);
  });

  it('pending and full deployments share the same running-job guard', async () => {
    let finish!: (results: []) => void;
    vi.mocked(deployAll).mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; }));
    markDirty(state.db!, 2, 'xray');
    const pending = await app.inject({ method: 'POST', url: '/api/deploy/pending' });
    try {
      const full = await app.inject({ method: 'POST', url: '/api/deploy/all' });
      expect(full.statusCode).toBe(409);
      expect(full.json().jobId).toBe(pending.json().jobId);
    } finally { finish([]); await Promise.resolve(); }
  });
});
