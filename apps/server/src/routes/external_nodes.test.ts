import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { DatabaseSync } from 'node:sqlite';
import { ZodError } from 'zod';
import { migrate } from '../db/client.js';
import { HttpError } from '../services/errors.js';
import { probeExternalNode } from '../core/external/probe.js';
import routes from './external_nodes.js';
import { camelize } from '../core/json.js';

const state = vi.hoisted(() => ({ db: null as DatabaseSync | null }));
vi.mock('../db/client.js', async original => ({ ...await original<typeof import('../db/client.js')>(), getDb: () => state.db! }));
vi.mock('../core/external/probe.js', () => ({ probeExternalNode: vi.fn(async () => ({ status: 'ok', latencyMs: 120, detail: 'HTTPS OK', checkedAt: '2026-11-12T00:00:00Z' })) }));
let app: FastifyInstance;
beforeEach(async () => {
  vi.clearAllMocks(); state.db = new DatabaseSync(':memory:'); migrate(state.db);
  app = Fastify();
  app.setErrorHandler((err, _req, reply) => reply.code(err instanceof HttpError ? err.status : err instanceof ZodError ? 400 : 500).send({ error: 'request failed' }));
  app.addHook('preSerialization', async (_req, _reply, payload) => camelize(payload));
  await app.register(routes, { prefix: '/api/external-nodes' });
});
afterEach(async () => { await app.close(); state.db!.close(); });
const inject = (method: 'GET' | 'POST' | 'PUT' | 'DELETE', route: string, payload?: Record<string, unknown>) => app.inject({ method, url: '/api/external-nodes' + route, payload });
const content = 'hy2://secret@example.com:443?obfs=salamander&obfs-password=secret-obfs#HY';
describe('external node API', () => {
  it('previews/imports, edits, controls subscriptions, tests QUIC through the core and deletes', async () => {
    const preview = await inject('POST', '/import/preview', { content });
    expect(preview.statusCode).toBe(200); expect(preview.body).not.toContain('secret');
    expect((await inject('POST', '/import', { content, indices: [0], includeInSub: true })).json().created).toBe(1);
    const [row] = (await inject('GET', '/')).json();
    expect(row).toMatchObject({ includeInSub: 1, probeStatus: null });
    expect(JSON.stringify(row)).not.toContain('secret');
    expect((await inject('PUT', `/${row.id}`, { name: 'Custom', note: 'memo', includeInSub: false })).statusCode).toBe(200);
    expect((await inject('POST', `/${row.id}/test`)).json()).toMatchObject({ status: 'ok', latencyMs: 120 });
    expect(probeExternalNode).toHaveBeenCalledWith(expect.objectContaining({ protocol: 'hysteria2', password: 'secret', obfsPassword: 'secret-obfs' }));
    expect((await inject('GET', '/')).json()[0]).toMatchObject({ name: 'Custom', note: 'memo', includeInSub: 0, probeStatus: 'ok', latencyMs: 120 });
    const batch = (await inject('POST', '/test', { ids: [row.id, row.id, 9999] })).json();
    expect(batch.results).toHaveLength(2); expect(batch.results[1].status).toBe('unavailable');
    expect((await inject('DELETE', `/${row.id}`)).statusCode).toBe(200);
    expect((await inject('POST', `/${row.id}/test`)).statusCode).toBe(404);
  });
  it('rejects empty or malformed imports, routing edits, blank names and unbounded test batches', async () => {
    expect((await inject('POST', '/import/preview', { content: '' })).statusCode).toBe(400);
    expect((await inject('POST', '/import', { content, indices: [999] })).statusCode).toBe(400);
    await inject('POST', '/import', { content });
    for (const patch of [{ name: ' ' }, { host: 'another.example' }, {}]) expect((await inject('PUT', '/1', patch)).statusCode).toBe(400);
    expect((await inject('POST', '/test', { ids: Array(51).fill(1) })).statusCode).toBe(400);
  });
});
