import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { getDb } from '../db/client.js';
import { previewExternal, importExternal, listExternal, externalPatchSchema, updateExternal, deleteExternal, testExternal } from '../services/externalNodes.js';

const input = z.object({ content: z.string().min(1).max(512_000) });
const idParam = z.object({ id: z.coerce.number().int().positive() });
const limited = (max: number) => ({ config: { rateLimit: { max, timeWindow: '1 minute' } } });

export default async function externalNodeRoutes(app: FastifyInstance): Promise<void> {
  app.get('/', async () => listExternal(getDb()));
  app.post('/import/preview', limited(20), async req => previewExternal(getDb(), input.parse(req.body).content));
  app.post('/import', limited(10), async req => {
    const b = input.extend({ indices: z.array(z.number().int().min(0)).min(1).max(500).optional(), includeInSub: z.boolean().default(false) }).parse(req.body);
    return importExternal(getDb(), b.content, b.indices, b.includeInSub);
  });
  app.put('/:id', async req => updateExternal(getDb(), idParam.parse(req.params).id, externalPatchSchema.parse(req.body)));
  app.delete('/:id', async req => deleteExternal(getDb(), idParam.parse(req.params).id));
  app.post('/:id/test', limited(30), async req => testExternal(getDb(), idParam.parse(req.params).id));
  app.post('/test', limited(4), async req => {
    const { ids } = z.object({ ids: z.array(z.number().int().positive()).min(1).max(50) }).parse(req.body);
    const db = getDb();
    const results = await Promise.all([...new Set(ids)].map(async id => {
      try { return { id, ...await testExternal(db, id) }; }
      catch { return { id, status: 'unavailable', latencyMs: null, detail: '节点不存在或测试暂不可用，请刷新后重试', checkedAt: new Date().toISOString() }; }
    }));
    return { results };
  });
}
