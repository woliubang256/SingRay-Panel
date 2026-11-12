import { beforeEach, afterEach, describe, it, expect, vi } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { migrate } from '../db/client.js';
import { previewExternal, importExternal, listExternal, updateExternal, deleteExternal, testExternal, externalViews } from './externalNodes.js';

let db: DatabaseSync;
const content = 'trojan://super-secret@example.com:443?sni=tls.example#External';
beforeEach(() => { db = new DatabaseSync(':memory:'); migrate(db); });
afterEach(() => db.close());
describe('external node management', () => {
  it('previews safely, encrypts credentials, skips duplicates across renamed imports, and defaults out of subscriptions', () => {
    const preview = previewExternal(db, content);
    expect(preview.items[0]).toMatchObject({ name: 'External', duplicate: false, formats: ['base64', 'singbox', 'clash'] });
    expect(JSON.stringify(preview)).not.toContain('super-secret');
    expect(listExternal(db)).toHaveLength(0);
    expect(importExternal(db, content, [0], false)).toMatchObject({ created: 1, skipped: 0 });
    expect(importExternal(db, content.replace('#External', '#Renamed'), [0], true)).toMatchObject({ created: 0, skipped: 1 });
    expect(previewExternal(db, content).items[0].duplicate).toBe(true);
    expect(listExternal(db)[0]).toMatchObject({ include_in_sub: 0, enabled: 1 });
    expect(JSON.stringify(db.prepare('SELECT * FROM external_nodes').all())).not.toContain('super-secret');
    expect(JSON.stringify(listExternal(db))).not.toContain('super-secret');
  });
  it('supports partial imports and note/name edits, subscription toggles and disabled nodes', () => {
    const source = content + '\ninvalid\nss://YWVzLTEyOC1nY206cHc@example.com:8388#SS';
    expect(previewExternal(db, source).errors).toHaveLength(1);
    expect(importExternal(db, source, [0], true).created).toBe(1);
    const id = listExternal(db)[0].id;
    updateExternal(db, id, { name: 'Custom', note: 'memo' });
    const views = externalViews(db, 'clash', new Set(['Custom']));
    expect(views).toHaveLength(1); expect(views[0].name).not.toBe('Custom');
    expect(views[0].external?.password).toBe('super-secret');
    updateExternal(db, id, { includeInSub: false }); expect(externalViews(db, 'clash')).toHaveLength(0);
    updateExternal(db, id, { includeInSub: true, enabled: false }); expect(externalViews(db, 'singbox')).toHaveLength(0);
    deleteExternal(db, id); expect(listExternal(db)).toHaveLength(0);
    expect(() => updateExternal(db, id, { name: 'missing' })).toThrow(/不存在/);
  });
  it('persists real test results, coalesces overlapping requests and does not recreate deleted rows', async () => {
    importExternal(db, content, [0], false);
    const id = listExternal(db)[0].id;
    let release!: () => void;
    const gate = new Promise<void>(r => { release = r; });
    const probe = vi.fn(async () => { await gate; return { status: 'ok' as const, latencyMs: 123, detail: 'HTTPS OK', checkedAt: '2026-11-12T00:00:00Z' }; });
    const a = testExternal(db, id, probe), b = testExternal(db, id, probe);
    await Promise.resolve(); release(); await Promise.all([a, b]);
    expect(probe).toHaveBeenCalledTimes(1);
    expect(listExternal(db)[0]).toMatchObject({ probe_status: 'ok', latency_ms: 123 });
    const running = testExternal(db, id, probe); deleteExternal(db, id); await running;
    expect(listExternal(db)).toHaveLength(0);
  });

  it('limits concurrent cores to three and releases a failed test slot to the queue', async () => {
    importExternal(db, Array.from({ length: 7 }, (_, i) => content.replace('example.com', `node${i}.example.com`)).join('\n'), undefined);
    let active = 0, peak = 0, started = 0;
    const gates: (() => void)[] = [];
    const probe = vi.fn(async () => {
      const index = started++;
      peak = Math.max(peak, ++active);
      await new Promise<void>(resolve => gates.push(resolve));
      active--;
      if (index === 0) throw new Error('core failed');
      return { status: 'ok' as const, latencyMs: 20, detail: 'HTTPS OK', checkedAt: new Date().toISOString() };
    });
    const tasks = listExternal(db).map(row => testExternal(db, row.id, probe));
    const completion = Promise.allSettled(tasks);
    try {
      await vi.waitFor(() => expect(probe).toHaveBeenCalledTimes(3));
      gates.shift()!();
      await vi.waitFor(() => expect(probe).toHaveBeenCalledTimes(4));
      expect(active).toBe(3);
    } finally {
      while (started < tasks.length || active > 0) {
        gates.splice(0).forEach(release => release());
        await new Promise(resolve => setTimeout(resolve, 0));
      }
      const results = await completion;
      expect(results.filter(r => r.status === 'fulfilled')).toHaveLength(6);
      expect(peak).toBe(3);
    }
  });
});
