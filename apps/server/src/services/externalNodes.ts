import { createHmac } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import { z } from 'zod';
import { config } from '../config.js';
import { decryptSecret, encryptSecret } from './creds.js';
import { HttpError } from './errors.js';
import type { Row } from './row.js';
import { parseExternalInput } from '../core/external/parse.js';
import { compatibleFormats, normalizeExternal, type ExternalNode, type ExternalFormat } from '../core/external/types.js';
import { probeExternalNode, type ExternalProbeResult } from '../core/external/probe.js';
import type { NodeView } from '../core/subscribe/index.js';

const read = (row: Row): ExternalNode => ({ ...normalizeExternal(JSON.parse(decryptSecret(row.config_enc))), name: row.name });
const find = (db: DatabaseSync, id: number): Row => {
  const row = db.prepare('SELECT * FROM external_nodes WHERE id = ?').get(id) as Row | undefined;
  if (!row) throw new HttpError(404, '外部节点不存在');
  return row;
};
function stable(value: unknown): string {
  if (Array.isArray(value)) return '[' + value.map(stable).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => JSON.stringify(k) + ':' + stable(v)).join(',') + '}';
  return JSON.stringify(value);
}
function fingerprint(node: ExternalNode): string {
  const { name: _name, ...params } = node;
  return createHmac('sha256', config.appSecret).update(stable(params)).digest('hex');
}
function parsed(content: string) {
  try { return parseExternalInput(content); }
  catch (err) { throw new HttpError(400, (err as Error).message); }
}

export function previewExternal(db: DatabaseSync, content: string) {
  const existing = new Set((db.prepare('SELECT fingerprint FROM external_nodes').all() as { fingerprint: string }[]).map(r => r.fingerprint));
  const rows = parsed(content);
  const items = rows.flatMap(r => {
    if (!r.node) return [];
    const key = fingerprint(r.node), duplicate = existing.has(key); existing.add(key);
    return [{ index: r.index, name: r.node.name, protocol: r.node.protocol, host: r.node.host, port: r.node.port,
      formats: compatibleFormats(r.node), duplicate,
      warning: r.node.transport === 'xhttp' ? 'XHTTP 仅进入通用链接订阅，当前测试核心不支持该传输' :
        !compatibleFormats(r.node).includes('base64') ? '该参数组合仅进入 Clash 和 sing-box 订阅' : '' }];
  });
  return { items, errors: rows.filter(r => r.error).map(r => ({ index: r.index, error: r.error! })) };
}

export function importExternal(db: DatabaseSync, content: string, indices: number[] | undefined, includeInSub = false) {
  const rows = parsed(content), selected = indices ? new Set(indices) : new Set(rows.map(r => r.index));
  if (!selected.size || [...selected].some(i => !Number.isInteger(i) || i < 0 || i >= rows.length)) throw new HttpError(400, '请选择有效节点');
  let created = 0, skipped = 0;
  db.exec('BEGIN');
  try {
    for (const r of rows) {
      if (!selected.has(r.index)) continue;
      if (!r.node) { skipped++; continue; }
      const n = r.node;
      const info = db.prepare(`INSERT INTO external_nodes (name, protocol, host, port, config_enc, fingerprint, include_in_sub)
        VALUES (?,?,?,?,?,?,?) ON CONFLICT(fingerprint) DO NOTHING`)
        .run(n.name, n.protocol, n.host, n.port, encryptSecret(JSON.stringify(n)), fingerprint(n), includeInSub ? 1 : 0);
      if (info.changes) created++; else skipped++;
    }
    db.exec('COMMIT');
  } catch (err) { db.exec('ROLLBACK'); throw err; }
  return { created, skipped };
}

export function listExternal(db: DatabaseSync) {
  return (db.prepare('SELECT * FROM external_nodes ORDER BY id').all() as Row[]).map(row => ({
    id: row.id as number, name: row.name as string, protocol: row.protocol as string, host: row.host as string, port: row.port as number,
    enabled: row.enabled as number, include_in_sub: row.include_in_sub as number, note: row.note as string,
    probe_status: row.probe_status as string | null, latency_ms: row.latency_ms as number | null,
    probe_detail: row.probe_detail as string, checked_at: row.checked_at as string | null, created_at: row.created_at as string,
    formats: compatibleFormats(read(row)),
  }));
}

export const externalPatchSchema = z.object({
  name: z.string().trim().min(1, '请输入名称').max(200).optional(), note: z.string().max(2000).optional(),
  enabled: z.boolean().optional(), includeInSub: z.boolean().optional(),
}).strict().refine(v => Object.values(v).some(x => x !== undefined), '至少提供一个修改字段');

export function updateExternal(db: DatabaseSync, id: number, patch: z.infer<typeof externalPatchSchema>) {
  const p = externalPatchSchema.parse(patch); find(db, id);
  db.prepare('UPDATE external_nodes SET name=COALESCE(?,name), note=COALESCE(?,note), enabled=COALESCE(?,enabled), include_in_sub=COALESCE(?,include_in_sub) WHERE id=?')
    .run(p.name ?? null, p.note ?? null, p.enabled === undefined ? null : Number(p.enabled), p.includeInSub === undefined ? null : Number(p.includeInSub), id);
  return { ok: true };
}
export function deleteExternal(db: DatabaseSync, id: number) {
  find(db, id); db.prepare('DELETE FROM external_nodes WHERE id=?').run(id); return { ok: true };
}

// Bounded across all requests; repeated clicks on one node share the running test.
let active = 0;
const waiting: (() => void)[] = [];
const running = new WeakMap<DatabaseSync, Map<number, Promise<ExternalProbeResult>>>();
async function acquire() {
  if (active < 3) { active++; return; }
  if (waiting.length >= 100) throw new HttpError(409, '测试队列已满，请稍后重试');
  await new Promise<void>(resolve => waiting.push(resolve));
}
function release() { const next = waiting.shift(); if (next) next(); else active--; }

export function testExternal(db: DatabaseSync, id: number, probe = probeExternalNode): Promise<ExternalProbeResult> {
  let tasks = running.get(db); if (!tasks) { tasks = new Map(); running.set(db, tasks); }
  const existing = tasks.get(id); if (existing) return existing;
  const node = read(find(db, id));
  const task = (async () => {
    await acquire();
    try {
      const r = await probe(node);
      db.prepare('UPDATE external_nodes SET probe_status=?,latency_ms=?,probe_detail=?,checked_at=? WHERE id=?')
        .run(r.status, r.latencyMs, r.detail, r.checkedAt, id);
      return r;
    } finally { release(); }
  })();
  tasks.set(id, task);
  void task.then(() => tasks!.delete(id), () => tasks!.delete(id));
  return task;
}

/** Merge once per subscription format, retaining native node names and avoiding selector/tag collisions. */
export function externalViews(db: DatabaseSync, format: ExternalFormat, used = new Set<string>()): NodeView[] {
  const names = new Set([...used, 'PROXY', 'AUTO', 'auto', 'direct', 'block']);
  return (db.prepare('SELECT * FROM external_nodes WHERE enabled=1 AND include_in_sub=1 ORDER BY id').all() as Row[]).flatMap(row => {
    const n = read(row); if (!compatibleFormats(n).includes(format)) return [];
    let name = n.name;
    if (names.has(name)) name = `${name} [外部 #${row.id}]`;
    while (names.has(name)) name += '_';
    names.add(name);
    return [{ id: -row.id, name, protocol: n.protocol, host: n.host, port: n.port, sni: n.sni,
      ws_path: n.path, realityPublicKey: n.publicKey || null, shortId: n.shortId || null, creds: {}, external: n }];
  });
}
