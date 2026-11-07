import { describe, it, expect } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { mkdtempSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { migrate, migrationSnapshot } from '../db/client.js';
import { MIGRATIONS, ensureMigrationsTable } from '../db/migrations.js';

it('proxy migration preserves rows, references, constraints and AUTOINCREMENT sequences', () => {
  const db = new DatabaseSync(':memory:');
  try {
    db.exec('PRAGMA foreign_keys=ON');
    ensureMigrationsTable(db);
    for (const migration of MIGRATIONS.filter(m => m.name < '0017')) {
      db.exec(migration.sql);
      db.prepare('INSERT INTO schema_migrations(name) VALUES (?)').run(migration.name);
    }
    db.exec("INSERT INTO servers(id,name,role) VALUES (1,'entry','relay'),(2,'landing','landing')");
    for (const table of ['nodes', 'xray_nodes']) {
      db.prepare(`INSERT INTO ${table}(id,name,server_id,protocol,listen_port,outbound_type,landing_server_id,creds_enc,client_hosts) VALUES (7,'old',1,'vmess',30007,'relay',2,'encrypted',?)`).run(JSON.stringify(['entry.example.com']));
      db.exec(`INSERT INTO ${table}(id,name,server_id,protocol,listen_port) VALUES (99,'deleted',1,'socks',30099)`);
      db.exec(`DELETE FROM ${table} WHERE id=99`);
    }
    const before = ['nodes', 'xray_nodes'].map(table => db.prepare(`SELECT * FROM ${table} WHERE id=7`).get());
    migrate(db);
    for (const [index, table] of ['nodes', 'xray_nodes'].entries()) {
      expect(db.prepare(`SELECT * FROM ${table} WHERE id=7`).get()).toEqual({ ...before[index], proxy_url_enc: '' });
      expect(() => db.exec(`INSERT INTO ${table}(name,server_id,protocol,listen_port) VALUES ('duplicate',1,'socks',30007)`)).toThrow();
      expect(() => db.exec(`INSERT INTO ${table}(name,server_id,protocol,listen_port) VALUES ('missing',999,'socks',30009)`)).toThrow();
      const inserted = db.prepare(`INSERT INTO ${table}(name,server_id,protocol,listen_port,outbound_type) VALUES ('new',1,'socks',30100,'proxy')`).run();
      expect(Number(inserted.lastInsertRowid)).toBeGreaterThan(99);
    }
    expect(db.prepare('PRAGMA foreign_key_check').all()).toEqual([]);
    expect(() => migrate(db)).not.toThrow();
  } finally { db.close(); }
});

describe('baseline migration', () => {
  it('loads at least one migration file', () => {
    expect(MIGRATIONS.length).toBeGreaterThan(0);
  });

  it('applies cleanly on a fresh database and is idempotent', () => {
    const db = new DatabaseSync(':memory:');
    migrate(db);
    const tables = (db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all() as { name: string }[]).map((r) => r.name);
    for (const t of ['servers', 'nodes', 'xray_nodes', 'port_forwards', 'settings', 'users', 'sni_library', 'relay_settings', 'landing_settings', 'xray_server_settings', 'schema_migrations']) {
      expect(tables).toContain(t);
    }
    // port_forwards must have the explicit mechanism column
    const cols = db.prepare('PRAGMA table_info(port_forwards)').all().map((c) => (c as { name: string }).name);
    expect(cols).toContain('mechanism');
    expect(() => migrate(db)).not.toThrow();
    db.close();
  });

  // 真实文件 IO(VACUUM INTO 15 个迁移的库):Windows + 杀软下偶尔超过默认 5s
  it('迁移前留一份一致性快照(迁移失败才有回退点)', { timeout: 30_000 }, () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'singray-migrate-'));
    const dbPath = path.join(dir, 'panel.db');
    const db = new DatabaseSync(dbPath);
    migrate(db);

    // 无待执行迁移 → 不做快照
    expect(migrationSnapshot(db, dbPath)).toBeNull();

    // 让一个迁移重新变成"待执行"(迁移名不含 .sql 后缀)
    db.prepare("DELETE FROM schema_migrations WHERE name = '0001_init'").run();
    const snap = migrationSnapshot(db, dbPath);
    expect(snap).toBeTruthy();
    expect(readdirSync(dir).some((f) => f.includes('.pre-migrate-'))).toBe(true);

    // 快照可打开(一致的库,不是半截拷贝)
    const copy = new DatabaseSync(snap!, { readOnly: true });
    expect((copy.prepare('SELECT COUNT(*) c FROM servers').get() as { c: number }).c).toBe(0);
    copy.close();
    db.close();
  });
});
