CREATE TABLE external_nodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  protocol TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
  config_enc TEXT NOT NULL,
  fingerprint TEXT NOT NULL UNIQUE,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  include_in_sub INTEGER NOT NULL DEFAULT 0 CHECK(include_in_sub IN (0,1)),
  note TEXT NOT NULL DEFAULT '',
  probe_status TEXT,
  latency_ms INTEGER,
  probe_detail TEXT NOT NULL DEFAULT '',
  checked_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
