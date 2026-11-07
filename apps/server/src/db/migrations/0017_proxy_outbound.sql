-- Extend outbound modes while preserving node ids, credentials and client hosts.
CREATE TABLE nodes_new (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  protocol TEXT NOT NULL,
  listen_port INTEGER NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  creds_enc TEXT NOT NULL DEFAULT '',
  tls_mode TEXT NOT NULL DEFAULT 'none' CHECK(tls_mode IN ('none','reality','tls','shadowtls')),
  sni TEXT NOT NULL DEFAULT '',
  transport TEXT NOT NULL DEFAULT 'raw' CHECK(transport IN ('raw','ws')),
  ws_path TEXT NOT NULL DEFAULT '',
  outbound_type TEXT NOT NULL DEFAULT 'direct' CHECK(outbound_type IN ('direct','relay','proxy')),
  landing_server_id INTEGER REFERENCES servers(id),
  tunnel_address TEXT NOT NULL DEFAULT '',
  tunnel_port INTEGER,
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  client_hosts TEXT NOT NULL DEFAULT '[]',
  proxy_url_enc TEXT NOT NULL DEFAULT '',
  UNIQUE(server_id, listen_port)
);
INSERT INTO nodes_new (id, name, server_id, protocol, listen_port, enabled, creds_enc, tls_mode, sni, transport, ws_path, outbound_type, landing_server_id, tunnel_address, tunnel_port, note, created_at, client_hosts)
  SELECT id, name, server_id, protocol, listen_port, enabled, creds_enc, tls_mode, sni, transport, ws_path, outbound_type, landing_server_id, tunnel_address, tunnel_port, note, created_at, client_hosts FROM nodes;
UPDATE sqlite_sequence SET seq = MAX(seq, COALESCE((SELECT seq FROM sqlite_sequence WHERE name = 'nodes'), 0)) WHERE name = 'nodes_new';
DROP TABLE nodes;
ALTER TABLE nodes_new RENAME TO nodes;

CREATE TABLE xray_nodes_new (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  protocol TEXT NOT NULL,
  listen_port INTEGER NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  creds_enc TEXT NOT NULL DEFAULT '',
  tls_mode TEXT NOT NULL DEFAULT 'reality' CHECK(tls_mode IN ('none','reality','tls')),
  sni TEXT NOT NULL DEFAULT '',
  transport TEXT NOT NULL DEFAULT 'raw' CHECK(transport IN ('raw','ws','tcp','xhttp')),
  ws_path TEXT NOT NULL DEFAULT '',
  flow TEXT NOT NULL DEFAULT '',
  outbound_type TEXT NOT NULL DEFAULT 'direct' CHECK(outbound_type IN ('direct','relay','proxy')),
  landing_server_id INTEGER REFERENCES servers(id),
  tunnel_address TEXT NOT NULL DEFAULT '',
  tunnel_port INTEGER,
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  client_hosts TEXT NOT NULL DEFAULT '[]',
  proxy_url_enc TEXT NOT NULL DEFAULT '',
  UNIQUE(server_id, listen_port)
);
INSERT INTO xray_nodes_new (id, name, server_id, protocol, listen_port, enabled, creds_enc, tls_mode, sni, transport, ws_path, flow, outbound_type, landing_server_id, tunnel_address, tunnel_port, note, created_at, client_hosts)
  SELECT id, name, server_id, protocol, listen_port, enabled, creds_enc, tls_mode, sni, transport, ws_path, flow, outbound_type, landing_server_id, tunnel_address, tunnel_port, note, created_at, client_hosts FROM xray_nodes;
UPDATE sqlite_sequence SET seq = MAX(seq, COALESCE((SELECT seq FROM sqlite_sequence WHERE name = 'xray_nodes'), 0)) WHERE name = 'xray_nodes_new';
DROP TABLE xray_nodes;
ALTER TABLE xray_nodes_new RENAME TO xray_nodes;
