-- 多个对外地址共用机器/节点,不复制入站或凭据。
ALTER TABLE servers ADD COLUMN client_hosts TEXT NOT NULL DEFAULT '[]';
ALTER TABLE nodes ADD COLUMN client_hosts TEXT NOT NULL DEFAULT '[]';
ALTER TABLE xray_nodes ADD COLUMN client_hosts TEXT NOT NULL DEFAULT '[]';
UPDATE servers SET client_hosts = json_array(client_host) WHERE client_host != '';
