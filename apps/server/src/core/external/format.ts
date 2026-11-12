import { compatibleFormats, type ExternalNode, type JsonObject } from './types.js';

export function externalClash(n: ExternalNode): JsonObject | null {
  if (!compatibleFormats(n).includes('clash')) return null;
  const p: JsonObject = { name: n.name, type: n.protocol === 'shadowsocks' ? 'ss' : n.protocol, server: n.host, port: n.port, udp: n.udp };
  for (const key of ['uuid', 'password', 'username'] as const) if (n[key] !== undefined) p[key] = n[key]!;
  if (n.protocol === 'shadowsocks') p.cipher = n.method!;
  if (n.protocol === 'vmess') { p.cipher = n.cipher; p.alterId = n.alterId; }
  if (n.flow) p.flow = n.flow;
  if (['vless', 'vmess', 'http', 'socks5'].includes(n.protocol)) p.tls = n.security !== 'none';
  if (n.security !== 'none') {
    p[['vless', 'vmess', 'http', 'socks5'].includes(n.protocol) ? 'servername' : 'sni'] = n.sni || n.host;
    p['skip-cert-verify'] = n.insecure;
    if (n.alpn.length) p.alpn = n.alpn;
    if (n.fingerprint) p['client-fingerprint'] = n.fingerprint;
    if (n.security === 'reality') p['reality-opts'] = { 'public-key': n.publicKey, 'short-id': n.shortId };
  }
  if (n.transport !== 'tcp') p.network = n.transport;
  if (n.transport === 'ws') p['ws-opts'] = { path: n.path || '/', headers: n.headers };
  if (n.transport === 'grpc') p['grpc-opts'] = { 'grpc-service-name': n.serviceName };
  if (n.obfs) { p.obfs = n.obfs; p['obfs-password'] = n.obfsPassword; }
  if (n.protocol === 'tuic') { p['congestion-controller'] = n.congestion; p['udp-relay-mode'] = n.udpRelayMode; }
  return p;
}

export function externalSingbox(n: ExternalNode): JsonObject | null {
  if (!compatibleFormats(n).includes('singbox')) return null;
  const p: JsonObject = { tag: n.name, type: n.protocol === 'socks5' ? 'socks' : n.protocol, server: n.host, server_port: n.port };
  for (const key of ['uuid', 'password', 'username', 'method'] as const) if (n[key] !== undefined) p[key] = n[key]!;
  if (n.flow) p.flow = n.flow;
  if (n.protocol === 'vmess') { p.security = n.cipher; p.alter_id = n.alterId; }
  if (n.security !== 'none') {
    const tls: JsonObject = { enabled: true, server_name: n.sni || n.host, insecure: n.insecure };
    if (n.alpn.length) tls.alpn = n.alpn;
    if (n.fingerprint) tls.utls = { enabled: true, fingerprint: n.fingerprint };
    if (n.security === 'reality') tls.reality = { enabled: true, public_key: n.publicKey, short_id: n.shortId };
    p.tls = tls;
  }
  if (n.transport === 'ws') p.transport = { type: 'ws', path: n.path || '/', headers: n.headers };
  if (n.transport === 'grpc') p.transport = { type: 'grpc', service_name: n.serviceName };
  if (n.obfs) p.obfs = { type: n.obfs, password: n.obfsPassword };
  if (n.protocol === 'tuic') { p.congestion_control = n.congestion; p.udp_relay_mode = n.udpRelayMode; }
  if (!n.udp && n.protocol !== 'http') p.network = 'tcp';
  return p;
}

export function externalShareLink(n: ExternalNode): string | null {
  if (!compatibleFormats(n).includes('base64')) return null;
  const host = n.host.includes(':') ? `[${n.host}]` : n.host;
  const enc = encodeURIComponent;
  if (n.protocol === 'vmess') {
    const v = { v: '2', ps: n.name, add: n.host, port: n.port, id: n.uuid, aid: n.alterId, scy: n.cipher,
      net: n.transport, type: 'none', host: n.headers.Host || '', path: n.transport === 'grpc' ? n.serviceName : n.path,
      tls: n.security === 'none' ? '' : 'tls', sni: n.sni, alpn: n.alpn.join(','), fp: n.fingerprint, allowInsecure: n.insecure ? '1' : '0' };
    return 'vmess://' + Buffer.from(JSON.stringify(v)).toString('base64');
  }
  if (n.protocol === 'shadowsocks') return `ss://${Buffer.from(`${n.method}:${n.password}`).toString('base64url')}@${host}:${n.port}#${enc(n.name)}`;
  const q = new URLSearchParams();
  if (['vless', 'trojan', 'anytls'].includes(n.protocol)) { q.set('security', n.security); q.set('type', n.transport); }
  if (n.sni) q.set('sni', n.sni);
  if (n.security !== 'none') q.set('insecure', n.insecure ? '1' : '0');
  if (n.fingerprint) q.set('fp', n.fingerprint);
  if (n.alpn.length) q.set('alpn', n.alpn.join(','));
  if (n.security === 'reality') { q.set('pbk', n.publicKey); q.set('sid', n.shortId); }
  if (n.flow) q.set('flow', n.flow);
  if (n.path) q.set('path', n.path);
  if (n.headers.Host) q.set('host', n.headers.Host);
  if (n.serviceName) q.set('serviceName', n.serviceName);
  if (n.transport === 'xhttp') q.set('mode', n.mode);
  if (n.obfs) { q.set('obfs', n.obfs); q.set('obfs-password', n.obfsPassword); }
  if (n.protocol === 'tuic') { q.set('congestion_control', n.congestion); q.set('udp_relay_mode', n.udpRelayMode); }
  const auth = ['vless', 'tuic'].includes(n.protocol) ? enc(n.uuid!) + (n.protocol === 'tuic' ? ':' + enc(n.password!) : '')
    : ['socks5', 'http'].includes(n.protocol) ? n.username ? `${enc(n.username)}:${enc(n.password || '')}` : '' : enc(n.password!);
  const scheme = n.protocol === 'http' && n.security === 'tls' ? 'https' : n.protocol;
  return `${scheme}://${auth ? auth + '@' : ''}${host}:${n.port}${q.size ? '?' + q.toString() : ''}#${enc(n.name)}`;
}
