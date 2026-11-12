import { parseDocument } from 'yaml';
import { normalizeExternal, type ExternalNode } from './types.js';

type Obj = Record<string, any>;
export interface ParsedExternal { index: number; node?: ExternalNode; error?: string }
const obj = (v: unknown): Obj => {
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('节点格式应为对象');
  return v as Obj;
};
const keys = (v: Obj, allowed: string[]) => {
  if (Object.keys(v).some(k => !allowed.includes(k))) throw new Error('含暂不支持的参数，请精简为单节点配置后重试');
};
const bool = (v: unknown) => {
  if ([true, 'true', '1', 1].includes(v as string)) return true;
  if ([false, 'false', '0', 0, '', undefined, null].includes(v as string)) return false;
  throw new Error('布尔参数格式无效');
};
const protocol = (p: string) => ({ ss: 'shadowsocks', hy2: 'hysteria2', socks: 'socks5', https: 'http' }[p] ?? p);
const b64 = (v: string) => Buffer.from(v, 'base64url').toString('utf8');

function clash(v: Obj): ExternalNode {
  keys(v, ['name', 'type', 'server', 'port', 'uuid', 'password', 'username', 'cipher', 'alterId', 'flow', 'tls', 'servername', 'sni',
    'skip-cert-verify', 'client-fingerprint', 'alpn', 'reality-opts', 'network', 'ws-opts', 'grpc-opts', 'udp', 'obfs', 'obfs-password',
    'congestion-controller', 'udp-relay-mode']);
  const r = v['reality-opts'] ? obj(v['reality-opts']) : {};
  keys(r, ['public-key', 'short-id']);
  const ws = v['ws-opts'] ? obj(v['ws-opts']) : {}; keys(ws, ['path', 'headers']);
  const grpc = v['grpc-opts'] ? obj(v['grpc-opts']) : {}; keys(grpc, ['grpc-service-name']);
  const p = protocol(v.type);
  return normalizeExternal({ name: v.name || `${v.server}:${v.port}`, protocol: p, host: v.server, port: v.port,
    uuid: v.uuid, password: v.password, username: v.username, method: p === 'shadowsocks' ? v.cipher : undefined,
    cipher: p === 'vmess' ? v.cipher : undefined, alterId: v.alterId, flow: v.flow,
    security: r['public-key'] ? 'reality' : bool(v.tls) || ['trojan', 'hysteria2', 'tuic', 'anytls'].includes(p) ? 'tls' : 'none',
    sni: v.servername || v.sni, insecure: bool(v['skip-cert-verify']), fingerprint: v['client-fingerprint'], alpn: v.alpn,
    publicKey: r['public-key'], shortId: r['short-id'], transport: v.network === 'raw' ? 'tcp' : v.network,
    path: ws.path, headers: ws.headers, serviceName: grpc['grpc-service-name'], udp: v.udp,
    obfs: v.obfs, obfsPassword: v['obfs-password'], congestion: v['congestion-controller'], udpRelayMode: v['udp-relay-mode'] });
}

function singbox(v: Obj): ExternalNode {
  keys(v, ['type', 'tag', 'server', 'server_port', 'uuid', 'password', 'username', 'method', 'flow', 'security', 'alter_id',
    'tls', 'transport', 'obfs', 'congestion_control', 'udp_relay_mode', 'network']);
  if (v.network !== undefined && v.network !== 'tcp') throw new Error('暂不支持该网络限定参数');
  const t = v.tls ? obj(v.tls) : {}; keys(t, ['enabled', 'server_name', 'insecure', 'alpn', 'utls', 'reality']);
  const r = t.reality ? obj(t.reality) : {}; keys(r, ['enabled', 'public_key', 'short_id']);
  const u = t.utls ? obj(t.utls) : {}; keys(u, ['enabled', 'fingerprint']);
  const tr = v.transport ? obj(v.transport) : {}; keys(tr, ['type', 'path', 'headers', 'service_name']);
  const ob = v.obfs ? obj(v.obfs) : {}; keys(ob, ['type', 'password']);
  return normalizeExternal({ name: v.tag || `${v.server}:${v.server_port}`, protocol: protocol(v.type), host: v.server, port: v.server_port,
    uuid: v.uuid, password: v.password, username: v.username, method: v.method, flow: v.flow, cipher: v.security, alterId: v.alter_id,
    security: bool(r.enabled) ? 'reality' : bool(t.enabled) || ['hysteria2', 'tuic', 'trojan', 'anytls'].includes(v.type) ? 'tls' : 'none',
    sni: t.server_name, insecure: bool(t.insecure), alpn: t.alpn, fingerprint: bool(u.enabled) ? u.fingerprint : '',
    publicKey: r.public_key, shortId: r.short_id, transport: tr.type, path: tr.path, headers: tr.headers, serviceName: tr.service_name,
    obfs: ob.type, obfsPassword: ob.password, congestion: v.congestion_control, udpRelayMode: v.udp_relay_mode,
    udp: v.network === undefined ? undefined : v.network !== 'tcp' });
}

function xray(v: Obj): ExternalNode {
  keys(v, ['tag', 'protocol', 'settings', 'streamSettings']);
  const s = obj(v.settings); keys(s, ['vnext', 'servers']);
  const servers = s.vnext ?? s.servers;
  if (!Array.isArray(servers) || servers.length !== 1) throw new Error('请提供仅含一个服务器的 Xray 出站');
  const server = obj(servers[0]); keys(server, ['address', 'port', 'users', 'password', 'method']);
  const users = server.users ?? [{}];
  if (!Array.isArray(users) || users.length !== 1) throw new Error('请提供仅含一个用户的 Xray 出站');
  const user = obj(users[0]); keys(user, ['id', 'password', 'user', 'flow', 'encryption', 'security', 'alterId', 'level']);
  if (user.encryption && user.encryption !== 'none') throw new Error('暂不支持该 VLESS 加密参数');
  const st = v.streamSettings ? obj(v.streamSettings) : {};
  keys(st, ['network', 'security', 'tlsSettings', 'realitySettings', 'wsSettings', 'grpcSettings', 'xhttpSettings']);
  const t = st.realitySettings ?? st.tlsSettings ?? {}; keys(t, ['serverName', 'allowInsecure', 'fingerprint', 'alpn', 'publicKey', 'shortId', 'spiderX']);
  if (t.spiderX && t.spiderX !== '/') throw new Error('暂不支持该 Reality spiderX 参数');
  const ws = st.wsSettings ?? {}; keys(ws, ['path', 'headers']);
  const g = st.grpcSettings ?? {}; keys(g, ['serviceName']);
  const x = st.xhttpSettings ?? {}; keys(x, ['path', 'host', 'mode']);
  return normalizeExternal({ name: v.tag || `${server.address}:${server.port}`, protocol: protocol(v.protocol), host: server.address, port: server.port,
    uuid: user.id, password: server.password ?? user.password, username: user.user, method: server.method, flow: user.flow, cipher: user.security, alterId: user.alterId,
    security: st.security, sni: t.serverName, insecure: bool(t.allowInsecure), fingerprint: t.fingerprint, alpn: t.alpn,
    publicKey: t.publicKey, shortId: t.shortId, transport: st.network === 'raw' ? 'tcp' : st.network,
    path: x.path ?? ws.path, headers: x.host ? { Host: x.host } : ws.headers, serviceName: g.serviceName, mode: x.mode });
}

function vmess(v: Obj): ExternalNode {
  keys(v, ['v', 'ps', 'add', 'port', 'id', 'aid', 'scy', 'net', 'type', 'host', 'path', 'tls', 'sni', 'alpn', 'fp', 'allowInsecure']);
  if (v.type && v.type !== 'none') throw new Error('暂不支持该 VMess 伪装参数');
  return normalizeExternal({ name: v.ps || `${v.add}:${v.port}`, protocol: 'vmess', host: v.add, port: v.port, uuid: v.id,
    alterId: v.aid, cipher: v.scy, security: v.tls === 'tls' ? 'tls' : 'none', sni: v.sni || v.host || v.add,
    insecure: bool(v.allowInsecure), fingerprint: v.fp, alpn: typeof v.alpn === 'string' ? v.alpn.split(',').filter(Boolean) : v.alpn,
    transport: v.net, path: v.net === 'grpc' ? '' : v.path, serviceName: v.net === 'grpc' ? v.path : '', headers: v.net === 'ws' && v.host ? { Host: v.host } : {} });
}

function uri(line: string): ExternalNode {
  const scheme = /^([a-z0-9]+):\/\//i.exec(line)?.[1].toLowerCase();
  if (!scheme) throw new Error('无法识别节点链接');
  if (scheme === 'vmess') return vmess(obj(JSON.parse(b64(line.slice(8)))));
  if (scheme === 'ss') {
    const [body, fragment = ''] = line.slice(5).split('#');
    if (!body.includes('@')) return uri(`ss://${b64(body)}#${fragment}`);
    const at = body.lastIndexOf('@');
    const auth = body.slice(0, at).includes(':') ? decodeURIComponent(body.slice(0, at)) : b64(decodeURIComponent(body.slice(0, at)));
    const colon = auth.indexOf(':');
    if (colon < 1) throw new Error('SS 认证格式无效');
    const target = new URL(`ss://${body.slice(at + 1)}`);
    if (target.search) throw new Error('SS 链接含暂不支持的参数');
    return normalizeExternal({ name: decodeURIComponent(fragment) || target.hostname, protocol: 'shadowsocks', host: target.hostname.replace(/^\[|\]$/g, ''),
      port: target.port, method: auth.slice(0, colon), password: auth.slice(colon + 1) });
  }
  const url = new URL(line), q = Object.fromEntries(url.searchParams);
  keys(q, ['security', 'type', 'encryption', 'sni', 'peer', 'allowInsecure', 'insecure', 'allow_insecure', 'fp', 'pbk', 'sid', 'flow',
    'path', 'host', 'serviceName', 'alpn', 'obfs', 'obfs-password', 'congestion_control', 'udp_relay_mode', 'mode', 'headerType', 'spx']);
  if (q.encryption && q.encryption !== 'none') throw new Error('暂不支持该 VLESS 加密参数');
  if (q.headerType && q.headerType !== 'none') throw new Error('暂不支持该传输伪装参数');
  if (q.spx && q.spx !== '/') throw new Error('暂不支持该 Reality spiderX 参数');
  const p = protocol(scheme), user = decodeURIComponent(url.username), pass = decodeURIComponent(url.password);
  return normalizeExternal({ name: decodeURIComponent(url.hash.slice(1)) || url.hostname, protocol: p, host: url.hostname.replace(/^\[|\]$/g, ''),
    port: url.port || (scheme === 'https' ? 443 : scheme === 'http' ? 80 : undefined),
    uuid: ['vless', 'tuic'].includes(p) ? user : undefined,
    password: ['trojan', 'hysteria2', 'anytls'].includes(p) ? user + (pass ? ':' + pass : '') : pass || undefined,
    username: ['socks5', 'http'].includes(p) ? user || undefined : undefined,
    security: q.security || (['trojan', 'hysteria2', 'tuic', 'anytls'].includes(p) || scheme === 'https' ? 'tls' : 'none'),
    sni: q.sni || q.peer, insecure: bool(q.allowInsecure ?? q.insecure ?? q.allow_insecure), fingerprint: q.fp,
    publicKey: q.pbk, shortId: q.sid, flow: q.flow, transport: q.type === 'raw' ? 'tcp' : q.type,
    path: q.path, headers: q.host ? { Host: q.host } : {}, serviceName: q.serviceName, alpn: q.alpn?.split(',').filter(Boolean),
    obfs: q.obfs, obfsPassword: q['obfs-password'], congestion: q.congestion_control, udpRelayMode: q.udp_relay_mode, mode: q.mode });
}

/** Never return parser error messages from third-party libraries: they may contain passwords/source lines. */
export function parseExternalInput(content: string): ParsedExternal[] {
  let text = content.trim().replace(/^\uFEFF/, '');
  if (!text || Buffer.byteLength(text) > 512_000) throw new Error('导入内容为空或超过 500 KB');
  if (!text.includes('://') && /^[A-Za-z0-9+/_=\s-]+$/.test(text)) text = b64(text.replace(/\s/g, ''));
  let entries: unknown[];
  if (/^[a-z0-9]+:\/\//i.test(text)) entries = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  else {
    let document: unknown;
    try {
      const doc = parseDocument(text, { schema: 'core', uniqueKeys: true });
      if (doc.errors.length) throw new Error();
      document = doc.toJS({ maxAliasCount: 20 });
    } catch { throw new Error('YAML/JSON 格式无效，或包含不支持的引用'); }
    const root = Array.isArray(document) ? document : obj(document);
    entries = Array.isArray(root) ? root : Array.isArray(root.proxies) ? root.proxies : Array.isArray(root.outbounds) ? root.outbounds : [root];
  }
  if (!entries.length || entries.length > 500) throw new Error('每次请导入 1–500 个节点');
  return entries.map((entry, index) => {
    try {
      let node: ExternalNode;
      if (typeof entry === 'string') node = uri(entry);
      else {
        const v = obj(entry);
        node = v.protocol ? xray(v) : v.server_port !== undefined ? singbox(v) : clash(v);
      }
      return { index, node };
    } catch (err) {
      const safe = err instanceof Error && /^(节点|SS |Reality |含暂不支持|暂不支持|无法识别|布尔参数|请提供)/.test(err.message);
      return { index, error: safe ? (err as Error).message : '节点格式无效，请检查协议、地址、端口及认证参数' };
    }
  });
}
