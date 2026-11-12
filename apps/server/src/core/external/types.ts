import { z } from 'zod';

export const externalSchema = z.object({
  name: z.string().trim().min(1).max(200),
  protocol: z.enum(['vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'tuic', 'anytls', 'socks5', 'http']),
  host: z.string().min(1).max(253).refine(v => !/[\s/@?#\\]/.test(v)),
  port: z.coerce.number().int().min(1).max(65535),
  uuid: z.string().optional(), password: z.string().optional(), username: z.string().optional(), method: z.string().optional(),
  flow: z.string().default(''), cipher: z.string().default('auto'), alterId: z.coerce.number().int().min(0).default(0),
  security: z.enum(['none', 'tls', 'reality']).default('none'),
  sni: z.string().max(253).default(''), insecure: z.boolean().default(false),
  fingerprint: z.string().default(''), alpn: z.array(z.string()).default([]),
  publicKey: z.string().default(''), shortId: z.string().default(''),
  transport: z.enum(['tcp', 'ws', 'grpc', 'xhttp']).default('tcp'),
  path: z.string().default(''), headers: z.record(z.string(), z.string()).default({}), serviceName: z.string().default(''),
  mode: z.string().default('auto'),
  obfs: z.string().default(''), obfsPassword: z.string().default(''),
  congestion: z.string().default('cubic'), udpRelayMode: z.string().default('native'),
  udp: z.boolean().default(true),
});

export type ExternalNode = z.infer<typeof externalSchema>;
export type ExternalFormat = 'base64' | 'singbox' | 'clash';
export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

export function normalizeExternal(value: unknown): ExternalNode {
  const parsed = externalSchema.safeParse(value);
  if (!parsed.success) throw new Error(`节点字段无效：${parsed.error.issues[0]?.path.join('.') || '格式'}`);
  const n = parsed.data;
  const hostHeaders = Object.entries(n.headers).filter(([k]) => k.toLowerCase() === 'host');
  if (hostHeaders.length > 1) throw new Error('暂不支持重复的 Host 请求头');
  if (hostHeaders.length) {
    delete n.headers[hostHeaders[0][0]];
    n.headers.Host = hostHeaders[0][1];
  }
  if (['vless', 'vmess', 'tuic'].includes(n.protocol) && !n.uuid) throw new Error('节点缺少 UUID');
  if (['trojan', 'shadowsocks', 'hysteria2', 'tuic', 'anytls'].includes(n.protocol) && !n.password) throw new Error('节点缺少密码');
  if (n.protocol === 'shadowsocks' && !n.method) throw new Error('SS 节点缺少加密方式');
  if (n.security === 'reality' && !n.publicKey) throw new Error('Reality 节点缺少公钥');
  if (n.transport !== 'tcp' && !['vless', 'vmess', 'trojan'].includes(n.protocol)) throw new Error('暂不支持该协议的传输组合');
  if (n.flow && (n.protocol !== 'vless' || n.transport !== 'tcp')) throw new Error('暂不支持该 Flow 与传输组合');
  if (n.security === 'reality' && n.protocol !== 'vless') throw new Error('暂不支持该协议的 Reality 组合');
  if (n.obfs && (n.protocol !== 'hysteria2' || n.obfs !== 'salamander' || !n.obfsPassword)) throw new Error('暂不支持该混淆参数组合');
  if (!compatibleFormats(n).length) throw new Error('暂不支持该参数组合的订阅输出');
  return n;
}

export function compatibleFormats(n: ExternalNode): ExternalFormat[] {
  const link = n.udp && Object.keys(n.headers).every(k => k.toLowerCase() === 'host');
  return [...(link ? ['base64' as const] : []), ...(n.transport === 'xhttp' ? [] : ['singbox' as const, 'clash' as const])];
}
