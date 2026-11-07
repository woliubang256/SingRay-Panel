import { describe, expect, it } from 'vitest';
import { parseProxyUrl } from './proxy.js';
import { buildMachineConfig } from './singbox/index.js';
import { buildXrayConfig } from './xray/index.js';
import type { MachineCtx, SingboxNodeRow } from './types.js';
import type { XrayNodeRow } from './xray/index.js';

describe('proxy URL parsing', () => {
  it.each([
    ['socks5://user:p%40ss%3Aword@[2001:db8::1]:5678', { protocol: 'socks5', host: '2001:db8::1', port: 5678, username: 'user', password: 'p@ss:word' }],
    [' http://proxy.example.com:8080 ', { protocol: 'http', host: 'proxy.example.com', port: 8080 }],
    ['http://1.2.3.4:80', { protocol: 'http', host: '1.2.3.4', port: 80 }],
    ['socks5://proxy.example.com', { protocol: 'socks5', host: 'proxy.example.com', port: 1080 }],
  ])('parses %s', (url, endpoint) => expect(parseProxyUrl(url)).toMatchObject(endpoint));

  it.each(['', '1.2.3.4:8080', 'https://proxy:443', 'socks://proxy:1080', 'http://', 'socks5://x:0', 'socks5://x:65536', 'socks5://x:bad', 'http://x:80/path', 'http://x?secret=x', 'http://x#x', 'socks5://user:%xx@x:1080', 'socks5://:pass@x:1080', 'socks5://bad host:1080', 'http://user:secret@x:8080/path'])('rejects invalid URLs without leaking credentials: %s', url => {
    expect(() => parseProxyUrl(url)).toThrow(/代理链接/);
    try { parseProxyUrl(url); } catch (err) { expect((err as Error).message).not.toContain('secret'); }
  });
});

const machine: MachineCtx = { id: 1, name: 'entry', role: 'relay', host: '10.0.0.1' };
const base = { name: 'node', server_id: 1, protocol: 'socks', enabled: 1, creds: { username: 'inbound', password: 'pw' }, tls_mode: 'none', sni: '', transport: 'raw', ws_path: '', flow: '', note: '', tunnel_address: '', tunnel_port: null, landing_server_id: null } as const;
const nodes = [
  { ...base, id: 1, listen_port: 30001, outbound_type: 'direct' },
  { ...base, id: 2, listen_port: 30002, outbound_type: 'proxy', proxy_url: 'socks5://user:p%40ss@[2001:db8::1]:5678' },
  { ...base, id: 3, listen_port: 30003, outbound_type: 'proxy', proxy_url: 'http://proxy.example.com:8080' },
  { ...base, id: 4, listen_port: 30004, outbound_type: 'relay', landing_server_id: 2 },
  { ...base, id: 5, listen_port: 30005, outbound_type: 'proxy', proxy_url: 'invalid', enabled: 0 },
] as (SingboxNodeRow & XrayNodeRow)[];
const landings = { 2: { host: 'landing.example.com', in_port: 32002, method: 'aes-128-gcm', password: 'relay-password' } };

describe('proxy outbound config generation', () => {
  it('sing-box isolates SOCKS5, HTTP, relay and direct nodes and skips disabled nodes', () => {
    const cfg = buildMachineConfig({ machine, nodes, landings });
    expect(cfg.outbounds).toEqual([
      { type: 'direct', tag: 'direct' },
      { type: 'socks', tag: 'proxy-2', server: '2001:db8::1', server_port: 5678, version: '5', username: 'user', password: 'p@ss' },
      { type: 'http', tag: 'proxy-3', server: 'proxy.example.com', server_port: 8080 },
      { type: 'shadowsocks', tag: 'landing-4', server: 'landing.example.com', server_port: 32002, method: 'aes-128-gcm', password: 'relay-password' },
    ]);
    expect(cfg.route).toEqual({ final: 'direct', rules: [
      { inbound: ['relay-in-30002'], outbound: 'proxy-2' },
      { inbound: ['relay-in-30003'], outbound: 'proxy-3' },
      { inbound: ['relay-in-30004'], outbound: 'landing-4' },
    ] });
  });

  it('Xray emits the correct server authentication and per-inbound routing', () => {
    const cfg = buildXrayConfig({ machine, nodes, landings });
    expect(cfg.outbounds).toEqual([
      { protocol: 'freedom', tag: 'direct' },
      { protocol: 'socks', tag: 'proxy-2', settings: { servers: [{ address: '2001:db8::1', port: 5678, users: [{ user: 'user', pass: 'p@ss' }] }] } },
      { protocol: 'http', tag: 'proxy-3', settings: { servers: [{ address: 'proxy.example.com', port: 8080 }] } },
      { protocol: 'shadowsocks', tag: 'landing-4', settings: { servers: [{ address: 'landing.example.com', port: 32002, method: 'aes-128-gcm', password: 'relay-password' }] } },
    ]);
    expect(cfg.routing).toMatchObject({ rules: [
      { type: 'field', inboundTag: ['relay-in-30002'], outboundTag: 'proxy-2' },
      { type: 'field', inboundTag: ['relay-in-30003'], outboundTag: 'proxy-3' },
      { type: 'field', inboundTag: ['relay-in-30004'], outboundTag: 'landing-4' },
      { type: 'field', inboundTag: ['api-in'], outboundTag: 'api' },
    ] });
  });

  it.each(['', 'http://x:0', 'https://x:443'])('fails config generation for invalid active proxy URLs: %s', proxy_url => {
    const active = [{ ...nodes[1], proxy_url }];
    expect(() => buildMachineConfig({ machine, nodes: active, landings })).toThrow(/代理链接/);
    expect(() => buildXrayConfig({ machine, nodes: active, landings })).toThrow(/代理链接/);
  });
});
