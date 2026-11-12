import { describe, it, expect } from 'vitest';
import { toClashYaml, clashProxy } from './clash.js';
import type { NodeView } from './index.js';
import { parse } from 'yaml';
import { normalizeExternal } from '../external/types.js';

const vlessReality: NodeView = {
  id: 1, name: 'Dedirock-vless-reality-xray', protocol: 'vless', host: 'dedirocks.1o1.top', port: 49464,
  sni: 'dl.google.com', ws_path: '', realityPublicKey: 'PBK123', shortId: 'abcd1234',
  creds: { uuid: 'u-1', flow: 'xtls-rprx-vision' },
};
const vmess: NodeView = { ...vlessReality, id: 2, name: 'Dedirock-vmess-ws-tls-xray', protocol: 'vmess', ws_path: '/ws-x', realityPublicKey: null, creds: { uuid: 'u-2' } };
const ss: NodeView = { ...vlessReality, id: 3, name: 'Dedirock-shadowsocks-xray', protocol: 'shadowsocks', realityPublicKey: null, creds: { method: 'aes-128-gcm', password: 'p+/=' } };

describe('clash/mihomo subscription', () => {
  it('vless reality proxy maps reality-opts + flow + fingerprint', () => {
    const p = clashProxy(vlessReality)!;
    expect(p.type).toBe('vless');
    expect(p['reality-opts']).toEqual({ 'public-key': 'PBK123', 'short-id': 'abcd1234' });
    expect(p.flow).toBe('xtls-rprx-vision');
    expect(p['client-fingerprint']).toBe('chrome');
  });

  it('yaml output is structurally valid (key lines + quoting survives special chars)', () => {
    const yaml = toClashYaml([vlessReality, vmess, ss]);
    expect(yaml).toContain('- name: "Dedirock-vless-reality-xray"');
    expect(yaml).toContain('type: "vless"');
    expect(yaml).toContain('public-key: "PBK123"');
    expect(yaml).toContain('proxy-groups:');
    expect(yaml).toContain('MATCH,PROXY');
    // ss 密码含 +/= 特殊字符 → 双引号包裹
    expect(yaml).toContain('password: "p+/="');
  });

  it('keeps hysteria nodes (protocol name is hysteria, mihomo type is hysteria2)', () => {
    const hy = { ...ss, id: 9, name: 'HY-1', protocol: 'hysteria', creds: { password: 'pw-hy' } } as NodeView;
    const p = clashProxy(hy)!;
    expect(p.type).toBe('hysteria2');
    expect(p.password).toBe('pw-hy');
    expect(toClashYaml([hy])).toContain('type: "hysteria2"');
  });

  it('quotes custom header names that have YAML meaning', () => {
    const external = normalizeExternal({ name: 'custom headers', protocol: 'vless', host: 'example.com', port: 443,
      uuid: 'u-1', security: 'tls', transport: 'ws', headers: { '!custom': 'value', 'X-Note: detail': 'quoted' } });
    const yaml = toClashYaml([{ ...vlessReality, name: external.name, external }]);
    expect(parse(yaml).proxies[0]['ws-opts'].headers).toEqual(external.headers);
  });

  it('retains an empty WS header object', () => {
    const external = normalizeExternal({ name: 'plain WS', protocol: 'vless', host: 'example.com', port: 443,
      uuid: 'u-1', transport: 'ws' });
    expect(parse(toClashYaml([{ ...vlessReality, name: external.name, external }])).proxies[0]['ws-opts'].headers).toEqual({});
  });

  it('skips unsupported protocols (naive/tunnel/shadowtls)', () => {
    const yaml = toClashYaml([{ ...ss, name: 'n1', protocol: 'naive' }, { ...ss, name: 'n2', protocol: 'tunnel' }]);
    expect(yaml).not.toContain('n1');
    expect(yaml).not.toContain('n2');
    expect(toClashYaml([{ ...ss, name: 'ok', protocol: 'shadowsocks' }])).toContain('type: "ss"');
  });
});
