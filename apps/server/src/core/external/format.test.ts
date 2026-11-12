import { describe, it, expect } from 'vitest';
import { parseExternalInput } from './parse.js';
import { externalClash, externalShareLink, externalSingbox } from './format.js';
import { compatibleFormats } from './types.js';

describe('external subscription conversion', () => {
  const parse = (s: string) => parseExternalInput(s)[0].node!;
  it('preserves TLS verification, WS Host and path across all formats', () => {
    const n = parse('vless://uuid@example.com:443?security=tls&type=ws&host=cdn.example&path=%2Fws&sni=tls.example#N');
    expect(externalClash(n)).toMatchObject({ tls: true, 'skip-cert-verify': false, network: 'ws', 'ws-opts': { path: '/ws', headers: { Host: 'cdn.example' } } });
    expect(externalSingbox(n)).toMatchObject({ tls: { enabled: true, insecure: false }, transport: { type: 'ws', path: '/ws', headers: { Host: 'cdn.example' } } });
    expect(parse(externalShareLink(n)!)).toEqual(n);
    const lower = parse(JSON.stringify({ name: 'lower', type: 'vless', server: 'example.com', port: 443, uuid: 'uuid', tls: true,
      network: 'ws', 'ws-opts': { path: '/ws', headers: { host: 'cdn.example' } } }));
    expect(parse(externalShareLink(lower)!)).toHaveProperty('headers.Host', 'cdn.example');
  });
  it('does not turn plain VLESS into TLS/Reality and retains Reality flow', () => {
    const plain = parse('vless://uuid@example.com:80?security=none#P');
    expect(externalClash(plain)).toMatchObject({ tls: false });
    expect(externalSingbox(plain)).not.toHaveProperty('tls');
    const reality = parse('vless://uuid@example.com:443?security=reality&pbk=pub&sid=ab&sni=sni.example&fp=chrome&flow=xtls-rprx-vision#R');
    expect(externalClash(reality)).toMatchObject({ flow: 'xtls-rprx-vision', 'reality-opts': { 'public-key': 'pub', 'short-id': 'ab' } });
    expect(externalSingbox(reality)).toMatchObject({ flow: 'xtls-rprx-vision', tls: { reality: { enabled: true, public_key: 'pub', short_id: 'ab' } } });
    expect(parse(externalShareLink(reality)!)).toEqual(reality);
  });
  it('retains Hysteria2 obfs, TUIC credentials, IPv6 and renamed labels', () => {
    const hy = parse('hy2://p%40ss@[2001:db8::1]:443?sni=tls.example&obfs=salamander&obfs-password=op#HY');
    expect(parse(externalShareLink(hy)!)).toEqual(hy);
    expect(externalClash(hy)).toMatchObject({ obfs: 'salamander', 'obfs-password': 'op', 'skip-cert-verify': false });
    const tuic = parse('tuic://uuid:pw@example.com:443?alpn=h3&congestion_control=bbr#TUIC');
    expect(externalSingbox(tuic)).toMatchObject({ type: 'tuic', uuid: 'uuid', password: 'pw', congestion_control: 'bbr', tls: { alpn: ['h3'] } });
    expect(parse(externalShareLink({ ...tuic, name: '新名称' })!).name).toBe('新名称');
  });
  it('reports formats that cannot preserve transport/header options', () => {
    const x = parse('vless://uuid@example.com:443?security=tls&type=xhttp&path=%2Fx#X');
    expect(compatibleFormats(x)).toEqual(['base64']);
    expect(externalClash(x)).toBeNull(); expect(externalSingbox(x)).toBeNull();
    const ws = { ...x, transport: 'ws' as const, headers: { Authorization: 'custom' } };
    expect(compatibleFormats(ws)).toEqual(['singbox', 'clash']);
    expect(externalShareLink(ws)).toBeNull();
    const restricted = { ...ws, headers: {}, udp: false };
    expect(compatibleFormats(restricted)).not.toContain('base64');
    expect(externalSingbox(restricted)).toHaveProperty('network', 'tcp');
  });
});
