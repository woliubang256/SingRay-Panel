import { describe, it, expect } from 'vitest';
import { parseExternalInput } from './parse.js';

const uuid = 'c11c19a2-d901-4d32-9865-412d5c774f11';
const link = `vless://${uuid}@example.com:443?security=tls&type=ws&path=%2Fws&host=cdn.example.com&sni=tls.example.com#%E9%A6%99%E6%B8%AF`;
describe('external node import', () => {
  it('retains external TLS verification and WS headers rather than applying panel defaults', () => {
    expect(parseExternalInput(link)[0].node).toMatchObject({ name: '香港', protocol: 'vless', security: 'tls', insecure: false,
      sni: 'tls.example.com', transport: 'ws', path: '/ws', headers: { Host: 'cdn.example.com' } });
  });
  it('handles multiline links, IPv6 and encoded passwords with a separate error per invalid line', () => {
    const rows = parseExternalInput(`trojan://p%40ss%3Aword@[2001:db8::1]:8443?sni=test.example#T\ninvalid\n${link}`);
    expect(rows).toHaveLength(3);
    expect(rows[0].node).toMatchObject({ host: '2001:db8::1', password: 'p@ss:word', security: 'tls' });
    expect(rows[1].error).toBeTruthy(); expect(rows[2].node?.name).toBe('香港');
  });
  it('accepts Clash YAML, JSON lists, sing-box outbounds and Xray outbounds', () => {
    const yaml = `proxies:\n  - name: YAML\n    type: vless\n    server: example.com\n    port: 443\n    uuid: ${uuid}\n    tls: true\n    reality-opts: {public-key: testkey, short-id: abcd}\n    servername: test.example\n`;
    expect(parseExternalInput(yaml)[0].node).toMatchObject({ security: 'reality', publicKey: 'testkey', shortId: 'abcd' });
    const sb = { outbounds: [{ type: 'vless', tag: 'SB', server: 'example.com', server_port: 443, uuid,
      tls: { enabled: true, server_name: 'tls.example', insecure: false }, transport: { type: 'grpc', service_name: 'svc' } }] };
    expect(parseExternalInput(JSON.stringify(sb))[0].node).toMatchObject({ name: 'SB', transport: 'grpc', serviceName: 'svc', insecure: false });
    const xr = { outbounds: [{ tag: 'XR', protocol: 'vless', settings: { vnext: [{ address: 'example.com', port: 443, users: [{ id: uuid, encryption: 'none' }] }] },
      streamSettings: { security: 'tls', network: 'ws', tlsSettings: { serverName: 'tls.example' }, wsSettings: { path: '/test', headers: { Host: 'cdn.example' } } } }] };
    expect(parseExternalInput(JSON.stringify(xr))[0].node).toMatchObject({ name: 'XR', path: '/test', headers: { Host: 'cdn.example' } });
    expect(parseExternalInput(JSON.stringify([{ name: 'ss', type: 'ss', server: 'example.com', port: 80, cipher: 'aes-128-gcm', password: 'secret' }]))[0].node?.method).toBe('aes-128-gcm');
  });
  it('accepts VMess and legacy/SIP002 SS links and QUIC protocols', () => {
    const vmess = Buffer.from(JSON.stringify({ v: '2', ps: 'VM', add: 'vm.example', port: '443', id: uuid, net: 'ws', host: 'cdn.example', path: '/v', tls: 'tls', aid: '0' })).toString('base64');
    expect(parseExternalInput(`vmess://${vmess}`)[0].node).toMatchObject({ protocol: 'vmess', security: 'tls', path: '/v' });
    for (const ss of [`ss://${Buffer.from('aes-128-gcm:p@ss').toString('base64')}@example.com:8388#SS`,
      `ss://${Buffer.from('aes-128-gcm:p@ss@example.com:8388').toString('base64')}#SS`]) {
      expect(parseExternalInput(ss)[0].node).toMatchObject({ protocol: 'shadowsocks', password: 'p@ss', port: 8388 });
    }
    expect(parseExternalInput('hy2://pw@example.com:443?sni=test.example&obfs=salamander&obfs-password=op')[0].node).toMatchObject({ protocol: 'hysteria2', obfsPassword: 'op' });
    expect(parseExternalInput(`tuic://${uuid}:pw@example.com:443?alpn=h3&congestion_control=bbr`)[0].node).toMatchObject({ protocol: 'tuic', alpn: ['h3'], congestion: 'bbr' });
  });
  it('rejects unsupported options without echoing credentials, and rejects malformed documents', () => {
    const rejected = parseExternalInput(`${link}&unknown=1`); // fragment data is still a valid name
    expect(rejected[0].node).toBeDefined();
    const bad = parseExternalInput(`trojan://super-secret@example.com:443?plugin=unsupported`)[0];
    expect(bad.error).toContain('不支持'); expect(bad.error).not.toContain('super-secret');
    expect(() => parseExternalInput('proxies: [')).toThrow(/格式/);
    expect(parseExternalInput('vless://id@example.com:99999')[0].error).toBeTruthy();
    expect(parseExternalInput('proxies: [{name: p, type: ss, server: example.com, port: 80, cipher: aes-128-gcm, password: secret, plugin: obfs}]')[0].error).toContain('不支持');
  });
  it('preserves TCP-only restrictions and rejects transport settings that cannot be retained', () => {
    const sb = { type: 'shadowsocks', tag: 'TCP only', server: 'example.com', server_port: 8388, method: 'aes-128-gcm', password: 'pw', network: 'tcp' };
    expect(parseExternalInput(JSON.stringify(sb))[0].node?.udp).toBe(false);
    expect(parseExternalInput(JSON.stringify({ ...sb, network: 'udp' }))[0].error).toContain('不支持');
    expect(parseExternalInput(JSON.stringify({ ...sb, type: 'vless', uuid, transport: { type: 'ws', path: '/x', max_early_data: 2048 } }))[0].error).toContain('不支持');
  });
});
