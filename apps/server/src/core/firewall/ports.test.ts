import { describe, expect, it } from 'vitest';
import { inboundPorts } from './ports.js';

describe('externally listening firewall ports', () => {
  it('opens Trojan TCP only and excludes the loopback Xray statistics API', () => {
    expect(inboundPorts('xray', { inbounds: [
      { protocol: 'trojan', listen: '0.0.0.0', port: 31250 },
      { protocol: 'dokodemo-door', listen: '127.0.0.1', port: 18482 },
      { protocol: 'http', listen: '::1', port: 8080 },
    ] })).toEqual([{ port: 31250, protocol: 'tcp', family: 'ipv4' }]);
  });
  it('opens QUIC UDP and shadowsocks TCP/UDP, including shared landing inbounds', () => {
    expect(inboundPorts('singbox', { inbounds: [
      { type: 'hysteria2', listen: '::', listen_port: 24000 },
      { type: 'tuic', listen: '::', listen_port: 24001 },
      { type: 'shadowsocks', listen: '::', listen_port: 24002 },
    ] })).toEqual([
      { port: 24000, protocol: 'udp', family: 'dual' }, { port: 24001, protocol: 'udp', family: 'dual' },
      { port: 24002, protocol: 'tcp', family: 'dual' }, { port: 24002, protocol: 'udp', family: 'dual' },
    ]);
  });
  it('honors an explicitly TCP-only direct tunnel and Xray SOCKS UDP setting', () => {
    expect(inboundPorts('singbox', { inbounds: [{ type: 'direct', listen: '::', listen_port: 8443, network: 'tcp' }] }))
      .toEqual([{ port: 8443, protocol: 'tcp', family: 'dual' }]);
    expect(inboundPorts('xray', { inbounds: [{ protocol: 'socks', listen: '0.0.0.0', port: 1080, settings: { udp: true } }] }))
      .toHaveLength(2);
  });
  it('deduplicates aliases sharing one inbound and rejects invalid ports before any shell command', () => {
    const inbound = { type: 'trojan', listen: '::', listen_port: 443 };
    expect(inboundPorts('singbox', { inbounds: [inbound, inbound] })).toHaveLength(1);
    expect(() => inboundPorts('singbox', { inbounds: [{ ...inbound, listen_port: '443;reboot' }] })).toThrow('端口');
  });
});
