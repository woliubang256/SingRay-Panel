import { isIP } from 'node:net';

export interface InboundPort {
  port: number;
  protocol: 'tcp' | 'udp';
  family: 'ipv4' | 'ipv6' | 'dual';
}

/** Use rendered, enabled inbounds, including shared landing ports. UDP carried
 * inside Trojan/VLESS is not a separate UDP listener. Loopback APIs stay private. */
export function inboundPorts(core: 'singbox' | 'xray', config: Record<string, any>): InboundPort[] {
  const ports: InboundPort[] = [];
  for (const inbound of config.inbounds ?? []) {
    const listen = String(inbound.listen ?? (core === 'xray' ? '0.0.0.0' : '::')).toLowerCase();
    if (listen === 'localhost' || listen === '::1' || /^127\./.test(listen) || /^::ffff:127\./.test(listen)) continue;
    const port = core === 'xray' ? inbound.port : inbound.listen_port;
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('防火墙入站端口不合法');
    const family: InboundPort['family'] = listen === '::' || listen === '' ? 'dual' : isIP(listen) === 6 ? 'ipv6' : 'ipv4';
    const type = core === 'xray' ? inbound.protocol : inbound.type;
    let protocols: InboundPort['protocol'][];
    if (core === 'singbox') {
      if (['hysteria', 'hysteria2', 'tuic'].includes(type)) protocols = ['udp'];
      else if (['shadowsocks', 'socks', 'mixed', 'naive', 'direct'].includes(type)) {
        protocols = inbound.network === 'tcp' ? ['tcp'] : inbound.network === 'udp' ? ['udp'] : ['tcp', 'udp'];
      } else if (['vless', 'vmess', 'trojan', 'http', 'shadowtls', 'anytls'].includes(type)) protocols = ['tcp'];
      else throw new Error('无法确定该 sing-box 入站需要的防火墙协议');
    } else if (type === 'shadowsocks') {
      const network = inbound.settings?.network;
      protocols = network === 'tcp' ? ['tcp'] : network === 'udp' ? ['udp'] : ['tcp', 'udp'];
    } else if (type === 'socks') protocols = inbound.settings?.udp ? ['tcp', 'udp'] : ['tcp'];
    else if (['vless', 'vmess', 'trojan', 'http'].includes(type)) protocols = ['tcp'];
    else throw new Error('无法确定该 Xray 入站需要的防火墙协议');
    for (const protocol of protocols) ports.push({ port, protocol, family });
  }
  return [...new Map(ports.map(port => [`${port.port}/${port.protocol}/${port.family}`, port])).values()];
}
