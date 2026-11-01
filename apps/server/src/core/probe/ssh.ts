// TLS runs in the panel, over an SSH forward to the server's loopback listener.
// No remote openssl/python dependency, no proxy password sent by this probe.
import tls from 'node:tls';
import type { Client } from 'ssh2';
import type { Duplex } from 'node:stream';
import { connectClient, type SshConn } from '../ssh/executor.js';

export interface LocalProbeResult {
  status: 'ok' | 'error' | 'unavailable';
  detail: string;
}

export function probeLocalNode(
  conn: SshConn,
  target: { port: number; mode: 'tcp' | 'tls'; sni?: string; timeoutMs?: number; host?: '127.0.0.1' | '::1' },
): Promise<LocalProbeResult> {
  return new Promise(resolve => {
    let settled = false;
    let connected = false;
    let client: Client | undefined;
    let stream: Duplex | undefined;
    let secure: tls.TLSSocket | undefined;
    const mode = target.mode === 'tls' ? 'TLS' : 'TCP';
    const finish = (status: LocalProbeResult['status'], detail: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      secure?.destroy();
      stream?.destroy();
      client?.end();
      resolve({ status, detail });
    };
    const timer = setTimeout(() => finish(connected ? 'error' : 'unavailable',
      connected ? `本机 ${mode} 探测超时` : 'SSH 连接或本机隧道超时，无法判断本机服务'), target.timeoutMs ?? 15_000);
    void connectClient(conn).then(c => {
      if (settled) { c.end(); return; }
      client = c;
      c.on('error', () => finish('unavailable', 'SSH 连接中断，无法完成本机探测'));
      c.on('close', () => finish('unavailable', 'SSH 连接关闭，无法完成本机探测'));
      c.forwardOut('127.0.0.1', 0, target.host ?? '127.0.0.1', target.port, (err, channel) => {
        if (settled) { channel?.destroy(); return; }
        if (err) {
          const refused = /connection refused/i.test(err.message);
          finish(refused ? 'error' : 'unavailable', refused ? '本机端口拒绝连接' : 'SSH 本机隧道不可用，请检查 SSH 转发权限');
          return;
        }
        connected = true;
        stream = channel;
        channel.on('error', () => finish('error', `本机 ${mode} 连接异常断开`));
        if (target.mode === 'tcp') { finish('ok', '本机 TCP 端口可连接'); return; }
        try {
          secure = tls.connect({ socket: channel, servername: target.sni || undefined, rejectUnauthorized: false });
          secure.on('secureConnect', () => finish('ok', `本机 TLS 握手成功（${secure?.getProtocol() ?? 'TLS'}，未校验证书信任）`));
          secure.on('error', () => finish('error', '本机 TLS 握手失败，请检查运行配置、证书及服务日志摘要'));
          secure.on('end', () => finish('error', '本机 TLS 握手完成前连接被关闭'));
          secure.on('close', () => finish('error', '本机 TLS 握手完成前连接被关闭'));
        } catch {
          finish('error', '无法开始本机 TLS 握手');
        }
      });
    }).catch(() => finish('unavailable', 'SSH 连接失败，无法完成本机探测'));
  });
}
