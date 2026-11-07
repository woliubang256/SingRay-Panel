import tls from 'node:tls';
import type { Duplex } from 'node:stream';
import type { Client } from 'ssh2';
import type { ProxyEndpoint } from '../configgen/proxy.js';
import { connectClient, type SshConn } from '../ssh/executor.js';
import type { LocalProbeResult } from './ssh.js';

const probeHost = 'www.gstatic.com';

// Pull exactly the protocol bytes needed, leaving subsequent bytes in the stream.
function readBytes(stream: Duplex, length: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      stream.off('readable', ready); stream.off('error', failed);
      stream.off('end', failed); stream.off('close', failed);
    };
    const failed = () => { cleanup(); reject(new Error('closed or truncated')); };
    const ready = () => {
      const data = stream.read(length) as Buffer | null;
      if (data) {
        if (data.length !== length) { failed(); return; }
        cleanup(); resolve(data);
      } else if (stream.destroyed || stream.readableEnded) failed();
    };
    // Keep the listener attached while waiting for a full frame. Reattaching it
    // on each partial read can repeatedly emit 'readable' and starve the timer.
    stream.on('readable', ready); stream.once('error', failed);
    stream.once('end', failed); stream.once('close', failed);
    ready();
  });
}

async function readHeaders(stream: Duplex): Promise<string> {
  const bytes: number[] = [];
  while (bytes.length < 16_384) {
    bytes.push((await readBytes(stream, 1))[0]);
    if (bytes.length >= 4 && bytes.slice(-4).join(',') === '13,10,13,10') return Buffer.from(bytes).toString('latin1');
  }
  throw new Error('oversized headers');
}

/** Validate the upstream from the node's network, including authentication and a
 * certificate-verified HTTPS response. Credentials never enter shell commands or results. */
export function probeOutboundProxy(
  conn: SshConn,
  proxy: ProxyEndpoint,
  options: { timeoutMs?: number } = {},
): Promise<LocalProbeResult> {
  return new Promise(resolve => {
    let settled = false;
    let sshReady = false;
    let client: Client | undefined;
    let stream: Duplex | undefined;
    let secure: tls.TLSSocket | undefined;
    let failure = '出口代理连接失败，请检查代理地址、端口、DNS 和网络';
    const finish = (status: LocalProbeResult['status'], detail: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      secure?.destroy(); stream?.destroy(); client?.end();
      resolve({ status, detail });
    };
    const timer = setTimeout(() => finish(sshReady ? 'error' : 'unavailable', sshReady
      ? `${failure}（探测超时）` : 'SSH 连接超时，未验证出口代理'), options.timeoutMs ?? 15_000);

    const negotiate = async (channel: Duplex) => {
      if (proxy.protocol === 'http') {
        failure = 'HTTP 代理握手失败，请检查代理协议及连接';
        const auth = proxy.username === undefined ? ''
          : `Proxy-Authorization: Basic ${Buffer.from(`${proxy.username}:${proxy.password ?? ''}`).toString('base64')}\r\n`;
        channel.write(`CONNECT ${probeHost}:443 HTTP/1.1\r\nHost: ${probeHost}:443\r\n${auth}\r\n`);
        const response = await readHeaders(channel);
        const code = Number(/^HTTP\/1\.[01] (\d{3})(?: |\r)/.exec(response)?.[1]);
        if (code === 407) { finish('error', 'HTTP 出口代理认证失败，请检查用户名和密码'); return; }
        if (code !== 200) { finish('error', 'HTTP 出口代理无法建立检测目标连接，请检查代理权限及网络'); return; }
      } else {
        failure = 'SOCKS5 代理握手失败，请检查代理协议及连接';
        const method = proxy.username === undefined ? 0 : 2;
        channel.write(Buffer.from([5, 1, method]));
        const greeting = await readBytes(channel, 2);
        if (greeting[0] !== 5 || greeting[1] !== method) {
          finish('error', 'SOCKS5 出口代理认证方式不匹配或不受支持，请检查用户名和密码'); return;
        }
        if (method === 2) {
          failure = 'SOCKS5 出口代理认证失败，请检查用户名和密码';
          const user = Buffer.from(proxy.username!);
          const pass = Buffer.from(proxy.password ?? '');
          if (user.length > 255 || pass.length > 255) { finish('error', 'SOCKS5 代理用户名或密码超过 255 字节'); return; }
          channel.write(Buffer.concat([Buffer.from([1, user.length]), user, Buffer.from([pass.length]), pass]));
          const auth = await readBytes(channel, 2);
          if (auth[0] !== 1 || auth[1] !== 0) { finish('error', failure); return; }
        }
        failure = 'SOCKS5 出口代理无法连接检测目标，请检查代理权限、DNS 及网络';
        const host = Buffer.from(probeHost);
        channel.write(Buffer.concat([Buffer.from([5, 1, 0, 3, host.length]), host, Buffer.from([1, 187])]));
        const response = await readBytes(channel, 4);
        if (response[0] !== 5 || response[1] !== 0 || response[2] !== 0) { finish('error', failure); return; }
        const length = response[3] === 1 ? 4 : response[3] === 4 ? 16
          : response[3] === 3 ? (await readBytes(channel, 1))[0] : 0;
        if (!length) { finish('error', failure); return; }
        await readBytes(channel, length + 2);
      }
      if (settled) return;
      failure = '出口代理隧道已建立，但检测目标 TLS 验证失败或连接中断';
      secure = tls.connect({ socket: channel, servername: probeHost, rejectUnauthorized: true });
      secure.on('error', () => finish('error', failure));
      await new Promise<void>((resolve, reject) => {
        secure!.once('secureConnect', resolve);
        secure!.once('error', reject);
        secure!.once('close', () => reject(new Error('closed')));
      });
      if (settled) return;
      failure = '出口代理隧道已建立，但 HTTPS 检测目标访问失败（www.gstatic.com/generate_204）';
      secure.write(`GET /generate_204 HTTP/1.1\r\nHost: ${probeHost}\r\nConnection: close\r\n\r\n`);
      const response = await readHeaders(secure);
      if (!/^HTTP\/1\.[01] 204(?: |\r)/.test(response)) { finish('error', failure); return; }
      finish('ok', '已从节点机器经出口代理完成认证、TLS 验证及 HTTPS 访问（www.gstatic.com/generate_204）');
    };

    void connectClient(conn).then(c => {
      if (settled) { c.end(); return; }
      client = c; sshReady = true;
      c.on('error', () => finish('unavailable', 'SSH 连接中断，未完成出口代理验证'));
      c.on('close', () => finish('unavailable', 'SSH 连接关闭，未完成出口代理验证'));
      c.forwardOut('127.0.0.1', 0, proxy.host, proxy.port, (err, channel) => {
        if (settled) { channel?.destroy(); return; }
        if (err) {
          const prohibited = /administratively prohibited/i.test(err.message) || (err as Error & { reason?: number }).reason === 1;
          finish(prohibited ? 'unavailable' : 'error', prohibited ? 'SSH 转发权限受限，未验证出口代理' : failure);
          return;
        }
        stream = channel;
        channel.on('error', () => finish('error', failure));
        void negotiate(channel).catch(() => finish('error', failure));
      });
    }).catch(() => finish('unavailable', 'SSH 连接失败，未验证出口代理'));
  });
}
