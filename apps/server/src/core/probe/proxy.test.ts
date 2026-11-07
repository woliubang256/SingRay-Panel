import { EventEmitter } from 'node:events';
import net from 'node:net';
import tls from 'node:tls';
import type { Duplex } from 'node:stream';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { connectClient } from '../ssh/executor.js';
import { genSelfSignedCert } from '../configgen/cert.js';
import { probeOutboundProxy } from './proxy.js';

vi.mock('../ssh/executor.js', () => ({ connectClient: vi.fn() }));
const conn = { serverId: 1, host: 'node.example.com', sudo: false };
const proxy = { protocol: 'http' as const, host: 'proxy.example.com', port: 8080, username: 'user', password: 'SECRET-PASSWORD' };
const cert = genSelfSignedCert({ commonName: 'probe', altNames: ['www.gstatic.com'] });
let client: EventEmitter & { forwardOut: ReturnType<typeof vi.fn>; end: ReturnType<typeof vi.fn> };
let servers: net.Server[];
let sockets: Set<Duplex>;

beforeEach(() => {
  vi.resetAllMocks();
  servers = []; sockets = new Set();
  client = Object.assign(new EventEmitter(), { end: vi.fn(), forwardOut: vi.fn() });
  vi.mocked(connectClient).mockResolvedValue(client as never);
});
afterEach(async () => {
  vi.restoreAllMocks();
  for (const socket of sockets) socket.destroy();
  await Promise.all(servers.map(server => new Promise<void>(resolve => server.close(() => resolve()))));
});

async function forward(handler: (socket: net.Socket) => void) {
  const server = net.createServer(socket => { sockets.add(socket); handler(socket); });
  servers.push(server);
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  client.forwardOut.mockImplementation((_a, _b, _host, _port, cb) => {
    const socket = net.connect({ host: '127.0.0.1', port: (server.address() as net.AddressInfo).port });
    sockets.add(socket);
    socket.once('connect', () => cb(null, socket));
  });
}

function serveHttps(socket: net.Socket, status = 204) {
  const secure = new tls.TLSSocket(socket, { isServer: true, secureContext: tls.createSecureContext({ key: cert.keyPem, cert: cert.certPem }) });
  sockets.add(secure);
  secure.on('error', () => {});
  secure.once('data', request => {
    expect(request.toString()).toContain('GET /generate_204 HTTP/1.1');
    expect(request.toString()).not.toContain('SECRET-PASSWORD');
    secure.end(`HTTP/1.1 ${status} Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
  });
}

function trustProbeCertificate() {
  const connect = tls.connect;
  return vi.spyOn(tls, 'connect').mockImplementation(((options: tls.ConnectionOptions) =>
    connect({ ...options, ca: cert.certPem })) as typeof tls.connect);
}

describe('outbound proxy validation from the node machine', () => {
  it('fails on HTTP proxy authentication even when its TCP port is reachable', async () => {
    await forward(socket => socket.once('data', request => {
      expect(request.toString()).toContain('CONNECT www.gstatic.com:443 HTTP/1.1');
      expect(request.toString()).toContain(`Proxy-Authorization: Basic ${Buffer.from('user:SECRET-PASSWORD').toString('base64')}`);
      socket.end('HTTP/1.1 407 Proxy Authentication Required\r\nX-Secret: SECRET-PASSWORD\r\n\r\n');
    }));
    const result = await probeOutboundProxy(conn, proxy);
    expect(result).toMatchObject({ status: 'error', detail: expect.stringContaining('认证失败') });
    expect(JSON.stringify(result)).not.toContain('SECRET-PASSWORD');
    expect(client.forwardOut).toHaveBeenCalledWith('127.0.0.1', 0, 'proxy.example.com', 8080, expect.any(Function));
    expect(client.end).toHaveBeenCalled();
  });

  it('fails on SOCKS5 password rejection instead of treating the greeting as success', async () => {
    await forward(socket => socket.once('data', greeting => {
      expect([...greeting]).toEqual([5, 1, 2]);
      socket.write(Buffer.from([5, 2]));
      socket.once('data', auth => {
        expect(auth.includes(Buffer.from('SECRET-PASSWORD'))).toBe(true);
        socket.end(Buffer.from([1, 1]));
      });
    }));
    expect(await probeOutboundProxy(conn, { ...proxy, protocol: 'socks5' })).toMatchObject({ status: 'error', detail: expect.stringContaining('认证失败') });
  });

  it('requires HTTPS access after an authenticated HTTP CONNECT succeeds', async () => {
    const connect = trustProbeCertificate();
    await forward(socket => socket.once('data', () => {
      socket.write('HTTP/1.1 200 Connection established\r\n\r\n');
      serveHttps(socket);
    }));
    expect(await probeOutboundProxy(conn, proxy)).toMatchObject({ status: 'ok' });
    expect(connect).toHaveBeenCalledWith(expect.objectContaining({ servername: 'www.gstatic.com', rejectUnauthorized: true }));
  });

  it('supports fragmented SOCKS5 negotiation, credentials and connect replies before HTTPS', async () => {
    trustProbeCertificate();
    await forward(socket => socket.once('data', () => {
      socket.write(Buffer.from([5]));
      setImmediate(() => socket.write(Buffer.from([2])));
      socket.once('data', () => {
        socket.write(Buffer.from([1, 0]));
        socket.once('data', request => {
          expect(request.subarray(5, -2).toString()).toBe('www.gstatic.com');
          socket.write(Buffer.from([5, 0, 0, 3, 1]));
          setImmediate(() => {
            socket.write(Buffer.from([120, 0, 0]));
            serveHttps(socket);
          });
        });
      });
    }));
    expect(await probeOutboundProxy(conn, { ...proxy, protocol: 'socks5' })).toMatchObject({ status: 'ok' });
  });

  it('supports a SOCKS5 proxy without authentication and rejects a failed CONNECT', async () => {
    await forward(socket => socket.once('data', greeting => {
      expect([...greeting]).toEqual([5, 1, 0]);
      socket.write(Buffer.from([5, 0]));
      socket.once('data', () => socket.end(Buffer.from([5, 5, 0, 1, 0, 0, 0, 0, 0, 0])));
    }));
    expect(await probeOutboundProxy(conn, { protocol: 'socks5', host: proxy.host, port: proxy.port })).toMatchObject({ status: 'error', detail: expect.stringContaining('目标') });
  });

  it.each([1, 4])('validates unauthenticated SOCKS5 HTTPS with a bound address type of %s', async addressType => {
    trustProbeCertificate();
    await forward(socket => socket.once('data', () => {
      socket.write(Buffer.from([5, 0]));
      socket.once('data', () => {
        socket.write(Buffer.concat([Buffer.from([5, 0, 0, addressType]), Buffer.alloc(addressType === 1 ? 6 : 18)]));
        serveHttps(socket);
      });
    }));
    expect(await probeOutboundProxy(conn, { protocol: 'socks5', host: proxy.host, port: proxy.port })).toMatchObject({ status: 'ok' });
  });

  it('rejects a truncated SOCKS5 address before trying TLS', async () => {
    const connect = vi.spyOn(tls, 'connect');
    await forward(socket => socket.once('data', () => {
      socket.write(Buffer.from([5, 0]));
      socket.once('data', () => socket.end(Buffer.from([5, 0, 0, 1, 0])));
    }));
    expect(await probeOutboundProxy(conn, { protocol: 'socks5', host: proxy.host, port: proxy.port })).toMatchObject({ status: 'error' });
    expect(connect).not.toHaveBeenCalled();
  });

  it('times out an incomplete SOCKS5 frame without starving the deadline', async () => {
    await forward(socket => socket.once('data', () => socket.write(Buffer.from([5]))));
    expect(await probeOutboundProxy(conn, { protocol: 'socks5', host: proxy.host, port: proxy.port }, { timeoutMs: 100 }))
      .toMatchObject({ status: 'error', detail: expect.stringContaining('超时') });
    expect(client.end).toHaveBeenCalled();
  });

  it.each([false, true])('rejects an untrusted TLS peer or an unexpected HTTPS response (trusted=%s)', async trusted => {
    if (trusted) trustProbeCertificate();
    await forward(socket => socket.once('data', () => {
      socket.write('HTTP/1.1 200 Connection established\r\n\r\n');
      serveHttps(socket, 403);
    }));
    expect(await probeOutboundProxy(conn, proxy)).toMatchObject({ status: 'error', detail: expect.stringContaining(trusted ? 'HTTPS' : 'TLS') });
  });

  it('does not call a proxy healthy merely because CONNECT succeeded', async () => {
    await forward(socket => socket.once('data', () => socket.end('HTTP/1.1 200 Connection established\r\n\r\n')));
    expect(await probeOutboundProxy(conn, proxy)).toMatchObject({ status: 'error' });
  });

  it('bounds stalled or oversized proxy replies and releases SSH', async () => {
    await forward(() => {});
    expect(await probeOutboundProxy(conn, proxy, { timeoutMs: 100 })).toMatchObject({ status: 'error', detail: expect.stringContaining('超时') });
    await forward(socket => socket.once('data', () => socket.write('HTTP/1.1 200 OK\r\nX: ' + 'a'.repeat(17000))));
    expect(await probeOutboundProxy(conn, proxy)).toMatchObject({ status: 'error' });
    expect(client.end).toHaveBeenCalledTimes(2);
  });

  it('distinguishes connection refusal from disabled SSH forwarding without exposing errors', async () => {
    client.forwardOut.mockImplementation((_a, _b, _c, _d, cb) => cb(new Error('connect ECONNREFUSED SECRET-PASSWORD')));
    expect(await probeOutboundProxy(conn, proxy)).toMatchObject({ status: 'error', detail: expect.not.stringContaining('SECRET-PASSWORD') });
    client.forwardOut.mockImplementation((_a, _b, _c, _d, cb) => cb(new Error('administratively prohibited SECRET-PASSWORD')));
    expect(await probeOutboundProxy(conn, proxy)).toMatchObject({ status: 'unavailable', detail: expect.not.stringContaining('SECRET-PASSWORD') });
  });

  it('closes a late SSH connection after the total timeout', async () => {
    let ready!: (value: never) => void;
    vi.mocked(connectClient).mockReturnValue(new Promise(resolve => { ready = resolve; }));
    expect(await probeOutboundProxy(conn, proxy, { timeoutMs: 20 })).toMatchObject({ status: 'unavailable' });
    ready(client as never);
    await vi.waitFor(() => expect(client.end).toHaveBeenCalled());
    expect(client.forwardOut).not.toHaveBeenCalled();
  });
});
