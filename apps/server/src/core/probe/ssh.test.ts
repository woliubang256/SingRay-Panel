import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { probeLocalNode } from './ssh.js';
import { connectClient } from '../ssh/executor.js';
import tls from 'node:tls';
import net from 'node:net';
import { genSelfSignedCert } from '../configgen/cert.js';

vi.mock('../ssh/executor.js', () => ({ connectClient: vi.fn() }));
vi.mock('node:tls', () => ({ default: { connect: vi.fn() } }));
const conn = { serverId: 1, host: 'server.example.com', sudo: false };
let client: EventEmitter & { forwardOut: ReturnType<typeof vi.fn>; end: ReturnType<typeof vi.fn> };
let socket: PassThrough;
beforeEach(() => {
  vi.resetAllMocks();
  socket = new PassThrough();
  client = Object.assign(new EventEmitter(), { end: vi.fn(), forwardOut: vi.fn((_a, _b, _c, _d, cb) => cb(null, socket)) });
  vi.mocked(connectClient).mockResolvedValue(client as never);
});

describe('node probe through the server SSH tunnel', () => {
  it('does not leave a TLS probe pending when the listener closes without a handshake', async () => {
    const secure = new PassThrough();
    vi.mocked(tls.connect).mockReturnValue(secure as never);
    const pending = probeLocalNode(conn, { port: 31250, mode: 'tls', sni: 'hk.example.com' });
    await vi.waitFor(() => expect(tls.connect).toHaveBeenCalled());
    secure.emit('end');
    expect(await pending).toMatchObject({ status: 'error', detail: expect.stringContaining('TLS') });
    expect(client.end).toHaveBeenCalled();
  });

  it('distinguishes a prohibited SSH tunnel from a failed Trojan handshake', async () => {
    client.forwardOut.mockImplementation((_a, _b, _c, _d, cb) => cb(new Error('administratively prohibited: secret')));
    const result = await probeLocalNode(conn, { port: 31250, mode: 'tls' });
    expect(result).toMatchObject({ status: 'unavailable' });
    expect(JSON.stringify(result)).not.toContain('secret');
    expect(client.end).toHaveBeenCalled();
  });

  it('bounds the handshake wait and releases the connection', async () => {
    vi.mocked(tls.connect).mockReturnValue(new PassThrough() as never);
    const result = await probeLocalNode(conn, { port: 31250, mode: 'tls', timeoutMs: 30 });
    expect(result).toMatchObject({ status: 'error', detail: expect.stringContaining('超时') });
    expect(client.end).toHaveBeenCalled();
  });

  it('closes a late SSH connection after the total timeout', async () => {
    let ready!: (value: never) => void;
    vi.mocked(connectClient).mockReturnValue(new Promise(resolve => { ready = resolve; }));
    expect(await probeLocalNode(conn, { port: 31250, mode: 'tcp', timeoutMs: 20 })).toMatchObject({ status: 'unavailable' });
    ready(client as never);
    await vi.waitFor(() => expect(client.end).toHaveBeenCalled());
    expect(client.forwardOut).not.toHaveBeenCalled();
  });

  it('completes a real native TLS handshake over the forwarded stream', async () => {
    const native = await vi.importActual<typeof import('node:tls')>('node:tls');
    vi.mocked(tls.connect).mockImplementation(native.connect);
    const cert = genSelfSignedCert({ commonName: 'local', altNames: ['hk.example.com'] });
    const server = native.createServer({ key: cert.keyPem, cert: cert.certPem });
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as net.AddressInfo).port;
    client.forwardOut.mockImplementation((_a, _b, host, forwardedPort, cb) => {
      const forwarded = net.connect({ host, port: forwardedPort });
      forwarded.once('connect', () => cb(null, forwarded));
    });
    try {
      expect(await probeLocalNode(conn, { port, mode: 'tls', sni: 'hk.example.com' })).toMatchObject({ status: 'ok' });
      expect(client.end).toHaveBeenCalled();
    } finally { await new Promise<void>((resolve, reject) => server.close(err => err ? reject(err) : resolve())); }
  });
});
