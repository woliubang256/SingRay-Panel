import { createPublicKey } from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { genSelfSignedCert } from '../core/configgen/cert.js';
import { diagnoseXrayNode } from './nodeDiagnostics.js';
import type { ExecFn } from '../core/ssh/executor.js';

const conn = { serverId: 1, host: '10.0.0.1', sudo: false };
const target = { host: 'hk.example.com', port: 31250, sni: 'hk.example.com', protocol: 'trojan',
  tlsMode: 'tls', transport: 'raw', wsPath: '', enabled: true, pending: false, nodeId: 7, outboundType: 'direct' };
const cert = genSelfSignedCert({ commonName: 'HK', altNames: ['hk.example.com'] });
const publicKey = createPublicKey(cert.keyPem).export({ type: 'spki', format: 'pem' }).toString();
let config: Record<string, any>;
let listener: string;
let journal: string;
let execFn: ReturnType<typeof vi.fn<ExecFn>>;
const probeFn = vi.fn();
const localProbeFn = vi.fn();
const proxyProbeFn = vi.fn();
const run = (patch = {}) => diagnoseXrayNode(conn, { ...target, ...patch }, { execFn, probeFn, localProbeFn, proxyProbeFn });

function healthyProxyInput() {
  config.inbounds[0].tag = 'relay-in-31250';
  config.inbounds[0].streamSettings.security = 'none';
  config.outbounds = [{ tag: 'proxy-7', protocol: 'socks', settings: {
    servers: [{ address: 'proxy.example.com', port: 1080, users: [{ user: 'proxy-user', pass: 'PROXY-SECRET' }] }],
  } }];
  config.routing = { rules: [{ type: 'field', inboundTag: ['relay-in-31250'], outboundTag: 'proxy-7' }] };
  localProbeFn.mockResolvedValue({ status: 'ok', detail: '本机 TCP 连接成功' });
  probeFn.mockResolvedValue({ ok: true, latency_ms: 1, detail: 'OK' });
  const original = execFn.getMockImplementation()!;
  execFn.mockImplementation(async (conn, cmd, opts) => cmd.includes('# SINGRAY_FIREWALL_SNAPSHOT')
    ? { stdout: '__SINGRAY_FW_STATE__\nunavailable\n__SINGRAY_FW_END__\n', stderr: '' } : original(conn, cmd, opts));
  return { tlsMode: 'none', outboundType: 'proxy', proxyUrl: 'socks5://proxy-user:PROXY-SECRET@proxy.example.com:1080' };
}

beforeEach(() => {
  vi.resetAllMocks();
  config = { inbounds: [{ port: 31250, listen: '0.0.0.0', protocol: 'trojan', settings: { clients: [{ password: 'NEVER-EXPOSE' }] },
    streamSettings: { network: 'tcp', security: 'tls', tlsSettings: { certificates: [{ certificateFile: '/cert.pem', keyFile: '/key.pem' }] } } }] };
  listener = 'State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\nLISTEN 0 128 *:31250 *:* users:(("xray",pid=123,fd=9))';
  journal = '';
  execFn = vi.fn(async (_conn, cmd) => {
    expect(cmd).not.toMatch(/systemctl (restart|reload|stop)|\brm\s|\binstall\s/);
    if (cmd.startsWith('systemctl show')) return { stdout: 'ActiveState=active\nMainPID=123\n', stderr: '' };
    if (cmd.startsWith('ss ')) return { stdout: listener, stderr: '' };
    if (cmd.includes('/proc/123/cmdline')) return { stdout: '/usr/local/bin/xray\nrun\n-c\n/etc/xray/config.json\n', stderr: '' };
    if (cmd.includes("'/etc/xray/config.json'")) return { stdout: JSON.stringify(config), stderr: '' };
    if (cmd.includes("'/cert.pem'")) return { stdout: cert.certPem, stderr: '' };
    if (cmd.startsWith('openssl pkey')) return { stdout: publicKey, stderr: '' };
    if (cmd.startsWith('journalctl ')) return { stdout: journal, stderr: '' };
    throw new Error('unexpected command: ' + cmd);
  });
  probeFn.mockResolvedValue({ ok: false, latency_ms: null, detail: 'tls handshake timeout after 5000ms' });
  localProbeFn.mockResolvedValue({ status: 'error', detail: '本机 TLS 握手失败' });
});

describe('read-only single node diagnostics', () => {
  it.each(['代理连接失败', '代理认证失败'])('rejects a healthy inbound when the outbound reports %s', async detail => {
    const input = healthyProxyInput();
    proxyProbeFn.mockResolvedValue({ status: 'error', detail });
    const result = await run(input);
    expect(result.checks).toContainEqual(expect.objectContaining({ key: 'proxy', status: 'error', detail }));
    expect(result.status).toBe('error');
    expect(result.summary).toContain('出口代理');
    expect(JSON.stringify(result)).not.toMatch(/PROXY-SECRET|proxy-user/);
  });

  it('does not call unverified proxy access successful when SSH forwarding is unavailable', async () => {
    const input = healthyProxyInput();
    proxyProbeFn.mockResolvedValue({ status: 'unavailable', detail: 'SSH 转发不可用，未验证出口代理' });
    const result = await run(input);
    expect(result.status).toBe('warning');
    expect(result.checks).toContainEqual(expect.objectContaining({ key: 'proxy', status: 'warning' }));
  });

  it('detects a proxy route that is still direct despite a successful proxy probe', async () => {
    const input = healthyProxyInput();
    config.routing.rules[0].outboundTag = 'direct';
    proxyProbeFn.mockResolvedValue({ status: 'ok', detail: '代理联网成功' });
    const result = await run(input);
    expect(result.status).toBe('error');
    expect(result.checks).toContainEqual(expect.objectContaining({ key: 'proxyConfig', status: 'error' }));
  });

  it.each(['address', 'port', 'password', 'protocol', 'missing'])('detects a stale proxy %s without returning secrets', async field => {
    const input = healthyProxyInput();
    const server = config.outbounds[0].settings.servers[0];
    if (field === 'address') server.address = 'old.example.com';
    if (field === 'port') server.port = 7890;
    if (field === 'password') server.users[0].pass = 'OLD-PROXY-SECRET';
    if (field === 'protocol') config.outbounds[0].protocol = 'http';
    if (field === 'missing') config.outbounds = [];
    proxyProbeFn.mockResolvedValue({ status: 'ok', detail: '代理联网成功' });
    const result = await run(input);
    expect(result.status).toBe('error');
    expect(result.checks).toContainEqual(expect.objectContaining({ key: 'proxyConfig', status: 'error' }));
    expect(JSON.stringify(result)).not.toMatch(/PROXY-SECRET|proxy-user/);
  });

  it('only passes after the SOCKS5 configuration and actual access both pass', async () => {
    const input = healthyProxyInput();
    proxyProbeFn.mockResolvedValue({ status: 'ok', detail: '代理联网成功' });
    const result = await run(input);
    expect(result.status).toBe('ok');
    expect(result.checks).toContainEqual(expect.objectContaining({ key: 'proxyConfig', status: 'ok' }));
    expect(proxyProbeFn).toHaveBeenCalledWith(conn, { protocol: 'socks5', host: 'proxy.example.com', port: 1080, username: 'proxy-user', password: 'PROXY-SECRET' });
    expect(result.summary).toContain('出口代理');
    expect(execFn.mock.calls.some(([, cmd]) => /PROXY-SECRET|proxy-user/.test(cmd))).toBe(false);
  });

  it('also validates an HTTP proxy without authentication', async () => {
    const input = healthyProxyInput();
    config.outbounds[0].protocol = 'http';
    delete config.outbounds[0].settings.servers[0].users;
    proxyProbeFn.mockResolvedValue({ status: 'ok', detail: '代理联网成功' });
    expect((await run({ ...input, proxyUrl: 'http://proxy.example.com:1080' })).status).toBe('ok');
  });

  it.each(['', 'http://proxy.example.com:bad'])('fails for a missing or invalid saved URL without probing', async proxyUrl => {
    const input = healthyProxyInput();
    const result = await run({ ...input, proxyUrl });
    expect(result.status).toBe('error');
    expect(result.checks).toContainEqual(expect.objectContaining({ key: 'proxyConfig', status: 'error' }));
    expect(proxyProbeFn).not.toHaveBeenCalled();
  });

  it('keeps unreadable config or unrecognized routing inconclusive even if access passes', async () => {
    const input = healthyProxyInput();
    proxyProbeFn.mockResolvedValue({ status: 'ok', detail: '代理联网成功' });
    config.routing.rules.unshift({ type: 'field', domain: ['example.com'], outboundTag: 'direct' });
    expect((await run(input)).checks).toContainEqual(expect.objectContaining({ key: 'proxyConfig', status: 'warning' }));
    const original = execFn.getMockImplementation()!;
    execFn.mockImplementation(async (conn, cmd, opts) => cmd.includes("'/etc/xray/config.json'")
      ? { stdout: '{broken', stderr: '' } : original(conn, cmd, opts));
    expect((await run(input)).checks).toContainEqual(expect.objectContaining({ key: 'proxyConfig', status: 'warning' }));
  });

  it('sanitizes unexpected proxy probe exceptions and never probes a direct node', async () => {
    const input = healthyProxyInput();
    proxyProbeFn.mockRejectedValue(new Error('PROXY-SECRET'));
    const result = await run(input);
    expect(result.checks).toContainEqual(expect.objectContaining({ key: 'proxy', status: 'warning' }));
    expect(JSON.stringify(result)).not.toContain('PROXY-SECRET');
    proxyProbeFn.mockClear();
    await run();
    expect(proxyProbeFn).not.toHaveBeenCalled();
  });

  it('identifies missing INPUT permissions with the exact zone, port and persistence scope', async () => {
    localProbeFn.mockResolvedValue({ status: 'ok', detail: '本机 TLS 握手成功' });
    const original = execFn.getMockImplementation()!;
    execFn.mockImplementation(async (conn, cmd, opts) => cmd.includes('# SINGRAY_FIREWALL_SNAPSHOT') ? { stdout:
      '__SINGRAY_FW_STATE__\nrunning\n__SINGRAY_FW_DEFAULT__\npublic\n__SINGRAY_FW_RUNTIME__\npublic\n  interfaces: eth0\n  ports:\n'
      + '__SINGRAY_FW_PERMANENT__\npublic\n  interfaces: eth0\n  ports:\n__SINGRAY_FW_ROUTES4__\ndefault dev eth0\n'
      + '__SINGRAY_FW_ROUTES6__\n__SINGRAY_FW_PANIC__\nno\n__SINGRAY_FW_END__\n', stderr: '' } : original(conn, cmd, opts));
    const result = await run();
    expect(result.checks).toContainEqual(expect.objectContaining({ key: 'firewall', status: 'error', detail: expect.stringContaining('31250/tcp') }));
    expect(result.checks.find(c => c.key === 'firewall')?.detail).toContain('永久 zone public');
    expect(result.summary).toContain('firewalld');
    expect(execFn.mock.calls.every(([,cmd]) => !cmd.includes('--add-port='))).toBe(true);
  });

  it('reports an unreadable firewall as inconclusive without returning command errors', async () => {
    const original = execFn.getMockImplementation()!;
    execFn.mockImplementation(async (conn, cmd, opts) => {
      if (cmd.includes('# SINGRAY_FIREWALL_SNAPSHOT')) throw new Error('SECRET-FIREWALL-ERROR');
      return original(conn, cmd, opts);
    });
    const result = await run();
    expect(result.checks).toContainEqual(expect.objectContaining({ key: 'firewall', status: 'warning' }));
    expect(JSON.stringify(result)).not.toContain('SECRET-FIREWALL-ERROR');
  });

  it('does not call an active process healthy when its TLS handshake fails', async () => {
    const result = await run();
    expect(result.status).toBe('error');
    expect(result.checks).toContainEqual(expect.objectContaining({ key: 'service', status: 'ok' }));
    expect(result.checks).toContainEqual(expect.objectContaining({ key: 'local', status: 'error' }));
    expect(result.summary).toContain('本机');
    expect(JSON.stringify(result)).not.toContain('NEVER-EXPOSE');
  });

  it('identifies a listener owned by a different process without returning raw process data', async () => {
    listener = 'LISTEN 0 128 *:31250 *:* users:(("other-secret",pid=999,fd=9))';
    const result = await run();
    expect(result.checks).toContainEqual(expect.objectContaining({ key: 'listener', status: 'error', detail: expect.stringContaining('其他进程') }));
    expect(JSON.stringify(result)).not.toContain('other-secret');
  });

  it('detects a missing or stale inbound in the actual process configuration', async () => {
    config.inbounds = [];
    expect((await run()).checks).toContainEqual(expect.objectContaining({ key: 'config', status: 'error' }));
  });

  it('checks transport and TLS instead of relying on the protocol name alone', async () => {
    config.inbounds[0].streamSettings.security = 'none';
    expect((await run()).checks).toContainEqual(expect.objectContaining({ key: 'config', status: 'error' }));
  });

  it('detects certificate/SNI and private key mismatches', async () => {
    const other = genSelfSignedCert({ commonName: 'other', altNames: ['other.example.com'] });
    execFn.mockImplementation(async (_conn, cmd) => ({ stdout: cmd.startsWith('systemctl show') ? 'ActiveState=active\nMainPID=123' :
      cmd.startsWith('ss ') ? listener : cmd.includes('/proc/') ? '/usr/local/bin/xray\nrun\n-c\n/etc/xray/config.json\n' :
      cmd.includes("'/etc/xray/config.json'") ? JSON.stringify(config) : cmd.includes("'/cert.pem'") ? other.certPem :
      cmd.startsWith('openssl pkey') ? publicKey : '', stderr: '' }));
    const result = await run();
    expect(result.checks).toContainEqual(expect.objectContaining({ key: 'certificate', status: 'error', detail: expect.stringContaining('SNI') }));
    expect(result.checks).toContainEqual(expect.objectContaining({ key: 'key', status: 'error' }));
  });

  it('distinguishes external failure from successful local TLS and shows a network hint', async () => {
    localProbeFn.mockResolvedValue({ status: 'ok', detail: '本机 TLS 握手成功' });
    const result = await run();
    expect(result.summary).toContain('外部');
    expect(result.summary).toContain('防火墙');
  });

  it('returns bounded log categories rather than raw logs, credentials or parser exceptions', async () => {
    journal = 'TLS handshake error password=NEVER-EXPOSE token=TOP-SECRET\nfailed to read certificate /private/SECRET-PATH';
    const result = await run();
    expect(result.checks.find(c => c.key === 'logs')?.detail).toContain('TLS');
    expect(JSON.stringify(result)).not.toMatch(/NEVER-EXPOSE|TOP-SECRET|SECRET-PATH/);
    execFn.mockRejectedValue(new Error('password=NEVER-EXPOSE'));
    expect(JSON.stringify(await run())).not.toContain('NEVER-EXPOSE');
  });

  it('marks unsupported SSH forwarding as inconclusive and preserves external results', async () => {
    localProbeFn.mockResolvedValue({ status: 'unavailable', detail: 'SSH 本机隧道不可用' });
    const result = await run();
    expect(result.checks).toContainEqual(expect.objectContaining({ key: 'local', status: 'warning' }));
    expect(result.checks).toContainEqual(expect.objectContaining({ key: 'external', status: 'error' }));
  });

  it('warns about unapplied changes and disabled nodes', async () => {
    const result = await run({ pending: true, enabled: false });
    expect(result.checks).toContainEqual(expect.objectContaining({ key: 'deployment', status: 'warning' }));
    expect(result.checks).toContainEqual(expect.objectContaining({ key: 'firewall', status: 'skipped' }));
    expect(execFn.mock.calls.every(([,cmd]) => !cmd.includes('# SINGRAY_FIREWALL_SNAPSHOT'))).toBe(true);
  });

  it('prioritizes the wrong listener over an external network hint even if local TLS succeeds', async () => {
    listener = 'LISTEN 0 128 *:31250 *:* users:(("other",pid=999,fd=9))';
    localProbeFn.mockResolvedValue({ status: 'ok', detail: '本机 TLS 握手成功' });
    expect((await run()).summary).not.toContain('请检查域名解析');
  });

  it('detects an expired certificate independently of handshake success', async () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date('2045-01-01T00:00:00Z'));
      localProbeFn.mockResolvedValue({ status: 'ok', detail: '本机 TLS 握手成功' });
      expect((await run()).checks).toContainEqual(expect.objectContaining({ key: 'certificate', status: 'error', detail: expect.stringContaining('过期') }));
    } finally { vi.useRealTimers(); }
  });

  it('does not return JSON parser excerpts containing passwords', async () => {
    const original = execFn.getMockImplementation()!;
    execFn.mockImplementation(async (conn, cmd, opts) => cmd.includes("'/etc/xray/config.json'")
      ? { stdout: '{"password":"NEVER-EXPOSE",broken', stderr: '' } : original(conn, cmd, opts));
    const result = await run();
    expect(result.checks).toContainEqual(expect.objectContaining({ key: 'config', status: 'warning' }));
    expect(JSON.stringify(result)).not.toContain('NEVER-EXPOSE');
  });
});
