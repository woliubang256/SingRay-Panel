import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { externalClash } from './format.js';
import type { ExternalNode } from './types.js';

export const EXTERNAL_PROBE_URL = 'https://www.gstatic.com/generate_204';
export interface ExternalProbeResult {
  status: 'ok' | 'failed' | 'unsupported' | 'unavailable';
  latencyMs: number | null;
  detail: string;
  checkedAt: string;
}

async function freePort(): Promise<number> {
  const server = net.createServer();
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as net.AddressInfo).port;
      server.close(err => err ? reject(err) : resolve(port));
    });
  });
}

function api(port: number, secret: string, route: string, timeout: number): Promise<{ code: number; body: Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: '127.0.0.1', port, path: route, agent: false, headers: { Authorization: `Bearer ${secret}` } }, res => {
      let body = '';
      res.on('data', chunk => { body += chunk; if (body.length > 16_384) req.destroy(new Error('oversized')); });
      res.on('error', reject);
      res.on('end', () => { try { resolve({ code: res.statusCode ?? 500, body: JSON.parse(body) }); } catch { reject(new Error('invalid response')); } });
    });
    const timer = setTimeout(() => req.destroy(new Error('timeout')), Math.max(1, timeout));
    req.once('close', () => clearTimeout(timer));
    req.once('error', reject);
  });
}

/** Each test runs an isolated core; the controller is loopback-only and protected by a random secret.
 * No public proxy listener, remote config URL, user-controlled test URL, or credential-bearing command line. */
export async function probeExternalNode(node: ExternalNode, options: { corePath?: string; timeoutMs?: number; coreArgs?: string[]; testUrl?: string } = {}): Promise<ExternalProbeResult> {
  const result = (status: ExternalProbeResult['status'], detail: string, latencyMs: number | null = null): ExternalProbeResult =>
    ({ status, detail, latencyMs, checkedAt: new Date().toISOString() });
  const proxy = externalClash(node);
  if (!proxy) return result('unsupported', '该传输暂不受测试核心支持；可使用兼容的客户端测试');
  let directory: string | undefined;
  let child: ReturnType<typeof spawn> | undefined;
  let ended = false, missing = false;
  let closed: Promise<void> = Promise.resolve();
  try {
    const port = await freePort(), secret = randomBytes(32).toString('hex');
    directory = await mkdtemp(path.join(tmpdir(), 'singray-probe-'));
    const file = path.join(directory, 'config.json');
    await writeFile(file, JSON.stringify({
      'external-controller': `127.0.0.1:${port}`, secret, 'allow-lan': false, mode: 'rule', 'log-level': 'silent', ipv6: true,
      'geo-auto-update': false, profile: { 'store-selected': false, 'store-fake-ip': false },
      proxies: [{ ...proxy, name: 'probe' }], 'proxy-groups': [], rules: ['MATCH,probe'],
    }), { mode: 0o600 });
    child = spawn(options.corePath ?? process.env.PANEL_TEST_CORE_PATH ?? (process.platform === 'win32' ? 'mihomo.exe' : '/usr/local/bin/mihomo'),
      [...(options.coreArgs ?? []), '-d', directory, '-f', file], { stdio: 'ignore', windowsHide: true });
    closed = new Promise(resolve => child!.once('close', () => { ended = true; resolve(); }));
    child.once('error', err => { missing = (err as NodeJS.ErrnoException).code === 'ENOENT'; ended = true; });
    const deadline = Date.now() + (options.timeoutMs ?? 18_000);
    let ready = false;
    while (!ended && Date.now() < deadline - 1000) {
      try { ready = (await api(port, secret, '/version', 250)).code === 200; } catch { /* Core is still starting. */ }
      if (ready) break;
      await delay(75);
    }
    if (!ready) return result(missing ? 'unavailable' : 'failed', missing
      ? '未找到测试核心，请更新面板镜像或设置 PANEL_TEST_CORE_PATH' : '测试核心未能启动或加载节点配置，请检查协议参数');
    const timeout = Math.min(8000, deadline - Date.now() - 100);
    if (timeout <= 0) return result('failed', '测试超时');
    const response = await api(port, secret, `/proxies/probe/delay?timeout=${timeout}&url=${encodeURIComponent(options.testUrl ?? EXTERNAL_PROBE_URL)}`, timeout + 100);
    const latency = response.body.delay;
    if (response.code === 200 && typeof latency === 'number' && Number.isFinite(latency) && latency >= 0) {
      return result('ok', '已通过该节点访问 HTTPS 检测地址；延迟从面板所在网络测得', Math.round(latency));
    }
    const timedOut = /timeout|deadline/i.test(String(response.body.message ?? ''));
    return result('failed', timedOut ? '代理访问超时，请检查节点、认证参数及网络' : '代理连接、认证或 HTTPS 检测地址访问失败');
  } catch {
    return result('failed', '代理测试失败或超时，请检查节点配置和面板网络');
  } finally {
    if (child && !ended) {
      child.kill();
      await Promise.race([closed, delay(300)]);
      if (!ended) { child.kill('SIGKILL'); await Promise.race([closed, delay(2000)]); }
    }
    if (directory) await rm(directory, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
  }
}
