// Real POSIX command execution, isolated from the host firewall and network.
import { afterEach, describe, expect, it } from 'vitest';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { spawnSync } from 'node:child_process';
import { ensureFirewalldPorts, inspectFirewalldPorts } from './firewalld.js';
import type { ExecFn } from '../ssh/executor.js';

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) {
  if (!resolve(root).startsWith(resolve(tmpdir()) + sep)) throw new Error('Unsafe test cleanup');
  rmSync(root, { recursive: true, force: true });
} });
const q = (s: string) => "'" + s.replaceAll("'", "'\\''") + "'";
const posix = (s: string) => s.replaceAll('\\', '/');
const shellPath = (s: string) => posix(s).replace(/^([A-Za-z]):/, (_, drive: string) => '/' + drive.toLowerCase());
const conn = { serverId: 1, host: '127.0.0.1', sudo: false };
const ports = [{ port: 31250, protocol: 'tcp' as const, family: 'ipv4' as const }, { port: 24000, protocol: 'udp' as const, family: 'dual' as const }];
const cli = String.raw`
import fs from 'node:fs';
const file = process.env.SINGRAY_FIREWALL_TEST_STATE;
const state = JSON.parse(fs.readFileSync(file, 'utf8'));
const [name, ...args] = process.argv.slice(2);
const save = () => fs.writeFileSync(file, JSON.stringify(state));
state.calls.push([name, ...args]); save();
if (name === 'ip') { console.log('default via 10.0.0.254 dev eth0'); process.exit(0); }
if (name !== 'firewall-cmd') process.exit(2);
const permanent = args.includes('--permanent');
const scope = permanent ? 'permanent' : 'runtime';
if (args.includes('--state')) { console.log(state.running ? 'running' : 'not running'); process.exit(state.running ? 0 : 252); }
if (args.includes('--query-panic')) { console.log('no'); process.exit(1); }
if (args.includes('--get-default-zone')) { console.log('public'); process.exit(0); }
if (args.includes('--list-all-zones')) {
  for (const [zone, value] of Object.entries(state[scope])) {
    console.log(zone + '\n  target: default\n  interfaces: ' + value.interfaces.join(' ') + '\n  sources: ' + (value.sources || '')
      + '\n  ports: ' + value.ports.join(' ') + '\n  services: https\n');
  }
  process.exit(0);
}
if (args.some(a => a.startsWith('--info-service='))) { console.log('https\n  ports: 443/tcp\n  destination:\n'); process.exit(0); }
if (args.includes('--reload')) { state.runtime = structuredClone(state.permanent); save(); process.exit(0); }
const zone = args.find(a => a.startsWith('--zone='))?.slice(7);
const port = args.find(a => a.startsWith('--add-port='))?.slice(11);
if (!zone || !port || !state[scope][zone]) throw new Error('Invalid firewall arguments');
if (permanent && state.failPermanent) { console.error('read-only permanent configuration'); process.exit(1); }
if (!state[scope][zone].ports.includes(port)) state[scope][zone].ports.push(port);
save(); console.log('success');
`;
function host() {
  const root = mkdtempSync(join(tmpdir(), 'singray-input-')); roots.push(root);
  const bin = join(root, 'bin'); mkdirSync(bin);
  const stub = join(root, 'cli.mjs'); writeFileSync(stub, cli);
  const file = join(root, 'state.json');
  writeFileSync(file, JSON.stringify({ running: true, failPermanent: false, calls: [],
    runtime: { external: { interfaces: ['eth0'], ports: ['443/tcp'] }, public: { interfaces: [], ports: [] } },
    permanent: { work: { interfaces: ['eth0'], ports: ['443/tcp'] }, public: { interfaces: [], ports: [] } },
  }));
  for (const name of ['firewall-cmd', 'ip']) writeFileSync(join(bin, name), '#!/bin/sh\nexec ' + q(posix(process.execPath)) + ' ' + q(posix(stub)) + ' ' + name + ' "$@"\n', { mode: 0o755 });
  const bash = process.platform === 'win32' && existsSync('C:/Program Files/Git/bin/bash.exe') ? 'C:/Program Files/Git/bin/bash.exe' : 'bash';
  const exec: ExecFn = async (_conn, cmd) => {
    const result = spawnSync(bash, ['-s'], { input: 'export PATH=' + q(shellPath(bin)) + ':"$PATH"\n' + cmd,
      encoding: 'utf8', env: { ...process.env, SINGRAY_FIREWALL_TEST_STATE: file }, timeout: 20_000 });
    if (result.status !== 0) throw new Error(result.stderr || result.error?.message || 'shell exit ' + result.status);
    return { stdout: result.stdout, stderr: result.stderr };
  };
  return { exec, state: () => JSON.parse(readFileSync(file, 'utf8')), update: (value: unknown) => writeFileSync(file, JSON.stringify(value)) };
}

describe('isolated firewalld INPUT shell execution', () => {
  it('repairs both actual zones, survives reload, and preserves existing HTTPS permissions', async () => {
    const h = host();
    expect((await inspectFirewalldPorts(conn, ports, h.exec)).missing).toHaveLength(4);
    await ensureFirewalldPorts(conn, ports, h.exec);
    const before = h.state();
    expect(before.runtime.external.ports).toEqual(['443/tcp', '31250/tcp', '24000/udp']);
    expect(before.permanent.work.ports).toEqual(['443/tcp', '31250/tcp', '24000/udp']);
    expect(before.calls.every((args: string[]) => !args.includes('--reload'))).toBe(true);
    await h.exec(conn, 'firewall-cmd --reload');
    expect((await inspectFirewalldPorts(conn, ports, h.exec)).missing).toEqual([]);
  }, 30_000);
  it('reports a permanent failure and can complete a later retry', async () => {
    const h = host(); const state = h.state(); state.failPermanent = true; h.update(state);
    await expect(ensureFirewalldPorts(conn, ports, h.exec)).rejects.toThrow('永久');
    const updated = h.state(); updated.failPermanent = false; h.update(updated);
    expect((await ensureFirewalldPorts(conn, ports, h.exec)).missing).toEqual([]);
  }, 30_000);
  it('does not start or change an inactive firewall', async () => {
    const h = host(); const state = h.state(); state.running = false; h.update(state);
    expect((await ensureFirewalldPorts(conn, ports, h.exec)).state).toBe('inactive');
    expect(h.state().calls).toEqual([['firewall-cmd', '--state']]);
  });
  it('persists a NetworkManager runtime zone even when its XML has no interface binding', async () => {
    const h = host(); const state = h.state();
    state.permanent.work.interfaces = [];
    state.permanent.external = { interfaces: [], ports: [] };
    h.update(state);
    await ensureFirewalldPorts(conn, [ports[0]], h.exec);
    expect(h.state().permanent.external.ports).toContain('31250/tcp');
    expect(h.state().permanent.public.ports).toContain('31250/tcp');
    expect(h.state().permanent.external.interfaces).toEqual([]);
  }, 30_000);
});
