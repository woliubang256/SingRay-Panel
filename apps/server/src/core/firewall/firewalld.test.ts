import { describe, expect, it } from 'vitest';
import { ensureFirewalldPorts, inspectFirewalldPorts } from './firewalld.js';
import type { ExecFn } from '../ssh/executor.js';

const conn = { serverId: 1, host: '10.0.0.1', sudo: false };
const port = { port: 31250, protocol: 'tcp' as const, family: 'ipv4' as const };
const section = (name: string, data: string) => `__SINGRAY_FW_${name}__\n${data}\n`;
function firewallFixture(options: { inactive?: boolean; denied?: boolean; ignoreAdds?: boolean; runtimeZone?: string; permanentZone?: string; sources?: boolean; panic?: boolean; runtimePorts?: string; permanentPorts?: string; services?: string; networkManager?: boolean } = {}) {
  const runtimeZone = options.runtimeZone ?? 'public', permanentZone = options.permanentZone ?? 'public';
  const ports = { runtime: options.runtimePorts ?? '', permanent: options.permanentPorts ?? '' };
  const calls: string[] = [];
  const snapshot = () => section('STATE', options.inactive ? 'inactive' : 'running') + section('DEFAULT', 'public')
    + section('RUNTIME', `${runtimeZone} (active)\n  target: default\n  interfaces: eth0\n  sources:\n  ports: ${ports.runtime}\n  services: ${options.services ?? ''}\n${options.sources ? 'blocked\n  interfaces:\n  sources: 10.0.0.0/8\n  ports:\n' : ''}`)
    + section('PERMANENT', `${permanentZone}\n  target: default\n  interfaces: ${options.networkManager ? '' : 'eth0'}\n  sources:\n  ports: ${ports.permanent}\n  services: ${options.services ?? ''}${options.networkManager ? '\npublic\n  interfaces:\n  ports:\n' : ''}`)
    + section('ROUTES4', 'default via 10.0.0.254 dev eth0') + section('ROUTES6', '')
    + section('SERVICES_R', 'https\n  ports: 443/tcp\n  destination:\n') + section('SERVICES_P', 'https\n  ports: 443/tcp\n  destination:\n')
    + section('PANIC', options.panic ? 'yes' : 'no') + section('END', '');
  const exec: ExecFn = async (_conn, cmd) => {
    calls.push(cmd);
    if (cmd.includes('# SINGRAY_FIREWALL_SNAPSHOT')) return { stdout: snapshot(), stderr: '' };
    const scope = cmd.includes('--permanent') ? 'permanent' : 'runtime';
    if (scope === 'permanent' && options.denied) throw new Error('permission denied');
    if (!options.ignoreAdds) ports[scope] += ' ' + cmd.match(/--add-port='([^']+)'/)![1];
    return { stdout: 'success', stderr: '' };
  };
  return { exec, calls, ports };
}

describe('node INPUT firewalld inspection and repair', () => {
  it('finds a missing INPUT allow even when FORWARD could already be allowed', async () => {
    const h = firewallFixture();
    const result = await inspectFirewalldPorts(conn, [port], h.exec);
    expect(result.missing).toEqual([
      { zone: 'public', scope: 'runtime', port: 31250, protocol: 'tcp' },
      { zone: 'public', scope: 'permanent', port: 31250, protocol: 'tcp' },
    ]);
    expect(h.calls).toHaveLength(1);
  });
  it('repairs runtime and permanent state, verifies freshly and is idempotent without reload', async () => {
    const h = firewallFixture();
    expect((await ensureFirewalldPorts(conn, [port], h.exec)).missing).toEqual([]);
    const writes = h.calls.filter(cmd => cmd.includes('--add-port'));
    expect(writes).toHaveLength(2);
    expect(writes.every(cmd => !/--reload|--direct|--remove|iptables/.test(cmd))).toBe(true);
    await ensureFirewalldPorts(conn, [port], h.exec);
    expect(h.calls.filter(cmd => cmd.includes('--add-port'))).toHaveLength(2);
  });
  it('uses actual runtime and permanent interface zones separately instead of assuming public', async () => {
    const h = firewallFixture({ runtimeZone: 'external', permanentZone: 'work' });
    await ensureFirewalldPorts(conn, [port], h.exec);
    expect(h.calls.some(cmd => cmd.includes("--zone='external'") && !cmd.includes('--permanent') && cmd.includes('--add-port'))).toBe(true);
    expect(h.calls.some(cmd => cmd.includes("--zone='work'") && cmd.includes('--permanent') && cmd.includes('--add-port'))).toBe(true);
  });
  it('never claims success on a permanent write failure or a silently ignored add', async () => {
    await expect(ensureFirewalldPorts(conn, [port], firewallFixture({ denied: true }).exec)).rejects.toThrow('永久');
    await expect(ensureFirewalldPorts(conn, [port], firewallFixture({ ignoreAdds: true }).exec)).rejects.toThrow('核验');
  });
  it('covers NetworkManager-owned zones even when permanent XML has no interface binding', async () => {
    const h = firewallFixture({ runtimeZone: 'external', permanentZone: 'external', networkManager: true });
    expect((await inspectFirewalldPorts(conn, [port], h.exec)).missing).toContainEqual({ zone: 'external', scope: 'permanent', port: 31250, protocol: 'tcp' });
  });
  it('accepts ranges and normal services and preserves source-specific policies as a warning', async () => {
    const h = firewallFixture({ runtimePorts: '31000-32000/tcp', permanentPorts: '31000-32000/tcp', sources: true });
    expect((await inspectFirewalldPorts(conn, [port], h.exec)).missing).toEqual([]);
    expect((await inspectFirewalldPorts(conn, [port], h.exec)).warnings.join('')).toContain('来源');
    const https = firewallFixture({ services: 'https' });
    expect((await inspectFirewalldPorts(conn, [{ ...port, port: 443 }], https.exec)).missing).toEqual([]);
  });
  it('skips an inactive daemon, but refuses panic mode and incomplete snapshots', async () => {
    const h = firewallFixture({ inactive: true });
    expect((await ensureFirewalldPorts(conn, [port], h.exec)).state).toBe('inactive');
    expect(h.calls).toHaveLength(1);
    await expect(ensureFirewalldPorts(conn, [port], firewallFixture({ panic: true }).exec)).rejects.toThrow('panic');
    await expect(inspectFirewalldPorts(conn, [port], async () => ({ stdout: '', stderr: '' }))).rejects.toThrow('完整');
  });
});
