import { describe, expect, it } from 'vitest';
import { applyForward, reconcile, type ForwardSpec } from './index.js';
import type { ExecFn, SshConn } from '../ssh/executor.js';

const conn: SshConn = { serverId: 1, host: '10.0.0.1', sudo: false };
const spec: ForwardSpec = { id: 2, entryPort: 31221, landingHost: '163.192.29.143', targetPort: 31934, mechanism: 'iptables' };

describe('iptables forwarding regressions', () => {
  it('places forwarding before firewalld REJECT and provides a scoped return path', async () => {
    const commands: string[] = [];
    const exec: ExecFn = async (_conn, cmd) => {
      commands.push(cmd);
      return { stdout: '__SINGRAY_END__\n', stderr: '' };
    };
    await applyForward(conn, spec, false, exec, async () => {});
    const script = commands.join('\n');
    expect(script).toMatch(/-I FORWARD 1/);
    expect(script).toContain('MASQUERADE');
    expect(script).toContain('--ctorigdstport 31221');
    expect(script).toContain('--sport 31934');
    expect(script).toContain('ESTABLISHED,RELATED');
  });

  it('reports legacy DNAT as broken when forwarding is disabled and accepts follow REJECT', async () => {
    const exec: ExecFn = async (_conn, cmd) => ({
      stdout: cmd.includes('iptables') ? [
        '__SINGRAY_NAT4__',
        '-P PREROUTING ACCEPT',
        '-A PREROUTING -p tcp --dport 31221 -m comment --comment "singray:2" -j DNAT --to-destination 163.192.29.143:31934',
        '__SINGRAY_FILTER4__',
        '-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
        '-A FORWARD -j REJECT --reject-with icmp-host-prohibited',
        '-A FORWARD -d 163.192.29.143/32 -p tcp --dport 31934 -j ACCEPT',
        '__SINGRAY_FORWARD4__', '0',
        '__SINGRAY_END__',
      ].join('\n') : '',
      stderr: '',
    });
    const report = await reconcile(conn, [spec], exec);
    expect(report.missingIptables).toContain(2);
    expect(JSON.stringify(report)).toContain('转发');
    expect(JSON.stringify(report)).toContain('源地址转换');
  });

  it('does not claim a persistent repair when storing the restore service fails', async () => {
    const exec: ExecFn = async () => ({ stdout: '__SINGRAY_END__\n', stderr: '' });
    await expect(applyForward(conn, spec, false, exec, async () => {
      throw new Error('read-only filesystem');
    })).rejects.toThrow('read-only filesystem');
  });
});
