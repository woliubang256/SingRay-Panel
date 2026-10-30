import { describe, it, expect } from 'vitest';
import { certPaths, issueCert, hasRealCert } from './acme.js';
import type { SshConn, ExecFn } from '../ssh/executor.js';

describe('certPaths (domain is a trust boundary)', () => {
  it('builds paths for a real domain', () => {
    expect(certPaths('edge.example.com').fullchain).toContain('/etc/singray/certs/edge.example.com/fullchain.pem');
  });

  it('refuses a domain carrying shell metacharacters or traversal', () => {
    for (const bad of ['x; rm -rf /', 'a$(id)', '../etc/passwd', 'a b', '']) {
      expect(() => certPaths(bad), bad).toThrow(/证书域名不合法/);
    }
  });
});

describe('multi-domain certificate', () => {
  const conn = {} as SshConn;
  for (const token of ['', 'test-token']) {
    it(`issues all SAN domains with ${token ? 'DNS' : 'HTTP'} validation and expands an old certificate`, async () => {
      const commands: string[] = [];
      const execFn: ExecFn = async (_conn, command) => {
        commands.push(command);
        return { stdout: command.includes('--list') ? '1' : command.includes('-checkhost') ? 'NO' : 'YES', stderr: '' };
      };
      await issueCert(conn, 'a.example.com', execFn, token, ['a.example.com', 'b.example.com']);
      const issue = commands.find((c) => c.includes('--issue'))!;
      expect(issue).toContain("-d 'a.example.com' -d 'b.example.com'");
      expect(issue).toContain('--force');
      expect(issue).toContain(token ? '--dns dns_cf' : '--standalone');
      expect(commands.find((c) => c.includes('--install-cert'))).toContain('/a.example.com/fullchain.pem');
    });
  }
  it('skips redundant issuance when all domains are covered', async () => {
    const commands: string[] = [];
    const execFn: ExecFn = async (_conn, command) => {
      commands.push(command);
      return { stdout: command.includes('--list') ? '1' : 'YES', stderr: '' };
    };
    await issueCert(conn, 'a.example.com', execFn, '', ['b.example.com']);
    expect(commands.some((c) => c.includes('--issue'))).toBe(false);
    expect(commands.some((c) => c.includes("-checkhost 'b.example.com'"))).toBe(true);
  });
  it('rejects invalid aliases before executing SSH', async () => {
    const execFn: ExecFn = async () => { throw new Error('must not execute'); };
    await expect(issueCert(conn, 'a.example.com', execFn, '', ['b;id'])).rejects.toThrow('不合法');
  });
  it('accepts the full machine limit of 32 domains including the primary', async () => {
    const domains = Array.from({ length: 32 }, (_, i) => `d${i}.example.com`);
    const execFn: ExecFn = async () => ({ stdout: 'NO', stderr: '' });
    await expect(issueCert(conn, domains[0], execFn, '', domains)).resolves.toHaveProperty('method', 'http-01');
  });
  it('does not accept an existing certificate with incomplete coverage', async () => {
    const execFn: ExecFn = async (_conn, command) => ({ stdout: command.includes('-checkhost') ? 'NO' : 'YES', stderr: '' });
    expect(await hasRealCert(conn, 'a.example.com', execFn, ['a.example.com', 'b.example.com'])).toBe(false);
  });
});
