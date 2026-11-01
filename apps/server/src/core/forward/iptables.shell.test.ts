// Execute generated POSIX scripts against isolated CLI doubles. No host
// firewall, sysctl, service or /etc file is changed by these tests.
import { afterEach, describe, expect, it } from 'vitest';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { spawnSync } from 'node:child_process';
import { applyForward, reconcile, type ForwardSpec } from './index.js';
import type { ExecFn, SshConn } from '../ssh/executor.js';

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) {
    if (!resolve(root).startsWith(resolve(tmpdir()) + sep)) throw new Error('Unsafe test cleanup');
    rmSync(root, { recursive: true, force: true });
  }
});
const q = (s: string) => "'" + s.replaceAll("'", "'\\''") + "'";
const posix = (s: string) => s.replaceAll('\\', '/');
const shellPath = (s: string) => posix(s).replace(/^([A-Za-z]):/, (_, drive: string) => '/' + drive.toLowerCase());
const conn: SshConn = { serverId: 1, host: '127.0.0.1', sudo: false };
type Rule = { family: string; table: string; chain: string; args: string[] };
interface State { fw: boolean; rules: Rule[]; runtime: (Rule & { priority: number })[]; permanent: (Rule & { priority: number })[]; enabled: string[]; failPermanent?: boolean }
const specs: ForwardSpec[] = [
  { id: 2, entryPort: 31221, landingHost: '163.192.29.143', targetPort: 31934, mechanism: 'iptables' },
  { id: 3, entryPort: 31222, landingHost: '168.110.12.176', targetPort: 24100, mechanism: 'iptables' },
  { id: 4, entryPort: 31223, landingHost: '149.118.33.64', targetPort: 24000, mechanism: 'iptables' },
];
const cli = String.raw`
import fs from 'node:fs';
import path from 'node:path';
const file = process.env.SINGRAY_TEST_STATE;
const root = process.env.SINGRAY_TEST_ROOT;
const state = JSON.parse(fs.readFileSync(file, 'utf8'));
const [name, ...input] = process.argv.slice(2);
const save = () => fs.writeFileSync(file, JSON.stringify(state));
const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const value = (args, key) => args[args.indexOf(key) + 1];
const insert = (rule) => {
  const i = state.rules.findIndex(r => r.family === rule.family && r.table === rule.table && r.chain === rule.chain);
  state.rules.splice(i < 0 ? state.rules.length : i, 0, rule);
};
const materialize = (r) => {
  const jump = { family: r.family, table: r.table, chain: r.chain, args: ['-j', r.chain + '_direct'] };
  if (!state.rules.some(x => equal(x, jump))) insert(jump);
  insert({ family: r.family, table: r.table, chain: r.chain + '_direct', args: r.args });
};
if (name === 'iptables' || name === 'ip6tables') {
  const args = [...input];
  if (args[0] === '-w') args.shift();
  let table = 'filter';
  if (args[0] === '-t') { args.shift(); table = args.shift(); }
  const [op, chain, ...tail] = args;
  const family = name === 'iptables' ? 'ipv4' : 'ipv6';
  if (op === '-S') {
    console.log(state.rules.filter(r => r.family === family && r.table === table && (!chain || r.chain === chain))
      .map(r => '-A ' + r.chain + ' ' + r.args.join(' ')).join('\n'));
  } else {
    const rest = op === '-I' ? tail.slice(1) : tail;
    const rule = { family, table, chain, args: rest };
    const i = state.rules.findIndex(r => equal(r, rule));
    if (op === '-C') process.exit(i < 0 ? 1 : 0);
    if (op === '-D') { if (i < 0) process.exit(1); state.rules.splice(i, 1); }
    else if (op === '-I') insert(rule);
    else throw Error('Unexpected iptables operation: ' + op);
    save();
  }
} else if (name === 'firewall-cmd') {
  if (input.includes('--state')) { console.log(state.fw ? 'running' : 'not running'); process.exit(state.fw ? 0 : 1); }
  if (input.includes('--reload')) {
    state.rules = state.rules.filter(r => !r.args.includes('--comment') && !value(r.args, '-j')?.endsWith('_direct'));
    state.runtime = structuredClone(state.permanent);
    state.runtime.forEach(materialize); save(); process.exit(0);
  }
  const permanent = input.includes('--permanent');
  const bucket = permanent ? state.permanent : state.runtime;
  if (input.includes('--get-all-rules')) {
    console.log(bucket.map(r => [r.family, r.table, r.chain, r.priority, ...r.args].join(' ')).join('\n'));
  } else {
    const action = input.find(a => /--(add|remove)-rule/.test(a));
    if (permanent && state.failPermanent && action === '--add-rule') { console.error('permanent configuration is read-only'); process.exit(1); }
    const [family, table, chain, priority, ...args] = input.slice(input.indexOf(action) + 1);
    const rule = { family, table, chain, priority: Number(priority), args };
    const i = bucket.findIndex(r => equal(r, rule));
    if (action === '--remove-rule') {
      if (i < 0) process.exit(1);
      bucket.splice(i, 1);
      if (!permanent) state.rules = state.rules.filter(r => !(r.family === family && r.table === table && r.chain === chain + '_direct' && equal(r.args, args)));
    } else {
      if (i >= 0) { console.error('duplicate direct rule'); process.exit(1); }
      bucket.push(rule);
      if (!permanent) materialize(rule);
    }
    save();
  }
} else if (name === 'systemctl') {
  const [op, service] = input;
  if (op === 'is-enabled') { console.log(state.enabled.includes(service) ? 'enabled' : 'disabled'); process.exit(state.enabled.includes(service) ? 0 : 1); }
  if (op === 'enable' && !state.enabled.includes(service)) state.enabled.push(service);
  if (op === 'disable') state.enabled = state.enabled.filter(s => s !== input.at(-1));
  save();
} else if (name === 'sysctl') {
  const [key, val] = input.at(-1).split('=');
  const dest = path.join(root, 'proc/sys', key.replaceAll('.', '/'));
  fs.mkdirSync(path.dirname(dest), { recursive: true }); fs.writeFileSync(dest, val + '\n');
} else { process.exit(2); }
`;

function host(firewalld: boolean) {
  const root = mkdtempSync(join(tmpdir(), 'singray-forward-'));
  roots.push(root);
  const bin = join(root, 'bin');
  mkdirSync(bin);
  const stub = join(root, 'cli.mjs');
  writeFileSync(stub, cli);
  const file = join(root, 'state.json');
  const state: State = { fw: firewalld, runtime: [], permanent: [], enabled: [], rules: [
    { family: 'ipv4', table: 'filter', chain: 'FORWARD', args: ['-j', 'REJECT', '--reject-with', 'icmp-host-prohibited'] },
    ...specs.flatMap(s => [
      { family: 'ipv4', table: 'nat', chain: 'PREROUTING', args: ['-p', 'tcp', '--dport', String(s.entryPort), '-m', 'comment', '--comment', 'singray:' + s.id, '-j', 'DNAT', '--to-destination', s.landingHost + ':' + s.targetPort] },
      { family: 'ipv4', table: 'filter', chain: 'FORWARD', args: ['-p', 'tcp', '-d', s.landingHost, '--dport', String(s.targetPort), '-j', 'ACCEPT'] },
    ]),
  ] };
  writeFileSync(file, JSON.stringify(state));
  for (const name of ['iptables', 'ip6tables', 'firewall-cmd', 'systemctl', 'sysctl']) {
    writeFileSync(join(bin, name), '#!/bin/sh\nexec ' + q(posix(process.execPath)) + ' ' + q(posix(stub)) + ' ' + name + ' "$@"\n', { mode: 0o755 });
  }
  const bash = process.platform === 'win32' && existsSync('C:/Program Files/Git/bin/bash.exe') ? 'C:/Program Files/Git/bin/bash.exe' : 'bash';
  const exec: ExecFn = async (_conn, cmd) => {
    const script = 'export PATH=' + q(shellPath(bin)) + ':"$PATH"\n' +
      cmd.replaceAll('/etc/', shellPath(root) + '/etc/').replaceAll('/proc/sys/', shellPath(root) + '/proc/sys/');
    const result = spawnSync(bash, ['-s'], { input: script, encoding: 'utf8',
      env: { ...process.env, SINGRAY_TEST_STATE: file, SINGRAY_TEST_ROOT: root }, timeout: 20_000 });
    if (result.status !== 0) throw new Error(result.stderr || result.error?.message || 'shell exit ' + result.status);
    return { stdout: result.stdout, stderr: result.stderr };
  };
  const write = async (_conn: SshConn, path: string, content: string) => {
    const dest = join(root, path.replace(/^\//, ''));
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, content);
  };
  return { root, exec, write, state: () => JSON.parse(readFileSync(file, 'utf8')) as State,
    setState: (s: State) => writeFileSync(file, JSON.stringify(s)) };
}

describe('isolated forwarding shell execution', () => {
  it('does not remove a shared legacy allow while another route still uses it', async () => {
    const h = host(false);
    const state = h.state();
    const second = state.rules.find(r => r.args.includes('singray:3'))!;
    second.args[second.args.indexOf('--to-destination') + 1] = '163.192.29.143:31934';
    h.setState(state);
    await applyForward(conn, specs[0], true, h.exec, h.write);
    expect(h.state().rules.some(r => r.chain === 'FORWARD' && r.args.includes('163.192.29.143') && r.args.includes('31934'))).toBe(true);
    expect(h.state().rules.some(r => r.args.includes('singray:3'))).toBe(true);
  }, 60_000);

  it('repairs all three HK routes, stays idempotent and deletes only the selected route', async () => {
    const h = host(false);
    for (const s of specs) await applyForward(conn, s, false, h.exec, h.write);
    expect((await reconcile(conn, specs, h.exec)).ruleIssues).toEqual([]);
    for (const s of specs) await applyForward(conn, s, false, h.exec, h.write);
    const managed = h.state().rules.filter(r => r.args.includes('--comment'));
    expect(managed).toHaveLength(12);
    const forward = h.state().rules.filter(r => r.chain === 'FORWARD');
    const reject = forward.findIndex(r => r.args.includes('REJECT'));
    expect(forward.slice(0, reject).filter(r => r.args.includes('ACCEPT'))).toHaveLength(6);
    expect(managed.filter(r => r.args.includes('MASQUERADE')).map(r => r.args[r.args.indexOf('--ctorigdstport') + 1]).sort()).toEqual(['31221', '31222', '31223']);
    await applyForward(conn, { ...specs[0], landingHost: 'unresolvable.example.com' }, true, h.exec, h.write);
    expect(h.state().rules.filter(r => r.args.includes('--comment'))).toHaveLength(8);
    expect(h.state().rules.some(r => r.args.includes('REJECT'))).toBe(true);
    expect((await reconcile(conn, specs.slice(1), h.exec)).ruleIssues).toEqual([]);
  }, 60_000);

  it('survives firewalld reload and removes both runtime and permanent configuration', async () => {
    const h = host(true);
    for (const s of specs) await applyForward(conn, s, false, h.exec, h.write);
    expect((await reconcile(conn, specs, h.exec)).ruleIssues).toEqual([]);
    await h.exec(conn, 'firewall-cmd --reload');
    expect((await reconcile(conn, specs, h.exec)).ruleIssues).toEqual([]);
    await applyForward(conn, specs[0], false, h.exec, h.write);
    expect(h.state().permanent).toHaveLength(12);
    expect(h.state().runtime).toHaveLength(12);
    await applyForward(conn, specs[0], true, h.exec, h.write);
    expect(h.state().permanent).toHaveLength(8);
    expect(h.state().runtime).toHaveLength(8);
  }, 60_000);

  it('restores IPv6 rules on boot without requiring IPv4 forwarding', async () => {
    const h = host(false);
    const s = { ...specs[0], id: 9, landingHost: '2001:db8::9' };
    await applyForward(conn, s, false, h.exec, h.write);
    const state = h.state();
    state.rules = state.rules.filter(r => r.family !== 'ipv6');
    h.setState(state);
    const script = readFileSync(join(h.root, 'etc/singray/forwards/9.sh'), 'utf8');
    await h.exec(conn, script);
    await h.exec(conn, script);
    expect(h.state().rules.filter(r => r.family === 'ipv6')).toHaveLength(4);
    expect((await reconcile(conn, [s], h.exec)).ruleIssues).toEqual([]);
  }, 60_000);

  it('surfaces a failed firewalld permanent write and permits a clean retry', async () => {
    const h = host(true);
    h.setState({ ...h.state(), failPermanent: true });
    await expect(applyForward(conn, specs[0], false, h.exec, h.write)).rejects.toThrow('read-only');
    expect((await reconcile(conn, [specs[0]], h.exec)).missingIptables).toContain(2);
    h.setState({ ...h.state(), failPermanent: false });
    await applyForward(conn, specs[0], false, h.exec, h.write);
    expect(h.state().runtime).toHaveLength(4);
    expect(h.state().permanent).toHaveLength(4);
    expect((await reconcile(conn, [specs[0]], h.exec)).ruleIssues).toEqual([]);
  }, 60_000);
});
