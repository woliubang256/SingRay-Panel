// Complete, tagged TCP forwarding rules. firewalld owns its runtime/permanent
// rules; other hosts restore only our own rules through a per-rule systemd unit.
import { isIP } from 'node:net';
import { shQuote, type ExecFn, type SshConn } from '../ssh/executor.js';
import type { ForwardSpec } from './index.js';

type Family = 'ipv4' | 'ipv6';
interface Rule { family: Family; table: 'nat' | 'filter'; chain: string; args: string[]; priority?: number }
export interface ForwardIssue { id: number; entryPort: number; issues: string[] }
export interface ExpectedForward { id: number; entryPort: number; landingHost?: string; targetPort?: number }
type WriteFile = (conn: SshConn, path: string, content: string, exec: ExecFn) => Promise<void>;
const tag = (id: number) => `singray:${id}`;
const ipt = (family: Family) => family === 'ipv4' ? 'iptables' : 'ip6tables';
const scriptPath = (id: number) => `/etc/singray/forwards/${id}.sh`;
const unitName = (id: number) => `singray-iptables-${id}.service`;
const sysctlKey = (family: Family) => family === 'ipv4' ? 'net.ipv4.ip_forward' : 'net.ipv6.conf.all.forwarding';
const sysctlPath = (family: Family) => `/etc/sysctl.d/99-singray-forward-${family}.conf`;
const words = (args: string[]) => args.map((s) => /^[a-zA-Z0-9_.,:/=-]+$/.test(s) ? s : shQuote(s)).join(' ');
const tokens = (line: string) => (line.match(/"[^"]*"|'[^']*'|[^\s]+/g) ?? []).map((s) => s.replace(/^(['"])(.*)\1$/, '$2'));
const arg = (args: string[], key: string) => args.indexOf(key) < 0 ? '' : args[args.indexOf(key) + 1];
const owned = (rule: Rule, id: number) => arg(rule.args, '--comment') === tag(id);

function canonical(args: string[]): string {
  const pairs: string[] = [];
  for (let i = 0; i < args.length; i += 2) {
    const key = args[i];
    let value = args[i + 1];
    if (key === '-m' && value === 'tcp') continue; // iptables adds this module itself.
    if (key === '-s' || key === '-d') value = value?.replace(/\/(32|128)$/, '');
    if (key === '--ctstate') value = value?.split(',').sort().join(',');
    pairs.push(`${key}=${value}`);
  }
  return pairs.sort().join('|');
}

function same(a: Rule, b: Rule): boolean {
  return a.family === b.family && a.table === b.table && a.chain === b.chain && canonical(a.args) === canonical(b.args);
}

function parseRules(text: string, family: Family, table: 'nat' | 'filter'): Rule[] {
  return text.split('\n').flatMap((line) => {
    const [op, chain, ...args] = tokens(line);
    return op === '-A' ? [{ family, table, chain, args }] : [];
  });
}

function parseDirect(text: string): Rule[] {
  return text.split('\n').flatMap((line) => {
    const [family, table, chain, priority, ...args] = tokens(line);
    return (family === 'ipv4' || family === 'ipv6') && (table === 'nat' || table === 'filter') && /^-?\d+$/.test(priority)
      ? [{ family, table, chain, priority: Number(priority), args }] : [];
  });
}

export async function resolveTargetIP(conn: SshConn, host: string, exec: ExecFn): Promise<{ ip: string; family: 'v4' | 'v6' }> {
  if (isIP(host)) return { ip: host, family: isIP(host) === 6 ? 'v6' : 'v4' };
  const r = await exec(conn, `getent ahosts ${shQuote(host)} 2>/dev/null | awk '{print $1}' | sort -u`, { timeoutClass: 'quick' });
  const addrs = r.stdout.trim().split('\n').map((a) => a.trim()).filter((a) => isIP(a));
  const ip = addrs.find((a) => isIP(a) === 4) ?? addrs[0];
  if (!ip) throw new Error(`入口机无法解析落地主机 ${host}(检查 DNS / hosts)`);
  return { ip, family: isIP(ip) === 6 ? 'v6' : 'v4' };
}

function expectedRules(spec: ExpectedForward, ip: string): Rule[] {
  const family: Family = isIP(ip) === 6 ? 'ipv6' : 'ipv4';
  const ct = ['-m', 'conntrack', '--ctorigdstport', String(spec.entryPort)];
  const comment = ['-m', 'comment', '--comment', tag(spec.id)];
  const port = String(spec.targetPort);
  return [
    { family, table: 'nat', chain: 'PREROUTING', args: ['-p', 'tcp', '--dport', String(spec.entryPort), ...comment, '-j', 'DNAT', '--to-destination', `${family === 'ipv6' ? `[${ip}]` : ip}:${port}`] },
    { family, table: 'filter', chain: 'FORWARD', args: ['-p', 'tcp', '-d', ip, '--dport', port, ...ct, '--ctstate', 'DNAT', ...comment, '-j', 'ACCEPT'] },
    { family, table: 'filter', chain: 'FORWARD', args: ['-p', 'tcp', '-s', ip, '--sport', port, ...ct, '--ctstate', 'ESTABLISHED,RELATED', ...comment, '-j', 'ACCEPT'] },
    { family, table: 'nat', chain: 'POSTROUTING', args: ['-p', 'tcp', '-d', ip, '--dport', port, ...ct, '--ctstate', 'DNAT', ...comment, '-j', 'MASQUERADE'] },
  ];
}

function restoreScript(id: number, rules: Rule[]): string {
  // Only our exact comment is removed. Splitting awk output with globbing off
  // passes arguments to iptables without eval or executing remote rule text.
  const family = rules[0].family;
  const cleanup = ['nat', 'filter'].map((table) => `${ipt(family)} -w -t ${table} -S | awk -v tag=${tag(id)} '${
    '{ for (i=1;i<NF;i++) if ($i == "--comment") { gsub(/"/, "", $(i+1)); if ($(i+1) == tag) { $1="-D"; print; break } } }'
  }' | while IFS= read -r sr_rule; do ${ipt(family)} -w -t ${table} $sr_rule; done`);
  return ['#!/bin/sh', 'set -eu', 'set -f', `sysctl -w ${sysctlKey(family)}=1`, ...cleanup,
    ...rules.map((r) => `${ipt(r.family)} -w -t ${r.table} -I ${r.chain} 1 ${words(r.args)}`), ''].join('\n');
}

function restoreUnit(id: number): string {
  return ['[Unit]', `Description=SingRay TCP forwarding ${id}`,
    'After=network-online.target firewalld.service netfilter-persistent.service iptables.service ip6tables.service',
    'Wants=network-online.target', '', '[Service]', 'Type=oneshot',
    `ExecStart=/bin/sh ${scriptPath(id)}`, 'RemainAfterExit=yes', '', '[Install]', 'WantedBy=multi-user.target', ''].join('\n');
}

interface Snapshot { sections: Record<string, string>; rules: Rule[]; runtime: Rule[]; permanent: Rule[]; firewalld: boolean }

async function snapshot(conn: SshConn, ids: number[], exec: ExecFn): Promise<Snapshot> {
  const mark = (name: string) => `printf '%s\\n' '__SINGRAY_${name}__'`;
  const commands = ['set -e', mark('NAT4'), 'if command -v iptables >/dev/null; then iptables -w -t nat -S; fi',
    mark('FILTER4'), 'if command -v iptables >/dev/null; then iptables -w -t filter -S; fi',
    mark('NAT6'), 'ip6tables -w -t nat -S 2>/dev/null || true',
    mark('FILTER6'), 'ip6tables -w -t filter -S 2>/dev/null || true',
    mark('FORWARD4'), 'cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || true',
    mark('FORWARD6'), 'cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || true',
    mark('SYSCTL4'), `cat ${sysctlPath('ipv4')} 2>/dev/null || true`,
    mark('SYSCTL6'), `cat ${sysctlPath('ipv6')} 2>/dev/null || true`,
    mark('RESTORE_IDS'), "find /etc/singray/forwards -maxdepth 1 -name '*.sh' -printf '%f\\n' 2>/dev/null || true",
    "find /etc/systemd/system -maxdepth 1 -name 'singray-iptables-*.service' -printf '%f\\n' 2>/dev/null || true",
    mark('FIREWALLD'),
    'if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then',
    "printf '%s\\n' running", mark('DIRECT'), 'firewall-cmd --direct --get-all-rules',
    mark('PERMANENT'), 'firewall-cmd --permanent --direct --get-all-rules', 'fi'];
  for (const id of ids) commands.push(mark(`SCRIPT_${id}`), `cat ${scriptPath(id)} 2>/dev/null || true`,
    mark(`UNIT_${id}`), `cat /etc/systemd/system/${unitName(id)} 2>/dev/null || true`,
    mark(`ENABLED_${id}`), `systemctl is-enabled ${unitName(id)} 2>/dev/null || true`);
  commands.push(mark('END'));
  const { stdout } = await exec(conn, commands.join('\n'), { timeoutClass: 'config' });
  const sections: Record<string, string> = {};
  let section = '';
  for (const line of stdout.split(/\r?\n/)) {
    const m = /^__SINGRAY_(\w+)__$/.exec(line);
    if (m) { section = m[1]; sections[section] = ''; }
    else if (section) sections[section] += `${line}\n`;
  }
  if (!('END' in sections)) throw new Error('未能读取完整的防火墙状态，请检查 SSH 权限');
  return { sections, firewalld: sections.FIREWALLD?.trim() === 'running',
    rules: [...parseRules(sections.NAT4 ?? '', 'ipv4', 'nat'), ...parseRules(sections.FILTER4 ?? '', 'ipv4', 'filter'),
      ...parseRules(sections.NAT6 ?? '', 'ipv6', 'nat'), ...parseRules(sections.FILTER6 ?? '', 'ipv6', 'filter')],
    runtime: parseDirect(sections.DIRECT ?? ''), permanent: parseDirect(sections.PERMANENT ?? '') };
}

function removeRule(rule: Rule): string {
  const prefix = `${ipt(rule.family)} -w -t ${rule.table}`;
  return `while ${prefix} -C ${rule.chain} ${words(rule.args)} 2>/dev/null; do ${prefix} -D ${rule.chain} ${words(rule.args)}; done`;
}

function directCommand(rule: Rule, permanent: boolean, action: string): string {
  return `firewall-cmd ${permanent ? '--permanent ' : ''}--direct --${action}-rule ${rule.family} ${rule.table} ${rule.chain} ${rule.priority ?? 0} ${words(rule.args)}`;
}

function cleanup(state: Snapshot, id: number): string[] {
  const commands: string[] = [];
  for (const [rules, permanent] of [[state.runtime, false], [state.permanent, true]] as const) {
    for (const r of rules.filter((r) => owned(r, id))) commands.push(directCommand(r, permanent, 'remove'));
  }
  const ours = state.rules.filter((r) => owned(r, id));
  commands.push(...ours.map(removeRule));
  // The old release left an untagged outbound ACCEPT. Remove only the exact
  // legacy shape associated with one of this rule's tagged DNAT destinations.
  for (const dnat of ours.filter((r) => arg(r.args, '-j') === 'DNAT')) {
    const dest = arg(dnat.args, '--to-destination');
    // An untagged legacy ACCEPT may be shared by several entry ports.
    // Preserve it until the last DNAT using that destination is removed.
    if (state.rules.some((r) => r.family === dnat.family && r.table === 'nat' && !owned(r, id) &&
      arg(r.args, '-j') === 'DNAT' && arg(r.args, '--to-destination') === dest)) continue;
    const match = /^(?:\[([^\]]+)\]|([^:]+)):(\d+)$/.exec(dest ?? '');
    if (!match) continue;
    const legacy: Rule = { family: dnat.family, table: 'filter', chain: 'FORWARD',
      args: ['-p', 'tcp', '-d', match[1] ?? match[2], '--dport', match[3], '-j', 'ACCEPT'] };
    commands.push(...state.rules.filter((r) => same(r, legacy)).map(removeRule));
  }
  return commands;
}

export async function applyIptablesForward(conn: SshConn, spec: ForwardSpec, remove: boolean, exec: ExecFn, write: WriteFile): Promise<void> {
  const state = await snapshot(conn, [spec.id], exec);
  const commands = ['set -eu', ...cleanup(state, spec.id)];
  if (remove) {
    commands.push(`if test -f /etc/systemd/system/${unitName(spec.id)}; then systemctl disable --now ${unitName(spec.id)}; fi`,
      `rm -f ${scriptPath(spec.id)} /etc/systemd/system/${unitName(spec.id)}`, 'systemctl daemon-reload');
    await exec(conn, commands.join('\n'), { timeoutClass: 'config' });
    return;
  }
  const target = await resolveTargetIP(conn, spec.landingHost, exec);
  const rules = expectedRules(spec, target.ip);
  const family = rules[0].family;
  commands.push('mkdir -p /etc/sysctl.d', `printf '%s\\n' ${shQuote(`${sysctlKey(family)}=1`)} > ${sysctlPath(family)}`,
    `sysctl -w ${sysctlKey(family)}=1`);
  if (state.firewalld) {
    for (const rule of rules) commands.push(directCommand(rule, false, 'add'), directCommand(rule, true, 'add'));
    commands.push(`if test -f /etc/systemd/system/${unitName(spec.id)}; then systemctl disable --now ${unitName(spec.id)}; rm -f /etc/systemd/system/${unitName(spec.id)} ${scriptPath(spec.id)}; systemctl daemon-reload; fi`);
  } else {
    await exec(conn, 'mkdir -p /etc/singray/forwards /etc/systemd/system', { timeoutClass: 'config' });
    await write(conn, scriptPath(spec.id), restoreScript(spec.id, rules), exec);
    await write(conn, `/etc/systemd/system/${unitName(spec.id)}`, restoreUnit(spec.id), exec);
    commands.push(...rules.map((r) => `${ipt(r.family)} -w -t ${r.table} -I ${r.chain} 1 ${words(r.args)}`),
      'systemctl daemon-reload', `systemctl enable ${unitName(spec.id)}`);
  }
  await exec(conn, commands.join('\n'), { timeoutClass: 'config' });
}

export async function removeManagedIptables(conn: SshConn, id: number, exec: ExecFn): Promise<void> {
  if (!Number.isSafeInteger(id) || id <= 0) throw new Error('中转规则 id 不合法');
  await applyIptablesForward(conn, { id, entryPort: 0, landingHost: '127.0.0.1', targetPort: 0, mechanism: 'iptables' }, true, exec, async () => {});
}

function beforeReject(rule: Rule, rules: Rule[]): boolean {
  const chain = rules.filter((r) => r.family === rule.family && r.table === rule.table && r.chain === rule.chain);
  const index = chain.findIndex((r) => same(r, rule));
  if (index < 0) return false;
  const canReject = (name: string, visited = new Set<string>()): boolean => {
    if (name === 'DROP' || name === 'REJECT') return true;
    if (visited.has(name)) return false;
    visited.add(name);
    return rules.some((r) => r.family === rule.family && r.table === rule.table && r.chain === name && canReject(arg(r.args, '-j') ?? arg(r.args, '-g'), visited));
  };
  if (chain.slice(0, index).some((r) => canReject(arg(r.args, '-j') ?? arg(r.args, '-g')))) return false;
  if (rule.chain.endsWith('_direct')) {
    const parent = rule.chain.slice(0, -7);
    const jump = rules.find((r) => r.family === rule.family && r.table === rule.table && r.chain === parent && arg(r.args, '-j') === rule.chain);
    return !!jump && beforeReject(jump, rules);
  }
  return true;
}

export async function inspectIptablesForwards(conn: SshConn, specs: ExpectedForward[], exec: ExecFn): Promise<{
  actual: string[]; orphan: string[]; issues: ForwardIssue[];
}> {
  const state = await snapshot(conn, specs.map((r) => r.id), exec);
  const ids = new Set(specs.map((s) => s.id));
  const describe = (r: Rule) => `${r.family} ${r.table} -A ${r.chain} ${words(r.args)}`;
  const managed = state.rules.filter((r) => /^singray:\d+$/.test(arg(r.args, '--comment') ?? ''));
  const orphanById = new Map<number, Rule>();
  for (const r of [...managed, ...state.permanent]) {
    const m = /^singray:(\d+)$/.exec(arg(r.args, '--comment') ?? '');
    if (m && !ids.has(Number(m[1]))) orphanById.set(Number(m[1]), r);
  }
  const issues: ForwardIssue[] = [];
  for (const spec of specs) {
    const problems: string[] = [];
    let ip: string;
    try {
      if (!spec.landingHost || !spec.targetPort) throw new Error('缺少落地地址或目标端口，无法核对转发目标');
      ip = (await resolveTargetIP(conn, spec.landingHost, exec)).ip;
    } catch (err) {
      issues.push({ id: spec.id, entryPort: spec.entryPort, issues: [(err as Error).message] });
      continue;
    }
    const expected = expectedRules(spec, ip);
    const family = expected[0].family;
    const suffix = family === 'ipv4' ? '4' : '6';
    if (state.sections[`FORWARD${suffix}`]?.trim() !== '1') problems.push(`内核 IPv${suffix} 转发未开启`);
    if (state.sections[`SYSCTL${suffix}`]?.trim() !== `${sysctlKey(family)}=1`) problems.push('内核转发未持久化');
    const labels = ['DNAT 缺失或目标不一致', '去程放行缺失或位于拒绝规则之后', '回程放行缺失或位于拒绝规则之后', '源地址转换缺失或位于阻断规则之后'];
    for (const [i, rule] of expected.entries()) {
      const kernel = { ...rule, chain: rule.chain + (state.firewalld ? '_direct' : '') };
      if (!state.rules.some((r) => same(r, kernel)) || !beforeReject(kernel, state.rules)) problems.push(labels[i]);
    }
    if (managed.filter((r) => owned(r, spec.id)).length !== expected.length) problems.push('存在缺失、重复或过期的转发规则');
    if (state.firewalld) {
      if (state.permanent.filter((r) => owned(r, spec.id)).length !== expected.length || expected.some((e) => !state.permanent.some((r) => same(r, e) && r.priority === 0))) problems.push('firewalld 永久规则缺失或已过期');
      if (expected.some((e) => !state.runtime.some((r) => same(r, e) && r.priority === 0))) problems.push('firewalld 运行规则缺失或已过期');
    } else if (state.sections[`SCRIPT_${spec.id}`]?.trim() !== restoreScript(spec.id, expected).trim() ||
      state.sections[`UNIT_${spec.id}`]?.trim() !== restoreUnit(spec.id).trim() || state.sections[`ENABLED_${spec.id}`]?.trim() !== 'enabled') {
      problems.push('缺少开机恢复服务或持久化配置已过期');
    }
    if (problems.length) issues.push({ id: spec.id, entryPort: spec.entryPort, issues: problems });
  }
  const orphan = [...orphanById.values()].map(describe);
  const orphanIds = new Set(orphanById.keys());
  for (const line of (state.sections.RESTORE_IDS ?? '').split('\n')) {
    const m = /^(?:singray-iptables-)?(\d+)(?:\.sh|\.service)$/.exec(line);
    if (m && !ids.has(Number(m[1])) && !orphanIds.has(Number(m[1]))) {
      orphan.push(`restore --comment ${tag(Number(m[1]))}`);
      orphanIds.add(Number(m[1]));
    }
  }
  return { actual: managed.map(describe), orphan, issues };
}
