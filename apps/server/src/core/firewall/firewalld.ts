import { exec, shQuote, type ExecFn, type SshConn } from '../ssh/executor.js';
import type { InboundPort } from './ports.js';

export interface MissingPort { zone: string; scope: 'runtime' | 'permanent'; port: number; protocol: 'tcp' | 'udp' }
export interface FirewalldReport {
  state: 'running' | 'inactive' | 'unavailable';
  missing: MissingPort[];
  issues: string[];
  warnings: string[];
}
const marker = (name: string) => `printf '%s\\n' '__SINGRAY_FW_${name}__'`;
const snapshotCmd = [
  '# SINGRAY_FIREWALL_SNAPSHOT', 'set -e', marker('STATE'),
  `if ! command -v firewall-cmd >/dev/null 2>&1; then echo unavailable; ${marker('END')}; exit 0; fi`,
  'if state=$(firewall-cmd --state 2>/dev/null); then [ "$state" = running ]; else',
  `  [ "$state" = 'not running' ] || exit 1; echo inactive; ${marker('END')}; exit 0; fi`,
  'echo running', marker('DEFAULT'), 'firewall-cmd --get-default-zone',
  'runtime=$(firewall-cmd --list-all-zones)', 'permanent=$(firewall-cmd --permanent --list-all-zones)',
  marker('RUNTIME'), 'printf "%s\\n" "$runtime"', marker('PERMANENT'), 'printf "%s\\n" "$permanent"',
  marker('ROUTES4'), 'ip -o -4 route show default 2>/dev/null || true',
  marker('ROUTES6'), 'ip -o -6 route show default 2>/dev/null || true',
  // Only referenced services, not every installed service. Query both versions,
  // since permanent service definitions can differ until a firewalld reload.
  `services=$(printf '%s\\n%s\\n' "$runtime" "$permanent" | awk '/^[[:space:]]+services:/{for(i=2;i<=NF;i++) print $i}' | sort -u)`,
  marker('SERVICES_R'), 'for svc in $services; do firewall-cmd --info-service="$svc" 2>/dev/null || true; done',
  marker('SERVICES_P'), 'for svc in $services; do firewall-cmd --permanent --info-service="$svc" 2>/dev/null || true; done',
  marker('PANIC'), 'if firewall-cmd --query-panic; then :; else [ "$?" -eq 1 ]; fi', marker('END'),
].join('\n');

interface Settings { name: string; fields: Record<string, string>; customRules: boolean }
function settings(text: string): Settings[] {
  const items: Settings[] = [];
  let current: Settings | undefined;
  for (const line of text.split('\n')) {
    const name = /^([A-Za-z0-9_][A-Za-z0-9_.-]{0,127})(?:\s+\([^)]*\))*\s*$/.exec(line);
    if (name) { current = { name: name[1], fields: {}, customRules: false }; items.push(current); continue; }
    const field = /^\s{2}([a-z-]+):\s*(.*)$/.exec(line);
    if (current && field) current.fields[field[1]] = field[2].trim();
    else if (current && /^\s+rule\s/.test(line)) current.customRules = true;
  }
  return items;
}
function covers(list: string, port: InboundPort | MissingPort): boolean {
  return list.split(/\s+/).some(value => {
    const m = /^(\d+)(?:-(\d+))?\/(tcp|udp)$/.exec(value);
    return m && m[3] === port.protocol && Number(m[1]) <= port.port && Number(m[2] ?? m[1]) >= port.port;
  });
}
const words = (text = '') => text.split(/\s+/).filter(Boolean);
const describe = (p: MissingPort) => `${p.scope === 'runtime' ? '运行' : '永久'} zone ${p.zone} 缺少 ${p.port}/${p.protocol} 放行`;

export async function inspectFirewalldPorts(conn: SshConn, ports: InboundPort[], execFn: ExecFn = exec): Promise<FirewalldReport> {
  for (const p of ports) {
    if (!Number.isInteger(p.port) || p.port < 1 || p.port > 65535 || !['tcp', 'udp'].includes(p.protocol)
      || !['ipv4', 'ipv6', 'dual'].includes(p.family)) throw new Error('防火墙端口或协议不合法');
  }
  let raw: string;
  try { raw = (await execFn(conn, snapshotCmd, { timeoutClass: 'config' })).stdout; }
  catch { throw new Error('firewalld 状态读取失败，请检查 SSH、D-Bus 及防火墙管理权限'); }
  const sections: Record<string, string> = {};
  let section = '';
  for (const line of raw.replaceAll('\r', '').split('\n')) {
    const mark = /^__SINGRAY_FW_(\w+)__$/.exec(line);
    if (mark) { section = mark[1]; sections[section] = ''; }
    else if (section) sections[section] += line + '\n';
  }
  if (!('END' in sections)) throw new Error('未能读取完整的 firewalld 状态');
  const state = sections.STATE?.trim();
  if (state === 'inactive' || state === 'unavailable') return { state, missing: [], issues: [], warnings: [] };
  if (state !== 'running' || !['DEFAULT', 'RUNTIME', 'PERMANENT', 'PANIC', 'ROUTES4', 'ROUTES6'].every(k => k in sections)
    || !['yes', 'no'].includes(sections.PANIC.trim())) throw new Error('未能读取完整的 firewalld 配置');
  const report: FirewalldReport = { state, missing: [], issues: [], warnings: [] };
  if (sections.PANIC.trim() === 'yes') report.issues.push('firewalld 处于 panic 模式，自动端口放行不能解除该策略');
  const runtime = settings(sections.RUNTIME), permanent = settings(sections.PERMANENT);
  const defaultZone = sections.DEFAULT.trim();
  const unique = <T>(values: T[]) => [...new Set(values)];
  const devices = (family: '4' | '6') => unique([...sections['ROUTES' + family].matchAll(/\bdev\s+([A-Za-z0-9_.:@-]+)/g)].map(m => m[1]).filter(v => v !== 'lo'));
  for (const zones of [runtime, permanent]) {
    if (!zones.length) report.issues.push('无法解析 firewalld zone 配置');
    if (zones.some(z => z.fields.sources)) report.warnings.push('存在按来源划分的 zone，特定来源的访问可能受独立策略限制');
    if (zones.some(z => z.customRules)) report.warnings.push('存在 rich rule，自定义规则可能优先影响访问');
  }
  for (const port of ports) {
    let interfaces = unique([...(port.family !== 'ipv6' ? devices('4') : []), ...(port.family !== 'ipv4' ? devices('6') : [])]);
    if (!interfaces.length) {
      // A single active non-loopback interface is a safe fallback on minimal
      // systems without iproute. Multiple candidates require an explicit error.
      const active = unique(runtime.flatMap(z => words(z.fields.interfaces)).filter(v => v !== 'lo'));
      if (active.length === 1) interfaces = active;
      else { report.issues.push(`无法确定 ${port.port}/${port.protocol} 的入口网卡`); continue; }
    }
    for (const scope of ['runtime', 'permanent'] as const) {
      const zones = scope === 'runtime' ? runtime : permanent;
      const services = settings(sections[scope === 'runtime' ? 'SERVICES_R' : 'SERVICES_P'] ?? '');
      const names = unique(interfaces.flatMap(iface => {
        const bound = zones.filter(z => words(z.fields.interfaces).includes(iface));
        if (bound.length > 1) { report.issues.push(`网卡 ${iface} 的 ${scope} zone 绑定不唯一`); return []; }
        const candidates = [bound[0]?.name ?? defaultZone];
        // NetworkManager can own the runtime binding without putting it in
        // firewalld's permanent XML. Keep that zone durable as well, without
        // changing either interface binding or its source-specific policies.
        if (scope === 'permanent') {
          const current = runtime.find(z => words(z.fields.interfaces).includes(iface));
          if (current && zones.some(z => z.name === current.name)) candidates.push(current.name);
        }
        return candidates;
      }).filter(Boolean));
      for (const name of names) {
        const zone = zones.find(z => z.name === name);
        if (!zone) { report.issues.push(`无法确定 ${scope} zone ${name} 的配置`); continue; }
        const serviceAllowed = words(zone.fields.services).some(service => services.some(s => s.name === service && !s.fields.destination && covers(s.fields.ports ?? '', port)));
        if (zone.fields.target?.toUpperCase() === 'ACCEPT' || covers(zone.fields.ports ?? '', port) || serviceAllowed) continue;
        report.missing.push({ zone: name, scope, port: port.port, protocol: port.protocol });
      }
    }
  }
  report.missing = [...new Map(report.missing.map(p => [`${p.scope}/${p.zone}/${p.port}/${p.protocol}`, p])).values()];
  report.issues = unique(report.issues); report.warnings = unique(report.warnings);
  return report;
}

/** Add only required INPUT port permissions. Never reload/flush the firewall,
 * edit source/rich policies, remove existing ports or touch forwarding rules. */
export async function ensureFirewalldPorts(conn: SshConn, ports: InboundPort[], execFn: ExecFn = exec): Promise<FirewalldReport> {
  const before = await inspectFirewalldPorts(conn, ports, execFn);
  if (before.state !== 'running') return before;
  if (before.issues.length) throw new Error(before.issues.join('；'));
  const errors: string[] = [];
  for (const p of before.missing) {
    try {
      await execFn(conn, `firewall-cmd ${p.scope === 'permanent' ? '--permanent ' : ''}--zone=${shQuote(p.zone)} --add-port=${shQuote(`${p.port}/${p.protocol}`)}`, { timeoutClass: 'config' });
    } catch { errors.push(describe(p)); }
  }
  const after = await inspectFirewalldPorts(conn, ports, execFn);
  if (after.state !== 'running') throw new Error('firewalld 状态在放行期间发生变化，无法完成核验');
  if (errors.length || after.issues.length || after.missing.length) {
    throw new Error('firewalld 放行核验失败：' + [...new Set([...errors, ...after.issues, ...after.missing.map(describe)])].slice(0, 20).join('；'));
  }
  return after;
}

export function firewalldDetail(report: FirewalldReport): string {
  if (report.state !== 'running') return report.state === 'inactive' ? 'firewalld 未运行，未配置端口放行' : '未安装 firewall-cmd，未检查其他防火墙';
  return [...report.issues, ...report.missing.map(describe), ...report.warnings].join('；') || '入口 zone 的运行及永久放行规则已核验；不代表云安全组或完整外部链路可达';
}
