// Port-forward engine (design.md §4). iptables is the primary mechanism;
// socat (systemd unit) is an explicit user choice — never a silent fallback.
// All rules are tagged `singray:<id>` so reconcile can tell ours apart.

import type { SshConn, ExecFn } from '../ssh/executor.js';
import { exec, writeFile as defaultWriteFile, isSafeHost } from '../ssh/executor.js';
import { applyIptablesForward, inspectIptablesForwards, removeManagedIptables, type ForwardIssue } from './iptables.js';
export { resolveTargetIP } from './iptables.js';

export interface ForwardSpec {
  /** db row id, used in rule comments/unit names */
  id: number;
  entryPort: number;
  landingHost: string;
  targetPort: number;
  mechanism: 'iptables' | 'socat';
}

export interface PreflightResult {
  iptablesAvailable: boolean;
  socatAvailable: boolean;
  ipForward: '1' | '0' | 'unknown';
  entryPortBusy: boolean;
  issues: string[];
}

export async function preflight(conn: SshConn, entryPort: number, execFn: ExecFn = exec): Promise<PreflightResult> {
  const issues: string[] = [];
  let iptablesAvailable = false;
  try {
    const r = await execFn(conn, 'command -v iptables >/dev/null 2>&1 && echo YES || echo NO', { timeoutClass: 'quick' });
    iptablesAvailable = r.stdout.trim() === 'YES';
    if (!iptablesAvailable) issues.push('入口机缺少 iptables 命令');
  } catch (err) {
    issues.push(`iptables 可用性检测失败: ${(err as Error).message}`);
  }

  let ipForward: PreflightResult['ipForward'] = 'unknown';
  try {
    const r = await execFn(conn, 'cat /proc/sys/net/ipv4/ip_forward', { timeoutClass: 'quick' });
    ipForward = r.stdout.trim() === '1' ? '1' : '0';
    if (ipForward === '0') issues.push('入口机未开启 net.ipv4.ip_forward(创建 iptables 规则时将自动开启)');
  } catch {
    issues.push('无法读取 ip_forward 状态');
  }

  let socatAvailable = false;
  try {
    const r = await execFn(conn, 'command -v socat >/dev/null 2>&1 && echo YES || echo NO', { timeoutClass: 'quick' });
    socatAvailable = r.stdout.trim() === 'YES';
  } catch {
    // 探测失败按缺失处理,创建 socat 规则时会得到明确报错
  }

  let entryPortBusy = false;
  // entryPort <= 0 = 还没定端口(NAT 机器留空自动分配):跳过占用检查
  if (entryPort > 0) {
    try {
      const r = await execFn(conn, `ss -tln 2>/dev/null | grep -q ':${entryPort} ' && echo BUSY || echo FREE`, { timeoutClass: 'quick' });
      entryPortBusy = r.stdout.trim() === 'BUSY';
      if (entryPortBusy) issues.push(`入口端口 ${entryPort} 已被占用`);
    } catch {
      // ss 不可用时跳过占用检查,不视为硬错误
    }
  }

  return { iptablesAvailable, socatAvailable, ipForward, entryPortBusy, issues };
}

export async function applyForward(
  conn: SshConn,
  spec: ForwardSpec,
  remove: boolean,
  execFn: ExecFn = exec,
  /** injectable for tests; real impl stages via sftp + sudo install */
  writeFileFn: (conn: SshConn, path: string, content: string, execFn: ExecFn) => Promise<void> = defaultWriteFile,
): Promise<void> {
  // landingHost 来自落地机的 client_host/host,会拼进 getent/iptables/socat 命令:
  // 在这里一次拦住,两种机制都不再需要逐条转义。
  if (!isSafeHost(spec.landingHost)) {
    throw new Error(`落地地址不合法(只能是域名或 IP):${spec.landingHost}`);
  }
  if (spec.mechanism === 'iptables') {
    await applyIptablesForward(conn, spec, remove, execFn, writeFileFn);
    return;
  }

  // socat via systemd unit — explicit mechanism, created/removed idempotently
  const unit = `singray-fwd-${spec.entryPort}.service`;
  if (remove) {
    await removeSocatUnit(conn, unit, execFn);
    return;
  }
  // 确保 socat 二进制存在(显式安装,不是降级)
  await execFn(conn, `(command -v socat >/dev/null || (apt-get update -qq && apt-get install -y -qq socat) || (yum install -y -q socat))`, { timeoutClass: 'install' });
  // IPv6 目标需要 TCP6 + 方括号地址(socat 语法:TCP6:[2607:...]:443)
  const isV6 = spec.landingHost.includes(':');
  const socatTarget = isV6 ? `TCP6:[${spec.landingHost}]:${spec.targetPort}` : `TCP:${spec.landingHost}:${spec.targetPort}`;
  const unitContent = [
    '[Unit]',
    `Description=SingRayPanel port forward ${spec.entryPort} -> ${spec.landingHost}:${spec.targetPort}`,
    'After=network.target',
    '',
    '[Service]',
    'ExecStart=/usr/bin/socat TCP-LISTEN:' + spec.entryPort + ',fork,reuseaddr ' + socatTarget,
    'Restart=always',
    'RestartSec=3',
    '',
    '[Install]',
    'WantedBy=multi-user.target',
    '',
  ].join('\n');
  const { writeFile } = await import('../ssh/executor.js');
  await writeFileFn(conn, `/etc/systemd/system/${unit}`, unitContent, execFn);
  await execFn(conn, `systemctl daemon-reload && systemctl enable --now ${unit}`, { timeoutClass: 'config' });
}

/** 对账修复:停用并删除一个孤儿 socat unit(applyForward 的 socat 删除也走这里) */
export async function removeSocatUnit(conn: SshConn, unit: string, execFn: ExecFn = exec): Promise<void> {
  await execFn(
    conn,
    `systemctl stop ${unit} --quiet 2>/dev/null; systemctl disable ${unit} --quiet 2>/dev/null; rm -f /etc/systemd/system/${unit}; systemctl daemon-reload --quiet`,
    { timeoutClass: 'config' },
  );
}

/**
 * 对账修复:删除一条被判定为孤儿的 iptables 规则。
 * 入参是 `iptables -t nat -S` 的原样输出(`-A PREROUTING …`),把开头的 -A 换成 -D 重放即可。
 */
export async function removeIptablesLine(conn: SshConn, line: string, execFn: ExecFn = exec): Promise<void> {
  const id = /--comment\s+["']?singray:(\d+)\b/.exec(line)?.[1];
  if (!id) throw new Error('Refusing to remove an untagged forwarding rule');
  await removeManagedIptables(conn, Number(id), execFn);
}

export interface ReconcileReport {
  /** iptables DNAT rules with our tag actually present on the machine */
  actualIptables: string[];
  /** singray-fwd-* units actually present */
  actualSocatUnits: string[];
  /** db says iptables but machine lacks it */
  missingIptables: number[];
  /** db says socat but unit missing/inactive */
  missingSocat: number[];
  /** machine has our rules that db doesn't know */
  orphanIptables: string[];
  orphanSocat: string[];
  ruleIssues: ForwardIssue[];
}

/** 对账:机器实际规则 vs DB 期望。dbRules: [{id, mechanism, entryPort}] */
export async function reconcile(
  conn: SshConn,
  dbRules: { id: number; mechanism: 'iptables' | 'socat'; entryPort: number; landingHost?: string; targetPort?: number }[],
  execFn: ExecFn = exec,
): Promise<ReconcileReport> {
  const report: ReconcileReport = {
    actualIptables: [],
    actualSocatUnits: [],
    missingIptables: [],
    missingSocat: [],
    orphanIptables: [],
    orphanSocat: [],
    ruleIssues: [],
  };

  const ipt = await inspectIptablesForwards(conn, dbRules.filter((r) => r.mechanism === 'iptables'), execFn);
  report.actualIptables = ipt.actual;
  report.orphanIptables = ipt.orphan;
  report.ruleIssues = ipt.issues;
  report.missingIptables = ipt.issues.map((r) => r.id);

  const units = await execFn(
    conn,
    `systemctl list-units --quiet 'singray-fwd-*' --no-legend 2>/dev/null | awk '{print $1}' || true`,
    { timeoutClass: 'quick' },
  );
  report.actualSocatUnits = units.stdout.split('\n').map((l) => l.trim()).filter(Boolean);

  const dbSocat = new Set(dbRules.filter((r) => r.mechanism === 'socat').map((r) => r.entryPort));

  for (const unit of report.actualSocatUnits) {
    const m = unit.match(/singray-fwd-(\d+)\.service/);
    const port = m ? Number(m[1]) : null;
    if (port === null || !dbSocat.has(port)) report.orphanSocat.push(unit);
    else dbSocat.delete(port);
  }
  report.missingSocat = [...dbSocat];

  return report;
}
