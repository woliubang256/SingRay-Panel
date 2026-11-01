import { createPublicKey, X509Certificate } from 'node:crypto';
import { isIP } from 'node:net';
import { exec, shQuote, type ExecFn, type SshConn } from '../core/ssh/executor.js';
import { probeNode } from '../core/probe/index.js';
import { probeLocalNode } from '../core/probe/ssh.js';
import { inboundPorts } from '../core/firewall/ports.js';
import { inspectFirewalldPorts, firewalldDetail } from '../core/firewall/firewalld.js';

export interface DiagnosticCheck {
  key: string;
  label: string;
  status: 'ok' | 'error' | 'warning' | 'skipped';
  detail: string;
}
export interface DiagnosticTarget {
  host: string;
  port: number;
  sni: string;
  protocol: string;
  tlsMode: string;
  transport: string;
  wsPath: string;
  enabled: boolean;
  pending: boolean;
}
export interface NodeDiagnosticReport {
  checkedAt: string;
  target: { host: string; port: number; sni: string };
  status: 'ok' | 'error' | 'warning';
  summary: string;
  checks: DiagnosticCheck[];
}

type Obj = Record<string, any>;
const obj = (value: unknown): Obj => value && typeof value === 'object' && !Array.isArray(value) ? value as Obj : {};
const transport = (value: unknown) => !value || value === 'raw' ? 'tcp' : value;

/** Read-only; callers hold the machine lock. No raw configuration, SSH errors,
 * key material or journal lines may cross this service's response boundary. */
export async function diagnoseXrayNode(
  conn: SshConn,
  input: DiagnosticTarget,
  inject: { execFn?: ExecFn; probeFn?: typeof probeNode; localProbeFn?: typeof probeLocalNode } = {},
): Promise<NodeDiagnosticReport> {
  const checks: DiagnosticCheck[] = [];
  const add = (key: string, label: string, status: DiagnosticCheck['status'], detail: string) => checks.push({ key, label, status, detail });
  const run: (cmd: string) => Promise<string | null> = async cmd => {
    try { return (await (inject.execFn ?? exec)(conn, cmd, { timeoutClass: 'quick' })).stdout; }
    catch { return null; } // Never serialize SshExecError: its command/output can contain secrets.
  };
  const externalPending = (inject.probeFn ?? probeNode)({ host: input.host, port: input.port,
    sni: input.sni, mode: input.tlsMode === 'tls' ? 'tls' : 'tcp' })
    .catch(() => ({ ok: false, detail: '面板端探测异常' }));

  if (!input.enabled || input.pending) add('deployment', '部署状态', 'warning',
    [!input.enabled ? '节点已停用' : '', input.pending ? '该机器 Xray 有待部署变更，面板配置可能尚未生效' : ''].filter(Boolean).join('；'));
  const [service, listeners, journal] = await Promise.all([
    run('systemctl show xray -p ActiveState -p MainPID'),
    run(`ss -ltnp '( sport = :${input.port} )'`),
    run("journalctl -u xray --since '-15 minutes' -n 60 --no-pager -o cat 2>/dev/null"),
  ]);
  const active = /^ActiveState=active\s*$/m.test(service ?? '');
  const pid = Number(service?.match(/^MainPID=(\d+)\s*$/m)?.[1] ?? 0);
  add('service', 'Xray 进程', service === null ? 'warning' : active ? 'ok' : 'error',
    service === null ? '无法读取服务状态，请检查 SSH 权限及 systemd' : active ? `服务 active（PID ${pid}）` : '服务未处于 active 状态');
  if (listeners === null) add('listener', '端口归属', 'warning', '无法读取监听状态，请检查 ss 是否安装及 SSH 权限');
  else if (!/^LISTEN\s/m.test(listeners)) add('listener', '端口归属', 'error', `未发现 TCP ${input.port} 监听`);
  else {
    const pids = [...listeners.matchAll(/pid=(\d+)/g)].map(m => Number(m[1]));
    const ours = pid > 0 && pids.includes(pid);
    add('listener', '端口归属', pids.length && pid ? (ours && pids.every(p => p === pid) ? 'ok' : 'error') : 'warning',
      pids.length && pid ? (ours && pids.every(p => p === pid) ? '监听属于当前 Xray 主进程' : '该端口存在其他进程监听，与当前 Xray 主进程不一致') : '端口有监听，但无法确认进程归属');
  }

  // Inspect the config named by the running process, rather than assuming the default file is in use.
  let inbound: Obj | undefined;
  if (pid > 0) {
    const commandLine = await run(`tr '\\000' '\\n' < /proc/${pid}/cmdline`);
    const args = (commandLine ?? '').trim().split('\n');
    const flag = args.findIndex(a => ['-c', '-config', '--config'].includes(a));
    const path = flag >= 0 ? args[flag + 1] : args.find(a => /^(?:-c|-config|--config)=/.test(a))?.split('=').slice(1).join('=');
    const multiple = args.filter(a => /^(?:-c|-config|--config)(?:=|$)/.test(a)).length > 1 || args.some(a => /^--?confdir(?:=|$)/.test(a));
    if (!path?.startsWith('/') || multiple) add('config', '运行配置', 'warning', '无法确定唯一的进程配置文件（可能使用配置目录或多个文件）');
    else {
      const raw = await run(`head -c 262144 -- ${shQuote(path)}`);
      let config: Obj | undefined;
      try { if (raw !== null) config = obj(JSON.parse(raw)); } catch { /* no parser error snippets */ }
      if (!config) add('config', '运行配置', 'warning', '运行配置无法读取或不是可解析的 JSON（最大 256 KiB）');
      else {
        const matches = Array.isArray(config.inbounds) ? config.inbounds.map(obj).filter((n: Obj) => Number(n.port) === input.port) : [];
        if (matches.length !== 1) add('config', '运行配置', 'error', '运行配置中未找到唯一的对应端口入站，请检查是否已部署该节点');
        else {
          inbound = matches[0];
          const stream = obj(inbound!.streamSettings);
          const same = inbound!.protocol === input.protocol && transport(stream.network) === transport(input.transport)
            && (stream.security || 'none') === input.tlsMode
            && (input.transport !== 'ws' || (obj(stream.wsSettings).path || '/') === (input.wsPath || '/'));
          add('config', '运行配置', same ? 'ok' : 'error', same ? '进程配置中的协议、传输及 TLS 模式与面板一致' : '进程配置中的协议、传输或 TLS 模式与面板不一致，请重新部署该机器 Xray');
        }
      }
    }
  } else add('config', '运行配置', 'warning', '无法获取 Xray 主进程，未核对运行配置');

  const firewallPending = !input.enabled ? Promise.resolve(null) : Promise.resolve().then(() => inspectFirewalldPorts(conn, inboundPorts('xray', { inbounds: [{
    listen: inbound?.listen ?? '0.0.0.0', port: input.port, protocol: input.protocol, settings: { udp: input.protocol === 'socks' },
  }] }), inject.execFn ?? exec)).catch(() => null);

  if (input.tlsMode === 'tls' && inbound) {
    const certificates = obj(obj(inbound.streamSettings).tlsSettings).certificates;
    const entries: Obj[] = Array.isArray(certificates) ? certificates.slice(0, 8).map(obj) : [];
    const parsed: { cert: X509Certificate; entry: Obj; matches: boolean; valid: boolean }[] = [];
    for (const entry of entries) {
      const pem = typeof entry.certificateFile === 'string' ? await run(`head -c 262144 -- ${shQuote(entry.certificateFile)}`)
        : Array.isArray(entry.certificate) ? entry.certificate.join('\n') : null;
      try {
        if (!pem) continue;
        const cert = new X509Certificate(pem);
        const matches = Boolean(input.sni && (isIP(input.sni) ? cert.checkIP(input.sni) : cert.checkHost(input.sni)));
        parsed.push({ cert, entry, matches, valid: Date.parse(cert.validFrom) <= Date.now() && Date.parse(cert.validTo) > Date.now() });
      } catch { /* cert parsing errors must not include PEM fragments */ }
    }
    const selected = parsed.find(p => p.matches && p.valid) ?? parsed.find(p => p.matches) ?? parsed[0];
    if (!selected) add('certificate', 'TLS 证书', 'error', '无法读取有效证书，请检查运行配置中的证书路径及文件内容');
    else {
      const { cert, entry, matches, valid } = selected;
      const selfSigned = cert.subject === cert.issuer && cert.verify(cert.publicKey);
      add('certificate', 'TLS 证书', !matches || !valid ? 'error' : selfSigned ? 'warning' : 'ok',
        [matches ? '证书覆盖当前 SNI' : '证书未覆盖当前 SNI', valid ? `有效期至 ${new Date(cert.validTo).toISOString()}` : '证书已过期或尚未生效',
          selfSigned ? '使用自签证书，客户端需要信任该证书或明确允许跳过验证' : '此项未验证完整 CA 信任链'].join('；'));
      try {
        const key = typeof entry.keyFile === 'string' ? await run(`openssl pkey -in ${shQuote(entry.keyFile)} -passin pass: -pubout 2>/dev/null`)
          : Array.isArray(entry.key) ? entry.key.join('\n') : null;
        if (!key) throw new Error('unavailable');
        const publicDer = createPublicKey(key).export({ type: 'spki', format: 'der' });
        const same = publicDer.equals(cert.publicKey.export({ type: 'spki', format: 'der' }));
        add('key', '证书与私钥', same ? 'ok' : 'error', same ? '证书与私钥匹配（仅读取公钥进行比对）' : '证书与私钥不匹配');
      } catch { add('key', '证书与私钥', 'warning', '无法校验私钥匹配，请检查文件权限及 openssl；诊断不会返回私钥'); }
    }
  } else add('certificate', 'TLS 证书', 'skipped', input.tlsMode !== 'tls' ? '当前节点不使用普通 TLS 证书' : '尚未确定对应入站，无法检查证书');

  const local = await (inject.localProbeFn ?? probeLocalNode)(conn, { port: input.port, sni: input.sni,
    mode: input.tlsMode === 'tls' ? 'tls' : 'tcp', host: inbound?.listen === '::' || inbound?.listen === '::1' ? '::1' : '127.0.0.1' })
    .catch(() => ({ status: 'unavailable' as const, detail: 'SSH 本机探测异常，无法判断本机服务' }));
  add('local', input.tlsMode === 'tls' ? '本机 TLS 握手' : '本机 TCP 连接', local.status === 'unavailable' ? 'warning' : local.status, local.detail);
  const external = await externalPending;
  add('external', '面板访问入口', external.ok ? 'ok' : 'error', external.detail);
  const firewall = await firewallPending;
  if (!input.enabled) add('firewall', 'firewalld INPUT 放行', 'skipped', '节点已停用，不要求配置对外端口放行');
  else if (!firewall) add('firewall', 'firewalld INPUT 放行', 'warning', '无法读取完整的 firewalld 配置，请检查 SSH、防火墙权限及 D-Bus；未据此判断端口已放行');
  else add('firewall', 'firewalld INPUT 放行', firewall.state !== 'running' ? 'skipped'
    : firewall.issues.length || firewall.missing.some(p => p.scope === 'runtime') ? 'error'
    : firewall.missing.length || firewall.warnings.length ? 'warning' : 'ok',
    firewalldDetail(firewall) + (firewall.missing.length ? '；可在服务器页重新部署该机器 Xray 补齐' : ''));

  // Return only known error categories. Redacting arbitrary free-form journal text
  // cannot reliably remove old passwords, URLs or tokens from previous configs.
  const categories: [RegExp, string][] = [
    [/address already in use|bind.*permission denied/i, '端口绑定失败'],
    [/(?:failed|unable|error).*(?:certificate|private key)|(?:certificate|private key).*(?:failed|error)/i, '证书或私钥读取失败'],
    [/tls.*handshake.*(?:error|fail|timeout)|tls:.*(?:bad certificate|unknown certificate)/i, 'TLS 握手异常'],
    [/invalid (?:user|password)|authentication failed/i, '代理认证失败'],
    [/failed to (?:load|parse).*config/i, '配置加载失败'],
    [/failed to dial|network is unreachable|i\/o timeout|connection refused/i, '连接目标失败或超时'],
  ];
  const lines = (journal ?? '').slice(0, 65536).split('\n');
  const errors = categories.map(([pattern, label]) => ({ label, count: lines.filter(line => pattern.test(line)).length })).filter(c => c.count);
  add('logs', '最近 15 分钟日志摘要', journal === null ? 'warning' : errors.length ? 'warning' : 'skipped',
    journal === null ? '无法读取 journal 日志' : errors.length ? errors.map(c => `${c.label}：${c.count} 条`).join('；')
      : '最近最多 60 行未发现可识别的错误；原始日志不返回浏览器');

  const status = checks.some(c => c.status === 'error') ? 'error' : checks.some(c => c.status === 'warning') ? 'warning' : 'ok';
  const summary = local.status === 'error' ? '本机服务连接或握手异常，优先处理运行配置、监听及证书检查项。'
    : checks.some(c => !['external', 'local', 'firewall'].includes(c.key) && c.status === 'error') ? '发现本机进程、监听或配置异常，请优先处理下方异常项。'
    : checks.some(c => c.key === 'firewall' && c.status === 'error') ? 'firewalld INPUT 放行缺失或策略异常，请查看具体 zone/端口；可重新部署该机器 Xray 修复端口规则。'
    : !external.ok && local.status === 'ok' ? '本机连接正常，外部入口访问失败，请检查域名解析、安全组、防火墙及网络路径。'
    : status === 'error' ? '发现节点配置或入口访问异常，请按下方检查项处理。'
    : status === 'warning' ? '检查存在警告或未完成项目，请查看详情。'
    : '本次 TCP/TLS 与配置检查通过；未验证代理密码、Reality 认证及完整出站访问。';
  return { checkedAt: new Date().toISOString(), target: { host: input.host, port: input.port, sni: input.sni }, status, summary, checks };
}
