import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DIR = path.dirname(fileURLToPath(import.meta.url));

const RAW_DB = process.env.PANEL_DB ?? './data/panel.db';

// 下载前缀:`.env` 里写 `XXX_DOWNLOAD_BASE=`(空串)时必须回退默认值, 否则拼出的
// URL 会退化成 `/v1.13.18/...`, 直连必然失败, 镜像再拼成
// `https://gh-proxy.org//v1.13.18/...` 就是 404 —— 症状是"两个核心都下载失败"。
// 顺带去掉结尾斜杠, 避免出现 `//v...`。
function urlBase(raw: string | undefined, fallback: string): string {
  const v = (raw ?? '').trim().replace(/\/+$/, '');
  return v || fallback;
}

export const config = {
  host: process.env.PANEL_HOST ?? '127.0.0.1',
  port: Number(process.env.PANEL_PORT ?? 3000),
  // ':memory:' 哨兵直传(测试用),其余路径基于 server 包目录解析
  dbPath: RAW_DB === ':memory:' ? RAW_DB : path.resolve(DIR, '../..', RAW_DB),
  // 用 || 而非 ??:env 里写了 `PANEL_JWT_SECRET=`(空串)时也要视为未配置,
  // 否则空密钥既不触发下面的防护, 又会让 JWT 签名失去意义。
  jwtSecret: process.env.PANEL_JWT_SECRET || 'dev-only-change-me',
  // 字段加密密钥:旧面板用独立 APP_SECRET,迁移场景必须设为旧值,否则旧密文解不开
  appSecret: process.env.PANEL_APP_SECRET || process.env.PANEL_JWT_SECRET || 'dev-only-change-me',
  // 核心安装(生命周期)配置
  singboxDownloadBase: urlBase(process.env.SINGBOX_DOWNLOAD_BASE, 'https://github.com/SagerNet/sing-box/releases/download'),
  singboxVersion: (process.env.SINGBOX_VERSION ?? '').trim() || 'latest',
  xrayDownloadBase: urlBase(process.env.XRAY_DOWNLOAD_BASE, 'https://github.com/XTLS/Xray-core/releases/download'),
  xrayVersion: (process.env.XRAY_VERSION ?? '').trim() || 'latest',
  // 运维:数据库备份(空 = db 同目录 backups/;保留份数;每日备份小时)
  backupDir: process.env.PANEL_BACKUP_DIR ?? '',
  backupRetention: Number(process.env.PANEL_BACKUP_RETENTION ?? 14),
  backupHour: Number(process.env.PANEL_BACKUP_HOUR ?? 4),
  // 运维:健康检查间隔(分钟)
  healthIntervalMin: Number(process.env.PANEL_HEALTH_INTERVAL ?? 5),
  // ACME DNS-01:Cloudflare API Token(配置后证书签发走 DNS-01,无需 80 端口)
  cfToken: process.env.PANEL_CF_TOKEN ?? '',
  // 告警:Telegram Bot(未配置 = 仅落库不推送)
  tgBotToken: process.env.TG_BOT_TOKEN ?? '',
  tgChatId: process.env.TG_CHAT_ID ?? '',
};

// 生产防护:对外监听时禁止使用仓库默认密钥(否则任何知道仓库的人可伪造 admin JWT)
// 除代码兜底值外, 还要挡掉 .env.example 历史版本里出现过的占位串 —— 照抄模板的人
// 会带着一个人人可猜的密钥跑起来, 且看起来"已配置"。
const DEFAULT_SECRETS = new Set(['dev-only-change-me', 'change-me-openssl-rand-hex-32']);
const weakSecrets = [config.jwtSecret, config.appSecret].filter((s) => DEFAULT_SECRETS.has(s));
if (!['127.0.0.1', 'localhost'].includes(process.env.PANEL_HOST ?? '127.0.0.1') && weakSecrets.length > 0) {
  throw new Error(`拒绝启动:对外监听(PANEL_HOST 非 127.0.0.1)禁止使用默认密钥,请配置 ${weakSecrets.join(' 与 ')}(openssl rand -hex 32)`);
}
