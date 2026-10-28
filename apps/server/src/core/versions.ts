// 核心版本的默认值:**固定**版本,不追 latest。
//
// 理由:面板会在部署时自动安装核心二进制;默认 latest 意味着"某天上游发版,
// 你的机器第二天就跑上了没人验证过的核心"。升级应该是显式动作:
//   - 改 SINBOX_VERSION / XRAY_VERSION 环境变量,
//   - 或先用「回退版本」(lifecycle rollback)留好退路。
export const PINNED_SINGBOX_VERSION = '1.13.18';
export const PINNED_XRAY_VERSION = '24.11.30';

/** 合法取值:`latest` 或 `x.y.z`(允许前缀 v) */
export const isVersionSpec = (v: string): boolean => v === 'latest' || /^v?\d+\.\d+\.\d+$/.test(v);

export type CoreKind = 'singbox' | 'xray';

const RELEASE_REPOS: Record<CoreKind, string> = {
  singbox: 'SagerNet/sing-box',
  xray: 'XTLS/Xray-core',
};

interface ReleaseCatalog {
  versions: string[];
  expiresAt: number;
  warning?: string;
}

const catalogs = new Map<CoreKind, ReleaseCatalog>();
const pending = new Map<CoreKind, Promise<ReleaseCatalog>>();

async function loadCatalog(core: CoreKind): Promise<ReleaseCatalog> {
  try {
    const res = await fetch(`https://api.github.com/repos/${RELEASE_REPOS[core]}/releases?per_page=100`, {
      signal: AbortSignal.timeout(8000),
      headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'SingRay-Panel' },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const releases: unknown = await res.json();
    if (!Array.isArray(releases)) throw new Error('invalid releases');
    const versions = [...new Set(releases.flatMap((release: unknown) => {
      if (!release || typeof release !== 'object') return [];
      const r = release as Record<string, unknown>;
      return !r.draft && !r.prerelease && typeof r.tag_name === 'string' &&
        r.tag_name !== 'latest' && isVersionSpec(r.tag_name)
        ? [r.tag_name.replace(/^v/, '')] : [];
    }))];
    if (!versions.length) throw new Error('no stable releases');
    return { versions, expiresAt: Date.now() + 10 * 60_000 };
  } catch {
    return {
      versions: catalogs.get(core)?.versions ?? [],
      expiresAt: Date.now() + 60_000,
      warning: '暂时无法获取官方版本列表，可选择已有版本或手动输入版本号。',
    };
  }
}

/** 只访问固定官方仓库;短暂失败保留旧列表,并允许手动指定更早的稳定版本。 */
export async function getCoreVersions(core: CoreKind, defaultVersion: string): Promise<{
  defaultVersion: string;
  versions: string[];
  warning?: string;
}> {
  let catalog = catalogs.get(core);
  if (!catalog || catalog.expiresAt <= Date.now()) {
    let request = pending.get(core);
    if (!request) {
      request = loadCatalog(core).then((result) => {
        catalogs.set(core, result);
        return result;
      }).finally(() => pending.delete(core));
      pending.set(core, request);
    }
    catalog = await request;
  }
  return {
    defaultVersion,
    versions: [...new Set([defaultVersion, 'latest', ...catalog.versions])],
    ...(catalog.warning ? { warning: catalog.warning } : {}),
  };
}
