import { describe, it, expect, vi, afterEach } from 'vitest';
import { isVersionSpec, PINNED_SINGBOX_VERSION, PINNED_XRAY_VERSION } from './versions.js';

describe('versions', () => {
  it('默认固定版本自身必须是合法版本号', () => {
    expect(isVersionSpec(PINNED_SINGBOX_VERSION)).toBe(true);
    expect(isVersionSpec(PINNED_XRAY_VERSION)).toBe(true);
  });

  it('只接受 latest 或 x.y.z(可带 v 前缀)', () => {
    for (const ok of ['latest', '1.13.18', 'v24.11.30', '0.0.1']) expect(isVersionSpec(ok)).toBe(true);
    for (const bad of ['', 'v24', '1.13', 'latestx', '1.13.18-beta', ' ']) expect(isVersionSpec(bad)).toBe(false);
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('official core version catalog', () => {
  it('过滤预发布和非法版本,去重并复用缓存', async () => {
    vi.resetModules();
    const { getCoreVersions } = await import('./versions.js');
    const fetchFn = vi.fn(async (_url: string) => ({ ok: true, json: async () => [
      { tag_name: 'v1.13.18' }, { tag_name: '1.13.18' }, { tag_name: 'v1.12.0' },
      { tag_name: 'v1.14.0', prerelease: true }, { tag_name: 'v1.15.0', draft: true },
      { tag_name: 'v1.16.0;bad' }, null,
    ] }));
    vi.stubGlobal('fetch', fetchFn);
    const [a, b] = await Promise.all([
      getCoreVersions('singbox', '1.13.18'), getCoreVersions('singbox', '1.13.18'),
    ]);
    expect(a.versions).toEqual(['1.13.18', 'latest', '1.12.0']);
    expect(b).toEqual(a);
    await getCoreVersions('singbox', '1.12.0');
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(fetchFn.mock.calls[0]?.[0]).toContain('SagerNet/sing-box/releases');
  });

  it('上游失败仍返回面板默认版本和警告', async () => {
    vi.resetModules();
    const { getCoreVersions } = await import('./versions.js');
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('offline'); }));
    const result = await getCoreVersions('xray', '24.11.30');
    expect(result).toMatchObject({ defaultVersion: '24.11.30', versions: ['24.11.30', 'latest'] });
    expect(result.warning).toBeTruthy();
  });

  it('缓存过期后遇到限流保留之前的版本列表', async () => {
    vi.resetModules();
    const { getCoreVersions } = await import('./versions.js');
    const now = vi.spyOn(Date, 'now').mockReturnValue(1000);
    const fetchFn = vi.fn().mockResolvedValueOnce({ ok: true, json: async () => [{ tag_name: 'v25.1.1' }] })
      .mockResolvedValue({ ok: false, status: 403 });
    vi.stubGlobal('fetch', fetchFn);
    await getCoreVersions('xray', '24.11.30');
    now.mockReturnValue(601001);
    const result = await getCoreVersions('xray', '24.11.30');
    expect(result.versions).toContain('25.1.1');
    expect(result.warning).toBeTruthy();
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });
});
