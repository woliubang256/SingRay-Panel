import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { App } from 'antd';
import * as api from '../services/api';
import type { Server } from '../services/types';
import { CoreInstallModal } from './CoreInstallModal';

vi.mock('../services/api', () => ({ getCoreVersions: vi.fn(), serverLifecycle: vi.fn() }));

const server = { id: 7, name: 'HK1', singboxVersion: '1.13.18', xrayVersion: '24.11.30' } as Server;
const catalog = { defaultVersion: '1.13.18', versions: ['1.13.18', '1.12.0', 'latest'] };

function setup(core: api.CoreKind = 'singbox') {
  const onClose = vi.fn();
  const onInstalled = vi.fn();
  render(<App><CoreInstallModal server={server} core={core} onClose={onClose} onInstalled={onInstalled} /></App>);
  return { onClose, onInstalled };
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.getCoreVersions).mockResolvedValue(catalog);
  vi.mocked(api.serverLifecycle).mockResolvedValue({ ok: true, steps: ['download 1.12.0'] });
});

describe('CoreInstallModal', () => {
  it('取消弹窗不会安装', async () => {
    const { onClose } = setup();
    await waitFor(() => expect(screen.getByRole('combobox')).toHaveValue('1.13.18'));
    fireEvent.click(screen.getByRole('button', { name: /取\s*消/ }));
    expect(onClose).toHaveBeenCalledOnce();
    expect(api.serverLifecycle).not.toHaveBeenCalled();
  });

  it.each(['singbox', 'xray'] as const)('%s 确认后传递选定版本', async (core) => {
    const { onInstalled } = setup(core);
    const input = screen.getByRole('combobox');
    await waitFor(() => expect(input).toHaveValue('1.13.18'));
    fireEvent.change(input, { target: { value: 'v1.12.0' } });
    fireEvent.click(screen.getByRole('button', { name: '开始安装' }));
    await waitFor(() => expect(api.serverLifecycle).toHaveBeenCalledWith(7, core, 'install', '1.12.0'));
    await waitFor(() => expect(onInstalled).toHaveBeenCalledOnce());
  });

  it('列表加载失败仍可手动输入,非法版本不会提交', async () => {
    vi.mocked(api.getCoreVersions).mockRejectedValue(new Error('offline'));
    setup();
    await screen.findByText('版本列表加载失败，请手动输入版本号后安装。');
    const input = screen.getByRole('combobox');
    fireEvent.change(input, { target: { value: 'bad version' } });
    fireEvent.click(screen.getByRole('button', { name: '开始安装' }));
    await screen.findByText('请输入 x.y.z、vx.y.z 或 latest');
    expect(api.serverLifecycle).not.toHaveBeenCalled();
    fireEvent.change(input, { target: { value: '1.12.0' } });
    fireEvent.click(screen.getByRole('button', { name: '开始安装' }));
    await waitFor(() => expect(api.serverLifecycle).toHaveBeenCalledOnce());
  });

  it('迟到的版本列表不会覆盖手动输入,安装失败时保留输入', async () => {
    let resolve!: (value: typeof catalog) => void;
    vi.mocked(api.getCoreVersions).mockReturnValue(new Promise((done) => { resolve = done; }));
    vi.mocked(api.serverLifecycle).mockResolvedValue({ ok: false, error: 'download failed' });
    const { onInstalled } = setup();
    const input = screen.getByRole('combobox');
    fireEvent.change(input, { target: { value: '1.12.0' } });
    await act(async () => resolve(catalog));
    expect(input).toHaveValue('1.12.0');
    fireEvent.click(screen.getByRole('button', { name: '开始安装' }));
    await screen.findByText('download failed');
    expect(onInstalled).not.toHaveBeenCalled();
    expect(input).toHaveValue('1.12.0');
  });
});
