import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { App, ConfigProvider } from 'antd';
import * as api from '../services/api';
import { ExternalNodesPage } from './ExternalNodesPage';
const fx = vi.hoisted(() => ({ row: { id: 1, name: '外部香港', protocol: 'trojan', host: 'hk.example', port: 443, enabled: 1, includeInSub: 1,
  note: '备注', formats: ['base64', 'clash', 'singbox'], probeStatus: null, latencyMs: null, probeDetail: '', checkedAt: null, createdAt: '' } }));
vi.mock('../services/api', () => ({
  getExternalNodes: vi.fn(async () => [fx.row]),
  updateExternalNode: vi.fn(async () => ({ ok: true })), deleteExternalNode: vi.fn(async () => ({ ok: true })),
  testExternalNode: vi.fn(async () => ({ status: 'ok', latencyMs: 123, detail: 'HTTPS OK', checkedAt: '2026-11-12T00:00:00Z' })),
  testExternalNodes: vi.fn(async () => ({ results: [{ id: 1, status: 'failed', latencyMs: null, detail: '代理认证失败', checkedAt: '2026-11-12T00:00:00Z' }] })),
  previewExternalNodes: vi.fn(async () => ({ items: [{ index: 0, name: '导入节点', protocol: 'vless', host: 'example.com', port: 443, formats: ['base64', 'clash', 'singbox'], duplicate: false, warning: '' },
    { index: 2, name: '重复节点', protocol: 'vless', host: 'example.com', port: 443, formats: ['base64'], duplicate: true, warning: '' }], errors: [{ index: 1, error: '格式无效' }] })),
  importExternalNodes: vi.fn(async () => ({ created: 1, skipped: 0 })),
}));
const show = () => render(<ConfigProvider theme={{ token: { motion: false } }}><App><ExternalNodesPage /></App></ConfigProvider>);
beforeEach(() => { vi.clearAllMocks(); });
describe('external nodes page', () => {
  it('controls subscription inclusion and displays real latency and batch failure details', async () => {
    show(); const name = await screen.findByText('外部香港'); const row = within(name.closest('tr')!);
    fireEvent.click(row.getByRole('switch', { name: '加入订阅' }));
    await waitFor(() => expect(api.updateExternalNode).toHaveBeenCalledWith(1, { includeInSub: false }));
    fireEvent.click(row.getByRole('button', { name: /测试/ }));
    expect(await screen.findByText('123 ms')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /批量测试/ }));
    await waitFor(() => expect(api.testExternalNodes).toHaveBeenCalledWith([1]));
    expect(await screen.findByText('代理认证失败')).toBeInTheDocument();
  });
  it('previews before importing and selects only valid nonduplicate entries', async () => {
    show(); await screen.findByText('外部香港'); fireEvent.click(screen.getByRole('button', { name: /导入节点/ }));
    const modal = within(await screen.findByRole('dialog'));
    expect(modal.getByText('导入外部节点')).toBeInTheDocument();
    fireEvent.change(modal.getByLabelText('节点内容'), { target: { value: 'vless://uuid@example.com:443#N' } });
    fireEvent.click(modal.getByRole('button', { name: /预览/ }));
    expect(await modal.findByText('格式无效')).toBeInTheDocument();
    expect(api.importExternalNodes).not.toHaveBeenCalled();
    fireEvent.click(modal.getByRole('button', { name: /确认导入/ }));
    await waitFor(() => expect(api.importExternalNodes).toHaveBeenCalledWith('vless://uuid@example.com:443#N', [0], false));
  });
  it('edits labels without replacing connection details and keeps the dialog on failure', async () => {
    vi.mocked(api.updateExternalNode).mockRejectedValueOnce(new Error('save failed'));
    show(); const name = await screen.findByText('外部香港'); fireEvent.click(within(name.closest('tr')!).getByRole('button', { name: /编辑/ }));
    const modal = within(await screen.findByRole('dialog'));
    expect(modal.getByText('编辑外部节点')).toBeInTheDocument();
    expect(modal.getByLabelText('名称')).toHaveValue('外部香港');
    fireEvent.change(modal.getByLabelText('名称'), { target: { value: '自定义名称' } });
    fireEvent.change(modal.getByLabelText('备注'), { target: { value: '' } });
    fireEvent.click(modal.getByRole('button', { name: /保\s*存/ }));
    await waitFor(() => expect(api.updateExternalNode).toHaveBeenCalledWith(1, { name: '自定义名称', note: '' }));
    expect(modal.getByLabelText('名称')).toHaveValue('自定义名称');
  });
});
