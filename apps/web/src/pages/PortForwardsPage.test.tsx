import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { App } from 'antd';
import * as api from '../services/api';

const fx = vi.hoisted(() => ({
  partial: false,
  forwards: [2, 3, 4].map((id) => ({
    id, name: ['hk-sanjose-trojan', 'hk-tokyo-trojan', 'hk-singapore-trojan'][id - 2],
    entryServerId: 1, entryServerName: 'HK', landingServerId: 2, landingServerName: 'landing',
    targetNodeType: 'xray', targetNodeId: id, targetNodeName: 'trojan-' + id,
    entryPort: 31219 + id, targetPort: 31932 + id, mechanism: 'iptables',
    enabled: 1, includeInSub: 1, core: 'xray', auto: 0, note: '', createdAt: '',
  })),
}));
function report(ids: number[] = []) {
  return { actualIptables: [], actualSocatUnits: [], missingIptables: ids, missingSocat: [],
    orphanIptables: [], orphanSocat: [], verified: true,
    ruleIssues: ids.map(id => ({ id, entryPort: 31219 + id, issues: ['源地址转换缺失'] })) };
}
vi.mock('../services/api', () => ({
  getPortForwards: vi.fn(async () => fx.forwards),
  getServers: vi.fn(async () => [
    { id: 1, name: 'HK', host: '10.0.0.1', clientHost: '', role: 'relay', control: 'ssh' },
    { id: 2, name: 'landing', host: '10.0.0.2', clientHost: '', role: 'landing', control: 'ssh' },
  ]),
  getNodes: vi.fn(async () => []), getXrayNodes: vi.fn(async () => []),
  updatePortForward: vi.fn(async () => ({ ok: true })),
  reconcilePortForwards: vi.fn(async (_id: number, fix = false) => fix
    ? { ...report(fx.partial ? [3] : []), repaired: { reapplied: fx.partial ? [2, 4] : [2, 3, 4], removed: [], errors: fx.partial ? ['永久规则写入失败'] : [] } }
    : report([2, 3, 4])),
}));
import { PortForwardsPage } from './PortForwardsPage';
const initialForwards = fx.forwards.map((f) => ({ ...f }));
beforeEach(() => {
  vi.clearAllMocks(); fx.partial = false;
  fx.forwards = initialForwards.map((f) => ({ ...f }));
});

describe('forward name and note editing', () => {
  const openEdit = async (name = 'hk-sanjose-trojan') => {
    const cell = await screen.findByText(name);
    fireEvent.click(within(cell.closest('tr')!).getByRole('button', { name: /编辑/ }));
    return within(await screen.findByRole('dialog', { name: '编辑中转规则' }));
  };

  it('prefills the selected rule and saves only its name and note, then refreshes the list', async () => {
    fx.forwards[0].note = '原备注';
    vi.mocked(api.updatePortForward).mockImplementationOnce(async () => {
      fx.forwards = fx.forwards.map((f) => f.id === 2 ? { ...f, name: '香港→圣何塞', note: '主用线路' } : f);
      return { ok: true };
    });
    render(<App><PortForwardsPage /></App>);
    const modal = await openEdit();
    expect(modal.getByLabelText('名称')).toHaveValue('hk-sanjose-trojan');
    expect(modal.getByLabelText('备注')).toHaveValue('原备注');
    fireEvent.change(modal.getByLabelText('名称'), { target: { value: '  香港→圣何塞  ' } });
    fireEvent.change(modal.getByLabelText('备注'), { target: { value: '主用线路' } });
    fireEvent.click(modal.getByRole('button', { name: /保\s*存/ }));
    await waitFor(() => expect(api.updatePortForward).toHaveBeenCalledWith(2, { name: '香港→圣何塞', note: '主用线路' }));
    expect(await screen.findByText('香港→圣何塞')).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(screen.getByText('hk-tokyo-trojan')).toBeInTheDocument();
  });

  it('rejects blank names and discards cancelled changes before editing another rule', async () => {
    fx.forwards[1].note = '东京备注';
    render(<App><PortForwardsPage /></App>);
    const modal = await openEdit();
    fireEvent.change(modal.getByLabelText('名称'), { target: { value: '   ' } });
    fireEvent.click(modal.getByRole('button', { name: /保\s*存/ }));
    expect(await modal.findByText('请输入名称')).toBeInTheDocument();
    expect(api.updatePortForward).not.toHaveBeenCalled();
    fireEvent.click(modal.getByRole('button', { name: /取\s*消/ }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    const next = await openEdit('hk-tokyo-trojan');
    expect(next.getByLabelText('名称')).toHaveValue('hk-tokyo-trojan');
    expect(next.getByLabelText('备注')).toHaveValue('东京备注');
    expect(api.updatePortForward).not.toHaveBeenCalled();
  });

  it('keeps unsaved edits after an API failure and allows clearing a note on retry', async () => {
    fx.forwards[0].note = '原备注';
    vi.mocked(api.updatePortForward).mockRejectedValueOnce(new Error('保存失败')).mockImplementationOnce(async () => {
      fx.forwards = fx.forwards.map((f) => f.id === 2 ? { ...f, name: '重命名', note: '' } : f);
      return { ok: true };
    });
    render(<App><PortForwardsPage /></App>);
    const modal = await openEdit();
    fireEvent.change(modal.getByLabelText('名称'), { target: { value: '重命名' } });
    fireEvent.change(modal.getByLabelText('备注'), { target: { value: '' } });
    fireEvent.click(modal.getByRole('button', { name: /保\s*存/ }));
    await waitFor(() => expect(api.updatePortForward).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(modal.getByRole('button', { name: /保\s*存/ })).not.toHaveClass('ant-btn-loading'));
    expect(modal.getByLabelText('名称')).toHaveValue('重命名');
    expect(screen.getByText('hk-sanjose-trojan')).toBeInTheDocument();
    fireEvent.click(modal.getByRole('button', { name: /保\s*存/ }));
    await waitFor(() => expect(api.updatePortForward).toHaveBeenLastCalledWith(2, { name: '重命名', note: '' }));
    expect(await screen.findByText('重命名')).toBeInTheDocument();
  });
});

describe('forward configuration health', () => {
  it('automatically inspects the shared entry once and repairs all three routes from the page', async () => {
    render(<App><PortForwardsPage /></App>);
    expect(await screen.findAllByText('需要修复')).toHaveLength(3);
    expect(api.reconcilePortForwards).toHaveBeenCalledTimes(1);
    expect(api.reconcilePortForwards).toHaveBeenCalledWith(1, false);
    fireEvent.click(screen.getByRole('button', { name: '一键修复' }));
    await waitFor(() => expect(api.reconcilePortForwards).toHaveBeenCalledWith(1, true));
    expect(await screen.findAllByText('配置正常')).toHaveLength(3);
    expect(screen.queryByText('需要修复')).not.toBeInTheDocument();
    expect(vi.mocked(api.reconcilePortForwards).mock.calls.every(([id]) => id === 1)).toBe(true);
  });

  it('shows an SSH inspection failure instead of a healthy configuration', async () => {
    vi.mocked(api.reconcilePortForwards).mockRejectedValueOnce(new Error('SSH connection refused'));
    render(<App><PortForwardsPage /></App>);
    expect(await screen.findAllByText('检测失败')).toHaveLength(3);
    expect(screen.queryByText('配置正常')).not.toBeInTheDocument();
    expect(screen.getByText(/SSH connection refused/)).toBeInTheDocument();
  });

  it('keeps the failed route marked after a partial repair', async () => {
    fx.partial = true;
    render(<App><PortForwardsPage /></App>);
    await screen.findAllByText('需要修复');
    fireEvent.click(screen.getByRole('button', { name: '一键修复' }));
    expect(await screen.findAllByText('配置正常')).toHaveLength(2);
    expect(screen.getAllByText('需要修复')).toHaveLength(1);
    expect(await screen.findByText(/永久规则写入失败/)).toBeInTheDocument();
  });
});
