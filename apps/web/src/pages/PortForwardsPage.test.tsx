import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
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
  reconcilePortForwards: vi.fn(async (_id: number, fix = false) => fix
    ? { ...report(fx.partial ? [3] : []), repaired: { reapplied: fx.partial ? [2, 4] : [2, 3, 4], removed: [], errors: fx.partial ? ['永久规则写入失败'] : [] } }
    : report([2, 3, 4])),
}));
import { PortForwardsPage } from './PortForwardsPage';
beforeEach(() => { vi.clearAllMocks(); fx.partial = false; });

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
