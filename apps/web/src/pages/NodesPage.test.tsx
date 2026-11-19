// 页面级 smoke:NodesPage 能带着真实数据渲染(表格、探测列),不依赖手工点开浏览器
import { beforeEach, describe, it, expect, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { App } from 'antd';
import * as api from '../services/api';
import type { NodeItem } from '../services/types';

const fx = vi.hoisted(() => ({
  node: {
    id: 1,
    name: 'KEEP-HK',
    serverId: 1,
    serverName: 'HK1',
    protocol: 'vmess',
    listenPort: 30001,
    enabled: 1,
    includeInSub: 1,
    tlsMode: 'tls',
    transport: 'ws',
    outboundType: 'direct',
    shareLink: 'vmess://abc',
    shareLinks: [{ host: 'a.example.com', link: 'vmess://abc' }, { host: 'b.example.com', link: 'vmess://def' }],
    effectiveClientHosts: ['a.example.com', 'b.example.com'],
    note: '',
    createdAt: '2026-10-19T00:00:00.000Z',
  },
  server: {
    id: 1,
    name: 'HK1',
    role: 'relay',
    control: 'ssh',
    host: '1.2.3.4',
    clientHost: '',
    sshPort: 22,
    sshUser: 'root',
    sshAuthType: 'password',
    sshSudo: 0,
    region: 'HK',
    pingStatus: 'online',
    singboxVersion: '1.13.18',
    xrayVersion: '',
    xrayPingStatus: 'unknown',
    xrayLastSeen: null,
    lastSeen: null,
    jumpServerId: null,
    ipStack: 'v4',
    relayMechanism: 'socat',
    preferViaServerId: null,
    portAllow: '',
  },
}));

vi.mock('../services/api', () => ({
  getNodes: vi.fn(async () => [fx.node]),
  getServers: vi.fn(async () => [fx.server]),
  getSnis: vi.fn(async () => []),
  getProbes: vi.fn(async () => [
    { nodeType: 'singbox', nodeId: 1, nodeName: 'KEEP-HK', ok: true, latencyMs: 42, detail: 'TCP connected', checkedAt: new Date().toISOString() },
  ]),
  updateNode: vi.fn(),
  deleteNode: vi.fn(),
  testNode: vi.fn(),
}));

import { NodesPage } from './NodesPage';

beforeEach(() => vi.clearAllMocks());

describe('NodesPage', () => {
  it('toggles subscription visibility separately from enablement and reloads the saved value', async () => {
    render(<App><NodesPage /></App>);
    const toggle = await screen.findByRole('switch', { name: 'KEEP-HK 进订阅' });
    expect(toggle).toBeChecked();
    vi.mocked(api.getNodes).mockResolvedValueOnce([{ ...fx.node, includeInSub: 0 } as NodeItem]);
    fireEvent.click(toggle);
    await waitFor(() => expect(toggle).not.toBeChecked());
    expect(api.updateNode).toHaveBeenLastCalledWith(1, { includeInSub: false });
    expect(screen.getByRole('switch', { name: 'KEEP-HK 启用' })).toBeChecked();
    fireEvent.click(toggle);
    await waitFor(() => expect(api.updateNode).toHaveBeenLastCalledWith(1, { includeInSub: true }));
    await waitFor(() => expect(toggle).toBeChecked());
  });

  it('retains subscription visibility and permits retry when saving fails', async () => {
    vi.mocked(api.updateNode).mockRejectedValueOnce(new Error('save failed'));
    render(<App><NodesPage /></App>);
    const toggle = await screen.findByRole('switch', { name: 'KEEP-HK 进订阅' });
    const reads = vi.mocked(api.getNodes).mock.calls.length;
    fireEvent.click(toggle);
    await waitFor(() => expect(api.updateNode).toHaveBeenCalledWith(1, { includeInSub: false }));
    await waitFor(() => expect(toggle).toBeEnabled());
    expect(toggle).toBeChecked();
    expect(api.getNodes).toHaveBeenCalledTimes(reads);
  });

  it('copies every domain entry with one click', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
    render(<App><NodesPage /></App>);
    fireEvent.click(await screen.findByRole('button', { name: /分享.*2/ }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith('vmess://abc\nvmess://def'));
    expect(screen.getByText('a.example.com、b.example.com')).toBeInTheDocument();
  });
  it('渲染节点表格,并把自动探测结果放进「探测」列', async () => {
    render(
      <App>
        <NodesPage />
      </App>,
    );
    expect(screen.getByText('Singbox 节点')).toBeInTheDocument();
    expect(await screen.findByText('KEEP-HK')).toBeInTheDocument();
    // 探测列:有结果 → 通;hover 才显示延迟
    expect(await screen.findByText('通')).toBeInTheDocument();
    // 端口与入口机来自接口,不该是 undefined
    expect(screen.getByText('30001')).toBeInTheDocument();
    expect(screen.getAllByText('HK1').length).toBeGreaterThan(0);
  });
});
