import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { App } from 'antd';
import * as api from '../services/api';
import type { NodeItem, Server, XrayNodeItem } from '../services/types';
import { NodesPage } from '../pages/NodesPage';
import { XrayNodesPage } from '../pages/XrayNodesPage';
import { NodeCreateModal } from './NodeCreateModal';
import { XrayNodeCreateModal } from './XrayNodeCreateModal';

vi.mock('../services/api', () => ({
  getNodes: vi.fn(), getXrayNodes: vi.fn(), getServers: vi.fn(), getSnis: vi.fn(), getProbes: vi.fn(),
  createNode: vi.fn(), createXrayNode: vi.fn(), updateNode: vi.fn(), updateXrayNode: vi.fn(),
}));

const server = { id: 7, name: 'HK', role: 'relay', host: '10.0.0.7', clientHost: 'a.example.com',
  clientHosts: ['a.example.com', 'b.example.com'], pingStatus: 'online' } as Server;
const firstServer = { ...server, id: 3, name: 'JP' };
const landing = { ...server, id: 9, name: 'Landing', role: 'landing' as const };
const servers = [firstServer, server, landing];
const snis = [{ id: 1, domain: 'default.example.com', note: '', builtin: 1 }];
const source: NodeItem & XrayNodeItem = {
  id: 1, name: 'HK-main', serverId: 7, serverName: 'HK', protocol: 'vless', listenPort: 31001,
  enabled: 1, tlsMode: 'reality', transport: 'raw', sni: 'borrow.example.com', flow: 'xtls-rprx-vision',
  outboundType: 'proxy', proxyUrl: 'socks5://user:pass@1.2.3.4:5678', clientHosts: ['b.example.com'],
  effectiveClientHosts: ['b.example.com'], shareLink: 'vless://first',
  shareLinks: [{ host: 'a.example.com', link: 'vless://first' }, { host: 'b.example.com', link: 'vless://second' }],
  note: '', createdAt: '2026-11-08',
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.getNodes).mockResolvedValue([source]);
  vi.mocked(api.getXrayNodes).mockResolvedValue([source]);
  vi.mocked(api.getServers).mockResolvedValue(servers);
  vi.mocked(api.getSnis).mockResolvedValue(snis);
  vi.mocked(api.getProbes).mockResolvedValue([]);
  vi.mocked(api.createNode).mockResolvedValue({ ...source, id: 99 });
  vi.mocked(api.createXrayNode).mockResolvedValue({ ...source, id: 99 });
});

for (const core of ['singbox', 'xray'] as const) {
  const create = core === 'singbox' ? api.createNode : api.createXrayNode;
  const renderPage = () => render(<App>{core === 'singbox' ? <NodesPage /> : <XrayNodesPage />}</App>);

  describe(`${core} sharing and node copying`, () => {
    it('shares all entry links with the share icon and places node copying before editing', async () => {
      const writeText = vi.fn().mockResolvedValue(undefined);
      Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
      renderPage();
      const share = await screen.findByRole('button', { name: /分享.*2/ });
      expect(within(share).getByRole('img', { name: 'share-alt' })).toBeInTheDocument();
      fireEvent.click(share);
      await waitFor(() => expect(writeText).toHaveBeenCalledWith('vless://first\nvless://second'));
      const row = within(share.closest('tr')!);
      const actions = row.getAllByRole('button');
      const copy = row.getByText('复制').closest('button')!;
      const edit = row.getByText('编辑').closest('button')!;
      expect(actions.indexOf(copy)).toBeLessThan(actions.indexOf(edit));
      expect(create).not.toHaveBeenCalled();
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });

    it('opens an editable creation draft and creates with copied settings and an automatically allocated port', async () => {
      renderPage();
      fireEvent.click(await screen.findByText('复制'));
      const name = await screen.findByLabelText(/2 · 节点名称/);
      const dialog = within(name.closest('[role="dialog"]')!);
      await waitFor(() => expect(name).toHaveValue('HK-main-副本'));
      expect(screen.getByLabelText(/端口\(可选/)).toHaveValue('');
      expect(await screen.findByLabelText('代理链接')).toHaveValue(source.proxyUrl);
      expect(create).not.toHaveBeenCalled();
      fireEvent.change(name, { target: { value: 'HK-copy-edited' } });
      fireEvent.click(dialog.getByRole('button', { name: /创\s*建/ }));
      await waitFor(() => expect(create).toHaveBeenCalledWith(expect.objectContaining({
        template: core === 'singbox' ? 'vless-reality' : 'xray-vless-reality',
        name: 'HK-copy-edited', serverId: 7, clientHosts: ['b.example.com'], sni: 'borrow.example.com',
        outboundType: 'proxy', proxyUrl: source.proxyUrl, port: undefined,
      })));
      expect(api.updateNode).not.toHaveBeenCalled();
      expect(api.updateXrayNode).not.toHaveBeenCalled();
      expect(source.name).toBe('HK-main');
    });

    it('cancels without creating and resets the next ordinary creation form', async () => {
      renderPage();
      fireEvent.click(await screen.findByText('复制'));
      await waitFor(() => expect(screen.getByLabelText(/2 · 节点名称/)).toHaveValue('HK-main-副本'));
      const dialog = within(screen.getByLabelText(/2 · 节点名称/).closest('[role="dialog"]')!);
      fireEvent.change(screen.getByLabelText(/端口\(可选/), { target: { value: '32001' } });
      fireEvent.click(dialog.getByRole('button', { name: /取\s*消/ }));
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
      expect(create).not.toHaveBeenCalled();
      fireEvent.click(screen.getByText(core === 'singbox' ? '新建节点' : '新建 Xray 节点'));
      await waitFor(() => expect(screen.getByLabelText(/2 · 节点名称/)).toHaveValue(core === 'singbox' ? 'JP-vless-reality-sb' : 'JP-vless-reality-xray'));
      expect(screen.queryByLabelText('代理链接')).not.toBeInTheDocument();
      expect(screen.getByLabelText(/端口\(可选/)).toHaveValue('');
      fireEvent.click(within(screen.getByLabelText(/2 · 节点名称/).closest('[role="dialog"]')!).getByRole('button', { name: /创\s*建/ }));
      await waitFor(() => expect(create).toHaveBeenCalledWith(expect.objectContaining({
        serverId: 3, outboundType: 'direct', clientHosts: [], proxyUrl: undefined, port: undefined, sni: 'default.example.com',
      })));
    });
  });
}

it('allows configuring the Reality SNI when creating an XHTTP node', async () => {
  render(<App><XrayNodeCreateModal open servers={servers} landings={[landing]} snis={snis} onClose={vi.fn()} onCreated={vi.fn()} /></App>);
  fireEvent.click(screen.getByText('VLESS + XHTTP'));
  expect(await screen.findByLabelText('Reality 借站域名(SNI)')).toBeInTheDocument();
  expect(screen.queryByLabelText('Flow 控制')).not.toBeInTheDocument();
});

it('copies XHTTP as XHTTP, preserving its SNI and relay instead of enabling Vision flow', async () => {
  const initialNode: XrayNodeItem = { ...source, transport: 'xhttp', flow: '', outboundType: 'relay', landingServerId: 9 };
  render(<App><XrayNodeCreateModal open initialNode={initialNode} servers={servers} landings={[landing]} snis={snis} onClose={vi.fn()} onCreated={vi.fn()} /></App>);
  await waitFor(() => expect(screen.getByLabelText(/2 · 节点名称/)).toHaveValue('HK-main-副本'));
  expect(await screen.findByLabelText('Reality 借站域名(SNI)')).toBeInTheDocument();
  expect(screen.queryByLabelText('Flow 控制')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: /创\s*建/ }));
  await waitFor(() => expect(api.createXrayNode).toHaveBeenCalledWith(expect.objectContaining({
    template: 'xray-vless-xhttp', sni: 'borrow.example.com', flow: undefined, outboundType: 'relay', landingServerId: 9, proxyUrl: undefined,
  })));
});

it('copies Trojan with its certificate SNI and a new automatically generated password', async () => {
  render(<App><XrayNodeCreateModal open initialNode={{ ...source, protocol: 'trojan', tlsMode: 'tls' }} servers={servers} landings={[]} snis={snis} onClose={vi.fn()} onCreated={vi.fn()} /></App>);
  await waitFor(() => expect(screen.getByLabelText('TLS 证书域名(SNI)')).toHaveValue('borrow.example.com'));
  fireEvent.click(screen.getByRole('button', { name: /创\s*建/ }));
  await waitFor(() => expect(api.createXrayNode).toHaveBeenCalledWith(expect.objectContaining({ template: 'xray-trojan-tls', sni: 'borrow.example.com', flow: undefined, port: undefined })));
});

it('copies tunnel destinations without copying its listening port or proxy settings', async () => {
  render(<App><NodeCreateModal open initialNode={{ ...source, protocol: 'tunnel', tunnelAddress: '2001:db8::1', tunnelPort: 443 }} servers={servers} landings={[]} snis={snis} onClose={vi.fn()} onCreated={vi.fn()} /></App>);
  await waitFor(() => expect(screen.getByLabelText('转发目标地址(IPv4 / IPv6 / 域名)')).toHaveValue('2001:db8::1'));
  expect(screen.getByLabelText('转发目标端口')).toHaveValue('443');
  fireEvent.click(screen.getByRole('button', { name: /创\s*建/ }));
  await waitFor(() => expect(api.createNode).toHaveBeenCalledWith(expect.objectContaining({
    template: 'tunnel', tunnelAddress: '2001:db8::1', tunnelPort: 443, port: undefined, outboundType: undefined, proxyUrl: undefined,
  })));
});

it('copies SOCKS authentication and relay, then clears them when copying a different VMess node', async () => {
  const props = { servers, landings: [landing], snis, onClose: vi.fn(), onCreated: vi.fn() };
  const initialNode: NodeItem = { ...source, protocol: 'socks', tlsMode: 'none', outboundType: 'relay',
    landingServerId: 9, authUser: 'alice', authPassword: 'socks-password' };
  const view = render(<App><NodeCreateModal {...props} open initialNode={initialNode} /></App>);
  await waitFor(() => expect(screen.getByLabelText('用户名')).toHaveValue('alice'));
  expect(screen.getByLabelText('密码')).toHaveValue('socks-password');
  fireEvent.click(screen.getByRole('button', { name: /创\s*建/ }));
  await waitFor(() => expect(api.createNode).toHaveBeenCalledWith(expect.objectContaining({
    template: 'socks', outboundType: 'relay', landingServerId: 9, authUser: 'alice', authPassword: 'socks-password', port: undefined,
  })));
  view.rerender(<App><NodeCreateModal {...props} open initialNode={{ ...source, name: 'VMess', protocol: 'vmess',
    tlsMode: 'tls', transport: 'ws', outboundType: 'direct', clientHosts: [] }} /></App>);
  await waitFor(() => expect(screen.getByLabelText(/2 · 节点名称/)).toHaveValue('VMess-副本'));
  expect(screen.queryByLabelText('用户名')).not.toBeInTheDocument();
  expect(screen.queryByLabelText('代理链接')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: /创\s*建/ }));
  await waitFor(() => expect(api.createNode).toHaveBeenLastCalledWith(expect.objectContaining({
    template: 'vmess-ws-tls', outboundType: 'direct', landingServerId: undefined, proxyUrl: undefined,
    clientHosts: [], authUser: undefined, authPassword: undefined, port: undefined,
  })));
});
