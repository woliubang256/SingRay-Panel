import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { App } from 'antd';
import * as api from '../services/api';
import { nodeSchema, xrayNodeSchema } from '../services/contracts';
import type { NodeItem, Server, XrayNodeItem } from '../services/types';
import { NodeCreateModal } from './NodeCreateModal';
import { NodeEditModal } from './NodeEditModal';
import { XrayNodeCreateModal } from './XrayNodeCreateModal';
import { XrayNodeEditModal } from './XrayNodeEditModal';

vi.mock('../services/api', () => ({ createNode: vi.fn(), updateNode: vi.fn(), createXrayNode: vi.fn(), updateXrayNode: vi.fn() }));
const server = { id: 7, name: 'HK1', role: 'relay', host: '10.0.0.1', clientHost: 'entry.example.com' } as Server;
const node: NodeItem & XrayNodeItem = {
  id: 1, name: 'shared', serverId: 7, serverName: 'HK1', protocol: 'vmess', listenPort: 8443,
  enabled: 1, tlsMode: 'tls', transport: 'ws', outboundType: 'proxy', proxyUrl: 'socks5://user:pass@1.2.3.4:5678',
  shareLink: null, note: '', createdAt: '2026-11-08',
};
const snis = [{ id: 1, domain: 'www.microsoft.com', note: '', builtin: 1 }];

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.createNode).mockResolvedValue(node);
  vi.mocked(api.updateNode).mockResolvedValue(node);
  vi.mocked(api.createXrayNode).mockResolvedValue(node);
  vi.mocked(api.updateXrayNode).mockResolvedValue(node);
});

for (const core of ['singbox', 'xray'] as const) {
  const create = core === 'singbox' ? api.createNode : api.createXrayNode;
  const update = core === 'singbox' ? api.updateNode : api.updateXrayNode;
  const renderCreate = () => render(<App>{core === 'singbox'
    ? <NodeCreateModal open servers={[server]} landings={[]} snis={snis} onClose={vi.fn()} onCreated={vi.fn()} />
    : <XrayNodeCreateModal open servers={[server]} landings={[]} snis={snis} onClose={vi.fn()} onCreated={vi.fn()} />
  }</App>);
  const renderEdit = () => render(<App>{core === 'singbox'
    ? <NodeEditModal open node={node} server={server} landings={[]} snis={snis} onClose={vi.fn()} onSaved={vi.fn()} />
    : <XrayNodeEditModal open node={node} server={server} landings={[]} snis={snis} onClose={vi.fn()} onSaved={vi.fn()} />
  }</App>);

  describe(`${core} proxy outbound UI`, () => {
    it('shows the URL field only in proxy mode and submits a SOCKS5 link', async () => {
      renderCreate();
      expect(screen.queryByLabelText('代理链接')).not.toBeInTheDocument();
      fireEvent.click(screen.getByText('代理'));
      fireEvent.change(await screen.findByLabelText('代理链接'), { target: { value: ` ${node.proxyUrl} ` } });
      fireEvent.click(screen.getByRole('button', { name: /创\s*建/ }));
      await waitFor(() => expect(create).toHaveBeenCalledWith(expect.objectContaining({ outboundType: 'proxy', proxyUrl: node.proxyUrl, landingServerId: undefined })));
    });

    it('blocks empty and unsupported links, then accepts an HTTP proxy', async () => {
      renderCreate();
      fireEvent.click(screen.getByText('代理'));
      const field = await screen.findByLabelText('代理链接');
      fireEvent.click(screen.getByRole('button', { name: /创\s*建/ }));
      expect(await screen.findByText('请输入代理链接')).toBeInTheDocument();
      expect(create).not.toHaveBeenCalled();
      fireEvent.change(field, { target: { value: 'https://user:pass@proxy.example.com:443' } });
      fireEvent.click(screen.getByRole('button', { name: /创\s*建/ }));
      expect(await screen.findByText('请输入有效的 http:// 或 socks5:// 代理链接')).toBeInTheDocument();
      expect(create).not.toHaveBeenCalled();
      fireEvent.change(field, { target: { value: 'http://user:pass@proxy.example.com:8080' } });
      fireEvent.click(screen.getByRole('button', { name: /创\s*建/ }));
      await waitFor(() => expect(create).toHaveBeenCalledWith(expect.objectContaining({ outboundType: 'proxy', proxyUrl: 'http://user:pass@proxy.example.com:8080' })));
    });

    it('echoes a saved proxy URL and submits an edited URL', async () => {
      renderEdit();
      expect((core === 'singbox' ? nodeSchema : xrayNodeSchema).safeParse(node).success).toBe(true);
      const field = await screen.findByLabelText('代理链接');
      expect(field).toHaveValue(node.proxyUrl);
      fireEvent.change(field, { target: { value: 'http://proxy.example.com:8080' } });
      fireEvent.click(screen.getByRole('button', { name: /保\s*存/ }));
      await waitFor(() => expect(update).toHaveBeenCalledWith(1, expect.objectContaining({ outboundType: 'proxy', proxyUrl: 'http://proxy.example.com:8080' })));
    });

    it('omits hidden proxy data after switching to direct, even when the URL is invalid', async () => {
      renderEdit();
      fireEvent.change(await screen.findByLabelText('代理链接'), { target: { value: 'bad link' } });
      fireEvent.click(screen.getByText('直连'));
      await waitFor(() => expect(screen.queryByLabelText('代理链接')).not.toBeInTheDocument());
      fireEvent.click(screen.getByRole('button', { name: /保\s*存/ }));
      await waitFor(() => expect(update).toHaveBeenCalledWith(1, expect.objectContaining({ outboundType: 'direct', proxyUrl: undefined })));
    });
  });
}

it('does not offer outbound proxies for tunnel templates', async () => {
  render(<App><NodeCreateModal open servers={[server]} landings={[]} snis={snis} onClose={vi.fn()} onCreated={vi.fn()} /></App>);
  fireEvent.click(screen.getByText('隧道(端口转发)'));
  expect(await screen.findByLabelText('转发目标端口')).toBeInTheDocument();
  expect(screen.queryByText('代理', { selector: '.ant-segmented-item-label' })).not.toBeInTheDocument();
  expect(screen.queryByLabelText('代理链接')).not.toBeInTheDocument();
});
