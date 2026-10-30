import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from 'antd';
import * as api from '../services/api';
import type { Server, NodeItem, XrayNodeItem } from '../services/types';
import { ServerFormModal } from './ServerFormModal';
import { NodeEditModal } from './NodeEditModal';
import { XrayNodeEditModal } from './XrayNodeEditModal';

vi.mock('../services/api', () => ({ updateServer: vi.fn(), updateNode: vi.fn(), updateXrayNode: vi.fn() }));
const server = {
  id: 7, name: 'HK', role: 'relay', control: 'ssh', host: '10.0.0.1', clientHost: 'a.example.com',
  clientHosts: ['a.example.com', 'b.example.com'], sshPort: 22, sshUser: 'root', sshAuthType: 'key', sshSudo: 0,
} as Server;
const node = {
  id: 1, name: 'shared', serverId: 7, serverName: 'HK', protocol: 'vmess', listenPort: 8443,
  enabled: 1, tlsMode: 'tls', transport: 'ws', outboundType: 'direct', note: '', clientHosts: [],
} as unknown as NodeItem;

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.updateServer).mockResolvedValue(server);
  vi.mocked(api.updateNode).mockResolvedValue(node);
  vi.mocked(api.updateXrayNode).mockResolvedValue(node as unknown as XrayNodeItem);
});

describe('multiple domain management', () => {
  it('preserves existing domains and adds another in the server editor', async () => {
    const user = userEvent.setup();
    render(<App><ServerFormModal open record={server} onClose={vi.fn()} onSaved={vi.fn()} /></App>);
    const field = await screen.findByLabelText('对外域名 / 地址(可多个)');
    await user.type(field, 'c.example.com');
    fireEvent.keyDown(field, { key: 'Enter', keyCode: 13, which: 13 });
    fireEvent.click(screen.getByRole('button', { name: /保\s*存/ }));
    await waitFor(() => expect(api.updateServer).toHaveBeenCalledWith(7, expect.objectContaining({
      host: '10.0.0.1', clientHosts: ['a.example.com', 'b.example.com', 'c.example.com'],
    })));
  });

  for (const core of ['singbox', 'xray'] as const) {
    it(`${core} selects a subset and submits the shared node`, async () => {
      render(<App>{core === 'singbox'
        ? <NodeEditModal open node={node} server={server} landings={[]} snis={[]} onClose={vi.fn()} onSaved={vi.fn()} />
        : <XrayNodeEditModal open node={node as unknown as XrayNodeItem} server={server} landings={[]} snis={[]} onClose={vi.fn()} onSaved={vi.fn()} />
      }</App>);
      fireEvent.mouseDown(await screen.findByLabelText('节点入口域名'));
      fireEvent.click(await screen.findByText('b.example.com', { selector: '.ant-select-item-option-content' }));
      fireEvent.click(screen.getByRole('button', { name: /保\s*存/ }));
      await waitFor(() => expect(core === 'singbox' ? api.updateNode : api.updateXrayNode).toHaveBeenCalledWith(1, expect.objectContaining({
        clientHosts: ['b.example.com'], port: 8443,
      })));
    });
  }

  it('submits an empty selection to inherit all machine domains', async () => {
    render(<App><NodeEditModal open node={node} server={server} landings={[]} snis={[]} onClose={vi.fn()} onSaved={vi.fn()} /></App>);
    fireEvent.click(screen.getByRole('button', { name: /保\s*存/ }));
    await waitFor(() => expect(api.updateNode).toHaveBeenCalledWith(1, expect.objectContaining({ clientHosts: [] })));
  });
});
