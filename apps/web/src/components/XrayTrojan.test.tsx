import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { App } from 'antd';
import * as api from '../services/api';
import { xrayNodeSchema } from '../services/contracts';
import type { Server, XrayNodeItem } from '../services/types';
import { XrayNodeCreateModal } from './XrayNodeCreateModal';
import { XrayNodeEditModal } from './XrayNodeEditModal';

vi.mock('../services/api', () => ({ createXrayNode: vi.fn(), updateXrayNode: vi.fn() }));

const server = { id: 7, name: 'HK1', role: 'relay', host: '10.0.0.1', clientHost: 'proxy.example.com' } as Server;
const node: XrayNodeItem = {
  id: 1, name: 'Trojan', serverId: 7, serverName: 'HK1', protocol: 'trojan', listenPort: 8443, enabled: 1,
  tlsMode: 'tls', transport: 'raw', sni: 'cert.example.com', outboundType: 'direct',
  shareLink: 'trojan://password@proxy.example.com:8443?security=tls', note: '', createdAt: '2026-10-28',
  authPassword: 'generated-password-123',
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.createXrayNode).mockResolvedValue(node);
  vi.mocked(api.updateXrayNode).mockResolvedValue(node);
});

describe('Xray Trojan UI', () => {
  it('creates Trojan with a custom certificate SNI and no Reality flow', async () => {
    const onCreated = vi.fn();
    render(<App><XrayNodeCreateModal open servers={[server]} landings={[]} snis={[{
      id: 1, domain: 'www.microsoft.com', note: '', builtin: 1,
    }]} onClose={vi.fn()} onCreated={onCreated} /></App>);
    fireEvent.click(screen.getByText('Trojan + TLS'));
    expect(screen.queryByLabelText('Flow 控制')).not.toBeInTheDocument();
    const sni = screen.getByLabelText('TLS 证书域名(SNI)');
    expect(sni).toHaveValue('');
    fireEvent.change(sni, { target: { value: 'cert.example.com' } });
    fireEvent.click(screen.getByRole('button', { name: /创\s*建/ }));
    await waitFor(() => expect(api.createXrayNode).toHaveBeenCalledWith(expect.objectContaining({
      template: 'xray-trojan-tls', serverId: 7, sni: 'cert.example.com', flow: undefined,
    })));
    await waitFor(() => expect(onCreated).toHaveBeenCalledWith(node));
  });

  it('edits Trojan SNI and password without adding flow or XHTTP fields', async () => {
    const onSaved = vi.fn();
    render(<App><XrayNodeEditModal open node={node} landings={[]} snis={[]} onClose={vi.fn()} onSaved={onSaved} /></App>);
    expect(xrayNodeSchema.safeParse(node).success).toBe(true);
    const sni = await screen.findByLabelText('TLS 证书域名(SNI)');
    expect(sni).toHaveValue('cert.example.com');
    expect(screen.queryByLabelText('Flow 控制')).not.toBeInTheDocument();
    fireEvent.change(sni, { target: { value: 'next.example.com' } });
    fireEvent.change(screen.getByLabelText('Trojan 密码'), { target: { value: 'changed-password-123' } });
    fireEvent.click(screen.getByRole('button', { name: /保\s*存/ }));
    await waitFor(() => expect(api.updateXrayNode).toHaveBeenCalledWith(1, expect.objectContaining({
      protocol: 'trojan', sni: 'next.example.com', authPassword: 'changed-password-123', flow: undefined, wsPath: undefined,
    })));
    await waitFor(() => expect(onSaved).toHaveBeenCalledWith(node));
  });
});
