import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { App } from 'antd';
import * as api from '../services/api';

vi.mock('../services/api', () => ({
  getXrayNodes: vi.fn(async () => [{ id: 7, name: 'HK Trojan', protocol: 'trojan', serverId: 1,
    serverName: 'HK', listenPort: 31250, enabled: 1, includeInSub: 1, outboundType: 'direct', sni: 'hk.example.com', effectiveClientHosts: ['hk.example.com'] }]),
  getServers: vi.fn(async () => [{ id: 1, name: 'HK', role: 'relay', control: 'ssh', pingStatus: 'online' }]),
  getSnis: vi.fn(async () => []), testXrayNode: vi.fn(), diagnoseXrayNode: vi.fn(), updateXrayNode: vi.fn(),
}));
vi.mock('../components/XrayNodeCreateModal', () => ({ XrayNodeCreateModal: () => null }));
vi.mock('../components/XrayNodeEditModal', () => ({ XrayNodeEditModal: () => null }));
import { XrayNodesPage } from './XrayNodesPage';

beforeEach(() => vi.clearAllMocks());

describe('Xray node test feedback', () => {
  it('toggles subscription visibility without disabling the inbound', async () => {
    const [node] = await api.getXrayNodes();
    render(<App><XrayNodesPage /></App>);
    const toggle = await screen.findByRole('switch', { name: 'HK Trojan 进订阅' });
    expect(toggle).toBeChecked();
    vi.mocked(api.getXrayNodes).mockResolvedValueOnce([{ ...node, includeInSub: 0 }]);
    fireEvent.click(toggle);
    await waitFor(() => expect(toggle).not.toBeChecked());
    expect(api.updateXrayNode).toHaveBeenLastCalledWith(7, { includeInSub: false });
    expect(screen.getByRole('switch', { name: 'HK Trojan 启用' })).toBeChecked();
    fireEvent.click(toggle);
    await waitFor(() => expect(api.updateXrayNode).toHaveBeenLastCalledWith(7, { includeInSub: true }));
    await waitFor(() => expect(toggle).toBeChecked());
  });

  it('retains the saved switch value after an API failure', async () => {
    vi.mocked(api.updateXrayNode).mockRejectedValueOnce(new Error('save failed'));
    render(<App><XrayNodesPage /></App>);
    const toggle = await screen.findByRole('switch', { name: 'HK Trojan 进订阅' });
    const reads = vi.mocked(api.getXrayNodes).mock.calls.length;
    fireEvent.click(toggle);
    await waitFor(() => expect(api.updateXrayNode).toHaveBeenCalledWith(7, { includeInSub: false }));
    await waitFor(() => expect(toggle).toBeEnabled());
    expect(toggle).toBeChecked();
    expect(api.getXrayNodes).toHaveBeenCalledTimes(reads);
  });

  it('displays the backend TLS failure directly in the row', async () => {
    vi.mocked(api.testXrayNode).mockResolvedValue({ ok: false, detail: 'tls handshake timeout after 5000ms' });
    render(<App><XrayNodesPage /></App>);
    fireEvent.click(await screen.findByText('测速', { selector: 'button span' }));
    expect(await screen.findByText('tls handshake timeout after 5000ms')).toBeInTheDocument();
  });

  it('preserves the API exception instead of replacing it with a generic failure', async () => {
    vi.mocked(api.testXrayNode).mockRejectedValue(new Error('SSH connection refused'));
    render(<App><XrayNodesPage /></App>);
    fireEvent.click(await screen.findByText('测速', { selector: 'button span' }));
    expect(await screen.findByText('SSH connection refused')).toBeInTheDocument();
  });

  it('keeps successful latency visible', async () => {
    vi.mocked(api.testXrayNode).mockResolvedValue({ ok: true, latencyMs: 23, detail: 'TLS handshake OK' });
    render(<App><XrayNodesPage /></App>);
    fireEvent.click(await screen.findByText('测速', { selector: 'button span' }));
    expect(await screen.findByText('23ms')).toBeVisible();
  });

  it('opens diagnosis on demand without automatically probing every node', async () => {
    vi.mocked(api.diagnoseXrayNode).mockResolvedValue({ checkedAt: new Date().toISOString(),
      target: { host: 'hk.example.com', port: 31250, sni: 'hk.example.com' }, status: 'error',
      summary: '本机 TLS 握手异常', checks: [] });
    render(<App><XrayNodesPage /></App>);
    const button = await screen.findByText('诊断');
    expect(api.diagnoseXrayNode).not.toHaveBeenCalled();
    fireEvent.click(button);
    expect(await screen.findByText('本机 TLS 握手异常')).toBeInTheDocument();
    expect(api.diagnoseXrayNode).toHaveBeenCalledTimes(1);
    expect(api.diagnoseXrayNode).toHaveBeenCalledWith(7, 'hk.example.com');
  });
});
