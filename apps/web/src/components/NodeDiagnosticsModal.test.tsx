import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import * as api from '../services/api';
import type { NodeDiagnosticReport, XrayNodeItem } from '../services/types';
import { NodeDiagnosticsModal } from './NodeDiagnosticsModal';

vi.mock('../services/api', () => ({ diagnoseXrayNode: vi.fn() }));
const node = { id: 7, name: 'HK Trojan', effectiveClientHosts: ['hk.example.com', 'hk2.example.com'] } as XrayNodeItem;
const result: NodeDiagnosticReport = { checkedAt: '2026-11-01T12:00:00Z', target: { host: 'hk.example.com', port: 31250, sni: 'hk.example.com' },
  status: 'error', summary: '本机 TLS 握手失败，请检查证书。', checks: [{ key: 'local', label: '本机 TLS 握手', status: 'error', detail: '证书与私钥不匹配' }] };
beforeEach(() => { vi.resetAllMocks(); vi.mocked(api.diagnoseXrayNode).mockResolvedValue(result); });

describe('node diagnostics dialog', () => {
  it('displays the target, failed check and diagnosis limits', async () => {
    render(<NodeDiagnosticsModal node={node} onClose={() => {}} />);
    expect(await screen.findByText('证书与私钥不匹配')).toBeInTheDocument();
    expect(screen.getByText(/hk.example.com:31250/)).toBeInTheDocument();
    expect(screen.getByText(/不验证代理密码/)).toBeInTheDocument();
    expect(api.diagnoseXrayNode).toHaveBeenCalledWith(7, 'hk.example.com');
  });

  it('shows request failures in the dialog and allows retry', async () => {
    vi.mocked(api.diagnoseXrayNode).mockRejectedValueOnce(new Error('机器正在部署，请稍后重试'));
    render(<NodeDiagnosticsModal node={node} onClose={() => {}} />);
    expect(await screen.findByText('机器正在部署，请稍后重试')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /重新诊断/ }));
    expect(await screen.findByText('证书与私钥不匹配')).toBeInTheDocument();
  });

  it('diagnoses the chosen domain and ignores stale responses after switching entries', async () => {
    let first!: (value: NodeDiagnosticReport) => void;
    vi.mocked(api.diagnoseXrayNode).mockImplementationOnce(() => new Promise(resolve => { first = resolve; }));
    render(<NodeDiagnosticsModal node={node} onClose={() => {}} />);
    fireEvent.mouseDown(screen.getByRole('combobox'));
    fireEvent.click((await screen.findAllByText('hk2.example.com')).at(-1)!);
    await waitFor(() => expect(api.diagnoseXrayNode).toHaveBeenLastCalledWith(7, 'hk2.example.com'));
    expect(await screen.findByText('证书与私钥不匹配')).toBeInTheDocument();
    first({ ...result, summary: 'STALE-RESULT' });
    await waitFor(() => expect(screen.queryByText('STALE-RESULT')).not.toBeInTheDocument());
  });
});
