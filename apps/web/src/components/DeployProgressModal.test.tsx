import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { App } from 'antd';
import { DeployProgressModal } from './DeployProgressModal';

vi.mock('../services/api', () => ({ getDeployJob: vi.fn(async () => ({
  id: 'pending-job', scope: 'pending', done: true, machines: [{
    serverId: 7, name: 'tokyo', core: 'xray', status: 'done', result: {
      serverId: 7, serverName: 'tokyo', singbox: { ok: true, steps: ['skip'], skipped: true },
      xray: { ok: true, steps: ['health'] },
    },
  }],
})) }));

describe('DeployProgressModal', () => {
  it('shows pending deployment and marks the untouched sing-box core as skipped', async () => {
    const onFinished = vi.fn();
    render(<App><DeployProgressModal open jobId="pending-job" onClose={vi.fn()} onFinished={onFinished} /></App>);
    expect(await screen.findByText('部署待变更 — 完成')).toBeInTheDocument();
    expect(screen.getByText('跳过')).toBeInTheDocument();
    expect(screen.getAllByText('OK')).toHaveLength(1);
    expect(screen.getAllByText('tokyo')).toHaveLength(1);
    expect(onFinished).toHaveBeenCalledTimes(1);
  });
});
