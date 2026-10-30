import { Alert, Modal, Table, Tag, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { useEffect, useRef, useState } from 'react';
import * as api from '../services/api';
import type { DeployAllResult } from '../services/types';

interface DeployProgressModalProps {
  open: boolean;
  jobId: string | null;
  scope?: api.DeployScope;
  onClose: () => void;
  onFinished: () => void;
}

/** 按实际任务清单展示机器/核心进度,未选核心明确显示跳过。 */
export function DeployProgressModal({ open, jobId, scope = 'all', onClose, onFinished }: DeployProgressModalProps) {
  const [machines, setMachines] = useState<api.DeployJobMachine[]>([]);
  const [done, setDone] = useState(false);
  const [notFound, setNotFound] = useState(false);
  const [jobScope, setJobScope] = useState(scope);
  const finishedRef = useRef(false);

  useEffect(() => {
    if (!open || !jobId) return;
    finishedRef.current = false;
    setDone(false);
    setNotFound(false);
    setMachines([]);
    setJobScope(scope);
    let stop = false;
    const poll = async () => {
      try {
        const job = await api.getDeployJob(jobId);
        if (stop) return;
        setMachines(job.machines);
        setJobScope(job.scope ?? scope);
        if (job.done) {
          setDone(true);
          if (!finishedRef.current) {
            finishedRef.current = true;
            onFinished();
          }
          return;
        }
      } catch {
        if (stop) return;
        setNotFound(true);
        return;
      }
      setTimeout(poll, 2000);
    };
    void poll();
    return () => {
      stop = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, jobId, scope]);

  const label = jobScope === 'pending' ? '部署待变更' : '部署全部';
  const allOk = machines.every((m) => m.status === 'done' && m.result &&
    [m.result.singbox, m.result.xray].every((r) => !r || r.ok || r.skipped));
  const coreStatus = (result?: DeployAllResult['singbox']) =>
    !result || result.skipped ? <Tag>跳过</Tag> : result.ok ? <Tag color="success">OK</Tag> : <Tag color="error">失败</Tag>;

  const columns: ColumnsType<api.DeployJobMachine> = [
    { title: '机器', dataIndex: 'name', width: 140, render: (v: string) => <Typography.Text strong>{v}</Typography.Text> },
    {
      title: '状态',
      dataIndex: 'status',
      width: 130,
      render: (_, m) => {
        if (m.status === 'pending') return <Tag color="processing">排队中…</Tag>;
        const r = m.result;
        if (!r) return <Tag>—</Tag>;
        const sbOk = r.singbox?.ok;
        const xrOk = !r.xray || r.xray.ok || r.xray.skipped;
        return sbOk && xrOk ? <Tag color="success">完成</Tag> : <Tag color="error">失败</Tag>;
      },
    },
    {
      title: 'sing-box / xray',
      key: 'cores',
      render: (_, m) => {
        const r = m.result;
        if (m.status === 'pending' || !r) return <Typography.Text type="secondary">等待{m.core === 'singbox' ? ' sing-box' : m.core === 'xray' ? ' Xray' : ' sing-box / Xray'}…</Typography.Text>;
        return (
          <Typography.Text>
            sing-box: {coreStatus(r.singbox)}　xray: {coreStatus(r.xray)}
          </Typography.Text>
        );
      },
    },
    {
      title: '失败原因',
      key: 'error',
      render: (_, m) => {
        const errors = [m.result?.singbox?.error, m.result?.xray?.error].filter(Boolean) as string[];
        return errors.length ? <Typography.Text type="danger">{errors.join(';')}</Typography.Text> : <Typography.Text type="secondary">-</Typography.Text>;
      },
    },
  ];

  return (
    <Modal
      open={open}
      title={`${label} — ${done ? allOk ? '完成' : '部分失败' : '进行中'}`}
      footer={null}
      onCancel={onClose}
      width={760}
      maskClosable={false}
    >
      {notFound ? (
        <Alert type="error" showIcon message="部署任务不存在或已过期(面板可能已重启),请重新发起。" />
      ) : (
        <>
          {!done && (
            <Alert
              type="info"
              showIcon
              message="部署进行中…"
              description={jobScope === 'pending'
                ? '仅下发清单中有变更的机器和核心。可关闭此窗口，部署会在后台继续。'
                : '并发逐机下发所有机器的配置。可关闭此窗口，部署会在后台继续。'}
              style={{ marginBottom: 12 }}
            />
          )}
          {done && (
            <Alert
              type={allOk ? 'success' : 'warning'}
              showIcon
              message={machines.length === 0 && jobScope === 'pending' ? '没有待部署的变更' : allOk ? '部署完成' : '部分部署失败'}
              style={{ marginBottom: 12 }}
            />
          )}
          <Table<api.DeployJobMachine> rowKey="serverId" columns={columns} dataSource={machines} pagination={false} size="small" />
        </>
      )}
    </Modal>
  );
}
