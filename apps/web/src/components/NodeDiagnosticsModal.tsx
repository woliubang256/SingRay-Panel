import { useEffect, useState } from 'react';
import { Alert, Button, Flex, Modal, Select, Spin, Tag, Typography } from 'antd';
import * as api from '../services/api';
import type { NodeDiagnosticReport, XrayNodeItem } from '../services/types';

const statusMeta = {
  ok: { color: 'success', text: '通过' }, error: { color: 'error', text: '异常' },
  warning: { color: 'warning', text: '注意' }, skipped: { color: 'default', text: '说明' },
};

export function NodeDiagnosticsModal({ node, onClose }: { node: XrayNodeItem; onClose: () => void }) {
  const hosts = node.effectiveClientHosts ?? [];
  const [host, setHost] = useState<string | undefined>(hosts[0]);
  const [attempt, setAttempt] = useState(0);
  const [loading, setLoading] = useState(true);
  const [report, setReport] = useState<NodeDiagnosticReport | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    setLoading(true); setReport(null); setError('');
    void api.diagnoseXrayNode(node.id, host).then(result => {
      if (!cancelled) setReport(result);
    }).catch((err: unknown) => {
      if (!cancelled) setError(err instanceof Error ? err.message : '诊断请求失败');
    }).finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [node.id, host, attempt]);

  return <Modal open title={`${node.name} · 节点诊断`} onCancel={onClose} width={820} footer={[
    <Button key="close" onClick={onClose}>关闭</Button>,
    <Button key="retry" type="primary" loading={loading} onClick={() => setAttempt(value => value + 1)}>重新诊断</Button>,
  ]}>
    <Flex vertical gap={16}>
      <Typography.Text type="secondary">检查服务、运行配置和入口 TCP/TLS；使用代理出口时，还会验证代理认证与 HTTPS 联网。不验证节点客户端认证（含 Reality）及完整端到端访问。日志仅展示错误分类摘要。</Typography.Text>
      {hosts.length > 1 && <Flex gap={8} align="center" wrap>
        <Typography.Text>诊断入口</Typography.Text>
        <Select aria-label="诊断入口" value={host} onChange={setHost} style={{ minWidth: 240, maxWidth: '100%' }}
          options={hosts.map(value => ({ value, label: value }))} />
      </Flex>}
      {loading && <Spin description="正在检查节点状态与连通性…"><div style={{ minHeight: 100 }} /></Spin>}
      {error && <Alert type="error" showIcon title="诊断未完成" description={error} />}
      {report && <>
        <Typography.Text code style={{ overflowWrap: 'anywhere' }}>
          {report.target.host.includes(':') ? `[${report.target.host}]` : report.target.host}:{report.target.port} · SNI: {report.target.sni || '未设置'}
        </Typography.Text>
        <Alert showIcon type={report.status === 'ok' ? 'success' : report.status} title={report.summary} />
        {report.checks.map(check => <Flex vertical gap={4} key={check.key}>
          <Flex align="center" gap={8}>
            <Tag color={statusMeta[check.status].color}>{statusMeta[check.status].text}</Tag>
            <Typography.Text strong>{check.label}</Typography.Text>
          </Flex>
          <Typography.Paragraph style={{ margin: 0, overflowWrap: 'anywhere' }}>{check.detail}</Typography.Paragraph>
        </Flex>)}
        <Typography.Text type="secondary">检查时间：{new Date(report.checkedAt).toLocaleString()}</Typography.Text>
      </>}
    </Flex>
  </Modal>;
}
