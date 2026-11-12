import { useEffect, useState } from 'react';
import { Alert, App, Button, Checkbox, Flex, Form, Input, Modal, Popconfirm, Switch, Table, Tag, Tooltip, Typography, Upload } from 'antd';
import { CloudDownloadOutlined, DeleteOutlined, EditOutlined, ReloadOutlined, ThunderboltOutlined, UploadOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import * as api from '../services/api';
import type { ExternalFormat, ExternalImportPreview, ExternalNodeItem, ExternalTestResult } from '../services/types';
import { useAsyncData } from '../hooks/useAsyncData';

const FORMAT: Record<ExternalFormat, string> = { base64: '通用链接', clash: 'Clash / Mihomo', singbox: 'sing-box' };
const formats = (list: ExternalFormat[]) => list.map(f => <Tag key={f}>{FORMAT[f]}</Tag>);
const endpoint = (host: string, port: number) => `${host.includes(':') ? '[' + host + ']' : host}:${port}`;

export function ExternalNodesPage() {
  const { message } = App.useApp();
  const { data, loading, error, reload } = useAsyncData(api.getExternalNodes);
  const rows = data ?? [];
  const [selected, setSelected] = useState<number[]>([]);
  const [importOpen, setImportOpen] = useState(false);
  const [content, setContent] = useState('');
  const [preview, setPreview] = useState<ExternalImportPreview | null>(null);
  const [indices, setIndices] = useState<number[]>([]);
  const [include, setInclude] = useState(false);
  const [importBusy, setImportBusy] = useState(false);
  const [editing, setEditing] = useState<ExternalNodeItem | null>(null);
  const [saving, setSaving] = useState(false);
  const [changing, setChanging] = useState<number[]>([]);
  const [testing, setTesting] = useState<number[]>([]);
  const [results, setResults] = useState<Record<number, ExternalTestResult>>({});
  const [editForm] = Form.useForm<{ name: string; note: string }>();

  useEffect(() => {
    if (editing) { editForm.resetFields(); editForm.setFieldsValue({ name: editing.name, note: editing.note }); }
  }, [editing, editForm]);
  useEffect(() => { if (data) setSelected(ids => ids.filter(id => data.some(r => r.id === id))); }, [data]);

  const setSource = (text: string) => { setContent(text); setPreview(null); setIndices([]); };
  const handlePreview = async () => {
    setImportBusy(true);
    try {
      const p = await api.previewExternalNodes(content);
      setPreview(p); setIndices(p.items.filter(i => !i.duplicate).map(i => i.index));
    } catch { /* API reports the error. */ } finally { setImportBusy(false); }
  };
  const handleImport = async () => {
    if (!preview || !indices.length) return;
    setImportBusy(true);
    try {
      const r = await api.importExternalNodes(content, indices, include);
      message.success(`已导入 ${r.created} 个节点，跳过 ${r.skipped} 个重复或无效项`);
      setImportOpen(false); setSource(''); reload();
    } catch { /* Keep the preview for retry. */ } finally { setImportBusy(false); }
  };
  const patch = async (id: number, values: Parameters<typeof api.updateExternalNode>[1]) => {
    setChanging(ids => [...ids, id]);
    try { await api.updateExternalNode(id, values); reload(); }
    catch { /* API reports the error. */ } finally { setChanging(ids => ids.filter(x => x !== id)); }
  };
  const save = async (values: { name: string; note: string }) => {
    if (!editing || saving) return;
    setSaving(true);
    try {
      await api.updateExternalNode(editing.id, { name: values.name.trim(), note: values.note ?? '' });
      setEditing(null); reload(); message.success('已保存');
    } catch { /* Keep unsaved input. */ } finally { setSaving(false); }
  };
  const remove = async (row: ExternalNodeItem) => {
    try { await api.deleteExternalNode(row.id); reload(); message.success('已删除外部节点'); }
    catch { /* API reports the error. */ }
  };
  const test = async (ids: number[], batch: boolean) => {
    if (!ids.length) return;
    if (ids.length > 50) { message.warning('每次最多测试 50 个节点，请勾选后测试'); return; }
    setTesting(p => [...new Set([...p, ...ids])]);
    try {
      if (batch) {
        const r = await api.testExternalNodes(ids);
        setResults(p => ({ ...p, ...Object.fromEntries(r.results.map(i => [i.id, i])) }));
        message.info(`测试完成：成功 ${r.results.filter(i => i.status === 'ok').length} / ${r.results.length}`);
      } else {
        const r = await api.testExternalNode(ids[0]); setResults(p => ({ ...p, [ids[0]]: r }));
      }
    } catch { /* API reports the error; retain the previous result. */ }
    finally { setTesting(p => p.filter(id => !ids.includes(id))); }
  };
  const columns: ColumnsType<ExternalNodeItem> = [
    { title: '名称', dataIndex: 'name', width: 200, render: (name: string, row) => <Tooltip title={row.note || undefined}><Typography.Text strong>{name}</Typography.Text></Tooltip> },
    { title: '协议', dataIndex: 'protocol', width: 110, filters: [...new Set(rows.map(r => r.protocol))].map(p => ({ text: p, value: p })),
      onFilter: (v, row) => row.protocol === v, render: (v: string) => <Tag color="blue">{v.toUpperCase()}</Tag> },
    { title: '地址', key: 'address', width: 230, render: (_, row) => <Typography.Text code>{endpoint(row.host, row.port)}</Typography.Text> },
    { title: '订阅格式', dataIndex: 'formats', width: 230, render: formats },
    { title: '代理延迟', key: 'latency', width: 230, render: (_, row) => {
      if (testing.includes(row.id)) return <Tag color="processing">测试中</Tag>;
      const r = results[row.id] ?? { status: row.probeStatus, latencyMs: row.latencyMs, detail: row.probeDetail, checkedAt: row.checkedAt };
      if (!r.status) return <Typography.Text type="secondary">未测试</Typography.Text>;
      const time = r.checkedAt ? new Date(r.checkedAt).toLocaleString() : '';
      return <Flex vertical gap={4}>
        <Tooltip title={[r.detail, time].filter(Boolean).join('；')}>
          <Tag color={r.status === 'ok' ? 'success' : r.status === 'failed' ? 'error' : 'warning'}>
            {r.status === 'ok' ? `${r.latencyMs} ms` : r.status === 'failed' ? '测试失败' : r.status === 'unsupported' ? '暂不支持测试' : '测试不可用'}
          </Tag>
        </Tooltip>
        {r.status !== 'ok' && <Typography.Text type="secondary" style={{ fontSize: 12 }}>{r.detail}</Typography.Text>}
        {time && <Typography.Text type="secondary" style={{ fontSize: 12 }}>{time}</Typography.Text>}
      </Flex>;
    } },
    { title: '启用', key: 'enabled', width: 75, render: (_, r) => <Switch aria-label="启用节点" size="small" checked={r.enabled === 1}
      loading={changing.includes(r.id)} onChange={v => void patch(r.id, { enabled: v })} /> },
    { title: '进订阅', key: 'sub', width: 80, render: (_, r) => <Switch aria-label="加入订阅" size="small" checked={r.includeInSub === 1}
      loading={changing.includes(r.id)} onChange={v => void patch(r.id, { includeInSub: v })} /> },
    { title: '操作', key: 'actions', width: 210, render: (_, r) => <Flex gap={4}>
      <Button type="link" size="small" icon={<ThunderboltOutlined />} disabled={testing.length > 0} onClick={() => void test([r.id], false)}>测试</Button>
      <Button type="link" size="small" icon={<EditOutlined />} onClick={() => setEditing(r)}>编辑</Button>
      <Popconfirm title={`删除外部节点 ${r.name}？`} onConfirm={() => remove(r)} okText="删除" cancelText="取消" okButtonProps={{ danger: true }}>
        <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
      </Popconfirm>
    </Flex> },
  ];
  return <Flex vertical gap={16}>
    <Flex justify="space-between" align="center" wrap gap={12}>
      <Typography.Title level={4} style={{ margin: 0 }}>外部节点</Typography.Title>
      <Flex gap={8} wrap>
        <Button icon={<ReloadOutlined />} onClick={reload}>刷新</Button>
        <Button icon={<ThunderboltOutlined />} loading={testing.length > 0} disabled={!rows.length || testing.length > 0}
          onClick={() => void test(selected.length ? selected : rows.filter(r => r.enabled === 1).map(r => r.id), true)}>批量测试{selected.length ? ` (${selected.length})` : ''}</Button>
        <Button type="primary" icon={<CloudDownloadOutlined />} onClick={() => { setSource(''); setInclude(false); setImportOpen(true); }}>导入节点</Button>
      </Flex>
    </Flex>
    <Typography.Text type="secondary">导入外部分享链接或节点配置，自由选择是否加入现有订阅。代理延迟通过节点访问 HTTPS 检测地址，从面板所在网络测得。</Typography.Text>
    {error && <Alert type="error" title={error} action={<Button onClick={reload}>重试</Button>} />}
    <Table<ExternalNodeItem> rowKey="id" columns={columns} dataSource={rows} loading={loading} scroll={{ x: 1400 }}
      rowSelection={{ selectedRowKeys: selected, onChange: keys => setSelected(keys.map(Number)) }}
      pagination={{ pageSize: 20, showSizeChanger: true }} locale={{ emptyText: '还没有外部节点，点击“导入节点”添加' }} />

    <Modal open={importOpen} title="导入外部节点" width={860} mask={{ closable: false }} destroyOnHidden
      closable={!importBusy} keyboard={!importBusy} onCancel={() => { if (!importBusy) setImportOpen(false); }}
      footer={<Flex justify="space-between" wrap gap={8}>
        <Checkbox checked={include} disabled={importBusy} onChange={e => setInclude(e.target.checked)}>导入后加入订阅</Checkbox>
        <Flex gap={8}><Button disabled={importBusy} onClick={() => setImportOpen(false)}>取消</Button>
          <Button loading={importBusy} disabled={!content.trim()} onClick={() => void handlePreview()}>解析预览</Button>
          <Button type="primary" loading={importBusy} disabled={!preview || !indices.length} onClick={() => void handleImport()}>确认导入 ({indices.length})</Button>
        </Flex>
      </Flex>}>
      <Flex vertical gap={12}>
        <Typography.Text type="secondary">支持 VLESS、VMess、Trojan、SS、Hysteria2、TUIC、AnyTLS 等链接，以及 Clash/Mihomo YAML、sing-box/Xray JSON 的节点配置。每次最多 500 个节点、500 KB。</Typography.Text>
        <Upload accept=".yaml,.yml,.json,.txt" showUploadList={false} disabled={importBusy} beforeUpload={async file => {
          if (file.size > 512_000) { message.error('文件不能超过 500 KB'); return false; }
          try { setSource(await file.text()); } catch { message.error('无法读取文件'); }
          return false;
        }}><Button icon={<UploadOutlined />} disabled={importBusy}>选择文件</Button></Upload>
        <label htmlFor="external-import-content">节点内容</label>
        <Input.TextArea id="external-import-content" value={content} rows={7} maxLength={512_000} disabled={importBusy}
          spellCheck={false} autoComplete="off" placeholder="每行一个分享链接，或粘贴 YAML / JSON 配置" onChange={e => setSource(e.target.value)} />
        {preview && <>
          {preview.errors.length > 0 && <Alert type="warning" title={`${preview.errors.length} 项未能解析`}
            description={<Flex vertical>{preview.errors.map(e => <Typography.Text key={e.index}>第 {e.index + 1} 项：<span>{e.error}</span></Typography.Text>)}</Flex>} />}
          <Table<ExternalImportPreview['items'][number]> size="small" rowKey="index" dataSource={preview.items} pagination={{ pageSize: 8 }} scroll={{ x: 700 }}
            rowSelection={{ selectedRowKeys: indices, onChange: keys => setIndices(keys.map(Number)), getCheckboxProps: r => ({ disabled: r.duplicate || importBusy }) }}
            columns={[{ title: '名称', dataIndex: 'name' }, { title: '协议', dataIndex: 'protocol' },
              { title: '地址', render: (_, r) => endpoint(r.host, r.port) },
              { title: '结果', render: (_, r) => r.duplicate ? <Tag>已存在或重复</Tag> : <Flex vertical>{formats(r.formats)}{r.warning && <Typography.Text type="warning">{r.warning}</Typography.Text>}</Flex> }]} />
        </>}
      </Flex>
    </Modal>
    <Modal open={editing !== null} title="编辑外部节点" okText="保存" cancelText="取消" confirmLoading={saving}
      closable={!saving} keyboard={!saving} mask={{ closable: false }} destroyOnHidden cancelButtonProps={{ disabled: saving }}
      onCancel={() => { if (!saving) setEditing(null); }} onOk={() => editForm.submit()}>
      <Form name="external-edit" form={editForm} layout="vertical" disabled={saving} onFinish={save}>
        <Form.Item label="名称" name="name" rules={[{ required: true, whitespace: true, message: '请输入名称' }, { max: 200 }]}><Input autoFocus /></Form.Item>
        <Form.Item label="备注" name="note" rules={[{ max: 2000 }]}><Input.TextArea rows={3} /></Form.Item>
      </Form>
    </Modal>
  </Flex>;
}
