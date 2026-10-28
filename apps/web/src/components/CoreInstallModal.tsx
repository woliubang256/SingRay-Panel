import { useEffect, useRef, useState } from 'react';
import { Alert, App, AutoComplete, Flex, Form, Modal, Typography } from 'antd';
import * as api from '../services/api';
import type { Server } from '../services/types';

interface Props {
  server: Server;
  core: api.CoreKind;
  onClose: () => void;
  onInstalled: () => void;
}

/** 官方版本可搜索,也可直接输入未列出的稳定版本。 */
export function CoreInstallModal({ server, core, onClose, onInstalled }: Props) {
  const { message } = App.useApp();
  const [form] = Form.useForm<{ version: string }>();
  const [versions, setVersions] = useState<string[]>([]);
  const [defaultVersion, setDefaultVersion] = useState('');
  const [warning, setWarning] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [installing, setInstalling] = useState(false);
  const submitting = useRef(false);
  const label = core === 'singbox' ? 'sing-box' : 'Xray';
  const currentVersion = core === 'singbox' ? server.singboxVersion : server.xrayVersion;

  useEffect(() => {
    let active = true;
    void api.getCoreVersions(core).then((catalog) => {
      if (!active) return;
      setVersions(catalog.versions);
      setDefaultVersion(catalog.defaultVersion);
      setWarning(catalog.warning ?? '');
      // 慢请求不能覆盖用户已经输入的版本号。
      if (!form.isFieldTouched('version')) form.setFieldValue('version', catalog.defaultVersion);
    }).catch(() => {
      if (active) setWarning('版本列表加载失败，请手动输入版本号后安装。');
    }).finally(() => {
      if (active) setLoading(false);
    });
    return () => { active = false; };
  }, [core, form]);

  const handleInstall = async ({ version }: { version: string }) => {
    if (submitting.current) return;
    submitting.current = true;
    setInstalling(true);
    setError('');
    try {
      const result = await api.serverLifecycle(server.id, core, 'install', version.trim().replace(/^v/, ''));
      if (!result.ok) {
        setError(result.error ?? '安装失败，请检查服务器连接和版本号。');
        return;
      }
      message.success({ content: `${server.name} ${label} 安装成功（${(result.steps ?? []).join(' → ')}）`, duration: 6 });
      onInstalled();
    } catch (err) {
      setError(err instanceof Error ? err.message : '安装失败，请重试。');
    } finally {
      submitting.current = false;
      setInstalling(false);
    }
  };

  return (
    <Modal
      title={`安装 ${label} · ${server.name}`}
      open
      onCancel={() => { if (!submitting.current) onClose(); }}
      onOk={() => form.submit()}
      okText="开始安装"
      cancelText="取消"
      confirmLoading={installing}
      cancelButtonProps={{ disabled: installing }}
      closable={!installing}
      mask={{ closable: !installing }}
      keyboard={!installing}
      width={520}
    >
      <Flex vertical gap={12}>
        <Typography.Text type="secondary">当前版本：{currentVersion || '未安装 / 未检测到'}</Typography.Text>
        {warning && <Alert type="warning" showIcon title={warning} />}
        {error && <Alert type="error" showIcon title="安装失败" description={error} />}
        <Form form={form} layout="vertical" onFinish={handleInstall} disabled={installing}>
          <Form.Item
            name="version"
            label="安装版本"
            extra={loading ? '正在获取官方稳定版列表，也可直接输入版本号。' : '支持搜索或手动输入稳定版本号，如 1.13.18；latest 表示上游最新稳定版。'}
            rules={[
              { required: true, whitespace: true, message: '请选择或输入安装版本' },
              { max: 64, message: '版本号过长' },
              { validator: (_, value: unknown) => typeof value === 'string' && /^(latest|v?\d+\.\d+\.\d+)$/.test(value.trim())
                ? Promise.resolve() : Promise.reject(new Error('请输入 x.y.z、vx.y.z 或 latest')) },
            ]}
          >
            <AutoComplete
              allowClear
              placeholder="选择或输入版本号"
              options={versions.map((version) => ({
                value: version,
                label: `${version}${version === defaultVersion ? '（面板默认）' : ''}`,
              }))}
              filterOption={(input, option) => String(option?.value ?? '').toLowerCase().includes(input.toLowerCase())}
            />
          </Form.Item>
        </Form>
        <Alert
          type="info"
          showIcon
          title="所选版本仅用于本次安装"
          description="安装会写入最小配置；已有节点请在安装后执行「部署」恢复节点配置。"
        />
      </Flex>
    </Modal>
  );
}
