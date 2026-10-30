import { Form, Select } from 'antd';
import type { Server } from '../services/types';

export function NodeDomainsField({ server }: { server?: Server }) {
  const hosts = server?.clientHosts?.length ? server.clientHosts : [server?.clientHost || server?.host].filter((v): v is string => Boolean(v));
  return (
    <Form.Item
      name="clientHosts"
      label="节点入口域名"
      extra={`留空继承服务器全部地址${hosts.length ? `：${hosts.join('、')}` : ''}。各入口共用同一端口和凭据。`}
      rules={[{ validator: (_, value: string[] | undefined) =>
        value?.some((host) => !hosts.includes(host)) ? Promise.reject(new Error('请选择当前服务器的域名')) : Promise.resolve(),
      }]}
    >
      <Select mode="multiple" allowClear options={hosts.map((host) => ({ value: host, label: host }))} placeholder="继承全部域名" />
    </Form.Item>
  );
}
