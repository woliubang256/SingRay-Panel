import { Form, Input } from 'antd';

export const OUTBOUND_OPTIONS = [
  { label: '直连', value: 'direct' },
  { label: '中转', value: 'relay' },
  { label: '代理', value: 'proxy' },
];

export function ProxyUrlField() {
  return (
    <Form.Item
      name="proxyUrl"
      label="代理链接"
      extra="支持 HTTP 或 SOCKS5 代理，用户名和密码可选；特殊字符请使用 URL 编码。"
      rules={[
        { required: true, whitespace: true, message: '请输入代理链接' },
        { validator: async (_, value?: string) => {
          if (!value?.trim()) return;
          try {
            const text = value.trim();
            if (!/^(http|socks5):\/\//i.test(text) || /[\s\\]/.test(text)) throw new Error();
            const url = new URL(text);
            if (!url.hostname || (url.pathname && url.pathname !== '/') || url.search || url.hash) throw new Error();
            new URL(`http://${url.host}`);
            const port = Number(url.port || (url.protocol === 'http:' ? 80 : 1080));
            if (port < 1 || port > 65535 || (url.password && !url.username)) throw new Error();
            decodeURIComponent(url.username);
            decodeURIComponent(url.password);
          } catch {
            throw new Error('请输入有效的 http:// 或 socks5:// 代理链接');
          }
        } },
      ]}
    >
      <Input placeholder="socks5://user:pass@1.2.3.4:5678" autoComplete="off" spellCheck={false} maxLength={4096} />
    </Form.Item>
  );
}
