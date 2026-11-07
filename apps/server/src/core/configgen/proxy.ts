export interface ProxyEndpoint {
  protocol: 'http' | 'socks5';
  host: string;
  port: number;
  username?: string;
  password?: string;
}

/** Parse an outbound URL without including its credentials in error messages. */
export function parseProxyUrl(value: string): ProxyEndpoint {
  try {
    const text = value.trim();
    if (!/^(http|socks5):\/\//i.test(text) || /[\s\\]/.test(text)) throw new Error();
    const url = new URL(text);
    if (!url.hostname || (url.pathname && url.pathname !== '/') || url.search || url.hash) throw new Error();
    // SOCKS is a non-special URL scheme; validate its authority like an HTTP URL.
    const authority = new URL(`http://${url.host}`);
    const port = Number(url.port || (url.protocol === 'http:' ? 80 : 1080));
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error();
    const username = url.username ? decodeURIComponent(url.username) : undefined;
    const password = url.password ? decodeURIComponent(url.password) : undefined;
    if (password && !username) throw new Error();
    return {
      protocol: url.protocol === 'http:' ? 'http' : 'socks5',
      host: authority.hostname.replace(/^\[|\]$/g, ''),
      port,
      username,
      password,
    };
  } catch {
    throw new Error('请输入有效的 HTTP 或 SOCKS5 代理链接，如 socks5://user:pass@1.2.3.4:5678');
  }
}
