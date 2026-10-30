import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';
import { HttpError } from './errors.js';
import type { NodeView } from '../core/subscribe/index.js';

export interface HostServer {
  host: string;
  client_host: string;
  client_hosts?: string | string[] | null;
}

export function readHosts(value?: string | string[] | null): string[] {
  if (Array.isArray(value)) return value;
  if (!value) return [];
  return JSON.parse(value) as string[];
}

/** 只接受地址,不接受 URL/端口/通配符;统一大小写、IDN、重复项。 */
export function normalizeHosts(value: unknown): string[] {
  if (value === null || value === undefined) return [];
  if (!Array.isArray(value) || value.length > 32) throw new HttpError(400, '对外域名须为数组,最多 32 个');
  return [...new Set(value.map((item: unknown) => {
    if (typeof item !== 'string') throw new HttpError(400, '域名必须是字符串');
    const text = item.trim().toLowerCase().replace(/\.$/, '');
    if (isIP(text)) return text;
    const host = domainToASCII(text);
    if (!host || host.length > 253 || /[\s/:?#@\\]/.test(text) || !host.split('.').every((label) =>
      /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
      throw new HttpError(400, `对外域名不合法:${item}`);
    }
    return host;
  }))];
}

export function serverHosts(server: HostServer): string[] {
  const hosts = readHosts(server.client_hosts);
  return hosts.length ? hosts : [server.client_host || server.host].filter(Boolean);
}

export function selectHosts(value: unknown, server: HostServer): string[] {
  const hosts = normalizeHosts(value);
  const available = serverHosts(server);
  if (hosts.some((host) => !available.includes(host))) throw new HttpError(400, '节点域名必须从该服务器的对外域名中选择');
  return hosts;
}

export function nodeHosts(value: string | string[] | null | undefined, server: HostServer): string[] {
  const available = serverHosts(server);
  const selected = readHosts(value).filter((host) => available.includes(host));
  return selected.length ? selected : available;
}

export function certificateDomains(server: HostServer): string[] {
  return serverHosts(server).filter((host) => !isIP(host));
}

/** 名称按地址区分,端口/凭据/Reality 借站 SNI 始终共用。 */
export function expandHostViews(view: NodeView, hosts: string[], hostSni = false): NodeView[] {
  return hosts.map((host) => ({
    ...view, host,
    name: hosts.length > 1 ? `${view.name} [${host}]` : view.name,
    sni: hostSni ? host : view.sni,
  }));
}
