import { parseProxyUrl } from '../core/configgen/proxy.js';
import { decryptSecret, encryptSecret } from './creds.js';
import { HttpError } from './errors.js';

export function readProxyUrl(encrypted?: string): string | undefined {
  return encrypted ? decryptSecret(encrypted) : undefined;
}

/** Keep an omitted URL on partial updates, and clear it when leaving proxy mode. */
export function saveProxyUrl(outboundType: string, value?: string, previous = ''): string {
  if (outboundType !== 'proxy') return '';
  const url = value?.trim() ?? readProxyUrl(previous) ?? '';
  try {
    parseProxyUrl(url);
  } catch (err) {
    throw new HttpError(400, (err as Error).message);
  }
  return value === undefined && previous ? previous : encryptSecret(url);
}
