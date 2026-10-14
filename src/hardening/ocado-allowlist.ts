/**
 * Hardening: HTTP allowlist for the Ocado provider.
 *
 * Every request the Ocado axios client makes, and every redirect it would
 * follow, must match one of the rules below or it is refused before leaving
 * the process. Checkout, slots, login, account and payment paths are not on
 * the list, so they cannot be reached even if some code path tries.
 *
 * This is defence in depth: the container's egress proxy separately limits
 * which hosts are reachable at all.
 */
import type { AxiosInstance, InternalAxiosRequestConfig } from 'axios';

const ALLOWED_HOST = 'www.ocado.com';

type Method = 'GET' | 'POST' | 'PUT';

interface Rule {
  method: Method;
  path: RegExp;
  /** Optional extra check on the request body. */
  body?: (data: unknown) => boolean;
  why: string;
}

const RULES: Rule[] = [
  { method: 'GET', path: /^\/$/, why: 'home page, read CSRF token' },
  { method: 'GET', path: /^\/search$/, why: 'product search results page' },
  { method: 'GET', path: /^\/favorites$/, why: 'favourites page' },
  { method: 'GET', path: /^\/api\/cart\/v1\/carts\/active$/, why: 'read basket' },
  { method: 'POST', path: /^\/api\/cart\/v1\/carts\/active\/apply-quantity$/, why: 'change basket quantities' },
  { method: 'PUT', path: /^\/api\/webproductpagews\/v6\/products$/, why: 'product details by id' },
  {
    method: 'POST',
    path: /^\/graphql$/,
    body: (data) => parseBody(data)?.operationName === 'GetCompletedOrders',
    why: 'order history query only',
  },
  { method: 'GET', path: /^\/api\/order\/v6\/orders\/[A-Za-z0-9-]+$/, why: 'single past order' },
  { method: 'GET', path: /^\/api\/recurringshopping\/v2\/web\/definitions$/, why: 'regulars list' },
];

function parseBody(data: unknown): any {
  if (data === undefined || data === null) return null;
  if (typeof data === 'string') {
    try { return JSON.parse(data); } catch { return null; }
  }
  return data;
}

/** Reject anything that could smuggle a different path past the regexes. */
function suspiciousPath(rawPath: string): boolean {
  const lower = rawPath.toLowerCase();
  return (
    lower.includes('..') ||
    lower.includes('%2e') ||
    lower.includes('%2f') ||
    lower.includes('%5c') ||
    lower.includes('\\') ||
    lower.includes('//')
  );
}

export class BlockedRequestError extends Error {
  constructor(detail: string) {
    super(`Blocked by hardened allowlist: ${detail}`);
    this.name = 'BlockedRequestError';
  }
}

/**
 * Throws BlockedRequestError unless the request matches an allowlist rule.
 * Exported for tests.
 */
export function assertAllowed(method: string, absoluteUrl: string, data?: unknown): void {
  let url: URL;
  try {
    url = new URL(absoluteUrl);
  } catch {
    throw new BlockedRequestError(`unparseable URL`);
  }
  if (url.protocol !== 'https:') throw new BlockedRequestError(`protocol ${url.protocol}`);
  if (url.hostname !== ALLOWED_HOST) throw new BlockedRequestError(`host ${url.hostname}`);
  if (url.port !== '') throw new BlockedRequestError(`port ${url.port}`);
  if (url.username || url.password) throw new BlockedRequestError('credentials in URL');

  // Check the raw path as written as well as the parsed one.
  const rawPath = absoluteUrl.slice(absoluteUrl.indexOf(url.host) + url.host.length).split(/[?#]/)[0] || '/';
  if (suspiciousPath(rawPath) || suspiciousPath(url.pathname)) {
    throw new BlockedRequestError(`suspicious path ${url.pathname}`);
  }

  const m = method.toUpperCase();
  const rule = RULES.find((r) => r.method === m && r.path.test(url.pathname));
  if (!rule) throw new BlockedRequestError(`${m} ${url.pathname} is not on the allowlist`);
  if (rule.body && !rule.body(data)) {
    throw new BlockedRequestError(`${m} ${url.pathname} body not permitted`);
  }
}

function absoluteFrom(config: InternalAxiosRequestConfig): string {
  const base = config.baseURL ?? `https://${ALLOWED_HOST}`;
  const target = new URL(config.url ?? '/', base);
  // Merge axios `params` into the URL so the check sees the real request.
  if (config.params && typeof config.params === 'object') {
    for (const [k, v] of Object.entries(config.params)) {
      if (v !== undefined && v !== null) target.searchParams.set(k, String(v));
    }
  }
  return target.toString();
}

/** Install the allowlist on an axios client. Call once, right after axios.create. */
export function installOcadoAllowlist(client: AxiosInstance): void {
  client.interceptors.request.use((config: InternalAxiosRequestConfig) => {
    assertAllowed(config.method ?? 'GET', absoluteFrom(config), config.data);
    return config;
  });

  // Redirects are followed inside the HTTP layer and bypass interceptors,
  // so check each hop explicitly. A redirected request becomes a GET.
  client.defaults.maxRedirects = 3;
  (client.defaults as any).beforeRedirect = (options: any) => {
    const proto = options.protocol ?? 'https:';
    const host = options.hostname ?? options.host ?? '';
    const path = options.path ?? '/';
    const port = options.port ? `:${options.port}` : '';
    assertAllowed('GET', `${proto}//${host}${port}${path}`);
  };
}
