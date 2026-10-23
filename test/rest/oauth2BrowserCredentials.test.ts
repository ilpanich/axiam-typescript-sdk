// The browser persona withholds same-origin cookies from `/oauth2/*` — CONTRACT.md §12.1 rule 3
// (`credentials: "omit"` for browser SDKs), C163-12.
//
// axios's XHR adapter sends a same-origin cookie whatever `withCredentials` says, so an `/oauth2/*`
// request is issued through the fetch adapter with `credentials: 'omit'`. The assertion is on the
// per-request config the interceptor chain leaves; a capture interceptor registered before
// `installInterceptors` runs last (request interceptors run last-registered first), sees the final
// config and stops the request, so nothing reaches a network.

import { describe, expect, it } from 'vitest';
import type { AxiosRequestConfig } from 'axios';
import { installInterceptors } from '../../src/rest/interceptors.js';
import { createSession, type SharedSession } from '../../src/rest/session.js';
import { createNodeSession } from '../../src/node/session.js';

const BASE_URL = 'https://axiam.test';
const STOP = new Error('captured');

async function finalConfig(session: SharedSession, url: string): Promise<AxiosRequestConfig> {
  let captured: AxiosRequestConfig | undefined;
  session.axios.interceptors.request.use((config) => {
    captured = { ...config };
    throw STOP;
  });
  installInterceptors(session.axios, session);
  await session.axios.post(url, 'grant_type=client_credentials').catch((e: unknown) => {
    if (e !== STOP) throw e;
  });
  return captured!;
}

describe('browser persona: /oauth2/* carries the fetch adapter with credentials omitted (C163-12)', () => {
  it.each(['/oauth2/token', '/oauth2/device_authorization', '/oauth2/introspect', '/oauth2/revoke'])(
    '%s',
    async (path) => {
      const config = await finalConfig(createSession({ baseUrl: BASE_URL, tenantSlug: 'acme' }), path);

      expect(config.adapter).toBe('fetch');
      expect(config.fetchOptions).toEqual({ credentials: 'omit' });
      expect(config.withCredentials).toBe(false);
    },
  );

  it('an ordinary request keeps the default adapter and its credentials', async () => {
    const config = await finalConfig(
      createSession({ baseUrl: BASE_URL, tenantSlug: 'acme' }),
      '/api/v1/auth/federation/oauth2/start',
    );

    expect(config.adapter).not.toBe('fetch');
    expect(config.fetchOptions).toBeUndefined();
    expect(config.withCredentials).toBe(true);
  });

  it('the Node persona keeps its jar-free agent pair and does not switch adapter', async () => {
    const config = await finalConfig(
      createNodeSession({ baseUrl: BASE_URL, tenantSlug: 'acme' }),
      '/oauth2/token',
    );

    expect(config.adapter).not.toBe('fetch');
    expect(config.fetchOptions).toBeUndefined();
    expect(config.withCredentials).toBe(false);
    expect(config.httpsAgent).toBeDefined();
  });
});
