// The browser persona withholds same-origin cookies from `/oauth2/*` — CONTRACT.md §12.1 rule 3
// (`credentials: "omit"` for browser SDKs), C163-12.
//
// axios's XHR adapter sends a same-origin cookie whatever `withCredentials` says, so an `/oauth2/*`
// request is issued through the fetch adapter with `credentials: 'omit'`. The assertion is on the
// per-request config the interceptor chain leaves; a capture interceptor registered before
// `installInterceptors` runs last (request interceptors run last-registered first), sees the final
// config and stops the request, so nothing reaches a network.

import { afterEach, describe, expect, it, vi } from 'vitest';
import axios, { type AxiosRequestConfig } from 'axios';
import { installInterceptors } from '../../src/rest/interceptors.js';
import { createSession, type SharedSession } from '../../src/rest/session.js';
import { createNodeSession } from '../../src/node/session.js';
import { AxiamClient } from '../../src/rest/client.js';
import { readClientRegistration } from '../../src/rest/clientRegistration.js';
import { bareRequest } from '../../src/rest/bareTransport.js';
import { NetworkError } from '../../src/core/errors.js';

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
      expect(config.fetchOptions).toEqual({ credentials: 'omit', redirect: 'error' });
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

describe('what the fetch adapter does with that config (C164-19)', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('a request to /oauth2/token reaches fetch as a Request with credentials "omit"', async () => {
    // axios derives the Request's `credentials` from `withCredentials: false`;
    // `fetchOptions.credentials` is discarded. Asserting on the Request the adapter
    // builds is what would notice a later axios reading either differently.
    const fetchStub = vi.fn(async () => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
    vi.stubGlobal('fetch', fetchStub);
    const session = createSession({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    installInterceptors(session.axios, session);

    await session.axios.post('/oauth2/token', 'grant_type=client_credentials');

    expect(fetchStub).toHaveBeenCalledTimes(1);
    const request = (fetchStub.mock.calls[0] as unknown as [Request])[0];
    expect(request.credentials).toBe('omit');
  });
});

describe('the RFC 7592 calls on the bare transport (C164-06)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  /** The config `bareRequest` creates its instance with, for a `readClientRegistration`. */
  async function bareInstanceConfig(client: AxiamClient): Promise<Record<string, unknown>> {
    let created: Record<string, unknown> | undefined;
    vi.spyOn(axios, 'create').mockImplementation(((config: Record<string, unknown>) => {
      created = config;
      return { request: async () => ({ status: 200, data: {}, headers: {} }) };
    }) as unknown as typeof axios.create);
    await readClientRegistration(client, `${BASE_URL}/oauth2/register/c1`, 'registration-token').catch(() => undefined);
    return created!;
  }

  it('the browser persona uses the fetch adapter with credentials omitted', async () => {
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    const config = await bareInstanceConfig(client);

    expect(config.adapter).toBe('fetch');
    expect(config.fetchOptions).toEqual({ credentials: 'omit', redirect: 'error' });
    expect(config.withCredentials).toBe(false);
  });

  it('the Node persona keeps its jar-free agent pair and no adapter', async () => {
    const client = new AxiamClient(
      { baseUrl: BASE_URL, tenantSlug: 'acme' },
      createNodeSession({ baseUrl: BASE_URL, tenantSlug: 'acme' }),
    );
    const config = await bareInstanceConfig(client);

    expect(config.adapter).toBeUndefined();
    expect(config.fetchOptions).toBeUndefined();
    expect(config.withCredentials).toBe(false);
    expect(config.httpsAgent).toBeDefined();
  });
});

describe('the browser persona follows no redirect on /oauth2/* (CONTRACT.md §12.1 rule 3, C165-26)', () => {
  const OTHER_HOST = 'https://other.test';
  const SECRET = 'registration-secret-token';

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  /**
   * A `fetch` that behaves as the platform does: a 307 from the AXIAM host is followed to its
   * `Location` (a second request, with the body) unless the request says `redirect: 'error'`,
   * in which case it rejects the way a browser does. `hosts` records every host it was asked for.
   */
  function redirectingFetch(hosts: string[]): ReturnType<typeof vi.fn> {
    return vi.fn(async (input: Request) => {
      const url = new URL(input.url);
      hosts.push(url.origin);
      if (url.origin === OTHER_HOST) return new Response('{}', { status: 200 });
      if (input.redirect === 'error') throw new TypeError('Failed to fetch');
      if (input.redirect === 'follow') {
        hosts.push(OTHER_HOST);
        return new Response('{}', { status: 200 });
      }
      return new Response(null, { status: 307, headers: { location: `${OTHER_HOST}/oauth2/register/c1` } });
    });
  }

  it('a 307 on an RFC 7592 read is a NetworkError, the second host sees nothing and no secret is in the error', async () => {
    const hosts: string[] = [];
    vi.stubGlobal('fetch', redirectingFetch(hosts));
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme'});

    const error = await readClientRegistration(client, `${BASE_URL}/oauth2/register/c1`, SECRET).then(
      () => undefined,
      (e: unknown) => e,
    );

    expect(error).toBeInstanceOf(NetworkError);
    expect(hosts).not.toContain(OTHER_HOST);
    expect(hosts.every((h) => h === BASE_URL)).toBe(true);
    expect(String((error as Error).message)).not.toContain(SECRET);
    expect(JSON.stringify(error, Object.getOwnPropertyNames(error))).not.toContain(SECRET);
    expect(String((error as Error).message)).not.toContain(OTHER_HOST);
  });

  it('a redirect handed back as a response (opaque-redirect, status 0, or a 3xx) is a NetworkError too', async () => {
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    for (const status of [0, 302, 307, 308]) {
      vi.spyOn(axios, 'create').mockImplementationOnce((() => ({
        request: async () => ({ status, data: '', headers: { location: `${OTHER_HOST}/x` } }),
      })) as unknown as typeof axios.create);
      const error = await bareRequest(client.session, 'op', { method: 'POST', url: `${BASE_URL}/oauth2/register` }).then(
        () => undefined,
        (e: unknown) => e,
      );
      expect(error).toBeInstanceOf(NetworkError);
      expect(String((error as Error).message)).not.toContain(OTHER_HOST);
    }
    vi.restoreAllMocks();
  });

  it('a 307 on a main-client /oauth2/token POST never reaches the second host', async () => {
    const hosts: string[] = [];
    vi.stubGlobal('fetch', redirectingFetch(hosts));
    const session = createSession({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    installInterceptors(session.axios, session);

    await expect(session.axios.post('/oauth2/token', `refresh_token=${SECRET}`)).rejects.toBeDefined();

    expect(hosts).not.toContain(OTHER_HOST);
  });
});
