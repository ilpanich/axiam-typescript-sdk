// oidcDiscover: fetch, per-origin cache key, TTL, single-flight
// (CONTRACT.md §12.1, §12.3 rule 6).

import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { NetworkError } from '../../src/core/index.js';
import { MIN_DISCOVERY_TTL_MS, normalizeOrigin } from '../../src/node/oidc.js';
import {
  BASE_URL,
  createClient,
  createMockState,
  createServer,
  discoveryDocument,
  discoveryHandler,
  ISSUER,
} from './oidcTestKit.js';
import { DISCOVERY_PATH } from '../../src/node/oidc.js';

describe('oidcDiscover (§12.1, §12.3 rule 6)', () => {
  const server = createServer();

  beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
  afterEach(() => {
    server.resetHandlers();
    vi.restoreAllMocks();
  });
  afterAll(() => server.close());

  it('fetches GET /.well-known/openid-configuration and returns the typed document', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state));
    const { oidc } = createClient();

    const configuration = await oidc.oidcDiscover();

    expect(state.discoveryCalls).toBe(1);
    expect(configuration.issuer).toBe(ISSUER);
    expect(configuration.token_endpoint).toBe(`${BASE_URL}/oauth2/token`);
    expect(configuration.jwks_uri).toBe(`${BASE_URL}/oauth2/jwks`);
    expect(configuration.id_token_signing_alg_values_supported).toEqual(['EdDSA']);
  });

  it('serves the second call from cache (no second HTTP request)', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state));
    const { oidc } = createClient();

    await oidc.oidcDiscover();
    await oidc.oidcDiscover();
    await oidc.oidcDiscover();

    expect(state.discoveryCalls).toBe(1);
  });

  it('re-fetches once the TTL has elapsed', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state));
    const { oidc } = createClient();

    const realNow = Date.now();
    const clock = vi.spyOn(Date, 'now');
    clock.mockReturnValue(realNow);

    await oidc.oidcDiscover();
    expect(state.discoveryCalls).toBe(1);

    // Just inside the TTL: still cached.
    clock.mockReturnValue(realNow + MIN_DISCOVERY_TTL_MS - 1);
    await oidc.oidcDiscover();
    expect(state.discoveryCalls).toBe(1);

    // Past the TTL: one more fetch.
    clock.mockReturnValue(realNow + MIN_DISCOVERY_TTL_MS + 1);
    await oidc.oidcDiscover();
    expect(state.discoveryCalls).toBe(2);
  });

  it('floors a configured TTL below the 5-minute contract minimum', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state));
    const { oidc } = createClient({ discoveryTtlMs: 1 });

    const realNow = Date.now();
    const clock = vi.spyOn(Date, 'now');
    clock.mockReturnValue(realNow);
    await oidc.oidcDiscover();
    // 10 seconds later the 1 ms TTL would have expired, but §12.3 rule 6's
    // 5-minute floor means the document is still cached.
    clock.mockReturnValue(realNow + 10_000);
    await oidc.oidcDiscover();

    expect(state.discoveryCalls).toBe(1);
  });

  it('collapses N concurrent calls into exactly one HTTP request (single-flight)', async () => {
    let calls = 0;
    server.use(
      http.get(`${BASE_URL}${DISCOVERY_PATH}`, async () => {
        calls += 1;
        // Hold the response open so every caller is genuinely in flight.
        await new Promise((resolve) => setTimeout(resolve, 20));
        return HttpResponse.json(discoveryDocument());
      }),
    );
    const { oidc } = createClient();

    const documents = await Promise.all(Array.from({ length: 8 }, () => oidc.oidcDiscover()));

    expect(calls).toBe(1);
    for (const document of documents) {
      expect(document.issuer).toBe(ISSUER);
    }
  });

  it('clears the in-flight slot on failure so a later call retries', async () => {
    let calls = 0;
    server.use(
      http.get(`${BASE_URL}${DISCOVERY_PATH}`, () => {
        calls += 1;
        return calls === 1
          ? HttpResponse.json({ error: 'boom' }, { status: 500 })
          : HttpResponse.json(discoveryDocument());
      }),
    );
    const { oidc } = createClient();

    await expect(oidc.oidcDiscover()).rejects.toBeInstanceOf(NetworkError);
    const configuration = await oidc.oidcDiscover();

    expect(calls).toBe(2);
    expect(configuration.issuer).toBe(ISSUER);
  });

  it('does not reject a document whose issuer differs from the base URL (§12.3 rule 6)', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state, discoveryDocument({ issuer: 'https://public.proxy.example' })));
    const { oidc } = createClient();

    await expect(oidc.oidcDiscover()).resolves.toMatchObject({
      issuer: 'https://public.proxy.example',
    });
  });
});

describe('normalizeOrigin — the discovery cache key (§12.3 rule 6)', () => {
  it('lowercases scheme and host and makes the default port explicit', () => {
    expect(normalizeOrigin('HTTPS://IAM.Example.COM/base/path')).toBe('https://iam.example.com:443');
    expect(normalizeOrigin('http://iam.example.com')).toBe('http://iam.example.com:80');
  });

  it('treats an explicit default port as identical to an implicit one', () => {
    expect(normalizeOrigin('https://iam.example.com:443/x')).toBe(normalizeOrigin('https://iam.example.com'));
  });

  it('keys distinct origins distinctly — no cross-issuer collision', () => {
    const keys = new Set([
      normalizeOrigin('https://iam.example.com'),
      normalizeOrigin('http://iam.example.com'),
      normalizeOrigin('https://iam.example.com:8443'),
      normalizeOrigin('https://evil.example.com'),
    ]);
    expect(keys.size).toBe(4);
  });
});
