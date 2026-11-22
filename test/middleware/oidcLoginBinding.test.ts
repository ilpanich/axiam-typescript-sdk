// CONTRACT.md §12.8 (contract 1.68): the "Login with AXIAM" glue binds the
// callback to the browser that started the login (C7, login CSRF) and follows
// `returnTo` only as a same-origin relative path (C6, open redirect).
//
// Every case runs against BOTH framework adapters — Express `oidcLoginHandlers`
// and Fastify `oidcLoginPlugin` — because §12.8 rule 4 requires the tests per
// adapter: the binding cookie is adapter I/O, so one adapter could drop it
// while the shared core stayed correct.

import { createHash } from 'node:crypto';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import Fastify from 'fastify';
import type { Request, Response } from 'express';
import { oidcLoginHandlers } from '../../src/middleware/express.js';
import { oidcLoginPlugin } from '../../src/middleware/fastify.js';
import type { OidcLoginOptions } from '../../src/middleware/oidcLoginCore.js';
import { MemoryOidcStateStore, type OidcStateEntry } from '../../src/node/oidcState.js';
import { Sensitive } from '../../src/core/index.js';
import {
  CLIENT_SECRET,
  createClient,
  createMockState,
  createServer,
  discoveryHandler,
  generateSigningKey,
  jwksHandler,
  REDIRECT_URI,
  signIdToken,
  tokenResponse,
  TOKEN_ENDPOINT,
} from '../node/oidcTestKit.js';

const server = createServer();
beforeAll(() => server.listen({ onUnhandledFrame: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const HOST_COOKIE = '__Host-axiam_oidc_bind';
const LOOPBACK_COOKIE = 'axiam_oidc_bind';
const UNIFORM_401 = {
  error: 'authentication_failed',
  message: 'unknown, expired, or already-used login state',
};

/** What one HTTP exchange looked like from the browser's side. */
interface Exchange {
  status: number;
  location?: string;
  setCookies: string[];
  body?: unknown;
}

interface Harness {
  login(query?: string, cookie?: string): Promise<Exchange>;
  callback(query: string, cookie?: string): Promise<Exchange>;
  close(): Promise<void>;
}

type AnyOptions = OidcLoginOptions<unknown>;

// --- Express harness: the handlers against request/response doubles --------

function expressRes(): Response & { exchange: Exchange } {
  const exchange: Exchange = { status: 200, setCookies: [] };
  const res: Record<string, unknown> = { exchange };
  const addCookie = (name: string, value: unknown) => {
    if (name.toLowerCase() !== 'set-cookie') return;
    for (const v of Array.isArray(value) ? value : [value]) exchange.setCookies.push(String(v));
  };
  res.status = vi.fn((code: number) => {
    exchange.status = code;
    return res;
  });
  res.json = vi.fn((body: unknown) => {
    exchange.body = body;
    return res;
  });
  res.redirect = vi.fn((url: string) => {
    exchange.status = 302;
    exchange.location = url;
    return res;
  });
  res.append = vi.fn((name: string, value: unknown) => {
    addCookie(name, value);
    return res;
  });
  res.setHeader = vi.fn((name: string, value: unknown) => {
    addCookie(name, value);
    return res;
  });
  return res as unknown as Response & { exchange: Exchange };
}

function expressReq(query: string, cookie?: string): Request {
  return {
    query: Object.fromEntries(new URLSearchParams(query)),
    headers: cookie !== undefined ? { cookie } : {},
  } as unknown as Request;
}

function expressHarness(options: AnyOptions): Harness {
  const { login, callback } = oidcLoginHandlers(options);
  return {
    async login(query = '', cookie) {
      const res = expressRes();
      await login(expressReq(query, cookie), res, vi.fn());
      return res.exchange;
    },
    async callback(query, cookie) {
      const res = expressRes();
      await callback(expressReq(query, cookie), res, vi.fn());
      return res.exchange;
    },
    async close() {},
  };
}

// --- Fastify harness: a real app, driven with inject() ----------------------

async function fastifyHarness(options: AnyOptions): Promise<Harness> {
  const app = Fastify();
  await app.register(oidcLoginPlugin(options));
  await app.ready();
  const toExchange = (r: Awaited<ReturnType<typeof app.inject>>): Exchange => {
    const raw = r.headers['set-cookie'];
    return {
      status: r.statusCode,
      ...(typeof r.headers.location === 'string' ? { location: r.headers.location } : {}),
      setCookies: raw === undefined ? [] : Array.isArray(raw) ? raw : [raw],
      ...(r.body ? { body: JSON.parse(r.body) } : {}),
    };
  };
  return {
    async login(query = '', cookie) {
      return toExchange(
        await app.inject({
          method: 'GET',
          url: `/auth/login${query ? `?${query}` : ''}`,
          ...(cookie !== undefined ? { headers: { cookie } } : {}),
        }),
      );
    },
    async callback(query, cookie) {
      return toExchange(
        await app.inject({
          method: 'GET',
          url: `/auth/callback?${query}`,
          ...(cookie !== undefined ? { headers: { cookie } } : {}),
        }),
      );
    },
    async close() {
      await app.close();
    },
  };
}

const ADAPTERS: Array<[string, (options: AnyOptions) => Harness | Promise<Harness>]> = [
  ['Express', expressHarness],
  ['Fastify', fastifyHarness],
];

// --- shared fixtures ---------------------------------------------------------

/** A MemoryOidcStateStore that also records every entry saved. */
function capturingStore(): { store: MemoryOidcStateStore; saved: OidcStateEntry[] } {
  const store = new MemoryOidcStateStore();
  const saved: OidcStateEntry[] = [];
  const originalSave = store.save.bind(store);
  store.save = async (entry: OidcStateEntry) => {
    saved.push(entry);
    await originalSave(entry);
  };
  return { store, saved };
}

/**
 * Wire discovery, JWKS and a COUNTING token endpoint whose ID token echoes the
 * nonce `nonceOf()` returns. The count is what proves "no exchange".
 */
async function wireIdp(nonceOf: () => string): Promise<{ tokenCalls: () => number }> {
  const key = await generateSigningKey('binding-kid');
  const state = createMockState();
  let calls = 0;
  server.use(
    discoveryHandler(state),
    jwksHandler(state, [key.jwk]),
    http.post(TOKEN_ENDPOINT, async () => {
      calls += 1;
      return HttpResponse.json(tokenResponse({ id_token: await signIdToken(key, { nonce: nonceOf() }) }));
    }),
  );
  return { tokenCalls: () => calls };
}

/** The `name=value` pair a `Set-Cookie` line sets. */
function cookiePair(setCookie: string): { name: string; value: string; attrs: string[] } {
  const [pair, ...attrs] = setCookie.split(';').map((p) => p.trim());
  const eq = pair.indexOf('=');
  return { name: pair.slice(0, eq), value: pair.slice(eq + 1), attrs };
}

/** The binding value a login set, or `undefined` when it set none. */
function maybeBindingCookie(exchange: Exchange, name = HOST_COOKIE): string | undefined {
  const line = exchange.setCookies.find((c) => cookiePair(c).name === name);
  return line === undefined ? undefined : cookiePair(line).value;
}

function bindingCookieFrom(exchange: Exchange, name = HOST_COOKIE): string {
  const line = exchange.setCookies.find((c) => cookiePair(c).name === name);
  expect(line, `login response sets ${name}`).toBeDefined();
  return cookiePair(line!).value;
}

function expectCleared(exchange: Exchange, name = HOST_COOKIE): void {
  const line = exchange.setCookies.find((c) => cookiePair(c).name === name);
  expect(line, `response clears ${name}`).toBeDefined();
  const { value, attrs } = cookiePair(line!);
  expect(value).toBe('');
  expect(attrs.map((a) => a.toLowerCase())).toContain('max-age=0');
}

const sha256Hex = (value: string): string => createHash('sha256').update(value, 'ascii').digest('hex');

describe.each(ADAPTERS)('§12.8 login glue — %s', (_name, build) => {
  // ---------------------------------------------------------------- C7
  describe('rule 1 — browser binding (C7)', () => {
    it('the login response sets __Host-axiam_oidc_bind with HttpOnly, Secure, SameSite=Lax, Path=/ and no Domain', async () => {
      const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
      const { store, saved } = capturingStore();
      await wireIdp(() => saved[0].nonce);
      const h = await build({ client: oidc, store, redirectUri: REDIRECT_URI });

      const login = await h.login();
      expect(login.status).toBe(302);
      const line = login.setCookies.find((c) => cookiePair(c).name === HOST_COOKIE);
      expect(line).toBeDefined();
      const { value, attrs } = cookiePair(line!);
      const lower = attrs.map((a) => a.toLowerCase());
      expect(lower).toContain('httponly');
      expect(lower).toContain('secure');
      expect(lower).toContain('samesite=lax');
      expect(lower).toContain('path=/');
      expect(lower.some((a) => a.startsWith('domain'))).toBe(false);
      const maxAge = lower.find((a) => a.startsWith('max-age='));
      expect(maxAge).toBeDefined();
      expect(Number(maxAge!.slice('max-age='.length))).toBeLessThanOrEqual(600);
      // 32 CSPRNG bytes, base64url without padding.
      expect(value).toMatch(/^[A-Za-z0-9_-]{43}$/);
      // The entry stores SHA-256 of the value, never the value itself.
      expect(saved[0].bindingDigest).toBe(sha256Hex(value));
      expect(JSON.stringify(saved[0])).not.toContain(value);
      await h.close();
    });

    it('on an http://localhost redirect_uri it sets axiam_oidc_bind without Secure', async () => {
      const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
      const { store, saved } = capturingStore();
      await wireIdp(() => saved[0].nonce);
      const h = await build({ client: oidc, store, redirectUri: 'http://localhost:3000/auth/callback' });

      const login = await h.login();
      expect(login.setCookies.some((c) => cookiePair(c).name === HOST_COOKIE)).toBe(false);
      const line = login.setCookies.find((c) => cookiePair(c).name === LOOPBACK_COOKIE);
      expect(line).toBeDefined();
      const lower = cookiePair(line!).attrs.map((a) => a.toLowerCase());
      expect(lower).not.toContain('secure');
      expect(lower).toContain('httponly');
      expect(lower).toContain('samesite=lax');
      expect(lower).toContain('path=/');
      await h.close();
    });

    it('on plain HTTP to a non-loopback host it still uses the __Host- name', async () => {
      const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
      const { store, saved } = capturingStore();
      await wireIdp(() => saved[0].nonce);
      const h = await build({ client: oidc, store, redirectUri: 'http://app.example.com/auth/callback' });

      const login = await h.login();
      expect(login.setCookies.some((c) => cookiePair(c).name === HOST_COOKIE)).toBe(true);
      expect(login.setCookies.some((c) => cookiePair(c).name === LOOPBACK_COOKIE)).toBe(false);
      await h.close();
    });

    it('a callback with a valid state and NO binding cookie answers the uniform 401: no exchange, no onSuccess, state consumed', async () => {
      const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
      const { store, saved } = capturingStore();
      const idp = await wireIdp(() => saved[0].nonce);
      const onSuccess = vi.fn();
      const h = await build({ client: oidc, store, redirectUri: REDIRECT_URI, onSuccess });

      const login = await h.login('returnTo=%2Fdashboard');
      const query = `state=${encodeURIComponent(saved[0].state)}&code=attacker-code`;

      const res = await h.callback(query);
      expect(onSuccess).not.toHaveBeenCalled();
      expect(idp.tokenCalls()).toBe(0);
      expect(res.status).toBe(401);
      expect(res.body).toEqual(UNIFORM_401);
      expect(res.location).toBeUndefined();
      expectCleared(res);
      const cookie = bindingCookieFrom(login);

      // Consumed: the right cookie afterwards cannot revive the state.
      const retry = await h.callback(query, `${HOST_COOKIE}=${cookie}`);
      expect(retry.status).toBe(401);
      expect(idp.tokenCalls()).toBe(0);
      expect(onSuccess).not.toHaveBeenCalled();
      await h.close();
    });

    it("a callback with ANOTHER browser's binding cookie answers 401: no exchange, no onSuccess, state consumed", async () => {
      const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
      const { store, saved } = capturingStore();
      const idp = await wireIdp(() => saved[0].nonce);
      const onSuccess = vi.fn();
      const h = await build({ client: oidc, store, redirectUri: REDIRECT_URI, onSuccess });

      // Browser A (the attacker) starts a login; browser B (the victim) has a
      // binding cookie of its own from a login it started.
      const loginA = await h.login();
      const cookieB = maybeBindingCookie(await h.login()) ?? 'victim-browser-binding-value';
      const queryA = `state=${encodeURIComponent(saved[0].state)}&code=attacker-code`;

      const res = await h.callback(queryA, `${HOST_COOKIE}=${cookieB}`);
      expect(onSuccess).not.toHaveBeenCalled();
      expect(idp.tokenCalls()).toBe(0);
      expect(res.status).toBe(401);
      expect(res.body).toEqual(UNIFORM_401);
      expectCleared(res);
      const cookieA = bindingCookieFrom(loginA);
      expect(cookieB).not.toBe(cookieA);

      const retry = await h.callback(queryA, `${HOST_COOKIE}=${cookieA}`);
      expect(retry.status).toBe(401);
      expect(idp.tokenCalls()).toBe(0);
      await h.close();
    });

    it('a callback from the browser that started the login succeeds, onSuccess receives the request, cookie cleared, state consumed', async () => {
      const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
      const { store, saved } = capturingStore();
      const idp = await wireIdp(() => saved[0].nonce);
      const seen: Array<{ sub: unknown; returnTo: unknown; request: unknown }> = [];
      const h = await build({
        client: oidc,
        store,
        redirectUri: REDIRECT_URI,
        onSuccess: (tokens, entry, request) => {
          seen.push({ sub: tokens.idClaims?.sub, returnTo: entry.returnTo, request });
        },
      });

      const login = await h.login('returnTo=%2Fdashboard');
      const cookie = bindingCookieFrom(login);
      const query = `state=${encodeURIComponent(saved[0].state)}&code=idp-code`;

      const res = await h.callback(query, `other=1; ${HOST_COOKIE}=${cookie}`);
      expect(res.status).toBe(302);
      expect(res.location).toBe('/dashboard');
      expect(idp.tokenCalls()).toBe(1);
      expect(seen).toHaveLength(1);
      expect(seen[0].sub).toBe('user-1');
      expect(seen[0].returnTo).toBe('/dashboard');
      // The framework request object itself (§12.8 rule 2).
      expect(seen[0].request).toBeDefined();
      expect((seen[0].request as { headers: { cookie?: string } }).headers.cookie).toContain(HOST_COOKIE);
      expectCleared(res);
      expect(store.size).toBe(0);

      const replay = await h.callback(query, `${HOST_COOKIE}=${cookie}`);
      expect(replay.status).toBe(401);
      expect(idp.tokenCalls()).toBe(1);
      await h.close();
    });

    it('the loopback name is the only one read on an http://localhost redirect_uri', async () => {
      const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
      const { store, saved } = capturingStore();
      const idp = await wireIdp(() => saved[saved.length - 1].nonce);
      const redirectUri = 'http://localhost:3000/auth/callback';
      const h = await build({ client: oidc, store, redirectUri });

      const first = bindingCookieFrom(await h.login(), LOOPBACK_COOKIE);
      // The __Host- name carrying the right value is not the cookie this rule selects.
      const wrongName = await h.callback(
        `state=${encodeURIComponent(saved[0].state)}&code=c`,
        `${HOST_COOKIE}=${first}`,
      );
      expect(wrongName.status).toBe(401);
      expectCleared(wrongName, LOOPBACK_COOKIE);

      const second = bindingCookieFrom(await h.login(), LOOPBACK_COOKIE);
      const ok = await h.callback(
        `state=${encodeURIComponent(saved[1].state)}&code=c`,
        `${LOOPBACK_COOKIE}=${second}`,
      );
      expect(ok.status).toBe(200);
      expect(idp.tokenCalls()).toBe(1);
      expectCleared(ok, LOOPBACK_COOKIE);
      await h.close();
    });

    it('an entry with no bindingDigest (stored directly in the store) is refused 401', async () => {
      const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
      const store = new MemoryOidcStateStore();
      const idp = await wireIdp(() => 'direct-nonce');
      const onSuccess = vi.fn();
      const h = await build({ client: oidc, store, redirectUri: REDIRECT_URI, onSuccess });
      await store.save({
        state: 'legacy-state',
        nonce: 'direct-nonce',
        codeVerifier: new Sensitive('v'.repeat(43)),
        redirectUri: REDIRECT_URI,
      });

      const res = await h.callback('state=legacy-state&code=c', `${HOST_COOKIE}=anything`);
      expect(res.status).toBe(401);
      expect(res.body).toEqual(UNIFORM_401);
      expect(idp.tokenCalls()).toBe(0);
      expect(onSuccess).not.toHaveBeenCalled();
      expectCleared(res);
      await h.close();
    });

    it('every other callback error clears the cookie too', async () => {
      const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
      const h = await build({ client: oidc, store: new MemoryOidcStateStore(), redirectUri: REDIRECT_URI });
      const malformed = await h.callback('code=c');
      expect(malformed.status).toBe(400);
      expectCleared(malformed);
      const idpError = await h.callback('error=access_denied');
      expect(idpError.status).toBe(401);
      expectCleared(idpError);
      const unknown = await h.callback('state=nope&code=c', `${HOST_COOKIE}=x`);
      expect(unknown.status).toBe(401);
      expect(unknown.body).toEqual(UNIFORM_401);
      expectCleared(unknown);
      await h.close();
    });
  });

  // ---------------------------------------------------------------- C6
  describe('rule 3 — returnTo (C6)', () => {
    const REFUSED = [
      'https://evil.example/x',
      '//evil.example/x',
      '/\\evil.example',
      '/a\\b',
      '/a\r',
      '/a\u0000b',
      '/a\u007f',
      'javascript:alert(1)',
      'dashboard',
    ];

    it.each(REFUSED)('%j is dropped at login', async (value) => {
      const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
      const { store, saved } = capturingStore();
      await wireIdp(() => saved[0].nonce);
      const h = await build({ client: oidc, store, redirectUri: REDIRECT_URI });

      await h.login(`returnTo=${encodeURIComponent(value)}`);
      expect(saved).toHaveLength(1);
      expect(saved[0].returnTo).toBeUndefined();
      await h.close();
    });

    /** Store an entry directly (as a caller-supplied store or older glue would) and complete it. */
    async function completeStored(returnTo: string, extra: Partial<AnyOptions> = {}): Promise<Exchange> {
      const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
      const store = new MemoryOidcStateStore();
      await wireIdp(() => 'stored-nonce');
      const h = await build({ client: oidc, store, redirectUri: REDIRECT_URI, ...extra });
      const binding = 'b'.repeat(43);
      await store.save({
        state: 'stored-state',
        nonce: 'stored-nonce',
        codeVerifier: new Sensitive('v'.repeat(43)),
        redirectUri: REDIRECT_URI,
        returnTo,
        bindingDigest: sha256Hex(binding),
      });
      const res = await h.callback('state=stored-state&code=c', `${HOST_COOKIE}=${binding}`);
      await h.close();
      return res;
    }

    it.each(REFUSED)('%j stored directly in the entry is not redirected to at the callback', async (value) => {
      const res = await completeStored(value);
      expect(res.location).toBeUndefined();
      // Falls back exactly as if no returnTo had been supplied: the JSON summary.
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({ authenticated: true });
    });

    it('/dashboard?tab=1 is stored at login and redirected to', async () => {
      const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
      const { store, saved } = capturingStore();
      await wireIdp(() => saved[0].nonce);
      const h = await build({ client: oidc, store, redirectUri: REDIRECT_URI });
      const cookie = bindingCookieFrom(await h.login(`returnTo=${encodeURIComponent('/dashboard?tab=1')}`));
      expect(saved[0].returnTo).toBe('/dashboard?tab=1');
      const res = await h.callback(
        `state=${encodeURIComponent(saved[0].state)}&code=c`,
        `${HOST_COOKIE}=${cookie}`,
      );
      expect(res.status).toBe(302);
      expect(res.location).toBe('/dashboard?tab=1');
      await h.close();
    });

    it('a predicate accepting https://app.example/x widens the rule for that value only', async () => {
      const allowReturnTo = (value: string): boolean => value === 'https://app.example/x';
      const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
      const { store, saved } = capturingStore();
      await wireIdp(() => saved[saved.length - 1].nonce);
      const h = await build({ client: oidc, store, redirectUri: REDIRECT_URI, allowReturnTo } as AnyOptions);

      const okCookie = bindingCookieFrom(await h.login(`returnTo=${encodeURIComponent('https://app.example/x')}`));
      expect(saved[0].returnTo).toBe('https://app.example/x');
      const ok = await h.callback(`state=${encodeURIComponent(saved[0].state)}&code=c`, `${HOST_COOKIE}=${okCookie}`);
      expect(ok.status).toBe(302);
      expect(ok.location).toBe('https://app.example/x');

      await h.login(`returnTo=${encodeURIComponent('https://evil.example/x')}`);
      expect(saved[1].returnTo).toBeUndefined();
      await h.close();

      const stored = await completeStored('https://evil.example/x', { allowReturnTo } as Partial<AnyOptions>);
      expect(stored.location).toBeUndefined();
    });

    it('a configured successRedirect still wins over a valid returnTo', async () => {
      const res = await completeStored('/dashboard', { successRedirect: '/home' });
      expect(res.status).toBe(302);
      expect(res.location).toBe('/home');
    });
  });
});
