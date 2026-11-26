// docs/login-glue-binding.md, "The redirect target is encoded by the adapter"
// (review gate TYP-R3-1): the `Location` of the callback's 302 is the
// percent-encoded form of the destination, in BOTH adapters, so a `returnTo`
// that is a valid same-origin path but not valid in a header value (a space, a
// non-ASCII character, a lone surrogate, a CR/LF an integrator's predicate
// let through) still produces a 302 that clears the binding cookie.
//
// Both adapters run inside the REAL framework: Express through `res.redirect`
// (which encodes), Fastify through `reply.header('location', ...)` (which does
// not, and whose `writeHead` refuses a character outside latin1).

import { createHash } from 'node:crypto';
import { createServer as createHttpServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import express from 'express';
import Fastify from 'fastify';
import { http, HttpResponse } from 'msw';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { oidcLoginHandlers } from '../../src/middleware/express.js';
import { oidcLoginPlugin } from '../../src/middleware/fastify.js';
import type { OidcLoginOptions } from '../../src/middleware/oidcLoginCore.js';
import { MemoryOidcStateStore } from '../../src/node/oidcState.js';
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
beforeAll(() => server.listen({ onUnhandledFrame: 'bypass' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const HOST_COOKIE = '__Host-axiam_oidc_bind';
const BINDING = 'b'.repeat(43);
const NONCE = 'redirect-encoding-nonce';
const sha256Hex = (value: string): string => createHash('sha256').update(value, 'ascii').digest('hex');

interface Exchange {
  status: number;
  location: string | undefined;
  setCookies: string[];
  /** Every header name, lower-cased: proves nothing was injected. */
  headerNames: string[];
}

interface Harness {
  callback(): Promise<Exchange>;
  close(): Promise<void>;
}

type AnyOptions = OidcLoginOptions<unknown>;

async function expressHarness(options: AnyOptions): Promise<Harness> {
  const { callback } = oidcLoginHandlers(options);
  const app = express();
  app.get('/auth/callback', callback);
  const httpServer: Server = createHttpServer(app);
  await new Promise<void>((resolve) => httpServer.listen(0, '127.0.0.1', resolve));
  const { port } = httpServer.address() as AddressInfo;
  return {
    async callback() {
      const res = await fetch(`http://127.0.0.1:${port}/auth/callback?state=stored-state&code=c`, {
        headers: { cookie: `${HOST_COOKIE}=${BINDING}` },
        redirect: 'manual',
      });
      await res.arrayBuffer();
      return {
        status: res.status,
        location: res.headers.get('location') ?? undefined,
        setCookies: res.headers.getSetCookie(),
        headerNames: [...res.headers.keys()],
      };
    },
    close: () => new Promise<void>((resolve) => httpServer.close(() => resolve())),
  };
}

async function fastifyHarness(options: AnyOptions): Promise<Harness> {
  const app = Fastify();
  await app.register(oidcLoginPlugin(options));
  await app.ready();
  return {
    async callback() {
      const r = await app.inject({
        method: 'GET',
        url: '/auth/callback?state=stored-state&code=c',
        headers: { cookie: `${HOST_COOKIE}=${BINDING}` },
      });
      const raw = r.headers['set-cookie'];
      return {
        status: r.statusCode,
        location: typeof r.headers.location === 'string' ? r.headers.location : undefined,
        setCookies: raw === undefined ? [] : Array.isArray(raw) ? raw : [raw],
        headerNames: Object.keys(r.headers).map((n) => n.toLowerCase()),
      };
    },
    close: () => app.close(),
  };
}

const ADAPTERS: Array<[string, (options: AnyOptions) => Promise<Harness>]> = [
  ['Express', expressHarness],
  ['Fastify', fastifyHarness],
];

async function wireIdp(): Promise<void> {
  const key = await generateSigningKey('redirect-encoding-kid');
  const state = createMockState();
  server.use(
    discoveryHandler(state),
    jwksHandler(state, [key.jwk]),
    http.post(TOKEN_ENDPOINT, async () =>
      HttpResponse.json(tokenResponse({ id_token: await signIdToken(key, { nonce: NONCE }) })),
    ),
  );
}

async function storeWith(returnTo: string | undefined): Promise<MemoryOidcStateStore> {
  const store = new MemoryOidcStateStore();
  await store.save({
    state: 'stored-state',
    nonce: NONCE,
    codeVerifier: new Sensitive('v'.repeat(43)),
    redirectUri: REDIRECT_URI,
    ...(returnTo !== undefined ? { returnTo } : {}),
    bindingDigest: sha256Hex(BINDING),
  });
  return store;
}

function expectCleared(exchange: Exchange): void {
  const line = exchange.setCookies.find((c) => c.startsWith(`${HOST_COOKIE}=`));
  expect(line, `response clears ${HOST_COOKIE}`).toBeDefined();
  const [pair, ...attrs] = line!.split(';').map((p) => p.trim());
  expect(pair).toBe(`${HOST_COOKIE}=`);
  expect(attrs.map((a) => a.toLowerCase())).toContain('max-age=0');
}

// returnTo (as stored) -> the Location both adapters must send.
const ENCODED: Array<[string, string, string]> = [
  ['a space', '/a b', '/a%20b'],
  ['a latin1 character', '/café', '/caf%C3%A9'],
  ['a character above latin1', '/€', '/%E2%82%AC'],
  ['a non-ASCII path with a query', '/日本?q=é', '/%E6%97%A5%E6%9C%AC?q=%C3%A9'],
  ['a lone surrogate', '/a\uD800b', '/a%EF%BF%BDb'],
  ['two adjacent lone high surrogates', '/\uD800\uD800', '/%EF%BF%BD%EF%BF%BD'],
  ['two adjacent lone low surrogates', '/\uDC00\uDC00', '/%EF%BF%BD%EF%BF%BD'],
  ['a valid surrogate pair (an emoji)', '/\u{1F600}', '/%F0%9F%98%80'],
  ['a % before a well-formed escape', '/%%41', '/%25%41'],
  ['a truncated escape', '/a%2', '/a%252'],
  ['an existing percent-escape (not double-encoded)', '/a%20b?x=%E2%82%AC', '/a%20b?x=%E2%82%AC'],
  ['an already-safe path', '/dashboard?tab=1', '/dashboard?tab=1'],
];

describe.each(ADAPTERS)('login glue redirect target is encoded by the adapter — %s', (_name, build) => {
  it.each(ENCODED)('returnTo with %s: 302, percent-encoded Location, cookie cleared, onSuccess ran', async (_label, returnTo, expected) => {
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    await wireIdp();
    let onSuccessCalls = 0;
    const h = await build({
      client: oidc,
      store: await storeWith(returnTo),
      redirectUri: REDIRECT_URI,
      onSuccess: () => {
        onSuccessCalls += 1;
      },
    });
    const res = await h.callback();
    expect(res.status).toBe(302);
    expect(res.location).toBe(expected);
    expect(onSuccessCalls).toBe(1);
    expectCleared(res);
    await h.close();
  });

  it('a CR/LF an integrator predicate let through is encoded, and injects no header', async () => {
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    await wireIdp();
    const h = await build({
      client: oidc,
      store: await storeWith('/a\r\nX-Injected: 1'),
      redirectUri: REDIRECT_URI,
      allowReturnTo: (value: string) => value.startsWith('/'),
    } as AnyOptions);
    const res = await h.callback();
    expect(res.status).toBe(302);
    expect(res.location).toBe('/a%0D%0AX-Injected:%201');
    expect(res.headerNames).not.toContain('x-injected');
    expectCleared(res);
    await h.close();
  });

  it('a non-ASCII successRedirect configured by the application is encoded too', async () => {
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    await wireIdp();
    const h = await build({
      client: oidc,
      store: await storeWith(undefined),
      redirectUri: REDIRECT_URI,
      successRedirect: '/début',
    });
    const res = await h.callback();
    expect(res.status).toBe(302);
    expect(res.location).toBe('/d%C3%A9but');
    expectCleared(res);
    await h.close();
  });
});
