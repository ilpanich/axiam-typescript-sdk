// CONTRACT.md §12.8 rule 1 (d), "and any other error" (contract 1.68; review
// gate TYP-R1-2 / GLUE-R1-5): a callback whose state store or `onSuccess` hook
// THROWS still clears the binding cookie, and the error itself reaches the
// application's error handling unchanged.
//
// Unlike oidcLoginBinding.test.ts, both adapters run inside the REAL
// framework here — a listening Express 5 app driven with fetch, and a Fastify
// app driven with inject() — because what is under test is the error response
// the framework builds after the handler rejects, not the handler alone.

import { createHash } from 'node:crypto';
import { createServer as createHttpServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import express, { type NextFunction, type Request, type Response } from 'express';
import Fastify from 'fastify';
import { http, HttpResponse } from 'msw';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { oidcLoginHandlers } from '../../src/middleware/express.js';
import { oidcLoginPlugin } from '../../src/middleware/fastify.js';
import type { OidcLoginOptions } from '../../src/middleware/oidcLoginCore.js';
import type { OidcClient } from '../../src/node/oidc.js';
import { MemoryOidcStateStore, type OidcStateStore } from '../../src/node/oidcState.js';
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
// 'bypass': the Express app is a real local HTTP server the test fetches.
beforeAll(() => server.listen({ onUnhandledFrame: 'bypass' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const HOST_COOKIE = '__Host-axiam_oidc_bind';
const BINDING = 'b'.repeat(43);
const NONCE = 'error-path-nonce';
const sha256Hex = (value: string): string => createHash('sha256').update(value, 'ascii').digest('hex');

interface Exchange {
  status: number;
  setCookies: string[];
}

interface Harness {
  /** GET the callback with the right binding cookie for the stored entry. */
  callback(): Promise<Exchange>;
  /** Errors the application's error handler received (when one is installed). */
  handled: unknown[];
  close(): Promise<void>;
}

type AnyOptions = OidcLoginOptions<unknown>;

async function expressHarness(options: AnyOptions, customHandler: boolean): Promise<Harness> {
  const handled: unknown[] = [];
  const { callback } = oidcLoginHandlers(options);
  const app = express();
  app.get('/auth/callback', callback);
  if (customHandler) {
    app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
      handled.push(err);
      res.status(500).json({ error: 'internal_error' });
    });
  }
  const httpServer: Server = createHttpServer(app);
  await new Promise<void>((resolve) => httpServer.listen(0, '127.0.0.1', resolve));
  const { port } = httpServer.address() as AddressInfo;
  return {
    handled,
    async callback() {
      const res = await fetch(`http://127.0.0.1:${port}/auth/callback?state=stored-state&code=c`, {
        headers: { cookie: `${HOST_COOKIE}=${BINDING}` },
        redirect: 'manual',
      });
      await res.arrayBuffer();
      return { status: res.status, setCookies: res.headers.getSetCookie() };
    },
    close: () => new Promise<void>((resolve) => httpServer.close(() => resolve())),
  };
}

async function fastifyHarness(options: AnyOptions, customHandler: boolean): Promise<Harness> {
  const handled: unknown[] = [];
  const app = Fastify();
  if (customHandler) {
    app.setErrorHandler(async (err, _request, reply) => {
      handled.push(err);
      await reply.code(500).send({ error: 'internal_error' });
    });
  }
  await app.register(oidcLoginPlugin(options));
  await app.ready();
  return {
    handled,
    async callback() {
      const r = await app.inject({
        method: 'GET',
        url: '/auth/callback?state=stored-state&code=c',
        headers: { cookie: `${HOST_COOKIE}=${BINDING}` },
      });
      const raw = r.headers['set-cookie'];
      return { status: r.statusCode, setCookies: raw === undefined ? [] : Array.isArray(raw) ? raw : [raw] };
    },
    close: () => app.close(),
  };
}

const ADAPTERS: Array<[string, (options: AnyOptions, customHandler: boolean) => Promise<Harness>]> = [
  ['Express', expressHarness],
  ['Fastify', fastifyHarness],
];

/** Discovery, JWKS and a counting token endpoint whose ID token carries NONCE. */
async function wireIdp(): Promise<{ tokenCalls: () => number }> {
  const key = await generateSigningKey('error-path-kid');
  const state = createMockState();
  let calls = 0;
  server.use(
    discoveryHandler(state),
    jwksHandler(state, [key.jwk]),
    http.post(TOKEN_ENDPOINT, async () => {
      calls += 1;
      return HttpResponse.json(tokenResponse({ id_token: await signIdToken(key, { nonce: NONCE }) }));
    }),
  );
  return { tokenCalls: () => calls };
}

/** A store holding one entry bound to BINDING, as the login route would have saved it. */
async function boundStore(): Promise<MemoryOidcStateStore> {
  const store = new MemoryOidcStateStore();
  await store.save({
    state: 'stored-state',
    nonce: NONCE,
    codeVerifier: new Sensitive('v'.repeat(43)),
    redirectUri: REDIRECT_URI,
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

describe.each(ADAPTERS)('§12.8 rule 1 (d) on the error path — %s', (_name, build) => {
  it('onSuccess throws: the framework default error response still clears the binding cookie', async () => {
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    const idp = await wireIdp();
    const h = await build(
      {
        client: oidc,
        store: await boundStore(),
        redirectUri: REDIRECT_URI,
        onSuccess: () => {
          throw new Error('session store down');
        },
      },
      false,
    );
    const res = await h.callback();
    expect(idp.tokenCalls()).toBe(1);
    expect(res.status).toBe(500);
    expectCleared(res);
    await h.close();
  });

  it("onSuccess throws: the application's error handler receives that error, and the cookie is cleared", async () => {
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    await wireIdp();
    const boom = new Error('session store down');
    const h = await build(
      {
        client: oidc,
        store: await boundStore(),
        redirectUri: REDIRECT_URI,
        onSuccess: () => {
          throw boom;
        },
      },
      true,
    );
    const res = await h.callback();
    expect(res.status).toBe(500);
    expect(h.handled).toEqual([boom]);
    expectCleared(res);
    await h.close();
  });

  it('the state store rejects on consume: the cookie is cleared and nothing is exchanged', async () => {
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    const idp = await wireIdp();
    const storeDown = new Error('redis unavailable');
    const store: OidcStateStore = {
      save: async () => undefined,
      consume: async () => {
        throw storeDown;
      },
    };
    const h = await build({ client: oidc, store, redirectUri: REDIRECT_URI }, true);
    const res = await h.callback();
    expect(res.status).toBe(500);
    expect(h.handled).toEqual([storeDown]);
    expect(idp.tokenCalls()).toBe(0);
    expectCleared(res);
    await h.close();
  });

  it('the exchange throws an error that is neither AuthError nor NetworkError: 401, cookie cleared', async () => {
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    const failing = Object.create(oidc) as OidcClient;
    failing.oidcExchange = async () => {
      throw new TypeError('unexpected');
    };
    let called = false;
    const h = await build(
      {
        client: failing,
        store: await boundStore(),
        redirectUri: REDIRECT_URI,
        onSuccess: () => {
          called = true;
        },
      },
      true,
    );
    const res = await h.callback();
    expect(res.status).toBe(401);
    expect(called).toBe(false);
    expect(h.handled).toEqual([]);
    expectCleared(res);
    await h.close();
  });
});
