// CONTRACT.md §11.2 rule 11 (contract 1.68; N15, D-1): `requireRole` reads the
// verified token's `roles` claim and nothing else, fails closed when it is
// absent, and `requireScope` is the separate helper for OAuth2 scopes. Each
// case runs end to end — a real EdDSA token through the §10 guard and then the
// §11 helper — for Express, Fastify and the NestJS guard, so no adapter can
// keep deriving roles from `scope` on its own.
import 'reflect-metadata';

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import Fastify from 'fastify';
import { Reflector } from '@nestjs/core';
import type { ExecutionContext } from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';
import { exportJWK, generateKeyPair, SignJWT, type JWK } from 'jose';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { createVerifier, JWKS_PATH } from '../../src/node/jwks.js';
import * as expressAdapter from '../../src/middleware/express.js';
import * as fastifyAdapter from '../../src/middleware/fastify.js';
import * as nestDecorators from '../../src/nestjs/decorators.js';
import { AxiamGuard } from '../../src/nestjs/guard.js';
import { authenticateRequest } from '../../src/middleware/verifyCore.js';
import type { AuthzVerifiableSession } from '../../src/middleware/authzCore.js';

const BASE_URL = 'https://axiam-roles-claim.test';
const TENANT = '11111111-1111-1111-1111-111111111111';
const KID = 'roles-kid';

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledFrame: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

let privateKey: CryptoKey;
let publicJwk: JWK;
beforeAll(async () => {
  const pair = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
  privateKey = pair.privateKey;
  publicJwk = await exportJWK(pair.publicKey);
  publicJwk.kid = KID;
  publicJwk.alg = 'EdDSA';
});

function serveJwks(): void {
  server.use(http.get(`${BASE_URL}${JWKS_PATH}`, () => HttpResponse.json({ keys: [publicJwk] })));
}

/** An access token as a 1.68 server mints it: `typ: at+jwt`, a `kid`. */
async function token(claims: Record<string, unknown>): Promise<string> {
  return new SignJWT({ tenant_id: TENANT, ...claims })
    .setProtectedHeader({ alg: 'EdDSA', kid: KID, typ: 'at+jwt' })
    .setSubject('user-1')
    .setIssuer('https://axiam.example')
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(privateKey);
}

function session(): AuthzVerifiableSession {
  return { jwksVerifier: createVerifier(BASE_URL), tenantHeaderValue: TENANT };
}

/** The §11 helper names under test, resolved at call time (requireScope is new in 1.68). */
type Helper = 'role' | 'scope';

// ---------------------------------------------------------------------------
// Express: axiamMiddleware then requireRole / requireScope
// ---------------------------------------------------------------------------

async function expressStatus(helper: Helper, value: string, claims: Record<string, unknown>): Promise<number> {
  serveJwks();
  const s = session();
  const req = { headers: { authorization: `Bearer ${await token(claims)}` }, method: 'GET' } as unknown as Request;
  let status = 200;
  const res: Partial<Response> = {};
  res.status = vi.fn((code: number) => {
    status = code;
    return res as Response;
  });
  res.json = vi.fn().mockReturnValue(res);
  res.setHeader = vi.fn().mockReturnValue(res);
  let passedGuard = false;
  await expressAdapter.axiamMiddleware(s)(req, res as Response, (() => {
    passedGuard = true;
  }) as NextFunction);
  if (!passedGuard) return status;
  const factory =
    helper === 'role'
      ? expressAdapter.requireRole
      : (expressAdapter as unknown as { requireScope: typeof expressAdapter.requireRole }).requireScope;
  let admitted = false;
  await factory(s, value)(req, res as Response, (() => {
    admitted = true;
  }) as NextFunction);
  return admitted ? 200 : status;
}

// ---------------------------------------------------------------------------
// Fastify: axiamPlugin then requireRoleHook / requireScopeHook
// ---------------------------------------------------------------------------

async function fastifyStatus(helper: Helper, value: string, claims: Record<string, unknown>): Promise<number> {
  serveJwks();
  const s = session();
  const app = Fastify();
  await app.register(fastifyAdapter.axiamPlugin(s));
  const hook =
    helper === 'role'
      ? fastifyAdapter.requireRoleHook(s, value)
      : (fastifyAdapter as unknown as { requireScopeHook: typeof fastifyAdapter.requireRoleHook }).requireScopeHook(
          s,
          value,
        );
  app.get('/guarded', { preHandler: hook }, async () => ({ ok: true }));
  const response = await app.inject({
    method: 'GET',
    url: '/guarded',
    headers: { authorization: `Bearer ${await token(claims)}` },
  });
  await app.close();
  return response.statusCode;
}

// ---------------------------------------------------------------------------
// NestJS: AxiamGuard with @RequireRole / @RequireScope
// ---------------------------------------------------------------------------

async function nestStatus(helper: Helper, value: string, claims: Record<string, unknown>): Promise<number> {
  serveJwks();
  const s = session();
  class Controller {
    route(): void {}
  }
  const decoratorFactory =
    helper === 'role'
      ? nestDecorators.RequireRole
      : (nestDecorators as unknown as { RequireScope: typeof nestDecorators.RequireRole }).RequireScope;
  const descriptor = Object.getOwnPropertyDescriptor(Controller.prototype, 'route')!;
  (decoratorFactory(value) as MethodDecorator)(Controller.prototype, 'route', descriptor);
  const request: { axiamUser?: unknown } = {};
  request.axiamUser = await authenticateRequest(s, await token(claims));
  const context = {
    getHandler: () => Controller.prototype.route,
    getClass: () => Controller,
    switchToHttp: () => ({ getRequest: () => request }),
  } as unknown as ExecutionContext;
  try {
    return (await new AxiamGuard(new Reflector(), s).canActivate(context)) ? 200 : 403;
  } catch (err) {
    return (err as { getStatus?: () => number }).getStatus?.() ?? 500;
  }
}

const adapters = [
  ['Express', expressStatus],
  ['Fastify', fastifyStatus],
  ['NestJS', nestStatus],
] as const;

describe.each(adapters)('§11.2 rule 11 — %s', (_name, status) => {
  describe('requireRole reads the roles claim only', () => {
    it('roles ["admin"] with scope "openid" passes requireRole("admin")', async () => {
      expect(await status('role', 'admin', { roles: ['admin'], scope: 'openid' })).toBe(200);
    });

    it('no roles claim and scope "openid admin" is refused 403 (the N15 bypass)', async () => {
      expect(await status('role', 'admin', { scope: 'openid admin' })).toBe(403);
    });

    it('roles [] is refused 403', async () => {
      expect(await status('role', 'admin', { roles: [], scope: 'openid admin' })).toBe(403);
    });

    it('roles ["Admin"] is refused by requireRole("admin") (case-sensitive)', async () => {
      expect(await status('role', 'admin', { roles: ['Admin'] })).toBe(403);
    });

    it('a roles claim that is a string, not an array, is refused 403', async () => {
      expect(await status('role', 'admin', { roles: 'admin' })).toBe(403);
    });
  });

  describe('requireScope reads the scope claim only', () => {
    it('scope "openid admin" passes requireScope("admin")', async () => {
      expect(await status('scope', 'admin', { scope: 'openid admin' })).toBe(200);
    });

    it('roles ["admin"] with scope "openid" is refused 403 (the claims never stand in for each other)', async () => {
      expect(await status('scope', 'admin', { roles: ['admin'], scope: 'openid' })).toBe(403);
    });

    it('no scope claim is refused 403', async () => {
      expect(await status('scope', 'admin', { roles: ['admin'] })).toBe(403);
    });

    it('scope "administrator" does not pass requireScope("admin") (whole entries)', async () => {
      expect(await status('scope', 'admin', { scope: 'administrator' })).toBe(403);
    });
  });
});

describe('§10 identity keeps "no roles claim" and "roles: []" distinguishable', () => {
  it('absent roles is undefined, [] is [], and scope never fills roles', async () => {
    serveJwks();
    const absent = await authenticateRequest(session(), await token({ scope: 'openid admin' }));
    expect(absent.roles).toBeUndefined();
    const empty = await authenticateRequest(session(), await token({ roles: [], scope: 'openid admin' }));
    expect(empty.roles).toEqual([]);
    const held = await authenticateRequest(session(), await token({ roles: ['admin'], scope: 'openid' }));
    expect(held.roles).toEqual(['admin']);
  });
});
