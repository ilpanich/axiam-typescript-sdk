// AxiamGuard (CONTRACT.md §11, Tier 2 NestJS) — the same §11 matrix as the
// Express/Fastify guards: allow / deny->403 / unauthenticated->401 /
// unresolvable-resource->400 / transport-failure->503 (fail closed) /
// subjectId on the wire / scope passthrough / param vs literal vs resolver
// resource resolution / local-only requireRole / requireAuth-only routes /
// unrestricted routes with no decorator at all.
//
// `reflect-metadata` must be imported before any `Reflector` use — a real
// Nest application does this once at bootstrap; this test file is the
// standalone entry point for the guard, so it does the same.
import 'reflect-metadata';

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { Reflector } from '@nestjs/core';
import type { ExecutionContext } from '@nestjs/common';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { AxiamClient } from '../../src/rest/client.js';
import { createVerifier } from '../../src/node/jwks.js';
import { AxiamGuard } from '../../src/nestjs/guard.js';
import { RequireAccess, RequireAuth, RequireRole } from '../../src/nestjs/decorators.js';
import type { AuthzVerifiableSession } from '../../src/middleware/authzCore.js';

const BASE_URL = 'https://axiam-nestjs-guard.test';
const CHECK_PATH = `${BASE_URL}/api/v1/authz/check`;

// A plain (undecorated-by-`@`-syntax) controller stand-in: the §11 metadata
// decorators are applied by calling their returned decorator functions
// directly, exactly as `@Foo()` syntax would (this SDK's tsconfig does not
// enable `experimentalDecorators`, so no code here uses `@` decorator
// syntax — only the functions the decorator factories return).
class TestController {
  plain(): void {}
  authOnly(): void {}
  accessLiteral(): void {}
  accessParam(): void {}
  accessResolver(): void {}
  accessScoped(): void {}
  accessLogged(): void {}
  roleRoute(): void {}
}

function applyMethodDecorator(decorator: MethodDecorator, methodName: keyof TestController): void {
  const descriptor = Object.getOwnPropertyDescriptor(TestController.prototype, methodName);
  decorator(TestController.prototype, methodName as string, descriptor!);
}

applyMethodDecorator(RequireAuth(), 'authOnly');
applyMethodDecorator(RequireAccess('read', 'doc-1'), 'accessLiteral');
applyMethodDecorator(RequireAccess('read', { param: 'id' }), 'accessParam');
applyMethodDecorator(
  RequireAccess('read', (req: unknown) => (req as { body?: { docId?: string } }).body?.docId ?? ''),
  'accessResolver',
);
applyMethodDecorator(RequireAccess('read', 'doc-1', { scope: 'field-x' }), 'accessScoped');
applyMethodDecorator(RequireRole('admin', 'superuser'), 'roleRoute');

function contextFor(handlerName: keyof TestController, request: unknown): ExecutionContext {
  return {
    getHandler: () => TestController.prototype[handlerName],
    getClass: () => TestController,
    switchToHttp: () => ({ getRequest: () => request }),
  } as unknown as ExecutionContext;
}

function client(): AxiamClient {
  return new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'tenant-1' });
}

function sessionWith(authzClient?: AuthzVerifiableSession['authzClient']): AuthzVerifiableSession {
  return {
    jwksVerifier: createVerifier(BASE_URL),
    tenantHeaderValue: 'tenant-1',
    authzClient,
  };
}

const AXIAM_USER = { userId: 'user-1', tenantId: 'tenant-1', roles: ['reader'] };

const server = setupServer();
let lastCheckBody: Record<string, unknown> | undefined;

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => {
  server.resetHandlers();
  lastCheckBody = undefined;
});
afterAll(() => server.close());

function mockCheck(
  handler: (body: Record<string, unknown>) => { status: number; body: Record<string, unknown> },
) {
  server.use(
    http.post(CHECK_PATH, async ({ request }) => {
      const body = (await request.json()) as Record<string, unknown>;
      lastCheckBody = body;
      const { status, body: responseBody } = handler(body);
      return HttpResponse.json(responseBody, { status });
    }),
  );
}

describe('AxiamGuard', () => {
  it('a route with none of the three decorators is left unrestricted (true), regardless of auth state', async () => {
    const guard = new AxiamGuard(new Reflector(), sessionWith(undefined));
    const allowed = await guard.canActivate(contextFor('plain', {}));
    expect(allowed).toBe(true);
  });

  describe('@RequireAuth()', () => {
    it('401s when request.axiamUser is absent', async () => {
      const guard = new AxiamGuard(new Reflector(), sessionWith(undefined));
      await expect(guard.canActivate(contextFor('authOnly', {}))).rejects.toMatchObject({
        response: expect.objectContaining({ error: 'authentication_failed' }),
        status: 401,
      });
    });

    it('passes when request.axiamUser is present', async () => {
      const guard = new AxiamGuard(new Reflector(), sessionWith(undefined));
      const allowed = await guard.canActivate(contextFor('authOnly', { axiamUser: AXIAM_USER }));
      expect(allowed).toBe(true);
    });
  });

  describe('@RequireRole(...)', () => {
    it('401s when request.axiamUser is absent', async () => {
      const guard = new AxiamGuard(new Reflector(), sessionWith(undefined));
      await expect(guard.canActivate(contextFor('roleRoute', {}))).rejects.toMatchObject({ status: 401 });
    });

    it('403s when the identity has none of the required roles (local check, no server round-trip)', async () => {
      const guard = new AxiamGuard(new Reflector(), sessionWith(undefined));
      await expect(
        guard.canActivate(contextFor('roleRoute', { axiamUser: AXIAM_USER })),
      ).rejects.toMatchObject({
        response: expect.objectContaining({ error: 'authorization_denied' }),
        status: 403,
      });
    });

    it('passes when the identity has at least one required role', async () => {
      const guard = new AxiamGuard(new Reflector(), sessionWith(undefined));
      const allowed = await guard.canActivate(
        contextFor('roleRoute', { axiamUser: { ...AXIAM_USER, roles: ['superuser'] } }),
      );
      expect(allowed).toBe(true);
    });
  });

  describe('@RequireAccess(action, resource, opts?)', () => {
    it('throws (rejects) when session.authzClient is not configured', async () => {
      const guard = new AxiamGuard(new Reflector(), sessionWith(undefined));
      await expect(
        guard.canActivate(contextFor('accessLiteral', { axiamUser: AXIAM_USER })),
      ).rejects.toThrow(/authzClient/);
    });

    it('401s when request.axiamUser is absent (never performs its own token extraction)', async () => {
      const guard = new AxiamGuard(new Reflector(), sessionWith(client()));
      await expect(guard.canActivate(contextFor('accessLiteral', {}))).rejects.toMatchObject({ status: 401 });
    });

    it('allow: returns true and sends subjectId = axiamUser.userId on the wire (literal resource)', async () => {
      mockCheck((body) => {
        expect(body.subject_id).toBe('user-1');
        expect(body.resource_id).toBe('doc-1');
        expect(body.action).toBe('read');
        return { status: 200, body: { allowed: true } };
      });
      const guard = new AxiamGuard(new Reflector(), sessionWith(client()));
      const allowed = await guard.canActivate(contextFor('accessLiteral', { axiamUser: AXIAM_USER }));
      expect(allowed).toBe(true);
      expect(lastCheckBody?.subject_id).toBe('user-1');
    });

    it('resolves the resource id from { param: name }', async () => {
      mockCheck((body) => {
        expect(body.resource_id).toBe('param-42');
        return { status: 200, body: { allowed: true } };
      });
      const guard = new AxiamGuard(new Reflector(), sessionWith(client()));
      const allowed = await guard.canActivate(
        contextFor('accessParam', { axiamUser: AXIAM_USER, params: { id: 'param-42' } }),
      );
      expect(allowed).toBe(true);
    });

    it('resolves the resource id from a (request) => string resolver', async () => {
      mockCheck((body) => {
        expect(body.resource_id).toBe('resolved-42');
        return { status: 200, body: { allowed: true } };
      });
      const guard = new AxiamGuard(new Reflector(), sessionWith(client()));
      const allowed = await guard.canActivate(
        contextFor('accessResolver', { axiamUser: AXIAM_USER, body: { docId: 'resolved-42' } }),
      );
      expect(allowed).toBe(true);
    });

    it('passes scope through to checkAccess verbatim', async () => {
      mockCheck((body) => {
        expect(body.scope).toBe('field-x');
        return { status: 200, body: { allowed: true } };
      });
      const guard = new AxiamGuard(new Reflector(), sessionWith(client()));
      const allowed = await guard.canActivate(contextFor('accessScoped', { axiamUser: AXIAM_USER }));
      expect(allowed).toBe(true);
    });

    it('deny (allowed: false) -> rejects with a 403-shaped exception', async () => {
      mockCheck(() => ({ status: 200, body: { allowed: false, reason: 'not enough privilege' } }));
      const guard = new AxiamGuard(new Reflector(), sessionWith(client()));
      await expect(
        guard.canActivate(contextFor('accessLiteral', { axiamUser: AXIAM_USER })),
      ).rejects.toMatchObject({
        response: expect.objectContaining({ error: 'authorization_denied', message: 'not enough privilege' }),
        status: 403,
      });
    });

    it('unresolvable resource (missing route param) -> rejects with a 400-shaped exception, never a silent allow', async () => {
      const guard = new AxiamGuard(new Reflector(), sessionWith(client()));
      await expect(
        guard.canActivate(contextFor('accessParam', { axiamUser: AXIAM_USER, params: {} })),
      ).rejects.toMatchObject({
        response: expect.objectContaining({ error: 'invalid_request' }),
        status: 400,
      });
    });

    it('unresolvable resource (resolver returns an empty string) -> rejects with a 400-shaped exception', async () => {
      const guard = new AxiamGuard(new Reflector(), sessionWith(client()));
      await expect(
        guard.canActivate(contextFor('accessResolver', { axiamUser: AXIAM_USER, body: {} })),
      ).rejects.toMatchObject({
        response: expect.objectContaining({ error: 'invalid_request' }),
        status: 400,
      });
    });

    it('network failure while calling the authz endpoint -> rejects with a 503-shaped exception, fail closed', async () => {
      server.use(http.post(CHECK_PATH, () => HttpResponse.error()));
      const guard = new AxiamGuard(new Reflector(), sessionWith(client()));
      await expect(
        guard.canActivate(contextFor('accessLiteral', { axiamUser: AXIAM_USER })),
      ).rejects.toMatchObject({
        response: expect.objectContaining({ error: 'authz_unavailable' }),
        status: 503,
      });
    });

    it('invokes the optional debug logger on deny with action/resourceId, never the token', async () => {
      mockCheck(() => ({ status: 200, body: { allowed: false, reason: 'nope' } }));
      const logger = { debug: vi.fn() };
      applyMethodDecorator(RequireAccess('delete', 'doc-1', { logger }), 'accessLogged');
      const guard = new AxiamGuard(new Reflector(), sessionWith(client()));

      await expect(guard.canActivate(contextFor('accessLogged', { axiamUser: AXIAM_USER }))).rejects.toBeDefined();

      expect(logger.debug).toHaveBeenCalledWith(
        'axiam_sdk.authz',
        'access denied',
        expect.objectContaining({ action: 'delete', resourceId: 'doc-1' }),
      );
    });
  });
});
