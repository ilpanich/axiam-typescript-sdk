// requireAuthHook/requireAccessHook/requireRoleHook (Fastify) — CONTRACT.md
// §11 matrix: allow / deny->403 / unauthenticated->401 /
// unresolvable-resource->400 / transport-failure->503 (fail closed) /
// subjectId on the wire / scope passthrough / param vs literal vs resolver
// resource resolution.

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { createVerifier } from '../../src/node/jwks.js';
import { AxiamClient } from '../../src/rest/client.js';
import {
  requireAccessHook,
  requireAuthHook,
  requireRoleHook,
  type AxiamFastifyRequest,
} from '../../src/middleware/fastify.js';
import { fromParam, type AuthzVerifiableSession } from '../../src/middleware/authzCore.js';

const BASE_URL = 'https://axiam-mw-requireaccess-fastify.test';
const CHECK_PATH = `${BASE_URL}/api/v1/authz/check`;

function sessionWith(authzClient?: AuthzVerifiableSession['authzClient']): AuthzVerifiableSession {
  return {
    jwksVerifier: createVerifier(BASE_URL),
    tenantHeaderValue: 'tenant-1',
    authzClient,
  };
}

const AXIAM_USER = { userId: 'user-1', tenantId: 'tenant-1', roles: ['reader'] };

function withAxiamUser(app: FastifyInstance): void {
  app.addHook('preHandler', async (request: FastifyRequest) => {
    (request as AxiamFastifyRequest).axiamUser = AXIAM_USER;
  });
}

function client(): AxiamClient {
  return new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'tenant-1' });
}

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

describe('requireAccessHook (Fastify)', () => {
  it('throws synchronously at construction if session.authzClient is not configured', () => {
    const session = sessionWith(undefined);
    expect(() => requireAccessHook(session, 'read', 'doc-1')).toThrow(/authzClient/);
  });

  it('401s when request.axiamUser is absent', async () => {
    const app = Fastify();
    const session = sessionWith(client());
    app.get('/protected', { preHandler: requireAccessHook(session, 'read', 'doc-1') }, async () => ({ ok: true }));
    await app.ready();

    const response = await app.inject({ method: 'GET', url: '/protected' });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual(expect.objectContaining({ error: 'authentication_failed' }));
    await app.close();
  });

  it('allow: reaches the handler and sends subjectId = axiamUser.userId on the wire', async () => {
    mockCheck((body) => {
      expect(body.subject_id).toBe('user-1');
      expect(body.resource_id).toBe('doc-1');
      return { status: 200, body: { allowed: true } };
    });
    const app = Fastify();
    withAxiamUser(app);
    const session = sessionWith(client());
    app.get('/protected', { preHandler: requireAccessHook(session, 'read', 'doc-1') }, async () => ({ ok: true }));
    await app.ready();

    const response = await app.inject({ method: 'GET', url: '/protected' });

    expect(response.statusCode).toBe(200);
    expect(lastCheckBody?.subject_id).toBe('user-1');
    await app.close();
  });

  it('resolves the resource id from fromParam(name)', async () => {
    mockCheck((body) => {
      expect(body.resource_id).toBe('param-42');
      return { status: 200, body: { allowed: true } };
    });
    const app = Fastify();
    withAxiamUser(app);
    const session = sessionWith(client());
    app.get(
      '/protected/:id',
      { preHandler: requireAccessHook(session, 'read', fromParam('id')) },
      async () => ({ ok: true }),
    );
    await app.ready();

    const response = await app.inject({ method: 'GET', url: '/protected/param-42' });

    expect(response.statusCode).toBe(200);
    await app.close();
  });

  it('resolves the resource id from a (req) => string resolver', async () => {
    mockCheck((body) => {
      expect(body.resource_id).toBe('resolved-42');
      return { status: 200, body: { allowed: true } };
    });
    const app = Fastify();
    withAxiamUser(app);
    const session = sessionWith(client());
    app.get(
      '/protected/:id',
      {
        preHandler: requireAccessHook(session, 'read', (r: FastifyRequest) => `resolved-${(r.params as { id: string }).id}`),
      },
      async () => ({ ok: true }),
    );
    await app.ready();

    const response = await app.inject({ method: 'GET', url: '/protected/42' });

    expect(response.statusCode).toBe(200);
    await app.close();
  });

  it('passes scope through to checkAccess verbatim', async () => {
    mockCheck((body) => {
      expect(body.scope).toBe('field-x');
      return { status: 200, body: { allowed: true } };
    });
    const app = Fastify();
    withAxiamUser(app);
    const session = sessionWith(client());
    app.get(
      '/protected',
      { preHandler: requireAccessHook(session, 'read', 'doc-1', { scope: 'field-x' }) },
      async () => ({ ok: true }),
    );
    await app.ready();

    const response = await app.inject({ method: 'GET', url: '/protected' });

    expect(response.statusCode).toBe(200);
    await app.close();
  });

  it('deny (allowed: false) -> 403 authorization_denied', async () => {
    mockCheck(() => ({ status: 200, body: { allowed: false, reason: 'nope' } }));
    const app = Fastify();
    withAxiamUser(app);
    const session = sessionWith(client());
    app.get('/protected', { preHandler: requireAccessHook(session, 'write', 'doc-1') }, async () => ({ ok: true }));
    await app.ready();

    const response = await app.inject({ method: 'GET', url: '/protected' });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual(expect.objectContaining({ error: 'authorization_denied', message: 'nope' }));
    await app.close();
  });

  it('server 403 -> 403 authorization_denied', async () => {
    mockCheck(() => ({ status: 403, body: { error: 'authorization_denied', message: 'denied server-side' } }));
    const app = Fastify();
    withAxiamUser(app);
    const session = sessionWith(client());
    app.get('/protected', { preHandler: requireAccessHook(session, 'write', 'doc-1') }, async () => ({ ok: true }));
    await app.ready();

    const response = await app.inject({ method: 'GET', url: '/protected' });

    expect(response.statusCode).toBe(403);
    await app.close();
  });

  it('unresolvable resource (missing route param) -> 400 invalid_request, never a silent allow', async () => {
    const app = Fastify();
    withAxiamUser(app);
    const session = sessionWith(client());
    app.get(
      '/protected',
      { preHandler: requireAccessHook(session, 'read', fromParam('missingParam')) },
      async () => ({ ok: true }),
    );
    await app.ready();

    const response = await app.inject({ method: 'GET', url: '/protected' });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual(expect.objectContaining({ error: 'invalid_request' }));
    await app.close();
  });

  it('network failure while calling authz endpoint -> 503 authz_unavailable, fail closed', async () => {
    server.use(http.post(CHECK_PATH, () => HttpResponse.error()));
    const app = Fastify();
    withAxiamUser(app);
    const session = sessionWith(client());
    app.get('/protected', { preHandler: requireAccessHook(session, 'read', 'doc-1') }, async () => ({ ok: true }));
    await app.ready();

    const response = await app.inject({ method: 'GET', url: '/protected' });

    expect(response.statusCode).toBe(503);
    expect(response.json()).toEqual(expect.objectContaining({ error: 'authz_unavailable' }));
    await app.close();
  });

  it('invokes the optional debug logger on deny with action/resourceId, never the token', async () => {
    mockCheck(() => ({ status: 200, body: { allowed: false, reason: 'nope' } }));
    const app = Fastify();
    withAxiamUser(app);
    const session = sessionWith(client());
    const logger = { debug: vi.fn() };
    app.get(
      '/protected',
      { preHandler: requireAccessHook(session, 'delete', 'doc-1', { logger }) },
      async () => ({ ok: true }),
    );
    await app.ready();

    await app.inject({ method: 'GET', url: '/protected' });

    expect(logger.debug).toHaveBeenCalledWith(
      'axiam_sdk.authz',
      'access denied',
      expect.objectContaining({ action: 'delete', resourceId: 'doc-1' }),
    );
    await app.close();
  });
});

describe('requireAuthHook (Fastify)', () => {
  it('is sugar over the §10 guard: no credential -> 401', async () => {
    const app = Fastify();
    const session = sessionWith(undefined);
    app.get('/protected', { preHandler: requireAuthHook(session) }, async () => ({ ok: true }));
    await app.ready();

    const response = await app.inject({ method: 'GET', url: '/protected' });

    expect(response.statusCode).toBe(401);
    await app.close();
  });
});

describe('requireRoleHook (Fastify)', () => {
  async function buildApp(...roles: string[]): Promise<FastifyInstance> {
    const app = Fastify();
    const session = sessionWith(undefined);
    app.get('/protected', { preHandler: requireRoleHook(session, ...roles) }, async () => ({ ok: true }));
    await app.ready();
    return app;
  }

  it('401s when request.axiamUser is absent', async () => {
    const app = await buildApp('admin');
    const response = await app.inject({ method: 'GET', url: '/protected' });
    expect(response.statusCode).toBe(401);
    await app.close();
  });

  it('403s when the identity has none of the required roles', async () => {
    const app = Fastify();
    withAxiamUser(app);
    const session = sessionWith(undefined);
    app.get('/protected', { preHandler: requireRoleHook(session, 'admin') }, async () => ({ ok: true }));
    await app.ready();

    const response = await app.inject({ method: 'GET', url: '/protected' });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual(expect.objectContaining({ error: 'authorization_denied' }));
    await app.close();
  });

  it('reaches the handler when the identity has at least one required role', async () => {
    const app = Fastify();
    withAxiamUser(app);
    const session = sessionWith(undefined);
    app.get('/protected', { preHandler: requireRoleHook(session, 'reader') }, async () => ({ ok: true }));
    await app.ready();

    const response = await app.inject({ method: 'GET', url: '/protected' });

    expect(response.statusCode).toBe(200);
    await app.close();
  });
});
