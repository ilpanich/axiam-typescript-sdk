// requireAuth/requireAccess/requireRole (Express) — CONTRACT.md §11 matrix:
// allow / deny->403 / unauthenticated->401 / unresolvable-resource->400 /
// transport-failure->503 (fail closed) / subjectId on the wire / scope
// passthrough / param vs literal vs resolver resource resolution.

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import type { Request, Response } from 'express';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { createVerifier } from '../../src/node/jwks.js';
import { AxiamClient } from '../../src/rest/client.js';
import {
  requireAccess,
  requireAuth,
  requireRole,
  type AxiamRequest,
} from '../../src/middleware/express.js';
import { fromParam, type AuthzVerifiableSession } from '../../src/middleware/authzCore.js';

const BASE_URL = 'https://axiam-mw-requireaccess-express.test';
const CHECK_PATH = `${BASE_URL}/api/v1/authz/check`;

function fakeRes(): Response {
  const res: Partial<Response> = {};
  res.status = vi.fn().mockReturnValue(res);
  res.json = vi.fn().mockReturnValue(res);
  return res as Response;
}

function fakeReq(overrides: Partial<AxiamRequest> = {}): AxiamRequest {
  return { headers: {}, params: {}, ...overrides } as unknown as AxiamRequest;
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

function client(): AxiamClient {
  return new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'tenant-1' });
}

describe('requireAccess (Express)', () => {
  it('throws synchronously at construction if session.authzClient is not configured', () => {
    const session = sessionWith(undefined);
    expect(() => requireAccess(session, 'read', 'doc-1')).toThrow(/authzClient/);
  });

  it('401s when req.axiamUser is absent (never performs its own token extraction)', async () => {
    const session = sessionWith(client());
    const handler = requireAccess(session, 'read', 'doc-1');
    const req = fakeReq();
    const res = fakeRes();
    const next = vi.fn();

    await handler(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: 'authentication_failed' }));
  });

  it('allow: calls next() and sends subjectId = axiamUser.userId on the wire (literal resource)', async () => {
    mockCheck((body) => {
      expect(body.subject_id).toBe('user-1');
      expect(body.resource_id).toBe('doc-1');
      expect(body.action).toBe('read');
      return { status: 200, body: { allowed: true } };
    });
    const session = sessionWith(client());
    const handler = requireAccess(session, 'read', 'doc-1');
    const req = fakeReq({ axiamUser: AXIAM_USER });
    const res = fakeRes();
    const next = vi.fn();

    await handler(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect(res.status).not.toHaveBeenCalled();
    expect(lastCheckBody?.subject_id).toBe('user-1');
  });

  it('resolves the resource id from fromParam(name)', async () => {
    mockCheck((body) => {
      expect(body.resource_id).toBe('param-resource-42');
      return { status: 200, body: { allowed: true } };
    });
    const session = sessionWith(client());
    const handler = requireAccess(session, 'read', fromParam('id'));
    const req = fakeReq({ axiamUser: AXIAM_USER, params: { id: 'param-resource-42' } } as Partial<AxiamRequest>);
    const res = fakeRes();
    const next = vi.fn();

    await handler(req, res, next);

    expect(next).toHaveBeenCalledOnce();
  });

  it('resolves the resource id from a (req) => string resolver', async () => {
    mockCheck((body) => {
      expect(body.resource_id).toBe('resolved-from-body');
      return { status: 200, body: { allowed: true } };
    });
    const session = sessionWith(client());
    const handler = requireAccess(session, 'read', (r: Request) => (r as unknown as { body: { docId: string } }).body.docId);
    const req = fakeReq({ axiamUser: AXIAM_USER, body: { docId: 'resolved-from-body' } } as Partial<AxiamRequest>);
    const res = fakeRes();
    const next = vi.fn();

    await handler(req, res, next);

    expect(next).toHaveBeenCalledOnce();
  });

  it('passes scope through to checkAccess verbatim', async () => {
    mockCheck((body) => {
      expect(body.scope).toBe('sub-resource-scope');
      return { status: 200, body: { allowed: true } };
    });
    const session = sessionWith(client());
    const handler = requireAccess(session, 'read', 'doc-1', { scope: 'sub-resource-scope' });
    const req = fakeReq({ axiamUser: AXIAM_USER });
    const res = fakeRes();
    const next = vi.fn();

    await handler(req, res, next);

    expect(next).toHaveBeenCalledOnce();
  });

  it('deny (allowed: false) -> 403 authorization_denied, next() not called', async () => {
    mockCheck(() => ({ status: 200, body: { allowed: false, reason: 'not enough privilege' } }));
    const session = sessionWith(client());
    const handler = requireAccess(session, 'write', 'doc-1');
    const req = fakeReq({ axiamUser: AXIAM_USER });
    const res = fakeRes();
    const next = vi.fn();

    await handler(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ error: 'authorization_denied', message: 'not enough privilege' }),
    );
  });

  it('server 403 -> 403 authorization_denied', async () => {
    mockCheck(() => ({ status: 403, body: { error: 'authorization_denied', message: 'denied server-side' } }));
    const session = sessionWith(client());
    const handler = requireAccess(session, 'write', 'doc-1');
    const req = fakeReq({ axiamUser: AXIAM_USER });
    const res = fakeRes();
    const next = vi.fn();

    await handler(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: 'authorization_denied' }));
  });

  it('unresolvable resource (missing route param) -> 400 invalid_request, never a silent allow', async () => {
    const session = sessionWith(client());
    const handler = requireAccess(session, 'read', fromParam('missingParam'));
    const req = fakeReq({ axiamUser: AXIAM_USER, params: {} } as Partial<AxiamRequest>);
    const res = fakeRes();
    const next = vi.fn();

    await handler(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: 'invalid_request' }));
  });

  it('unresolvable resource (resolver returns empty string) -> 400 invalid_request', async () => {
    const session = sessionWith(client());
    const handler = requireAccess(session, 'read', () => '');
    const req = fakeReq({ axiamUser: AXIAM_USER });
    const res = fakeRes();
    const next = vi.fn();

    await handler(req, res, next);

    expect(res.status).toHaveBeenCalledWith(400);
  });

  it('network failure while calling authz endpoint -> 503 authz_unavailable, fail closed (never allow)', async () => {
    server.use(http.post(CHECK_PATH, () => HttpResponse.error()));
    const session = sessionWith(client());
    const handler = requireAccess(session, 'read', 'doc-1');
    const req = fakeReq({ axiamUser: AXIAM_USER });
    const res = fakeRes();
    const next = vi.fn();

    await handler(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(503);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: 'authz_unavailable' }));
  });

  it('an unexpected (non-Axiam) error from the checker -> 503 authz_unavailable, fail closed (never silently allow)', async () => {
    const session: AuthzVerifiableSession = {
      jwksVerifier: createVerifier(BASE_URL),
      tenantHeaderValue: 'tenant-1',
      authzClient: {
        checkAccess: () => Promise.reject(new Error('boom')),
      },
    };
    const handler = requireAccess(session, 'read', 'doc-1');
    const req = fakeReq({ axiamUser: AXIAM_USER });
    const res = fakeRes();
    const next = vi.fn();

    await handler(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(503);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: 'authz_unavailable' }));
  });

  it('5xx from the authz endpoint (NetworkError per §2) -> 503 authz_unavailable, fail closed', async () => {
    mockCheck(() => ({ status: 500, body: { message: 'boom' } }));
    const session = sessionWith(client());
    const handler = requireAccess(session, 'read', 'doc-1');
    const req = fakeReq({ axiamUser: AXIAM_USER });
    const res = fakeRes();
    const next = vi.fn();

    await handler(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(503);
  });

  it('invokes the optional debug logger on deny with action/resourceId, never the token', async () => {
    mockCheck(() => ({ status: 200, body: { allowed: false, reason: 'nope' } }));
    const session = sessionWith(client());
    const logger = { debug: vi.fn() };
    const handler = requireAccess(session, 'delete', 'doc-1', { logger });
    const req = fakeReq({ axiamUser: AXIAM_USER });
    const res = fakeRes();
    const next = vi.fn();

    await handler(req, res, next);

    expect(logger.debug).toHaveBeenCalledWith(
      'axiam_sdk.authz',
      'access denied',
      expect.objectContaining({ action: 'delete', resourceId: 'doc-1' }),
    );
  });
});

describe('requireAuth (Express)', () => {
  it('is sugar over the §10 guard: valid credential -> req.axiamUser set + next() called', async () => {
    // requireAuth performs the same extraction+verification as axiamMiddleware
    // (it IS axiamMiddleware under the §11 canonical name), so a request with
    // no credential at all is the cheapest way to exercise its 401 path
    // without needing a full JWKS/JWT fixture.
    const session = sessionWith(undefined);
    const handler = requireAuth(session);
    const req = fakeReq();
    const res = fakeRes();
    const next = vi.fn();

    await handler(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
  });
});

describe('requireRole (Express)', () => {
  const session = sessionWith(undefined);

  it('401s when req.axiamUser is absent', async () => {
    const handler = requireRole(session, 'admin');
    const req = fakeReq();
    const res = fakeRes();
    const next = vi.fn();

    await handler(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
  });

  it('403s when the identity has none of the required roles', async () => {
    const handler = requireRole(session, 'admin', 'superuser');
    const req = fakeReq({ axiamUser: AXIAM_USER });
    const res = fakeRes();
    const next = vi.fn();

    await handler(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: 'authorization_denied' }));
  });

  it('calls next() when the identity has at least one required role (no server round-trip)', async () => {
    const handler = requireRole(session, 'admin', 'reader');
    const req = fakeReq({ axiamUser: AXIAM_USER });
    const res = fakeRes();
    const next = vi.fn();

    await handler(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect(res.status).not.toHaveBeenCalled();
  });
});
