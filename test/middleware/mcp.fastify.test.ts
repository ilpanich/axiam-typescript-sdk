// CONTRACT.md §28.9 required tests 3, 4 and 5 on the Fastify surface, plus
// the regression §28.9 calls "more than all five": with `resourceMetadataUrl`
// unset, nothing changes.
//
// The same suite as `mcp.express.test.ts`, asserting the same values against
// the other framework — a §28 helper that works on one surface and not the
// other is half the section. Driven through `app.inject`, Fastify's own
// full-stack request path, so hooks, routing and header serialization all run.
//
// One deliberate difference from the Express file, and the only one: Fastify
// appends `; charset=utf-8` to any `*json*` content type that carries no
// charset parameter, and offers no supported way to suppress it. The media
// type is what §28.3 rule 1 pins and what a client parses, so that is what
// both files assert.
//
// The fixture is §28.9's, in `mcpFixture.ts`. Test 1 (document shape) and test
// 2 (challenge quoting) are framework-independent and live in
// `mcp.contract.test.ts`.

import Fastify, { type FastifyInstance } from 'fastify';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { AccessDecision } from '../../src/core/authz.js';
import { ValidationError } from '../../src/management/errors.js';
import type { AuthzChecker, AuthzVerifiableSession } from '../../src/middleware/authzCore.js';
import {
  axiamPlugin,
  requireAccessHook,
  requireRoleHook,
} from '../../src/middleware/fastify.js';
import {
  protectedResourceMetadata,
  serveProtectedResourceMetadata,
} from '../../src/middleware/mcpCore.js';
import { createVerifier, JWKS_PATH } from '../../src/node/jwks.js';
import { EXPECTED_AUDIENCE, FIXTURE, METADATA_PATH, METADATA_URL, VECTORS } from './mcpFixture.js';

const BASE_URL = 'https://axiam-mcp-fastify.test';
const TENANT = 'tenant-1';

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterAll(() => server.close());

let signingKey: CryptoKey;
let publicJwk: Record<string, unknown>;
const KID = 'mcp-fastify-kid';

beforeAll(async () => {
  const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
  signingKey = privateKey;
  const jwk = await exportJWK(publicKey);
  jwk.kid = KID;
  jwk.alg = 'EdDSA';
  publicJwk = jwk as Record<string, unknown>;
});

// Re-registered per test rather than once: every session below builds a fresh
// `createVerifier`, so each one fetches the key set for itself.
beforeEach(() => {
  server.resetHandlers();
  server.use(http.get(`${BASE_URL}${JWKS_PATH}`, () => HttpResponse.json({ keys: [publicJwk] })));
});

/** A signed AXIAM access token. `aud` and `exp` are what the §28 tests vary. */
async function token(options: { aud?: string; expired?: boolean } = {}): Promise<string> {
  let jwt = new SignJWT({ tenant_id: TENANT, scope: 'mcp:read' })
    .setProtectedHeader({ alg: 'EdDSA', kid: KID })
    .setSubject('user-1')
    .setIssuer('axiam')
    // Well past CLOCK_SKEW_LEEWAY_SEC, so an expired token is expired rather
    // than merely skewed.
    .setExpirationTime(options.expired ? '-10m' : '1h');
  if (options.aud !== undefined) jwt = jwt.setAudience(options.aud);
  return jwt.sign(signingKey);
}

/** A checker that answers with one fixed decision and makes no network call. */
function checker(decision: AccessDecision): AuthzChecker {
  return { checkAccess: async () => decision };
}

/**
 * The §28-configured session: `resourceMetadataUrl` set, and
 * `expectedAudience` set to the document's `resource` — §28.5 rule 2 makes the
 * second mandatory once the first is present.
 */
function mcpSession(authzClient?: AuthzChecker): AuthzVerifiableSession {
  return {
    jwksVerifier: createVerifier(BASE_URL),
    tenantHeaderValue: TENANT,
    expectedAudience: EXPECTED_AUDIENCE,
    resourceMetadataUrl: METADATA_URL,
    ...(authzClient ? { authzClient } : {}),
  };
}

/** The same session with §28 off — the regression's baseline. */
function plainSession(authzClient?: AuthzChecker): AuthzVerifiableSession {
  return {
    jwksVerifier: createVerifier(BASE_URL),
    tenantHeaderValue: TENANT,
    expectedAudience: EXPECTED_AUDIENCE,
    ...(authzClient ? { authzClient } : {}),
  };
}

/**
 * The deployment shape §28 describes: the §10 guard registered globally as a
 * `preHandler`, the metadata document served, one plain protected route and
 * one guarded by `requireAccessHook`.
 *
 * Note the registration order: the guard goes on FIRST and the metadata route
 * after it. A Fastify `preHandler` hook applies to every route in its context
 * regardless of order, so there is no ordering trick that could exempt the
 * document — the guard has to exempt the path itself, and this is where that
 * is proved.
 */
async function buildApp(
  session: AuthzVerifiableSession,
  opts: { serve?: boolean; scope?: string } = {},
): Promise<FastifyInstance> {
  const app = Fastify();
  await app.register(axiamPlugin(session));
  if (opts.serve !== false) {
    const metadata = protectedResourceMetadata(FIXTURE);
    serveProtectedResourceMetadata(app, metadata, session.resourceMetadataUrl ? session : undefined);
  }
  app.get('/mcp', async () => ({ ok: true }));
  if (session.authzClient) {
    app.get(
      '/tool',
      { preHandler: requireAccessHook(session, 'mcp:invoke', 'tool-1', opts.scope ? { scope: opts.scope } : {}) },
      async () => ({ ok: true }),
    );
  }
  await app.ready();
  return app;
}

/** The `Content-Type` media type, with any parameters dropped. */
function mediaType(value: string | undefined): string {
  return (value ?? '').split(';')[0]!.trim();
}

// ---------------------------------------------------------------------------
// §28.9 test 3 — 401 with the challenge
// ---------------------------------------------------------------------------

describe('§28.9 test 3 (Fastify) — 401 with the challenge', () => {
  it('a request with no Authorization header answers vector 1, and the §10 body is unchanged', async () => {
    const app = await buildApp(mcpSession());
    try {
      const res = await app.inject({ method: 'GET', url: '/mcp' });

      expect(res.statusCode).toBe(401);
      expect(res.headers['www-authenticate']).toBe(VECTORS.noCredential);
      // No `error` parameter: RFC 6750 §3 says a resource server SHOULD NOT
      // name an error code when the request carried no authentication
      // information at all. No credential is not a bad credential.
      expect(String(res.headers['www-authenticate'])).not.toContain('error=');
      // §28 adds a header. It does not touch the status or the body.
      expect(res.json()).toEqual({
        error: 'authentication_failed',
        message: 'missing authentication credentials',
      });
    } finally {
      await app.close();
    }
  });

  it('a request with an expired token answers vector 2, and says nothing else about why', async () => {
    const app = await buildApp(mcpSession());
    try {
      const res = await app.inject({
        method: 'GET',
        url: '/mcp',
        headers: {
          authorization: `Bearer ${await token({ aud: EXPECTED_AUDIENCE, expired: true })}`,
        },
      });

      expect(res.statusCode).toBe(401);
      expect(res.headers['www-authenticate']).toBe(VECTORS.invalidToken);
      // §28.4 and §28.8: the challenge carries no `error_description`, and no
      // part of the presented credential — not the token, not a prefix of it,
      // not a claim decoded from it.
      const challenge = String(res.headers['www-authenticate']);
      expect(challenge).not.toContain('error_description');
      expect(challenge).not.toContain('expired');
      expect(res.json().error).toBe('authentication_failed');
    } finally {
      await app.close();
    }
  });

  it('serves the document with no credential, with the guard registered globally', async () => {
    const app = await buildApp(mcpSession());
    try {
      const res = await app.inject({ method: 'GET', url: METADATA_PATH });

      // A document that 401s cannot start the handshake it exists to start.
      expect(res.statusCode).toBe(200);
      expect(res.headers['www-authenticate']).toBeUndefined();
      expect(mediaType(res.headers['content-type'] as string)).toBe('application/json');
      expect(res.headers['cache-control']).toBe('public, max-age=3600');
      expect(res.headers['access-control-allow-origin']).toBe('*');
      // Asking a browser to attach the user's cookies to a request that has no
      // use for them.
      expect(res.headers['access-control-allow-credentials']).toBeUndefined();
      expect(res.headers['set-cookie']).toBeUndefined();

      expect(res.json()).toEqual({
        resource: 'https://mcp.example.com/mcp',
        authorization_servers: ['https://axiam.example.com'],
        scopes_supported: ['mcp:read', 'mcp:tools'],
        bearer_methods_supported: ['header'],
        resource_documentation: 'https://mcp.example.com/docs',
      });
    } finally {
      await app.close();
    }
  });

  it('serves the same bytes to an authenticated caller as to an anonymous one', async () => {
    const app = await buildApp(mcpSession());
    try {
      const anonymous = await app.inject({ method: 'GET', url: METADATA_PATH });
      const authenticated = await app.inject({
        method: 'GET',
        url: METADATA_PATH,
        headers: { authorization: `Bearer ${await token({ aud: EXPECTED_AUDIENCE })}` },
      });

      // §28.3 rule 4: the response MUST NOT vary on the request. That is what
      // makes `Access-Control-Allow-Origin: *` safe.
      expect(authenticated.body).toBe(anonymous.body);
    } finally {
      await app.close();
    }
  });
});

// ---------------------------------------------------------------------------
// §28.9 test 4 — 403 insufficient_scope
// ---------------------------------------------------------------------------

describe('§28.9 test 4 (Fastify) — 403 insufficient_scope', () => {
  async function denial(
    decision: AccessDecision,
    scope?: string,
  ): Promise<{ statusCode: number; headers: Record<string, unknown>; body: string }> {
    const app = await buildApp(mcpSession(checker(decision)), { scope });
    try {
      const res = await app.inject({
        method: 'GET',
        url: '/tool',
        headers: { authorization: `Bearer ${await token({ aud: EXPECTED_AUDIENCE })}` },
      });
      return { statusCode: res.statusCode, headers: res.headers, body: res.body };
    } finally {
      await app.close();
    }
  }

  it('a no_grant denial on a route that named a scope answers vector 3, body unchanged', async () => {
    const res = await denial(
      { allowed: false, reason: 'no matching grant', reasonCode: 'no_grant' },
      'mcp:tools',
    );

    expect(res.statusCode).toBe(403);
    expect(res.headers['www-authenticate']).toBe(VECTORS.insufficientScope);
    // Read this twice: the JSON body does not change. `insufficient_scope`
    // appears ONLY as the `error` parameter inside the header.
    expect(JSON.parse(res.body).error).toBe('authorization_denied');
    expect(res.body).not.toContain('insufficient_scope');
  });

  it('names the scope the route asked for, verbatim', async () => {
    const res = await denial(
      { allowed: false, reason: 'no matching grant', reasonCode: 'no_grant' },
      'urn:example:tools.invoke',
    );

    // §28.5 rule 6: never synthesised, never derived from `action`/`resource`,
    // never substituted from the document's `scopes_supported`.
    expect(res.headers['www-authenticate']).toBe(
      `Bearer error="insufficient_scope", scope="urn:example:tools.invoke", resource_metadata="${METADATA_URL}"`,
    );
  });

  it('carries no challenge on denied_by_rule, on an absent reason_code, or with no scope argument', async () => {
    // `no_grant` means *ask for more*. `denied_by_rule` means *an
    // administrator has already decided*, and no amount of re-authorization
    // will change it.
    const byRule = await denial(
      { allowed: false, reason: 'denied', reasonCode: 'denied_by_rule' },
      'mcp:tools',
    );
    expect(byRule.statusCode).toBe(403);
    expect(byRule.headers['www-authenticate']).toBeUndefined();

    const noCode = await denial({ allowed: false, reason: 'denied' }, 'mcp:tools');
    expect(noCode.statusCode).toBe(403);
    expect(noCode.headers['www-authenticate']).toBeUndefined();

    const unknownCode = await denial(
      { allowed: false, reason: 'denied', reasonCode: 'quota_exhausted' },
      'mcp:tools',
    );
    expect(unknownCode.headers['www-authenticate']).toBeUndefined();

    // No scope argument: there is nothing to name, and §28 forbids guessing.
    const noScope = await denial({
      allowed: false,
      reason: 'denied',
      reasonCode: 'no_grant',
    });
    expect(noScope.statusCode).toBe(403);
    expect(noScope.headers['www-authenticate']).toBeUndefined();
  });

  it('touches no other response — a 2xx gains nothing', async () => {
    const app = await buildApp(mcpSession(checker({ allowed: true, reasonCode: 'allowed' })), {
      scope: 'mcp:tools',
    });
    try {
      const res = await app.inject({
        method: 'GET',
        url: '/tool',
        headers: { authorization: `Bearer ${await token({ aud: EXPECTED_AUDIENCE })}` },
      });
      expect(res.statusCode).toBe(200);
      // A challenge on a success is a client asking the authorization server
      // what went right.
      expect(res.headers['www-authenticate']).toBeUndefined();
    } finally {
      await app.close();
    }
  });

  it('a §11 hook\u2019s own missing-identity 401 carries the challenge, and picks the vector from the request', async () => {
    // §28.5 rule 4 puts the challenge on EVERY 401 the guard emits, including
    // §11's `authentication_failed` 401 — the one a route gets when the §10
    // guard was never registered ahead of it.
    const session = mcpSession(checker({ allowed: true }));
    const app = Fastify();
    app.get(
      '/unguarded',
      { preHandler: requireAccessHook(session, 'mcp:invoke', 'tool-1') },
      async () => ({ ok: true }),
    );
    await app.ready();
    try {
      const anonymous = await app.inject({ method: 'GET', url: '/unguarded' });
      expect(anonymous.statusCode).toBe(401);
      expect(anonymous.headers['www-authenticate']).toBe(VECTORS.noCredential);

      const withCredential = await app.inject({
        method: 'GET',
        url: '/unguarded',
        headers: { authorization: `Bearer ${await token({ aud: EXPECTED_AUDIENCE })}` },
      });
      expect(withCredential.statusCode).toBe(401);
      expect(withCredential.headers['www-authenticate']).toBe(VECTORS.invalidToken);
    } finally {
      await app.close();
    }
  });

  it('a requireRoleHook failure carries no challenge', async () => {
    const session = mcpSession();
    const app = Fastify();
    await app.register(axiamPlugin(session));
    // `mcp:read` is the token's only scope, so `admin` is missing.
    app.get('/admin', { preHandler: requireRoleHook(session, 'admin') }, async () => ({ ok: true }));
    await app.ready();
    try {
      const res = await app.inject({
        method: 'GET',
        url: '/admin',
        headers: { authorization: `Bearer ${await token({ aud: EXPECTED_AUDIENCE })}` },
      });
      expect(res.statusCode).toBe(403);
      expect(res.headers['www-authenticate']).toBeUndefined();
    } finally {
      await app.close();
    }
  });
});

// ---------------------------------------------------------------------------
// §28.9 test 5 — a token whose `aud` is not the resource is refused
// ---------------------------------------------------------------------------

describe('§28.9 test 5 (Fastify) — the audience this server announced', () => {
  async function get(bearer: string): Promise<{ statusCode: number; challenge: unknown }> {
    const app = await buildApp(mcpSession());
    try {
      const res = await app.inject({
        method: 'GET',
        url: '/mcp',
        headers: { authorization: `Bearer ${bearer}` },
      });
      return { statusCode: res.statusCode, challenge: res.headers['www-authenticate'] };
    } finally {
      await app.close();
    }
  }

  it('refuses a token minted for another resource server', async () => {
    const res = await get(await token({ aud: 'https://other.example.com/mcp' }));
    expect(res.statusCode).toBe(401);
    expect(res.challenge).toBe(VECTORS.invalidToken);
  });

  it('refuses a general-purpose axiam:user token identically', async () => {
    // A perfectly valid AXIAM token that simply was not minted for this
    // resource. An implementation that admits it has not implemented the
    // section — and the two refusals are indistinguishable from outside.
    const res = await get(await token({ aud: 'axiam:user' }));
    expect(res.statusCode).toBe(401);
    expect(res.challenge).toBe(VECTORS.invalidToken);
  });

  it('admits a token whose aud is this resource', async () => {
    const res = await get(await token({ aud: EXPECTED_AUDIENCE }));
    expect(res.statusCode).toBe(200);
    expect(res.challenge).toBeUndefined();
  });

  it('refuses at construction when resourceMetadataUrl is set with no expected audience', () => {
    const halfConfigured = {
      jwksVerifier: createVerifier(BASE_URL),
      tenantHeaderValue: TENANT,
      resourceMetadataUrl: METADATA_URL,
    };

    // Announcing yourself obliges you to check. The refusal happens when
    // `axiamPlugin(session)` is called — before `register`, before `ready`,
    // before the server is listening — and it names both options.
    let caught: unknown;
    try {
      axiamPlugin(halfConfigured);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(ValidationError);
    expect((caught as Error).message).toContain('resourceMetadataUrl');
    expect((caught as Error).message).toContain('expectedAudience');

    // Every guard factory refuses it, not just the §10 one.
    expect(() => requireRoleHook(halfConfigured, 'admin')).toThrow(ValidationError);
    expect(() =>
      requireAccessHook({ ...halfConfigured, authzClient: checker({ allowed: true }) }, 'a', 'r'),
    ).toThrow(ValidationError);
  });
});

// ---------------------------------------------------------------------------
// The regression that matters more than all five
// ---------------------------------------------------------------------------

describe('§28 off (Fastify) — a feature that is off is indistinguishable from one that is absent', () => {
  it('emits no WWW-Authenticate on any response when resourceMetadataUrl is unset', async () => {
    const app = await buildApp(
      plainSession(checker({ allowed: false, reason: 'no matching grant', reasonCode: 'no_grant' })),
      { serve: false, scope: 'mcp:tools' },
    );
    try {
      const bearer = `Bearer ${await token({ aud: EXPECTED_AUDIENCE })}`;
      const unauthenticated = await app.inject({ method: 'GET', url: '/mcp' });
      const authenticated = await app.inject({
        method: 'GET',
        url: '/mcp',
        headers: { authorization: bearer },
      });
      const denied = await app.inject({
        method: 'GET',
        url: '/tool',
        headers: { authorization: bearer },
      });

      // Assert the header's ABSENCE explicitly rather than the status: a 401
      // that grew a header is still a 401, and an implementation that emitted a
      // bare `Bearer` challenge unconditionally would pass every other test in
      // this file.
      expect(unauthenticated.statusCode).toBe(401);
      expect(unauthenticated.headers['www-authenticate']).toBeUndefined();
      expect(unauthenticated.json()).toEqual({
        error: 'authentication_failed',
        message: 'missing authentication credentials',
      });

      expect(authenticated.statusCode).toBe(200);
      expect(authenticated.headers['www-authenticate']).toBeUndefined();

      expect(denied.statusCode).toBe(403);
      expect(denied.headers['www-authenticate']).toBeUndefined();
      expect(denied.json().error).toBe('authorization_denied');
    } finally {
      await app.close();
    }
  });

  it('exempts no path when resourceMetadataUrl is unset', async () => {
    const app = await buildApp(plainSession(), { serve: false });
    try {
      // The exemption exists only where §28 is configured, and covers exactly
      // the one path that option names.
      const res = await app.inject({ method: 'GET', url: METADATA_PATH });
      expect(res.statusCode).toBe(401);
      expect(res.headers['www-authenticate']).toBeUndefined();
    } finally {
      await app.close();
    }
  });
});
