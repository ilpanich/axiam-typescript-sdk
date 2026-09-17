// CONTRACT.md §28.9 required tests 3, 4 and 5 on the Express surface, plus
// the regression §28.9 calls "more than all five": with `resourceMetadataUrl`
// unset, nothing changes.
//
// Driven against a real Express application on a real socket rather than
// against request/response doubles — §28 is entirely about what goes on the
// wire, so a double that recorded `setHeader` calls would prove the SDK asked
// for the header, not that the client receives it. `mcp.fastify.test.ts` is
// the same suite on the other framework surface; the two files assert the same
// values, so a helper that works on one and not the other fails here.
//
// The fixture is §28.9's, in `mcpFixture.ts`. Test 1 (document shape) and test
// 2 (challenge quoting) are framework-independent and live in
// `mcp.contract.test.ts`.

import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import express, { type Express } from 'express';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { AccessDecision } from '../../src/core/authz.js';
import { ValidationError } from '../../src/management/errors.js';
import type { AuthzChecker, AuthzVerifiableSession } from '../../src/middleware/authzCore.js';
import {
  axiamMiddleware,
  requireAccess,
  requireRole,
} from '../../src/middleware/express.js';
import {
  protectedResourceMetadata,
  serveProtectedResourceMetadata,
} from '../../src/middleware/mcpCore.js';
import { createVerifier, JWKS_PATH } from '../../src/node/jwks.js';
import { EXPECTED_AUDIENCE, FIXTURE, METADATA_PATH, METADATA_URL, VECTORS } from './mcpFixture.js';

const BASE_URL = 'https://axiam-mcp-express.test';
const TENANT = 'tenant-1';

// `bypass` rather than `error`: the JWKS fetch is mocked here, and the test's
// own requests go to a real loopback server that msw must let through.
const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: 'bypass' }));
afterAll(() => server.close());

let signingKey: CryptoKey;
let publicJwk: Record<string, unknown>;
const KID = 'mcp-express-kid';

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

interface Running {
  url: string;
  close: () => Promise<void>;
}

async function start(app: Express): Promise<Running> {
  const httpServer: Server = createServer(app);
  await new Promise<void>((resolve) => {
    httpServer.listen(0, '127.0.0.1', resolve);
  });
  const { port } = httpServer.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((resolve) => {
        httpServer.close(() => resolve());
      }),
  };
}

/**
 * The deployment shape §28 describes: the §10 guard mounted globally, the
 * metadata document served, one plain protected route and one guarded by
 * `requireAccess`.
 */
async function buildApp(
  session: AuthzVerifiableSession,
  opts: { serve?: boolean; scope?: string } = {},
): Promise<Running> {
  const app = express();
  app.use(axiamMiddleware(session));
  if (opts.serve !== false) {
    const metadata = protectedResourceMetadata(FIXTURE);
    serveProtectedResourceMetadata(app, metadata, session.resourceMetadataUrl ? session : undefined);
  }
  app.get('/mcp', (_req, res) => {
    res.json({ ok: true });
  });
  if (session.authzClient) {
    app.get(
      '/tool',
      requireAccess(session, 'mcp:invoke', 'tool-1', opts.scope ? { scope: opts.scope } : {}),
      (_req, res) => {
        res.json({ ok: true });
      },
    );
  }
  return start(app);
}

// ---------------------------------------------------------------------------
// §28.9 test 3 — 401 with the challenge
// ---------------------------------------------------------------------------

describe('§28.9 test 3 (Express) — 401 with the challenge', () => {
  it('a request with no Authorization header answers vector 1, and the §10 body is unchanged', async () => {
    const app = await buildApp(mcpSession());
    try {
      const res = await fetch(`${app.url}/mcp`);

      expect(res.status).toBe(401);
      expect(res.headers.get('www-authenticate')).toBe(VECTORS.noCredential);
      // No `error` parameter: RFC 6750 §3 says a resource server SHOULD NOT
      // name an error code when the request carried no authentication
      // information at all. No credential is not a bad credential.
      expect(res.headers.get('www-authenticate')).not.toContain('error=');
      // §28 adds a header. It does not touch the status or the body.
      expect(await res.json()).toEqual({
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
      const res = await fetch(`${app.url}/mcp`, {
        headers: { authorization: `Bearer ${await token({ aud: EXPECTED_AUDIENCE, expired: true })}` },
      });

      expect(res.status).toBe(401);
      expect(res.headers.get('www-authenticate')).toBe(VECTORS.invalidToken);
      // §28.4 and §28.8: the challenge carries no `error_description`, and no
      // part of the presented credential — not the token, not a prefix of it,
      // not a claim decoded from it. Every distinction a 401 draws for an
      // unauthenticated stranger is an oracle.
      const challenge = res.headers.get('www-authenticate') ?? '';
      expect(challenge).not.toContain('error_description');
      expect(challenge).not.toContain('expired');
      expect((await res.json()).error).toBe('authentication_failed');
    } finally {
      await app.close();
    }
  });

  it('serves the document with no credential, with the guard registered globally', async () => {
    const app = await buildApp(mcpSession());
    try {
      const res = await fetch(`${app.url}${METADATA_PATH}`);

      // A document that 401s cannot start the handshake it exists to start:
      // the client would be holding a 401 and being told to go read a page
      // that answers 401. The guard is mounted BEFORE this route and exempts
      // the path itself.
      expect(res.status).toBe(200);
      expect(res.headers.get('www-authenticate')).toBeNull();
      expect(res.headers.get('content-type')).toBe('application/json');
      expect(res.headers.get('cache-control')).toBe('public, max-age=3600');
      expect(res.headers.get('access-control-allow-origin')).toBe('*');
      // Asking a browser to attach the user's cookies to a request that has no
      // use for them.
      expect(res.headers.get('access-control-allow-credentials')).toBeNull();
      expect(res.headers.get('set-cookie')).toBeNull();

      expect(await res.json()).toEqual({
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
      const anonymous = await (await fetch(`${app.url}${METADATA_PATH}`)).text();
      const authenticated = await (
        await fetch(`${app.url}${METADATA_PATH}`, {
          headers: { authorization: `Bearer ${await token({ aud: EXPECTED_AUDIENCE })}` },
        })
      ).text();

      // §28.3 rule 4: the response MUST NOT vary on the request. That is what
      // makes `Access-Control-Allow-Origin: *` safe.
      expect(authenticated).toBe(anonymous);
    } finally {
      await app.close();
    }
  });
});

// ---------------------------------------------------------------------------
// §28.9 test 4 — 403 insufficient_scope
// ---------------------------------------------------------------------------

describe('§28.9 test 4 (Express) — 403 insufficient_scope', () => {
  async function denial(decision: AccessDecision, scope?: string): Promise<Response> {
    const app = await buildApp(mcpSession(checker(decision)), { scope });
    try {
      return await fetch(`${app.url}/tool`, {
        headers: { authorization: `Bearer ${await token({ aud: EXPECTED_AUDIENCE })}` },
      });
    } finally {
      await app.close();
    }
  }

  it('a no_grant denial on a route that named a scope answers vector 3, body unchanged', async () => {
    const res = await denial(
      { allowed: false, reason: 'no matching grant', reasonCode: 'no_grant' },
      'mcp:tools',
    );

    expect(res.status).toBe(403);
    expect(res.headers.get('www-authenticate')).toBe(VECTORS.insufficientScope);
    // Read this twice: the JSON body does not change. `insufficient_scope`
    // appears ONLY as the `error` parameter inside the header — an
    // implementation that put it in the body has changed §11's error taxonomy,
    // which §28 does not do.
    const body = await res.json();
    expect(body.error).toBe('authorization_denied');
    expect(JSON.stringify(body)).not.toContain('insufficient_scope');
  });

  it('names the scope the route asked for, verbatim', async () => {
    const res = await denial(
      { allowed: false, reason: 'no matching grant', reasonCode: 'no_grant' },
      'urn:example:tools.invoke',
    );

    // §28.5 rule 6: never synthesised, never derived from `action`/`resource`,
    // never substituted from the document's `scopes_supported`. Where a
    // deployment's AXIAM resource-scope names and its OAuth scope names differ,
    // that mapping is the operator's decision and the SDK cannot see it.
    expect(res.headers.get('www-authenticate')).toBe(
      `Bearer error="insufficient_scope", scope="urn:example:tools.invoke", resource_metadata="${METADATA_URL}"`,
    );
  });

  it('carries no challenge on denied_by_rule, on an absent reason_code, or with no scope argument', async () => {
    // `no_grant` means *ask for more*, which is what a challenge invites a
    // client to do. `denied_by_rule` means *an administrator has already
    // decided*, and challenging on it sends an MCP client all the way around
    // the authorization loop to arrive at the identical 403.
    const byRule = await denial(
      { allowed: false, reason: 'denied', reasonCode: 'denied_by_rule' },
      'mcp:tools',
    );
    expect(byRule.status).toBe(403);
    expect(byRule.headers.get('www-authenticate')).toBeNull();

    // An older server, or a code this SDK predates: §11 rule 9 requires an
    // unknown code to leave the outcome alone, and the outcome here is today's
    // header-free 403.
    const noCode = await denial({ allowed: false, reason: 'denied' }, 'mcp:tools');
    expect(noCode.status).toBe(403);
    expect(noCode.headers.get('www-authenticate')).toBeNull();

    const unknownCode = await denial(
      { allowed: false, reason: 'denied', reasonCode: 'quota_exhausted' },
      'mcp:tools',
    );
    expect(unknownCode.headers.get('www-authenticate')).toBeNull();

    // No scope argument: there is nothing to name, and §28 forbids guessing.
    const noScope = await denial({
      allowed: false,
      reason: 'denied',
      reasonCode: 'no_grant',
    });
    expect(noScope.status).toBe(403);
    expect(noScope.headers.get('www-authenticate')).toBeNull();
  });

  it('touches no other response — a 2xx gains nothing', async () => {
    const app = await buildApp(
      mcpSession(checker({ allowed: true, reasonCode: 'allowed' })),
      { scope: 'mcp:tools' },
    );
    try {
      const res = await fetch(`${app.url}/tool`, {
        headers: { authorization: `Bearer ${await token({ aud: EXPECTED_AUDIENCE })}` },
      });
      expect(res.status).toBe(200);
      // A challenge on a success is a client asking the authorization server
      // what went right.
      expect(res.headers.get('www-authenticate')).toBeNull();
    } finally {
      await app.close();
    }
  });

  it('a §11 guard\u2019s own missing-identity 401 carries the challenge, and picks the vector from the request', async () => {
    // §28.5 rule 4 puts the challenge on EVERY 401 the guard emits, including
    // §11's `authentication_failed` 401 — the one a route gets when the §10
    // guard was never mounted ahead of it. Which vector is chosen still depends
    // on the request: `invalid_token` when a credential was presented, no
    // `error` at all when none was.
    const session = mcpSession(checker({ allowed: true }));
    const app = express();
    app.get('/unguarded', requireAccess(session, 'mcp:invoke', 'tool-1'), (_req, res) => {
      res.json({ ok: true });
    });
    const running = await start(app);
    try {
      const anonymous = await fetch(`${running.url}/unguarded`);
      expect(anonymous.status).toBe(401);
      expect(anonymous.headers.get('www-authenticate')).toBe(VECTORS.noCredential);

      const withCredential = await fetch(`${running.url}/unguarded`, {
        headers: { authorization: `Bearer ${await token({ aud: EXPECTED_AUDIENCE })}` },
      });
      expect(withCredential.status).toBe(401);
      expect(withCredential.headers.get('www-authenticate')).toBe(VECTORS.invalidToken);
    } finally {
      await running.close();
    }
  });

  it('a requireRole failure carries no challenge, but its 401 does', async () => {
    const session = mcpSession();
    const app = express();
    app.use(axiamMiddleware(session));
    // `mcp:read` is the token's only scope, so `admin` is missing.
    app.get('/admin', requireRole(session, 'admin'), (_req, res) => {
      res.json({ ok: true });
    });
    const running = await start(app);
    try {
      const forbidden = await fetch(`${running.url}/admin`, {
        headers: { authorization: `Bearer ${await token({ aud: EXPECTED_AUDIENCE })}` },
      });
      expect(forbidden.status).toBe(403);
      expect(forbidden.headers.get('www-authenticate')).toBeNull();
    } finally {
      await running.close();
    }
  });
});

// ---------------------------------------------------------------------------
// §28.9 test 5 — a token whose `aud` is not the resource is refused
// ---------------------------------------------------------------------------

describe('§28.9 test 5 (Express) — the audience this server announced', () => {
  async function get(bearer: string): Promise<Response> {
    const app = await buildApp(mcpSession());
    try {
      return await fetch(`${app.url}/mcp`, { headers: { authorization: `Bearer ${bearer}` } });
    } finally {
      await app.close();
    }
  }

  it('refuses a token minted for another resource server', async () => {
    const res = await get(await token({ aud: 'https://other.example.com/mcp' }));
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toBe(VECTORS.invalidToken);
  });

  it('refuses a general-purpose axiam:user token identically', async () => {
    // A perfectly valid AXIAM token that simply was not minted for this
    // resource. An implementation that admits it has not implemented the
    // section — and the two refusals are indistinguishable from outside, which
    // is the point.
    const res = await get(await token({ aud: 'axiam:user' }));
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toBe(VECTORS.invalidToken);
  });

  it('admits a token whose aud is this resource', async () => {
    const res = await get(await token({ aud: EXPECTED_AUDIENCE }));
    expect(res.status).toBe(200);
    expect(res.headers.get('www-authenticate')).toBeNull();
  });

  it('refuses at construction when resourceMetadataUrl is set with no expected audience', () => {
    const halfConfigured = {
      jwksVerifier: createVerifier(BASE_URL),
      tenantHeaderValue: TENANT,
      resourceMetadataUrl: METADATA_URL,
    };

    // Announcing yourself obliges you to check. This is not discouraged — it is
    // impossible to configure, and the refusal names both options so the fix is
    // one line.
    let caught: unknown;
    try {
      axiamMiddleware(halfConfigured);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(ValidationError);
    expect((caught as Error).message).toContain('resourceMetadataUrl');
    expect((caught as Error).message).toContain('expectedAudience');

    // Every guard factory refuses it, not just the §10 one.
    expect(() => requireRole(halfConfigured, 'admin')).toThrow(ValidationError);
    expect(() =>
      requireAccess({ ...halfConfigured, authzClient: checker({ allowed: true }) }, 'a', 'r'),
    ).toThrow(ValidationError);
  });
});

// ---------------------------------------------------------------------------
// The regression that matters more than all five
// ---------------------------------------------------------------------------

describe('§28 off (Express) — a feature that is off is indistinguishable from one that is absent', () => {
  it('emits no WWW-Authenticate on any response when resourceMetadataUrl is unset', async () => {
    const app = await buildApp(
      plainSession(checker({ allowed: false, reason: 'no matching grant', reasonCode: 'no_grant' })),
      { serve: false, scope: 'mcp:tools' },
    );
    try {
      const unauthenticated = await fetch(`${app.url}/mcp`);
      const authenticated = await fetch(`${app.url}/mcp`, {
        headers: { authorization: `Bearer ${await token({ aud: EXPECTED_AUDIENCE })}` },
      });
      const denied = await fetch(`${app.url}/tool`, {
        headers: { authorization: `Bearer ${await token({ aud: EXPECTED_AUDIENCE })}` },
      });

      // Assert the header's ABSENCE explicitly rather than the status: a 401
      // that grew a header is still a 401, and an implementation that emitted a
      // bare `Bearer` challenge unconditionally would pass every other test in
      // this file.
      expect(unauthenticated.status).toBe(401);
      expect(unauthenticated.headers.get('www-authenticate')).toBeNull();
      expect(await unauthenticated.json()).toEqual({
        error: 'authentication_failed',
        message: 'missing authentication credentials',
      });

      expect(authenticated.status).toBe(200);
      expect(authenticated.headers.get('www-authenticate')).toBeNull();

      expect(denied.status).toBe(403);
      expect(denied.headers.get('www-authenticate')).toBeNull();
      expect((await denied.json()).error).toBe('authorization_denied');
    } finally {
      await app.close();
    }
  });

  it('exempts no path when resourceMetadataUrl is unset', async () => {
    const app = await buildApp(plainSession(), { serve: false });
    try {
      // The exemption exists only where §28 is configured, and covers exactly
      // the one path that option names — so with the option unset this is an
      // ordinary guarded request.
      const res = await fetch(`${app.url}${METADATA_PATH}`);
      expect(res.status).toBe(401);
      expect(res.headers.get('www-authenticate')).toBeNull();
    } finally {
      await app.close();
    }
  });
});
