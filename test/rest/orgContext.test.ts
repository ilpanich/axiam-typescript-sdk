// Organization context (CONTRACT.md §5): the client must forward org + tenant
// in the login body (the server resolves the workspace from the body, not the
// X-Tenant-ID header) and must send {tenant_id, org_id} UUIDs on refresh
// (RefreshRequest requires the UUID form). Covers both construction forms
// (slug vs UUID) and the Node persona's resolution of the UUIDs from the
// access-token claims after login.

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { CookieJar } from 'tough-cookie';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { AxiamClient } from '../../src/rest/client.js';
import { createSession } from '../../src/rest/session.js';
import { NodeSession } from '../../src/node/session.js';
import { TokenManager } from '../../src/node/tokenManager.js';
import { createVerifier } from '../../src/node/jwks.js';
import { ACCESS_COOKIE } from '../../src/node/cookieJar.js';

const BASE_URL = 'https://axiam-org.test';

interface CapturedBody {
  username_or_email?: string;
  password?: string;
  tenant_id?: string;
  tenant_slug?: string;
  org_id?: string;
  org_slug?: string;
}

let lastLoginBody: CapturedBody | undefined;
let lastRefreshBody: CapturedBody | undefined;

const server = setupServer(
  http.post(`${BASE_URL}/api/v1/auth/login`, async ({ request }) => {
    lastLoginBody = (await request.json()) as CapturedBody;
    return HttpResponse.json(
      {
        user: { id: 'user-1', username: 'alice', email: 'alice@example.com' },
        session_id: 'session-1',
        expires_in: 900,
      },
      { status: 200 },
    );
  }),
  http.post(`${BASE_URL}/api/v1/auth/refresh`, async ({ request }) => {
    lastRefreshBody = (await request.json()) as CapturedBody;
    return HttpResponse.json({ expires_in: 900 }, { status: 200 });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => {
  server.resetHandlers();
  lastLoginBody = undefined;
  lastRefreshBody = undefined;
});
afterAll(() => server.close());

/** Craft an unsigned-but-well-formed JWT carrying the given claims (payload is base64url-decodable). */
function jwtWith(claims: Record<string, unknown>): string {
  const b64 = (obj: Record<string, unknown>) =>
    Buffer.from(JSON.stringify(obj)).toString('base64url');
  return `${b64({ alg: 'EdDSA', typ: 'JWT' })}.${b64(claims)}.sig`;
}

describe('login body carries org + tenant context (§5)', () => {
  it('forwards slug forms when constructed with tenantSlug + orgSlug', async () => {
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme', orgSlug: 'globex' });
    await client.login('alice@example.com', 'pw');

    expect(lastLoginBody).toMatchObject({
      username_or_email: 'alice@example.com',
      tenant_slug: 'acme',
      org_slug: 'globex',
    });
    expect(lastLoginBody).not.toHaveProperty('tenant_id');
    expect(lastLoginBody).not.toHaveProperty('org_id');
  });

  it('forwards UUID forms when constructed with tenantId + orgId', async () => {
    const client = new AxiamClient({
      baseUrl: BASE_URL,
      tenantId: '11111111-1111-1111-1111-111111111111',
      orgId: '22222222-2222-2222-2222-222222222222',
    });
    await client.login('alice@example.com', 'pw');

    expect(lastLoginBody).toMatchObject({
      tenant_id: '11111111-1111-1111-1111-111111111111',
      org_id: '22222222-2222-2222-2222-222222222222',
    });
    expect(lastLoginBody).not.toHaveProperty('tenant_slug');
    expect(lastLoginBody).not.toHaveProperty('org_slug');
  });
});

describe('refresh body (§1) — buildRefreshBody()', () => {
  it('emits configured UUIDs directly (browser persona / no token decode)', () => {
    const session = createSession({
      baseUrl: BASE_URL,
      tenantId: '11111111-1111-1111-1111-111111111111',
      orgId: '22222222-2222-2222-2222-222222222222',
    });
    expect(session.buildRefreshBody()).toEqual({
      tenant_id: '11111111-1111-1111-1111-111111111111',
      org_id: '22222222-2222-2222-2222-222222222222',
    });
  });

  it('omits identifiers that are only known by slug (a slug is never sent where a UUID is required)', () => {
    const session = createSession({ baseUrl: BASE_URL, tenantSlug: 'acme', orgSlug: 'globex' });
    expect(session.buildRefreshBody()).toEqual({});
  });
});

describe('Node persona resolves refresh UUIDs from the access-token claims', () => {
  /** Build a NodeSession over a jar pre-seeded with the given access token. */
  function seededSession(accessToken: string, opts?: { tenantSlug?: string; orgSlug?: string }) {
    const jar = new CookieJar();
    // setCookie is async but resolves synchronously for a same-origin cookie;
    // await it in the test body for correctness.
    const options = { baseUrl: BASE_URL, tenantSlug: opts?.tenantSlug ?? 'acme', orgSlug: opts?.orgSlug };
    const base = createSession(options);
    const tokenManager = new TokenManager(jar, BASE_URL, base.tenantHeaderValue);
    const jwksVerifier = createVerifier(BASE_URL);
    return { session: new NodeSession(options, base, tokenManager, jwksVerifier, jar), jar, accessToken };
  }

  it('populates tenant_id/org_id from the token after onAuthenticated()', async () => {
    const token = jwtWith({
      tenant_id: '33333333-3333-3333-3333-333333333333',
      org_id: '44444444-4444-4444-4444-444444444444',
    });
    const { session, jar } = seededSession(token, { tenantSlug: 'acme', orgSlug: 'globex' });
    await jar.setCookie(`${ACCESS_COOKIE}=${token}; Path=/`, BASE_URL);

    await session.onAuthenticated();

    expect(session.resolvedTenantId).toBe('33333333-3333-3333-3333-333333333333');
    expect(session.resolvedOrgId).toBe('44444444-4444-4444-4444-444444444444');
    expect(session.buildRefreshBody()).toEqual({
      tenant_id: '33333333-3333-3333-3333-333333333333',
      org_id: '44444444-4444-4444-4444-444444444444',
    });
  });

  it('leaves resolved identifiers unset for a non-JWT token (best-effort, no throw)', async () => {
    const { session, jar } = seededSession('not-a-jwt');
    await jar.setCookie(`${ACCESS_COOKIE}=not-a-jwt; Path=/`, BASE_URL);

    await session.onAuthenticated();

    expect(session.resolvedTenantId).toBeUndefined();
    expect(session.resolvedOrgId).toBeUndefined();
  });
});

// CONTRACT.md §5.2.1 — signing in an organization-level principal.
//
// The reserved tenant holding an organization's cross-tenant principals has a
// fixed slug, `"organization"`, so §5.1's ordinary login body reaches it with
// nothing new. What §5.2.1 adds is the rule underneath: naming *no* tenant
// resolves that scope server-side, and an SDK MUST NOT send an empty-string
// slug in place of naming none.
//
// The MUST is not hypothetical. The admin UI sent `tenant_slug: ""` from a
// blank form field, and the server resolved a slug that cannot match — a 401
// raised before the tenant's OPAQUE mode was read, so the 404 of §23.4 rule 10
// never arrived, the client had no fallback to take, and an organization-level
// administrator could not sign in at all on a deployment with OPAQUE disabled.
describe('organization-level sign-in (§5.2.1)', () => {
  it('reaches the reserved scope by naming its slug, like any other tenant', async () => {
    const client = new AxiamClient({
      baseUrl: BASE_URL,
      tenantSlug: 'organization',
      orgSlug: 'globex',
    });
    await client.login('root@example.com', 'pw');

    expect(lastLoginBody).toMatchObject({
      tenant_slug: 'organization',
      org_slug: 'globex',
    });
  });

  it('never puts an empty slug on the wire — construction refuses one first', () => {
    // This is how the TypeScript SDK satisfies §5.2.1 rule 2: `''` is falsy, so
    // it fails §5's tenant requirement at construction and there is no client
    // from which an empty `tenant_slug` could ever be serialized. The
    // assertion pins that, rather than the incidental fact that
    // `buildLoginBody` also skips falsy values.
    expect(() => new AxiamClient({ baseUrl: BASE_URL, tenantSlug: '', orgSlug: 'globex' })).toThrow(
      /requires a tenant/,
    );
  });

  it('omits a tenant slug it was never given, rather than sending an empty one', () => {
    // Reached through `createSession` because `AxiamClient` refuses the
    // construction above — the point is what the body builder does with an
    // absent slug, which is the shape every workspace-taking route reads as
    // "the organization's own scope".
    const session = createSession({ baseUrl: BASE_URL, tenantId: '11111111-1111-1111-1111-111111111111', orgSlug: 'globex' });
    const body = session.buildLoginBody('root@example.com', 'pw');

    expect(body).not.toHaveProperty('tenant_slug');
    expect(body.org_slug).toBe('globex');
  });
});
