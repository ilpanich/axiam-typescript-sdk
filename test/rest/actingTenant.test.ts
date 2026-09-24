// CONTRACT.md §5.2 rule 1 (contract 1.51) — the acting tenant,
// `X-Axiam-Tenant`. Mirrors the reference (axiam-rust-sdk#115)'s
// tests/acting_tenant_test.rs, in this SDK's own idiom: a `new AxiamClient`
// at construction time (the "builder form"), and `client.actingTenant(id)` /
// `.clearActingTenant()` on an existing one.

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { AuthzError, NetworkError } from '../../src/core/index.js';
import { AxiamClient } from '../../src/rest/client.js';

const BASE_URL = 'https://axiam.test';
const TENANT_ID = '22222222-2222-4222-8222-222222222222';
const OTHER_TENANT = '99999999-9999-4999-8999-999999999999';
const THIRD_TENANT = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

function anyPassword(): string {
  // A fresh, non-literal credential per call (CodeQL rust/hard-coded-
  // cryptographic-value — see the reference's mutation-testing commit
  // c853412). The mock accepts any password.
  return `pw-${Math.random().toString(36).slice(2)}-${Date.now()}`;
}

function orgAdminUser(overrides: Record<string, unknown> = {}) {
  return {
    id: 'user-1',
    username: 'root',
    email: 'root@example.com',
    organization_level: true,
    tenant_id: TENANT_ID,
    principal_tenant_id: TENANT_ID,
    principal_tenant_slug: 'organization',
    org_id: 'org-1',
    ...overrides,
  };
}

interface Captured {
  method: string;
  url: string;
  headers: Headers;
}

let captured: Captured[] = [];

const server = setupServer(
  http.post(`${BASE_URL}/api/v1/auth/login`, async ({ request }) => {
    captured.push({ method: 'POST', url: request.url, headers: request.headers });
    const body = (await request.json()) as { username_or_email?: string };
    const overrides = body.username_or_email === 'tenant-admin' ? { organization_level: false } : {};
    return HttpResponse.json(
      { user: orgAdminUser(overrides), session_id: 'session-1', expires_in: 900 },
      { status: 200 },
    );
  }),
  http.get(`${BASE_URL}/api/v1/groups`, ({ request }) => {
    captured.push({ method: 'GET', url: request.url, headers: request.headers });
    return HttpResponse.json({ items: [], total: 0, offset: 0, limit: 200 });
  }),
  http.post(`${BASE_URL}/api/v1/authz/check`, ({ request }) => {
    captured.push({ method: 'POST', url: request.url, headers: request.headers });
    return HttpResponse.json({ allowed: true });
  }),
  http.post(`${BASE_URL}/api/v1/auth/refresh`, ({ request }) => {
    captured.push({ method: 'POST', url: request.url, headers: request.headers });
    return HttpResponse.json({ expires_in: 900 });
  }),
  http.post(`${BASE_URL}/api/v1/auth/logout`, ({ request }) => {
    captured.push({ method: 'POST', url: request.url, headers: request.headers });
    return new HttpResponse(null, { status: 204 });
  }),
  http.post(`${BASE_URL}/api/v1/users/me/resend-verification`, ({ request }) => {
    captured.push({ method: 'POST', url: request.url, headers: request.headers });
    return new HttpResponse(null, { status: 204 });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => {
  server.resetHandlers();
  captured = [];
});
afterAll(() => server.close());

function actingHeader(req: Captured): string | null {
  return req.headers.get('x-axiam-tenant');
}
function tenantIdHeader(req: Captured): string | null {
  return req.headers.get('x-tenant-id');
}

async function loggedInOrgAdmin(actingTenantId?: string): Promise<AxiamClient> {
  const client = new AxiamClient({
    baseUrl: BASE_URL,
    tenantSlug: 'organization',
    ...(actingTenantId ? { actingTenantId } : {}),
  });
  await client.login('root@example.com', anyPassword());
  return client;
}

describe('§5.2 rule 1 — construction-time actingTenantId', () => {
  it('sends X-Axiam-Tenant beside an unchanged X-Tenant-ID', async () => {
    const client = new AxiamClient({
      baseUrl: BASE_URL,
      tenantSlug: 'organization',
      actingTenantId: OTHER_TENANT,
    });
    await client.login('root@example.com', anyPassword());
    await client.management.groups.list();

    const req = captured.find((r) => r.url.includes('/groups'))!;
    expect(actingHeader(req)).toBe(OTHER_TENANT);
    expect(tenantIdHeader(req)).toBe('organization');
  });

  it('refuses a non-UUID client-side, before any wire call', () => {
    expect(
      () => new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'organization', actingTenantId: 'not-a-uuid' }),
    ).toThrow(NetworkError);
    expect(captured).toHaveLength(0);
  });
});

describe('§5.2 rule 1 — the I4 twin: no header when nothing was ever set', () => {
  it('a client that never called actingTenant sends no X-Axiam-Tenant anywhere', async () => {
    const client = await loggedInOrgAdmin();
    await client.management.groups.list();
    await client.checkAccess({ action: 'read', resourceId: 'doc:1' });
    await client.refresh();
    await client.resendOwnVerification();
    await client.logout();

    expect(captured.length).toBeGreaterThan(0);
    for (const req of captured) {
      expect(actingHeader(req)).toBeNull();
    }
  });
});

describe("§5.2 rule 1 — actingTenant()/clearActingTenant() rebind a handle", () => {
  it('acting on a tenant, then clearing, removes the header again — the original handle is unchanged', async () => {
    const base = await loggedInOrgAdmin();
    const acting = base.actingTenant(OTHER_TENANT);

    await acting.management.groups.list();
    let req = captured.at(-1)!;
    expect(actingHeader(req)).toBe(OTHER_TENANT);

    await base.management.groups.list();
    req = captured.at(-1)!;
    expect(actingHeader(req)).toBeNull();

    const cleared = acting.clearActingTenant();
    await cleared.management.groups.list();
    req = captured.at(-1)!;
    expect(actingHeader(req)).toBeNull();
  });

  it('two handles over one session can act on two tenants without cross-writing each other', async () => {
    const base = await loggedInOrgAdmin();
    const actingA = base.actingTenant(OTHER_TENANT);
    const actingB = base.actingTenant(THIRD_TENANT);

    await Promise.all([actingA.management.groups.list(), actingB.management.groups.list()]);

    const seen = captured.filter((r) => r.url.includes('/groups')).map(actingHeader).sort();
    expect(seen).toEqual([OTHER_TENANT, THIRD_TENANT].sort());
  });
});

describe('§5.2 rule 1 — gating on the reported principal scope', () => {
  it('a tenant principal (organizationLevel: false) is refused client-side, zero wire calls', async () => {
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    await client.login('tenant-admin', anyPassword());
    const before = captured.length;

    expect(() => client.actingTenant(OTHER_TENANT)).toThrow(AuthzError);
    expect(captured).toHaveLength(before);
  });

  it('reachableTenantIds bounds which tenant an org-level principal may act on', async () => {
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'organization' });
    server.use(
      http.post(`${BASE_URL}/api/v1/auth/login`, () => {
        return HttpResponse.json(
          {
            user: orgAdminUser({ reachable_tenant_ids: [OTHER_TENANT] }),
            session_id: 'session-1',
            expires_in: 900,
          },
          { status: 200 },
        );
      }),
    );
    await client.login('root@example.com', anyPassword());

    // Within reach — allowed.
    expect(() => client.actingTenant(OTHER_TENANT)).not.toThrow();
    // Outside reach — refused client-side.
    const before = captured.length;
    expect(() => client.actingTenant(THIRD_TENANT)).toThrow(AuthzError);
    expect(captured).toHaveLength(before);
  });

  // CONTRACT 1.52 N5.6 (C-12): "Tenant ids compare as UUIDs, never as
  // strings. Case and formatting MUST NOT decide reach." `requireUuid`'s
  // `UUID_RE` is case-insensitive (accepts an upper-case tenantId), but
  // `reachableTenantIds.includes(tenantId)` was a plain, case-SENSITIVE
  // string comparison — an upper-case UUID naming a tenant the server's
  // lower-case `reachable_tenant_ids` already lists was refused as if it
  // named a different tenant. THIRD_TENANT (not OTHER_TENANT, which is
  // all-digit and so unaffected by `.toUpperCase()`) is used because it
  // actually contains hex letters ('a'), the only case that exposes this.
  it('CONTRACT 1.52 N5.6 (C-12) — an upper-case UUID matches a lower-case reachableTenantIds entry', async () => {
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'organization' });
    server.use(
      http.post(`${BASE_URL}/api/v1/auth/login`, () => {
        return HttpResponse.json(
          // The server's canonical (lower-case) form.
          { user: orgAdminUser({ reachable_tenant_ids: [THIRD_TENANT] }), session_id: 'session-1', expires_in: 900 },
          { status: 200 },
        );
      }),
    );
    await client.login('root@example.com', anyPassword());

    // Same tenant, upper-case spelling — must still be within reach.
    expect(() => client.actingTenant(THIRD_TENANT.toUpperCase())).not.toThrow();
  });

  // I4 twin: a genuinely different tenant, even spelled in a matching case,
  // is still refused — guards against an over-broad fix (e.g. skipping the
  // membership check entirely) that would let ANY UUID through.
  it('twin (I4): a genuinely out-of-reach UUID is still refused regardless of case', async () => {
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'organization' });
    server.use(
      http.post(`${BASE_URL}/api/v1/auth/login`, () => {
        return HttpResponse.json(
          { user: orgAdminUser({ reachable_tenant_ids: [THIRD_TENANT] }), session_id: 'session-1', expires_in: 900 },
          { status: 200 },
        );
      }),
    );
    await client.login('root@example.com', anyPassword());

    expect(() => client.actingTenant(OTHER_TENANT.toUpperCase())).toThrow(AuthzError);
    expect(() => client.actingTenant(OTHER_TENANT)).toThrow(AuthzError);
  });

  it('without a login result, the header is sent and the server decides', () => {
    // A client with no completed login — an injected-token / device-token
    // scenario. session.principalScope is undefined: nothing to gate on.
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    expect(() => client.actingTenant(OTHER_TENANT)).not.toThrow();
  });

  it('logout forgets the gate — a later login as a different principal is judged on its own report', async () => {
    const client = await loggedInOrgAdmin();
    await client.logout();

    // Re-login as an ordinary tenant principal.
    server.use(
      http.post(`${BASE_URL}/api/v1/auth/login`, () => {
        return HttpResponse.json(
          { user: orgAdminUser({ organization_level: false }), session_id: 'session-2', expires_in: 900 },
          { status: 200 },
        );
      }),
    );
    await client.login('tenant-admin', anyPassword());
    expect(() => client.actingTenant(OTHER_TENANT)).toThrow(AuthzError);
  });
});

describe('§5.2 rule 1 (C-12) — the §17 decision memo is keyed on the acting tenant', () => {
  it('the same check on two acting tenants is answered separately, not from one cached entry', async () => {
    let calls = 0;
    server.use(
      http.post(`${BASE_URL}/api/v1/authz/check`, ({ request }) => {
        calls += 1;
        // Answer differently per acting tenant, so a memo collision would be
        // observable as the wrong decision, not just an extra wire call.
        const acting = request.headers.get('x-axiam-tenant');
        return HttpResponse.json({ allowed: acting === OTHER_TENANT });
      }),
    );
    const base = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme', decisionMemoTtlMs: 5000 });
    base.session.authenticated = true;
    const actingA = base.actingTenant(OTHER_TENANT);
    const actingB = base.actingTenant(THIRD_TENANT);

    const first = await actingA.checkAccess({ action: 'read', resourceId: 'doc:1' });
    expect(first.allowed).toBe(true);
    expect(calls).toBe(1);

    // Same (action, resourceId) — different acting tenant. Must NOT be
    // served from actingA's memo entry, and must get actingB's own answer.
    const second = await actingB.checkAccess({ action: 'read', resourceId: 'doc:1' });
    expect(second.allowed).toBe(false);
    expect(calls).toBe(2);

    // Repeating actingA's own check within the TTL DOES hit its memo.
    const third = await actingA.checkAccess({ action: 'read', resourceId: 'doc:1' });
    expect(third.allowed).toBe(true);
    expect(calls).toBe(2);
  });
});

describe('§5.2 rule 1 — a {tenant_id} path segment is untouched', () => {
  it('the acting tenant does not rewrite an implicit {tenant_id} path default (§27.4 rule 3)', async () => {
    // settings.getTenantOverride defaults {tenant_id} from the client's own
    // configured tenant (§27.4 rule 3's "implicit path context"), never from
    // the acting tenant — the header and the path parameter are read by
    // different mechanisms, and an SDK MUST NOT couple them (§5.2 rule 1).
    server.use(
      http.get(`${BASE_URL}/api/v1/tenants/*/settings`, ({ request }) => {
        captured.push({ method: 'GET', url: request.url, headers: request.headers });
        return HttpResponse.json({});
      }),
    );
    const client = new AxiamClient({
      baseUrl: BASE_URL,
      tenantId: TENANT_ID,
      actingTenantId: OTHER_TENANT,
    });
    client.session.authenticated = true;
    await client.settings.getTenantOverride();

    const req = captured.find((r) => r.url.includes('/settings'))!;
    expect(req.url).toContain(`/tenants/${TENANT_ID}/settings`);
    expect(req.url).not.toContain(OTHER_TENANT);
    expect(actingHeader(req)).toBe(OTHER_TENANT);
  });
});
