// Contract 1.34 §5.2.2 and contract 1.35 §5.2.3 — the acting tenant vs the
// principal tenant, and tenant-scoped role assignments.
//
// Two of these rules are the kind an SDK breaks silently rather than loudly,
// which is why they are pinned here rather than left to the generated surface
// test:
//
//   * §5.2.2 rule 2. A registration record for the caller's *own* password is
//     sealed against the tenant the account lives in, not the one the client
//     is pointed at. Get it wrong and the server answers "the OPAQUE session
//     was issued for a different tenant" — but only for an organization-level
//     principal that has switched tenant, so it passes every test written
//     against an ordinary account.
//   * §5.2.3 rule 1. `tenant_scope: []` is refused with 400. Optionality
//     alone does not prevent it: `JSON.stringify` drops `undefined` but keeps
//     `[]`, and `[]` is exactly what collecting into an array produces for
//     "no tenants named".

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { AxiamClient } from '../../src/rest/client.js';
import { NetworkError } from '../../src/core/index.js';
import { omitEmptyTenantScope } from '../../src/management/models.js';
import {
  __resetOpaqueModuleForTests,
  __setOpaqueModuleForTests,
} from '../../src/core/opaque.js';

const BASE_URL = 'https://axiam-135.test';
const LOGIN = `${BASE_URL}/api/v1/auth/login`;
const REGISTER_START = `${BASE_URL}/api/v1/auth/opaque/register/start`;
const PASSWORD = 'correct horse battery staple';

const server = setupServer();

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => {
  server.resetHandlers();
  __resetOpaqueModuleForTests();
});
afterAll(() => server.close());

beforeEach(() => {
  __setOpaqueModuleForTests({
    default: vi.fn(async () => undefined),
    opaqueAvailable: () => true,
    OpaqueKsf: {
      argon2id: () => ({ kind: 'argon2id' }),
      scrypt: () => ({ kind: 'scrypt' }),
    },
    OpaqueLogin: class {
      ke1 = 'aa'.repeat(96);
      constructor(_password: string) {}
      finish() {
        return { ke3: 'bb'.repeat(64), sessionKey: 'cc'.repeat(64), exportKey: 'dd'.repeat(64) };
      }
    },
    OpaqueRegistration: class {
      request = 'ee'.repeat(32);
      constructor(_password: string) {}
      finish() {
        return { record: 'ff'.repeat(192), exportKey: 'dd'.repeat(64) };
      }
    },
  });
});

function client(): AxiamClient {
  return new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme', orgSlug: 'acme' });
}

/** Mount `POST /auth/login` returning whichever §5.2.2 fields a test wants. */
function loginReturning(user: Record<string, unknown>) {
  return http.post(LOGIN, () =>
    HttpResponse.json({
      user: {
        id: '11111111-1111-4111-8111-111111111111',
        username: 'alice',
        email: 'alice@example.com',
        ...user,
      },
      session_id: '22222222-2222-4222-8222-222222222222',
      expires_in: 900,
    }),
  );
}

function registerStartCapturing(sink: Record<string, unknown>[]) {
  return http.post(REGISTER_START, async ({ request }) => {
    sink.push((await request.json()) as Record<string, unknown>);
    return HttpResponse.json({
      opaque_session: 'sealed-registration-session',
      registration_response: '34'.repeat(64),
      suite: 'ristretto255_sha512',
      ksf: 'argon2id',
      memory_kib: 8192,
      iterations: 1,
      parallelism: 1,
    });
  });
}

// ---------------------------------------------------------------------------
// §5.2.2 — acting tenant vs principal tenant
// ---------------------------------------------------------------------------

describe('§5.2.2 acting tenant vs principal tenant', () => {
  it('reads an absent principal_tenant_id as the acting tenant', async () => {
    const tenantId = '33333333-3333-4333-8333-333333333333';
    server.use(loginReturning({ tenant_id: tenantId }));

    const result = await client().login('alice@example.com', PASSWORD);

    expect(result.status).toBe('authenticated');
    if (result.status !== 'authenticated') return;
    expect(result.user.tenantId).toBe(tenantId);
    // A server older than contract 1.34 omits this and cannot switch the
    // acting tenant either, so absent means equal rather than unknown.
    expect(result.user.principalTenantId).toBe(tenantId);
  });

  it('reports a divergent principal tenant separately', async () => {
    const acting = '44444444-4444-4444-8444-444444444444';
    const principal = '55555555-5555-4555-8555-555555555555';
    const orgId = '66666666-6666-4666-8666-666666666666';
    server.use(
      loginReturning({
        tenant_id: acting,
        principal_tenant_id: principal,
        principal_tenant_slug: 'organization',
        org_id: orgId,
        organization_level: true,
      }),
    );

    const result = await client().login('alice@example.com', PASSWORD);
    if (result.status !== 'authenticated') throw new Error('expected authenticated');

    expect(result.user.tenantId).toBe(acting);
    expect(result.user.principalTenantId).toBe(principal);
    expect(result.user.principalTenantSlug).toBe('organization');
    // Rule 3: read the organization from the session rather than resolving a
    // slug through the `super-admin`-only `GET /api/v1/organizations`.
    expect(result.user.orgId).toBe(orgId);
  });

  it('surfaces reachable_tenant_ids alongside organization_level, not instead of it', async () => {
    const reachable = '77777777-7777-4777-8777-777777777777';
    server.use(
      loginReturning({
        tenant_id: '88888888-8888-4888-8888-888888888888',
        organization_level: true,
        reachable_tenant_ids: [reachable],
      }),
    );

    const result = await client().login('alice@example.com', PASSWORD);
    if (result.status !== 'authenticated') throw new Error('expected authenticated');

    // A narrowed principal still reports organizationLevel: true, which is
    // exactly why gating on that flag alone offers tenants the server refuses.
    expect(result.user.organizationLevel).toBe(true);
    expect(result.user.reachableTenantIds).toEqual([reachable]);
  });

  it('treats an absent reachable_tenant_ids as unrestricted rather than empty', async () => {
    server.use(loginReturning({ tenant_id: '99999999-9999-4999-8999-999999999999' }));

    const result = await client().login('alice@example.com', PASSWORD);
    if (result.status !== 'authenticated') throw new Error('expected authenticated');

    // `undefined`, never `[]` — an empty list would read as "reaches nothing".
    expect(result.user.reachableTenantIds).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// §5.2.2 rule 2 — which tenant a registration record is sealed against
// ---------------------------------------------------------------------------

describe('§5.2.2 rule 2 OPAQUE record tenancy', () => {
  it('seals opaqueEnrollment against the acting tenant', async () => {
    const bodies: Record<string, unknown>[] = [];
    server.use(
      loginReturning({
        tenant_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        principal_tenant_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      }),
      registerStartCapturing(bodies),
    );

    const c = client();
    await c.login('alice@example.com', PASSWORD);
    await c.opaqueEnrollment('new password');

    // Creating *another* account seals against the tenant it is created in —
    // the one this client was pointed at.
    expect(bodies[0]!.tenant_slug).toBe('acme');
    expect(bodies[0]!.tenant_id).toBeUndefined();
  });

  it('seals opaqueEnrollmentForSelf against the principal tenant', async () => {
    const principal = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
    const bodies: Record<string, unknown>[] = [];
    server.use(
      loginReturning({
        tenant_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        principal_tenant_id: principal,
        organization_level: true,
      }),
      registerStartCapturing(bodies),
    );

    const c = client();
    await c.login('alice@example.com', PASSWORD);
    await c.opaqueEnrollmentForSelf('new password');

    expect(bodies[0]!.tenant_id).toBe(principal);
    // The acting tenant's slug must not travel alongside the principal
    // tenant's id, or it out-votes it server-side.
    expect(bodies[0]!.tenant_slug).toBeUndefined();
  });

  it('refuses opaqueEnrollmentForSelf before a login rather than guessing', async () => {
    await expect(client().opaqueEnrollmentForSelf('new password')).rejects.toThrow(NetworkError);
  });
});

// ---------------------------------------------------------------------------
// §5.2.3 rules 1 and 2 — tenant_scope on an assignment
// ---------------------------------------------------------------------------

describe('§5.2.3 tenant_scope', () => {
  const scoped = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';

  it('drops an empty tenant_scope from the body', () => {
    // Rule 1. `[]` is refused with 400, and `[]` is what collecting into an
    // array produces for "no tenants named", so both spellings of absent must
    // travel the same way: by not appearing.
    const dropped = omitEmptyTenantScope({ user_id: 'u', tenant_scope: [] });
    expect('tenant_scope' in dropped).toBe(false);
    expect(JSON.stringify(dropped)).not.toContain('tenant_scope');
  });

  it('leaves a named tenant_scope alone', () => {
    // Rule 2. Dropping a scope the caller *did* name would turn a refusal
    // they need to see into a success that silently applied no restriction.
    const kept = omitEmptyTenantScope({ user_id: 'u', tenant_scope: [scoped] });
    expect(kept.tenant_scope).toEqual([scoped]);
  });

  it('leaves a body with no tenant_scope untouched, by identity', () => {
    const body = { user_id: 'u' };
    // The common path allocates nothing: 152 of the 155 operations have no
    // such field and must not pay for this.
    expect(omitEmptyTenantScope(body)).toBe(body);
  });

  it('sends an empty tenant_scope nowhere on the wire', async () => {
    const bodies: unknown[] = [];
    server.use(
      loginReturning({ tenant_id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' }),
      http.post(`${BASE_URL}/api/v1/roles/:roleId/users`, async ({ request }) => {
        bodies.push(await request.json());
        return new HttpResponse(null, { status: 204 });
      }),
    );

    const c = client();
    await c.login('alice@example.com', PASSWORD);
    await c.management.roles.assignToUser('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', {
      user_id: 'ffffffff-ffff-4fff-8fff-ffffffffffff',
      tenant_scope: [],
    });

    expect(bodies[0]).not.toHaveProperty('tenant_scope');
  });
});
