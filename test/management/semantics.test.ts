// CONTRACT §27.9 — the semantics that are not per-operation.
//
// Each assertion here exists because the thing it checks is easy to get wrong
// and silent when wrong. The per-operation coverage lives in the generated
// `management.surface.generated.test.ts`; this file is the part a generator
// cannot write.

import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';

import { AuthError, AuthzError, NetworkError } from '../../src/core/errors.js';
import { Sensitive } from '../../src/core/sensitive.js';
import { AxiamClient } from '../../src/rest/client.js';
import { ConflictError, NotFoundError, ValidationError } from '../../src/management/errors.js';
import {
  BASE_URL,
  EXAMPLE_ID,
  ORG_ID,
  TENANT_ID,
  anonymousClient,
  managementClient,
  mockServer,
  mountJson,
} from '../managementSupport.js';

const userBody = (email: string) => ({
  id: EXAMPLE_ID,
  tenant_id: TENANT_ID,
  username: 'alice',
  email,
  status: 'Active',
  mfa_enabled: false,
  email_verified: true,
  metadata: {},
  created_at: '2026-08-26T00:00:00Z',
  updated_at: '2026-08-26T00:00:00Z',
  failed_login_attempts: 0,
  is_locked: false,
});

describe('§27.4 rule 1 — the authentication precondition', () => {
  // The assertion that matters is the request count. Letting the request go
  // out trades a clear local error for a 401 that then enters the §9 refresh
  // guard and fails there, two indirections from the actual mistake.
  it('makes no wire call when there is no session', async () => {
    const server = mockServer();
    let reached = 0;
    server.use(
      http.get(`${BASE_URL}/api/v1/users/:id`, () => {
        reached += 1;
        return HttpResponse.json(userBody('a@b.c'));
      }),
    );

    const client = anonymousClient();
    await expect(client.users.get(EXAMPLE_ID)).rejects.toBeInstanceOf(AuthError);
    expect(reached).toBe(0);
  });
});

describe('§27.4 rule 3 — implicit path context', () => {
  it('takes the org and tenant from the client, and puts them in the path', async () => {
    const server = mockServer();
    const paths: string[] = [];
    server.use(
      http.get(`${BASE_URL}/api/v1/organizations/:org/tenants`, ({ request }) => {
        paths.push(new URL(request.url).pathname);
        return HttpResponse.json({ items: [], total: 0, offset: 0, limit: 50 });
      }),
      http.get(`${BASE_URL}/api/v1/tenants/:tenant/webauthn/attestation-policy`, ({ request }) => {
        paths.push(new URL(request.url).pathname);
        return HttpResponse.json({
          mode: 'none',
          require_fido_certified: false,
          block_revoked_status: false,
          effective_unknown_aaguid: 'allow',
        });
      }),
    );

    const client = managementClient();
    await client.tenants.list({ limit: 50 });
    await client.webauthnPolicy.get();

    expect(paths).toEqual([
      `/api/v1/organizations/${ORG_ID}/tenants`,
      `/api/v1/tenants/${TENANT_ID}/webauthn/attestation-policy`,
    ]);
  });

  it('lets an explicit override change the path', async () => {
    const server = mockServer();
    const other = '44444444-4444-4444-8444-444444444444';
    let seen = '';
    server.use(
      http.get(`${BASE_URL}/api/v1/organizations/:org/tenants`, ({ request }) => {
        seen = new URL(request.url).pathname;
        return HttpResponse.json({ items: [], total: 0, offset: 0, limit: 50 });
      }),
    );

    await managementClient().tenants.inOrg(other).list({ limit: 50 });
    expect(seen).toBe(`/api/v1/organizations/${other}/tenants`);
  });

  // §27.4 rule 3 forbids resolving the slug behind the caller's back, so the
  // request count is again the real assertion.
  it('refuses a UUID route on a slug-only client, without calling', async () => {
    const server = mockServer();
    let reached = 0;
    server.use(
      http.get(`${BASE_URL}/api/v1/organizations/:org/tenants`, () => {
        reached += 1;
        return HttpResponse.json({ items: [], total: 0, offset: 0, limit: 50 });
      }),
    );

    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme', orgSlug: 'acme' });
    client.session.authenticated = true;

    await expect(client.tenants.list({ limit: 50 })).rejects.toThrow(/organization/i);
    expect(reached).toBe(0);
  });
});

describe('§27.4 rule 4 — pagination', () => {
  // Asserted against a fixture where total and items.length differ: a `Page`
  // that reports total === items.length passes every single-page test.
  it('reports the whole set in `total`, not the page', async () => {
    const server = mockServer();
    server.use(
      http.get(`${BASE_URL}/api/v1/users`, () =>
        HttpResponse.json({ items: [userBody('a@b.c')], total: 97, offset: 0, limit: 1 }),
      ),
    );

    const page = await managementClient().users.list({ limit: 1 });
    expect(page.items).toHaveLength(1);
    expect(page.total).toBe(97);
  });

  it('walks every page in listAll, with the expected offsets', async () => {
    const server = mockServer();
    const offsets: string[] = [];
    server.use(
      http.get(`${BASE_URL}/api/v1/users`, ({ request }) => {
        const offset = new URL(request.url).searchParams.get('offset') ?? '';
        offsets.push(offset);
        const emails = ['a@b.c', 'd@e.f', 'g@h.i'];
        return HttpResponse.json({
          items: [userBody(emails[Number(offset)] as string)],
          total: 3,
          offset: Number(offset),
          limit: 1,
        });
      }),
    );

    const all = await managementClient().users.listAll({ limit: 1 });
    expect(all).toHaveLength(3);
    expect(offsets).toEqual(['0', '1', '2']);
    expect(all[2]?.email).toBe('g@h.i');
  });

  // A server that keeps answering with no items would otherwise loop forever;
  // one wasted request is the right price.
  it('stops on an empty page even when `total` insists there is more', async () => {
    const server = mockServer();
    let calls = 0;
    server.use(
      http.get(`${BASE_URL}/api/v1/users`, () => {
        calls += 1;
        return HttpResponse.json({ items: [], total: 900, offset: 0, limit: 50 });
      }),
    );

    const all = await managementClient().users.listAll({ limit: 50 });
    expect(all).toEqual([]);
    expect(calls).toBe(1);
  });
});

describe('§27.4 rule 5 — sparse updates', () => {
  // The assertion is on the full key set. Asserting the field is present
  // passes even when every other field went along as null — which is the bug,
  // since the server reads an explicit null as "set this to null".
  it('sends only the fields that were set', async () => {
    const server = mockServer();
    let body: Record<string, unknown> = {};
    server.use(
      http.put(`${BASE_URL}/api/v1/users/:id`, async ({ request }) => {
        body = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json(userBody('new@example.com'));
      }),
    );

    await managementClient().users.update(EXAMPLE_ID, { email: 'new@example.com' });
    expect(Object.keys(body)).toEqual(['email']);
  });
});

describe('§27.4 rule 7 — error mapping', () => {
  const mount404 = () =>
    mountJson(mockServer(), 'GET', `/api/v1/users/${EXAMPLE_ID}`, 404, { message: 'nope' });

  it('maps 404 to NotFoundError, which is still an AuthzError', async () => {
    mount404();
    const err = await managementClient().users.get(EXAMPLE_ID).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(NotFoundError);
    expect(err).toBeInstanceOf(AuthzError);
    expect((err as NotFoundError).operation).toBe('users.get');
  });

  it('maps 409 to ConflictError and issues the write exactly once', async () => {
    const server = mockServer();
    let calls = 0;
    server.use(
      http.post(`${BASE_URL}/api/v1/roles`, () => {
        calls += 1;
        return HttpResponse.json({ message: 'role name already taken' }, { status: 409 });
      }),
    );

    const err = await managementClient()
      .roles.create({ name: 'Editor', description: 'Edits', is_global: false })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ConflictError);
    expect(err).toBeInstanceOf(AuthzError);
    expect(calls).toBe(1);
  });

  it('maps 400 to ValidationError with field detail, and it is a NetworkError', async () => {
    mountJson(mockServer(), 'POST', '/api/v1/users', 400, {
      errors: [{ field: 'email', message: 'is not a valid address' }],
    });

    const err = await managementClient()
      .users.create({
        username: 'alice',
        email: 'not-an-email',
        password: new Sensitive('hunter2hunter2'),
      })
      .catch((e: unknown) => e);

    expect(err).toBeInstanceOf(ValidationError);
    expect(err).toBeInstanceOf(NetworkError);
    const v = err as ValidationError;
    expect(v.status).toBe(400);
    expect(v.operation).toBe('users.create');
    expect(v.fields).toEqual([{ field: 'email', message: 'is not a valid address' }]);
  });

  it('leaves an ordinary 403 as a plain AuthzError', async () => {
    mountJson(mockServer(), 'GET', `/api/v1/users/${EXAMPLE_ID}`, 403, { message: 'denied' });
    const err = await managementClient().users.get(EXAMPLE_ID).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AuthzError);
    expect(err).not.toBeInstanceOf(NotFoundError);
    expect(err).not.toBeInstanceOf(ConflictError);
  });

  // §27.4 rule 6: a caller retrying a failed delete needs to know whether it
  // is finishing its own job or looking at someone else's.
  it('does not swallow a repeated delete into success', async () => {
    mountJson(mockServer(), 'DELETE', `/api/v1/users/${EXAMPLE_ID}`, 404, { message: 'gone' });
    await expect(managementClient().users.delete(EXAMPLE_ID)).rejects.toBeInstanceOf(NotFoundError);
  });
});

describe('§27.4 rule 8 — retry', () => {
  it('issues a write exactly once on a 503, even one that looks idempotent', async () => {
    const server = mockServer();
    let calls = 0;
    server.use(
      http.post(`${BASE_URL}/api/v1/service-accounts/:id/rotate-secret`, () => {
        calls += 1;
        return new HttpResponse(null, { status: 503 });
      }),
    );

    // Retry is on for this client, so the assertion is about eligibility, not
    // about the switch being off.
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantId: TENANT_ID, orgId: ORG_ID });
    client.session.authenticated = true;

    await expect(client.serviceAccounts.rotateSecret(EXAMPLE_ID)).rejects.toBeTruthy();
    expect(calls).toBe(1);
  });
});

describe('§27.5 — secrets', () => {
  // Scans the rendered output for the fixture value rather than asserting on
  // the type: the type can be right while a field renders through some other
  // sink.
  it('redacts a returned one-time secret from every rendering', async () => {
    const secret = 'sk_live_do_not_log_me_0123456789';
    mountJson(mockServer(), 'POST', '/api/v1/scim-tokens', 201, {
      id: EXAMPLE_ID,
      tenant_id: TENANT_ID,
      user_id: EXAMPLE_ID,
      created_by: EXAMPLE_ID,
      name: 'provisioning',
      status: 'active',
      created_at: '2026-08-26T00:00:00Z',
      expires_at: '2027-08-26T00:00:00Z',
      provisioning_token: secret,
    });

    const token = await managementClient().scimTokens.create({
      name: 'provisioning',
      user_id: EXAMPLE_ID,
    });

    expect(token.provisioning_token.expose()).toBe(secret);
    expect(JSON.stringify(token)).not.toContain(secret);
    expect(String(token.provisioning_token)).not.toContain(secret);
  });

  // A create body reaches a log exactly as easily as a response does, and
  // `users.create(spec)` with a plaintext password is the most-logged object
  // on this surface.
  it('redacts a supplied password, but still sends it', async () => {
    const password = 'correct horse battery staple';
    const server = mockServer();
    let sent: Record<string, unknown> = {};
    server.use(
      http.post(`${BASE_URL}/api/v1/users`, async ({ request }) => {
        sent = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json(userBody('alice@example.com'), { status: 201 });
      }),
    );

    const body = {
      username: 'alice',
      email: 'alice@example.com',
      password: new Sensitive(password),
    };
    expect(JSON.stringify(body)).not.toContain(password);

    await managementClient().users.create(body);
    // The wire twin is what makes both true at once: redacted in the object,
    // present on the socket.
    expect(sent['password']).toBe(password);
  });
});

describe('§27.2 — handle rules', () => {
  it('makes no request when a handle is acquired', async () => {
    const server = mockServer();
    let reached = 0;
    server.use(http.all(`${BASE_URL}/*`, () => { reached += 1; return new HttpResponse(null); }));

    const client = managementClient();
    void client.users;
    void client.roles;
    void client.caCertificates.inOrg(ORG_ID);
    void client.settings.forTenant(TENANT_ID);
    void client.management.users;

    expect(reached).toBe(0);
  });

  it('reaches the same namespaces through `client.management`', () => {
    const client = managementClient();
    expect(client.management.users.constructor.name).toBe(client.users.constructor.name);
  });
});
