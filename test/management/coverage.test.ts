// The §27 paths the surface and semantics tests do not reach.
//
// Not a grab-bag: each of these is a branch that only runs when something has
// gone wrong or when a caller takes the less common of two routes, which is
// exactly the code least likely to be exercised before a user finds it.

import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';

import { NetworkError } from '../../src/core/errors.js';
import { Sensitive } from '../../src/core/sensitive.js';
import { AxiamClient } from '../../src/rest/client.js';
import { parseFieldErrors } from '../../src/management/errors.js';
import { hasMore, pageQuery } from '../../src/management/page.js';
import { BASE_URL, EXAMPLE_ID, ORG_ID, TENANT_ID, managementClient, mockServer } from '../managementSupport.js';

const NOW = '2026-08-26T00:00:00Z';
const EMPTY_PAGE = { items: [], total: 0, offset: 0, limit: 200 };

describe('validation-error bodies', () => {
  it('reads the array form', () => {
    expect(parseFieldErrors({ errors: [{ field: 'email', message: 'bad' }] })).toEqual([
      { field: 'email', message: 'bad' },
    ]);
  });

  it('reads the object-keyed form', () => {
    expect(parseFieldErrors({ errors: { email: 'bad', name: 'worse' } })).toEqual([
      { field: 'email', message: 'bad' },
      { field: 'name', message: 'worse' },
    ]);
  });

  // A body in neither shape yields no fields rather than an error: failing to
  // parse an error body would replace a useful message with a useless one.
  it('yields nothing for a body it does not recognise', () => {
    expect(parseFieldErrors(undefined)).toEqual([]);
    expect(parseFieldErrors('a proxy error page')).toEqual([]);
    expect(parseFieldErrors({ errors: 42 })).toEqual([]);
    expect(parseFieldErrors({ errors: [{ nope: true }] })).toEqual([]);
    expect(parseFieldErrors({ errors: { ok: 'yes', bad: 7 } })).toEqual([
      { field: 'ok', message: 'yes' },
    ]);
  });
});

describe('page helpers', () => {
  it('reports whether more pages follow', () => {
    expect(hasMore({ items: [1], total: 9, offset: 0, limit: 1 })).toBe(true);
    expect(hasMore({ items: [1], total: 1, offset: 0, limit: 1 })).toBe(false);
    // An empty page ends the walk regardless of what `total` claims.
    expect(hasMore({ items: [], total: 900, offset: 0, limit: 50 })).toBe(false);
  });

  // `limit=0` reads as "none" server-side, which would return an empty page —
  // so an unset limit is omitted rather than sent as zero.
  it('omits an unset limit instead of sending zero', () => {
    expect(pageQuery({})).toEqual({ offset: '0', limit: undefined });
    expect(pageQuery({ offset: 5, limit: 10 })).toEqual({ offset: '5', limit: '10' });
  });
});

describe('scope resolution failures', () => {
  it('refuses a tenant-scoped route on a tenant-slug client', async () => {
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme', orgId: ORG_ID });
    client.session.authenticated = true;
    await expect(client.settings.getTenantOverride()).rejects.toThrow(/tenant UUID/);
  });

  it('names the missing configuration when the client has no org at all', async () => {
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantId: TENANT_ID });
    client.session.authenticated = true;
    await expect(client.tenants.list()).rejects.toThrow(/has none/);
  });

  it('lets forTenant reach another tenant on a tenant-scoped route', async () => {
    const server = mockServer();
    const other = '55555555-5555-4555-8555-555555555555';
    let seen = '';
    server.use(
      http.delete(`${BASE_URL}/api/v1/tenants/:tenant/email-config`, ({ request }) => {
        seen = new URL(request.url).pathname;
        return new HttpResponse(null, { status: 204 });
      }),
    );
    await managementClient().emailConfig.forTenant(other).deleteTenant();
    expect(seen).toBe(`/api/v1/tenants/${other}/email-config`);
  });

  it('lets inOrg reach another organization on organizations.get', async () => {
    const server = mockServer();
    const other = '66666666-6666-4666-8666-666666666666';
    let seen = '';
    server.use(
      http.get(`${BASE_URL}/api/v1/organizations/:org`, ({ request }) => {
        seen = new URL(request.url).pathname;
        return HttpResponse.json({
          id: other,
          name: 'Other',
          slug: 'other',
          created_at: NOW,
          updated_at: NOW,
        });
      }),
    );
    await managementClient().organizations.inOrg(other).get();
    expect(seen).toBe(`/api/v1/organizations/${other}`);
  });
});

describe('transport failures', () => {
  // No response at all — the shared §2 mapper owns it, and the point is that
  // it does not become a NotFound/Conflict/Validation by accident.
  it('surfaces a connection failure as a NetworkError', async () => {
    const server = mockServer();
    server.use(http.get(`${BASE_URL}/api/v1/users/:id`, () => HttpResponse.error()));
    await expect(managementClient().users.get(EXAMPLE_ID)).rejects.toBeInstanceOf(NetworkError);
  });

  it('carries a plain-text error body into the message', async () => {
    const server = mockServer();
    server.use(
      http.get(`${BASE_URL}/api/v1/users/:id`, () =>
        HttpResponse.text('the tenant is suspended', { status: 404 }),
      ),
    );
    await expect(managementClient().users.get(EXAMPLE_ID)).rejects.toThrow(/tenant is suspended/);
  });

  it('rejects every operation once the client is closed', async () => {
    const client = managementClient();
    client.close();
    await expect(client.users.get(EXAMPLE_ID)).rejects.toThrow(/closed/);
  });
});

describe('manifest — the update half of the reconciler', () => {
  // Every earlier test drives an empty tenant, so only the Create arms run.
  // These are the other half, and the half where a wrong request body quietly
  // overwrites a field nobody meant to touch.
  it('updates every drifted kind', async () => {
    const server = mockServer();
    server.use(
      http.get(`${BASE_URL}/api/v1/resources`, () =>
        HttpResponse.json({
          items: [
            {
              id: EXAMPLE_ID,
              tenant_id: TENANT_ID,
              name: 'documents',
              resource_type: 'folder',
              parent_id: null,
              metadata: {},
              created_at: NOW,
              updated_at: NOW,
            },
          ],
          total: 1,
          offset: 0,
          limit: 200,
        }),
      ),
      http.get(`${BASE_URL}/api/v1/resources/:id/scopes`, () => HttpResponse.json([])),
      http.get(`${BASE_URL}/api/v1/permissions`, () =>
        HttpResponse.json({
          items: [
            {
              id: EXAMPLE_ID,
              tenant_id: TENANT_ID,
              action: 'document:read',
              description: 'stale',
              created_at: NOW,
              updated_at: NOW,
            },
          ],
          total: 1,
          offset: 0,
          limit: 200,
        }),
      ),
      http.get(`${BASE_URL}/api/v1/roles`, () =>
        HttpResponse.json({
          items: [
            {
              id: EXAMPLE_ID,
              tenant_id: TENANT_ID,
              name: 'Editor',
              description: 'stale',
              is_global: false,
              created_at: NOW,
              updated_at: NOW,
            },
          ],
          total: 1,
          offset: 0,
          limit: 200,
        }),
      ),
      http.get(`${BASE_URL}/api/v1/roles/:id/permissions`, () => HttpResponse.json([])),
      http.get(`${BASE_URL}/api/v1/roles/:id/users`, () => HttpResponse.json([])),
      http.get(`${BASE_URL}/api/v1/roles/:id/groups`, () => HttpResponse.json([])),
      http.get(`${BASE_URL}/api/v1/groups`, () =>
        HttpResponse.json({
          items: [
            {
              id: EXAMPLE_ID,
              tenant_id: TENANT_ID,
              name: 'Staff',
              description: 'stale',
              metadata: {},
              created_at: NOW,
              updated_at: NOW,
            },
          ],
          total: 1,
          offset: 0,
          limit: 200,
        }),
      ),
      http.get(`${BASE_URL}/api/v1/groups/:id/members`, () => HttpResponse.json(EMPTY_PAGE)),
      http.get(`${BASE_URL}/api/v1/users`, () =>
        HttpResponse.json({
          items: [
            {
              id: EXAMPLE_ID,
              tenant_id: TENANT_ID,
              username: 'alice',
              email: 'stale@example.com',
              status: 'Active',
              mfa_enabled: false,
              email_verified: true,
              metadata: {},
              created_at: NOW,
              updated_at: NOW,
              failed_login_attempts: 0,
              is_locked: false,
            },
          ],
          total: 1,
          offset: 0,
          limit: 200,
        }),
      ),
      // Writes. Each answers with the shape its route really returns.
      http.put(`${BASE_URL}/api/v1/resources/:id`, () =>
        HttpResponse.json({
          id: EXAMPLE_ID,
          tenant_id: TENANT_ID,
          name: 'documents',
          resource_type: 'collection',
          parent_id: null,
          metadata: {},
          created_at: NOW,
          updated_at: NOW,
        }),
      ),
      http.post(`${BASE_URL}/api/v1/resources/:id/scopes`, () =>
        HttpResponse.json(
          {
            id: EXAMPLE_ID,
            tenant_id: TENANT_ID,
            resource_id: EXAMPLE_ID,
            name: 'draft',
            description: 'Unpublished',
            created_at: NOW,
            updated_at: NOW,
          },
          { status: 201 },
        ),
      ),
      http.put(`${BASE_URL}/api/v1/permissions/:id`, () =>
        HttpResponse.json({
          id: EXAMPLE_ID,
          tenant_id: TENANT_ID,
          action: 'document:read',
          description: 'Read a document',
          created_at: NOW,
          updated_at: NOW,
        }),
      ),
      http.put(`${BASE_URL}/api/v1/roles/:id`, () =>
        HttpResponse.json({
          id: EXAMPLE_ID,
          tenant_id: TENANT_ID,
          name: 'Editor',
          description: 'Edits documents',
          is_global: false,
          created_at: NOW,
          updated_at: NOW,
        }),
      ),
      http.post(`${BASE_URL}/api/v1/roles/:id/permissions`, () => new HttpResponse(null, { status: 204 })),
      http.post(`${BASE_URL}/api/v1/roles/:id/groups`, () => new HttpResponse(null, { status: 204 })),
      http.post(`${BASE_URL}/api/v1/roles/:id/users`, () => new HttpResponse(null, { status: 204 })),
      http.put(`${BASE_URL}/api/v1/groups/:id`, () =>
        HttpResponse.json({
          id: EXAMPLE_ID,
          tenant_id: TENANT_ID,
          name: 'Staff',
          description: 'All staff',
          metadata: {},
          created_at: NOW,
          updated_at: NOW,
        }),
      ),
      http.post(`${BASE_URL}/api/v1/groups/:id/members`, () => new HttpResponse(null, { status: 204 })),
      http.put(`${BASE_URL}/api/v1/users/:id`, () =>
        HttpResponse.json({
          id: EXAMPLE_ID,
          tenant_id: TENANT_ID,
          username: 'alice',
          email: 'alice@example.com',
          status: 'Active',
          mfa_enabled: false,
          email_verified: true,
          metadata: {},
          created_at: NOW,
          updated_at: NOW,
          failed_login_attempts: 0,
          is_locked: false,
        }),
      ),
    );

    const client = managementClient();
    const manifest = {
      resources: [
        {
          key: 'docs',
          name: 'documents',
          resourceType: 'collection',
          scopes: [{ key: 'draft', name: 'draft', description: 'Unpublished' }],
        },
      ],
      permissions: [{ key: 'read', action: 'document:read', description: 'Read a document' }],
      roles: [
        {
          key: 'editor',
          name: 'Editor',
          description: 'Edits documents',
          grants: [{ permission: 'read', scopes: ['draft'] }],
        },
      ],
      groups: [{ key: 'staff', name: 'Staff', description: 'All staff', roles: ['editor'] }],
      users: [
        {
          key: 'alice',
          username: 'alice',
          email: 'alice@example.com',
          roles: ['editor'],
          groups: ['staff'],
        },
      ],
    };

    const plan = await client.manifest.plan(manifest);
    expect(plan.actions.filter((a) => a.change === 'update')).toHaveLength(5);

    const report = await client.manifest.apply(manifest);
    expect(report.steps.some((s) => s.outcome.status === 'failed')).toBe(false);
  });

  // A manifest is a description of shape. Silently resetting a live account's
  // password because a config file mentions one is not a shape change.
  it('never sends the initialPassword for a user that already exists', async () => {
    const server = mockServer();
    let writes = 0;
    server.use(
      http.get(`${BASE_URL}/api/v1/users`, () =>
        HttpResponse.json({
          items: [
            {
              id: EXAMPLE_ID,
              tenant_id: TENANT_ID,
              username: 'alice',
              email: 'alice@example.com',
              status: 'Active',
              mfa_enabled: false,
              email_verified: true,
              metadata: {},
              created_at: NOW,
              updated_at: NOW,
              failed_login_attempts: 0,
              is_locked: false,
            },
          ],
          total: 1,
          offset: 0,
          limit: 200,
        }),
      ),
    );
    for (const route of ['resources', 'permissions', 'roles', 'groups']) {
      server.use(http.get(`${BASE_URL}/api/v1/${route}`, () => HttpResponse.json(EMPTY_PAGE)));
    }
    server.events.on('request:start', ({ request }) => {
      if (request.method !== 'GET') writes += 1;
    });

    const report = await managementClient().manifest.apply({
      users: [
        {
          key: 'alice',
          username: 'alice',
          email: 'alice@example.com',
          initialPassword: new Sensitive('never-sent'),
        },
      ],
    });

    expect(report.steps.every((s) => s.outcome.status === 'unchanged')).toBe(true);
    expect(writes).toBe(0);
    server.events.removeAllListeners();
  });
});
