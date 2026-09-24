// CONTRACT.md §27.6.1 — the three 1.51 manifest additions: resources[].metadata,
// the two-shape role binding (plain key vs. { role, resource, inherit }), and
// service accounts. Mirrors the reference (axiam-rust-sdk#115)'s
// tests/manifest_additions_test.rs in this SDK's own idiom, reusing
// manifest.test.ts's msw/managementSupport pattern.

import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';

import { Sensitive } from '../../src/core/sensitive.js';
import type { ManagementManifest } from '../../src/management/manifest/index.js';
import { failure, isComplete, isConverged } from '../../src/management/manifest/index.js';
import { BASE_URL, TENANT_ID, managementClient, mockServer } from '../managementSupport.js';

const NOW = '2026-09-24T00:00:00Z';
const EMPTY_PAGE = { items: [], total: 0, offset: 0, limit: 200 };

const ROLE_ID = '44444444-4444-4444-8444-444444444444';
const USER_ID = '55555555-5555-4555-8555-555555555555';
const GROUP_ID = '66666666-6666-4666-8666-666666666666';
const SA_ID = '77777777-7777-4777-8777-777777777777';
const SA_ID_2 = '77777777-7777-4777-8777-777777777778';
const SITE1_ID = '88888888-8888-4888-8888-888888888881';
const SITE2_ID = '88888888-8888-4888-8888-888888888882';

const resourceJson = (id: string, name: string, parent: string | null, metadata: unknown = {}) => ({
  id,
  tenant_id: TENANT_ID,
  name,
  resource_type: 'site',
  parent_id: parent,
  metadata,
  created_at: NOW,
  updated_at: NOW,
});

const roleJson = (isGlobal = false) => ({
  id: ROLE_ID,
  tenant_id: TENANT_ID,
  name: 'Concierge',
  description: 'Concierge',
  is_global: isGlobal,
  created_at: NOW,
  updated_at: NOW,
});

const userJson = () => ({
  id: USER_ID,
  tenant_id: TENANT_ID,
  username: 'ann',
  email: 'ann@example.com',
  email_verified: false,
  failed_login_attempts: 0,
  is_locked: false,
  metadata: {},
  mfa_enabled: false,
  status: 'Active',
  created_at: NOW,
  updated_at: NOW,
});

const groupJson = () => ({
  id: GROUP_ID,
  tenant_id: TENANT_ID,
  name: 'Staff',
  description: 'Staff',
  metadata: {},
  created_at: NOW,
  updated_at: NOW,
});

const saJson = (id: string, name: string, description: string | null = null) => ({
  id,
  tenant_id: TENANT_ID,
  name,
  client_id: `client-${id}`,
  status: 'Active',
  description,
  created_at: NOW,
  updated_at: NOW,
});

function mountReads(server: ReturnType<typeof mockServer>, overrides: Partial<Record<string, unknown[]>> = {}): void {
  const page = (key: string) => {
    const items = overrides[key] ?? [];
    return { items, total: items.length, offset: 0, limit: 200 };
  };
  server.use(
    http.get(`${BASE_URL}/api/v1/resources`, () => HttpResponse.json(page('resources'))),
    http.get(`${BASE_URL}/api/v1/permissions`, () => HttpResponse.json(page('permissions'))),
    http.get(`${BASE_URL}/api/v1/roles`, () => HttpResponse.json(page('roles'))),
    http.get(`${BASE_URL}/api/v1/groups`, () => HttpResponse.json(page('groups'))),
    http.get(`${BASE_URL}/api/v1/users`, () => HttpResponse.json(page('users'))),
    http.get(`${BASE_URL}/api/v1/service-accounts`, () => HttpResponse.json(page('serviceAccounts'))),
    http.get(`${BASE_URL}/api/v1/roles/:id/permissions`, () => HttpResponse.json([])),
    http.get(`${BASE_URL}/api/v1/roles/:id/users`, () => HttpResponse.json(overrides.roleUsers ?? [])),
    http.get(`${BASE_URL}/api/v1/roles/:id/groups`, () => HttpResponse.json(overrides.roleGroups ?? [])),
    http.get(`${BASE_URL}/api/v1/roles/:id/service-accounts`, () =>
      HttpResponse.json(overrides.roleServiceAccounts ?? []),
    ),
    http.get(`${BASE_URL}/api/v1/resources/:id/scopes`, () => HttpResponse.json([])),
  );
}


describe('§27.6.1 item 1 — resources[].metadata', () => {
  it('round-trips on Create, and an Update sends the whole stated object', async () => {
    const server = mockServer();
    mountReads(server, { resources: [resourceJson(SITE1_ID, 'site-1', null, { owner: 'ops' })] });
    let putBody: unknown;
    let postBody: unknown;
    server.use(
      http.put(`${BASE_URL}/api/v1/resources/:id`, async ({ request }) => {
        putBody = await request.json();
        const body = putBody as { metadata?: unknown };
        return HttpResponse.json(resourceJson(SITE1_ID, 'site-1', null, body.metadata ?? {}));
      }),
      http.post(`${BASE_URL}/api/v1/resources`, async ({ request }) => {
        postBody = await request.json();
        const body = postBody as { name: string; metadata?: unknown };
        return HttpResponse.json(resourceJson(SITE2_ID, body.name, null, body.metadata ?? {}), { status: 201 });
      }),
    );

    const manifest: ManagementManifest = {
      resources: [
        { key: 's1', name: 'site-1', resourceType: 'site', metadata: { owner: 'concierge' } },
        { key: 's2', name: 'site-2', resourceType: 'site', metadata: { fresh: true } },
      ],
    };

    const report = await managementClient().manifest.apply(manifest);
    expect(isComplete(report)).toBe(true);

    expect((putBody as { metadata: unknown }).metadata).toEqual({ owner: 'concierge' });
    expect((postBody as { metadata: unknown }).metadata).toEqual({ fresh: true });
  });

  it('an unstated metadata never drifts, and an empty stated one matches "none"', async () => {
    const server = mockServer();
    mountReads(server, { resources: [resourceJson(SITE1_ID, 'site-1', null, {})] });

    // No metadata key at all on the spec — must not drift regardless of what
    // the server holds.
    const unstated = await managementClient().manifest.plan({
      resources: [{ key: 's1', name: 'site-1', resourceType: 'site' }],
    });
    expect(isConverged(unstated)).toBe(true);

    // Stated as {} — matches what the server returns for "none".
    const statedEmpty = await managementClient().manifest.plan({
      resources: [{ key: 's1', name: 'site-1', resourceType: 'site', metadata: {} }],
    });
    expect(isConverged(statedEmpty)).toBe(true);

    // Stated as something real — IS drift.
    const statedReal = await managementClient().manifest.plan({
      resources: [{ key: 's1', name: 'site-1', resourceType: 'site', metadata: { a: 1 } }],
    });
    expect(isConverged(statedReal)).toBe(false);
  });
});

describe('§27.6.1 item 2 — the two-shape role binding', () => {
  it('a resource-scoped binding sends inherit only when false, and round-trips through plan', async () => {
    const server = mockServer();
    mountReads(server, {
      resources: [resourceJson(SITE1_ID, 'site-1', null)],
      roles: [roleJson()],
      users: [userJson()],
    });
    let sentBody: unknown;
    server.use(
      http.post(`${BASE_URL}/api/v1/roles/:id/users`, async ({ request }) => {
        sentBody = await request.json();
        return new HttpResponse(null, { status: 204 });
      }),
    );

    const manifest: ManagementManifest = {
      resources: [{ key: 's1', name: 'site-1', resourceType: 'site' }],
      roles: [{ key: 'concierge', name: 'Concierge', description: 'Concierge' }],
      users: [
        {
          key: 'ann',
          username: 'ann',
          email: 'ann@example.com',
          roles: [{ role: 'concierge', resource: 's1', inherit: false }],
        },
      ],
    };

    const plan = await managementClient().manifest.plan(manifest);
    const binding = plan.actions.find((a) => a.target === 'user-role')!;
    expect(binding.change).toBe('create');

    await managementClient().manifest.apply(manifest);
    expect(sentBody).toMatchObject({ user_id: USER_ID, resource_id: SITE1_ID, inherit: false });
  });

  it('an inheritable scoped binding omits inherit — byte-for-byte a pre-1.51 body', async () => {
    const server = mockServer();
    mountReads(server, {
      resources: [resourceJson(SITE1_ID, 'site-1', null)],
      roles: [roleJson()],
      groups: [groupJson()],
    });
    let sentBody: unknown;
    server.use(
      http.post(`${BASE_URL}/api/v1/roles/:id/groups`, async ({ request }) => {
        sentBody = await request.json();
        return new HttpResponse(null, { status: 204 });
      }),
      http.get(`${BASE_URL}/api/v1/groups/:id/members`, () => HttpResponse.json(EMPTY_PAGE)),
    );

    const manifest: ManagementManifest = {
      resources: [{ key: 's1', name: 'site-1', resourceType: 'site' }],
      roles: [{ key: 'concierge', name: 'Concierge', description: 'Concierge' }],
      groups: [{ key: 'staff', name: 'Staff', description: 'Staff', roles: [{ role: 'concierge', resource: 's1' }] }],
    };
    await managementClient().manifest.apply(manifest);
    expect(sentBody).not.toHaveProperty('inherit');
    expect(sentBody).toMatchObject({ group_id: GROUP_ID, resource_id: SITE1_ID });
  });

  it('a changed binding is unassign then assign, and keeps tenant_scope', async () => {
    const server = mockServer();
    const scopeTenant = 'aaaaaaaa-1111-4aaa-8aaa-aaaaaaaaaaaa';
    mountReads(server, {
      resources: [resourceJson(SITE1_ID, 'site-1', null), resourceJson(SITE2_ID, 'site-2', null)],
      roles: [roleJson()],
      users: [userJson()],
      roleUsers: [
        { user: userJson(), resource_id: SITE1_ID, inherit: true, tenant_scope: [scopeTenant] },
      ],
    });
    const writeLog: Array<{ method: string; url: string; body?: unknown }> = [];
    server.use(
      http.delete(`${BASE_URL}/api/v1/roles/:id/users/:userId`, ({ request }) => {
        writeLog.push({ method: 'DELETE', url: request.url });
        return new HttpResponse(null, { status: 204 });
      }),
      http.post(`${BASE_URL}/api/v1/roles/:id/users`, async ({ request }) => {
        writeLog.push({ method: 'POST', url: request.url, body: await request.json() });
        return new HttpResponse(null, { status: 204 });
      }),
    );

    const manifest: ManagementManifest = {
      resources: [
        { key: 's1', name: 'site-1', resourceType: 'site' },
        { key: 's2', name: 'site-2', resourceType: 'site' },
      ],
      roles: [{ key: 'concierge', name: 'Concierge', description: 'Concierge' }],
      users: [
        {
          key: 'ann',
          username: 'ann',
          email: 'ann@example.com',
          roles: [{ role: 'concierge', resource: 's2' }],
        },
      ],
    };

    const plan = await managementClient().manifest.plan(manifest);
    const binding = plan.actions.find((a) => a.target === 'user-role')!;
    expect(binding.change).toBe('update');

    const report = await managementClient().manifest.apply(manifest);
    expect(isComplete(report)).toBe(true);

    expect(writeLog).toHaveLength(2);
    expect(writeLog[0]!.method).toBe('DELETE');
    expect(writeLog[0]!.url).toContain(SITE1_ID);
    expect(writeLog[1]!.method).toBe('POST');
    expect((writeLog[1]!.body as { resource_id: string; tenant_scope: string[] }).resource_id).toBe(SITE2_ID);
    expect((writeLog[1]!.body as { tenant_scope: string[] }).tenant_scope).toEqual([scopeTenant]);
  });

  it('a failed reassignment restores the previous binding, and apply reports it incomplete', async () => {
    const server = mockServer();
    mountReads(server, {
      resources: [resourceJson(SITE1_ID, 'site-1', null), resourceJson(SITE2_ID, 'site-2', null)],
      roles: [roleJson()],
      users: [userJson()],
      roleUsers: [{ user: userJson(), resource_id: SITE1_ID, inherit: false }],
    });
    const posts: unknown[] = [];
    server.use(
      http.delete(`${BASE_URL}/api/v1/roles/:id/users/:userId`, () => new HttpResponse(null, { status: 204 })),
      http.post(`${BASE_URL}/api/v1/roles/:id/users`, async ({ request }) => {
        const body = (await request.json()) as { resource_id?: string };
        posts.push(body);
        if (body.resource_id === SITE2_ID) {
          return HttpResponse.json({ error: 'conflict' }, { status: 409 });
        }
        return new HttpResponse(null, { status: 204 });
      }),
    );

    const manifest: ManagementManifest = {
      resources: [
        { key: 's1', name: 'site-1', resourceType: 'site' },
        { key: 's2', name: 'site-2', resourceType: 'site' },
      ],
      roles: [{ key: 'concierge', name: 'Concierge', description: 'Concierge' }],
      users: [
        {
          key: 'ann',
          username: 'ann',
          email: 'ann@example.com',
          roles: [{ role: 'concierge', resource: 's2' }],
        },
      ],
    };

    const report = await managementClient().manifest.apply(manifest);
    expect(isComplete(report)).toBe(false);
    const f = failure(report);
    expect(f).toBeDefined();
    expect(f!.action.target).toBe('user-role');

    // Two POSTs: the failed one at s2, then the restore at s1.
    expect(posts).toHaveLength(2);
    expect((posts[0] as { resource_id: string }).resource_id).toBe(SITE2_ID);
    expect((posts[1] as { resource_id: string }).resource_id).toBe(SITE1_ID);
    expect((posts[1] as { inherit: boolean }).inherit).toBe(false);
  });

  it('one role bound twice to one subject is refused with no wire call (plain + scoped)', async () => {
    const server = mockServer();
    let reached = 0;
    server.use(http.all(`${BASE_URL}/*`, () => {
      reached += 1;
      return HttpResponse.json(EMPTY_PAGE);
    }));

    await expect(
      managementClient().manifest.plan({
        resources: [{ key: 's1', name: 'site-1', resourceType: 'site' }],
        roles: [{ key: 'concierge', name: 'Concierge', description: 'Concierge' }],
        users: [
          {
            key: 'ann',
            username: 'ann',
            email: 'ann@example.com',
            roles: ['concierge', { role: 'concierge', resource: 's1' }],
          },
        ],
      }),
    ).rejects.toThrow(/more than once/);
    expect(reached).toBe(0);
  });

  it('a global role bound with inherit: false is refused client-side', async () => {
    await expect(
      managementClient().manifest.plan({
        roles: [{ key: 'admin', name: 'Admin', description: 'Admin', isGlobal: true }],
        users: [
          {
            key: 'ann',
            username: 'ann',
            email: 'ann@example.com',
            roles: [{ role: 'admin', inherit: false }],
          },
        ],
      }),
    ).rejects.toThrow(/global role/);
  });

  it('a plain binding over an existing resource-scoped assignment is an Update', async () => {
    const server = mockServer();
    mountReads(server, {
      roles: [roleJson()],
      users: [userJson()],
      roleUsers: [{ user: userJson(), resource_id: SITE1_ID, inherit: true }],
    });

    const plan = await managementClient().manifest.plan({
      roles: [{ key: 'concierge', name: 'Concierge', description: 'Concierge' }],
      users: [
        { key: 'ann', username: 'ann', email: 'ann@example.com', roles: ['concierge'] },
      ],
    });
    const binding = plan.actions.find((a) => a.target === 'user-role')!;
    expect(binding.change).toBe('update');
  });
});

describe('§27.6.1 item 3 — service accounts', () => {
  it("a created service account's secret survives a later failure and is never rotated", async () => {
    const server = mockServer();
    mountReads(server, { roles: [roleJson()] });
    server.use(
      http.post(`${BASE_URL}/api/v1/service-accounts`, () =>
        HttpResponse.json(
          { ...saJson(SA_ID, 'device-fleet'), client_secret: 'the-one-time-secret' },
          { status: 201 },
        ),
      ),
      http.post(`${BASE_URL}/api/v1/roles/:id/service-accounts`, () =>
        HttpResponse.json({ error: 'server exploded' }, { status: 500 }),
      ),
    );

    const manifest: ManagementManifest = {
      roles: [{ key: 'concierge', name: 'Concierge', description: 'Concierge' }],
      serviceAccounts: [
        { key: 'fleet', name: 'device-fleet', roles: ['concierge'] },
      ],
    };

    const report = await managementClient().manifest.apply(manifest);
    expect(isComplete(report)).toBe(false);

    const created = report.steps.find((s) => s.action.target === 'service-account')!;
    expect(created.outcome.status).toBe('created');
    const secret = (created.outcome as { serviceAccountSecret?: Sensitive<string> }).serviceAccountSecret;
    expect(secret).toBeDefined();
    expect(secret!.expose()).toBe('the-one-time-secret');
    // Never rendered in plain string form.
    expect(String(secret)).not.toContain('the-one-time-secret');

    const failed = report.steps.find((s) => s.action.target === 'service-account-role')!;
    expect(failed.outcome.status).toBe('failed');
  });

  it('an ambiguous service account name fails plan before any write', async () => {
    const server = mockServer();
    mountReads(server, {
      serviceAccounts: [saJson(SA_ID, 'device-fleet'), saJson(SA_ID_2, 'device-fleet')],
    });
    let wrote = false;
    server.use(
      http.post(`${BASE_URL}/*`, () => {
        wrote = true;
        return HttpResponse.json({}, { status: 201 });
      }),
    );

    await expect(
      managementClient().manifest.plan({
        serviceAccounts: [{ key: 'fleet', name: 'device-fleet' }],
      }),
    ).rejects.toThrow(/does not enforce unique names|matches 2 existing/);
    expect(wrote).toBe(false);
  });

  it('only a stated description is reconciled (sparse Update)', async () => {
    const server = mockServer();
    mountReads(server, { serviceAccounts: [saJson(SA_ID, 'device-fleet', 'old description')] });

    // No description stated at all — never drifts.
    const unstated = await managementClient().manifest.plan({
      serviceAccounts: [{ key: 'fleet', name: 'device-fleet' }],
    });
    expect(isConverged(unstated)).toBe(true);

    // Description stated and different — drifts.
    const stated = await managementClient().manifest.plan({
      serviceAccounts: [{ key: 'fleet', name: 'device-fleet', description: 'new description' }],
    });
    expect(isConverged(stated)).toBe(false);
  });
});

describe('§27.6.1 — apply(m) then plan(m) converges with every addition (rule 6)', () => {
  it('converges: metadata, a scoped binding, and a service account', async () => {
    const server = mockServer();
    mountReads(server);
    server.use(
      http.post(`${BASE_URL}/api/v1/resources`, () =>
        HttpResponse.json(resourceJson(SITE1_ID, 'site-1', null, { owner: 'ops' }), { status: 201 }),
      ),
      http.post(`${BASE_URL}/api/v1/roles`, () => HttpResponse.json(roleJson(), { status: 201 })),
      http.post(`${BASE_URL}/api/v1/users`, () =>
        HttpResponse.json(userJson(), { status: 201 }),
      ),
      http.post(`${BASE_URL}/api/v1/service-accounts`, () =>
        HttpResponse.json({ ...saJson(SA_ID, 'fleet'), client_secret: 's3cr3t' }, { status: 201 }),
      ),
      http.post(`${BASE_URL}/api/v1/roles/:id/users`, () => new HttpResponse(null, { status: 204 })),
      http.post(`${BASE_URL}/api/v1/roles/:id/service-accounts`, () => new HttpResponse(null, { status: 204 })),
    );

    const manifest: ManagementManifest = {
      resources: [{ key: 's1', name: 'site-1', resourceType: 'site', metadata: { owner: 'ops' } }],
      roles: [{ key: 'concierge', name: 'Concierge', description: 'Concierge' }],
      users: [
        {
          key: 'ann',
          username: 'ann',
          email: 'ann@example.com',
          initialPassword: new Sensitive('irrelevant-for-this-test'),
          roles: [{ role: 'concierge', resource: 's1', inherit: false }],
        },
      ],
      serviceAccounts: [{ key: 'fleet', name: 'fleet', roles: ['concierge'] }],
    };

    const report = await managementClient().manifest.apply(manifest);
    expect(isComplete(report)).toBe(true);

    // Re-plan against a tenant that now holds exactly what was applied.
    mountReads(server, {
      resources: [resourceJson(SITE1_ID, 'site-1', null, { owner: 'ops' })],
      roles: [roleJson()],
      users: [userJson()],
      serviceAccounts: [saJson(SA_ID, 'fleet')],
      roleUsers: [{ user: userJson(), resource_id: SITE1_ID, inherit: false }],
      roleServiceAccounts: [{ service_account: saJson(SA_ID, 'fleet'), inherit: true }],
    });
    const plan = await managementClient().manifest.plan(manifest);
    expect(isConverged(plan)).toBe(true);
  });
});
