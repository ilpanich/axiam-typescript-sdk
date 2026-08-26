// CONTRACT §27.6 / §27.9 — the declarative manifest.
//
// The assertions here are the ones that decide whether the layer is safe to
// point at a real tenant: that `plan` writes nothing, that `apply` converges,
// that a broken manifest is refused before anything has been changed, and that
// a failure halfway through is reported rather than papered over.

import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';

import { Sensitive } from '../../src/core/sensitive.js';
import type { ManagementManifest } from '../../src/management/manifest/index.js';
import { changes, failure, isComplete, isConverged } from '../../src/management/manifest/index.js';
import { BASE_URL, EXAMPLE_ID, TENANT_ID, managementClient, mockServer } from '../managementSupport.js';

const NOW = '2026-08-26T00:00:00Z';
const EMPTY_PAGE = { items: [], total: 0, offset: 0, limit: 200 };

const resourceJson = (name: string, parent: string | null = null, type = 'collection') => ({
  id: EXAMPLE_ID,
  tenant_id: TENANT_ID,
  name,
  resource_type: type,
  parent_id: parent,
  metadata: {},
  created_at: NOW,
  updated_at: NOW,
});

const roleJson = (name: string, description: string) => ({
  id: EXAMPLE_ID,
  tenant_id: TENANT_ID,
  name,
  description,
  is_global: false,
  created_at: NOW,
  updated_at: NOW,
});

/** A manifest exercising every stage of the reconciler. */
const fullManifest = (): ManagementManifest => ({
  resources: [
    { key: 'root', name: 'workspace', resourceType: 'collection' },
    {
      key: 'docs',
      name: 'documents',
      resourceType: 'collection',
      parent: 'root',
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
      initialPassword: new Sensitive('correct horse battery staple'),
      groups: ['staff'],
    },
  ],
});

/** Mount every read a plan performs, all answering "nothing exists yet". */
function mountEmptyReads(server: ReturnType<typeof mockServer>): void {
  for (const route of ['resources', 'permissions', 'roles', 'groups', 'users']) {
    server.use(http.get(`${BASE_URL}/api/v1/${route}`, () => HttpResponse.json(EMPTY_PAGE)));
  }
}

describe('§27.6 rule 1 — plan writes nothing', () => {
  // This is what makes the layer safe to point at production, so it is
  // asserted on the transport rather than trusted from the code.
  it('issues no write', async () => {
    const server = mockServer();
    const verbs: string[] = [];
    server.events.on('request:start', ({ request }) => verbs.push(request.method));
    mountEmptyReads(server);

    const plan = await managementClient().manifest.plan(fullManifest());
    expect(changes(plan).length).toBeGreaterThan(0);
    expect(verbs.filter((v) => v !== 'GET')).toEqual([]);
    server.events.removeAllListeners();
  });

  // §27.6 rule 8: a plan that reorders between runs cannot be diffed, and
  // diffing it is most of the reason it exists.
  it('is stable across runs', async () => {
    mountEmptyReads(mockServer());
    const client = managementClient();
    const manifest = fullManifest();
    expect(await client.manifest.plan(manifest)).toEqual(await client.manifest.plan(manifest));
  });
});

describe('§27.6 rule 5 — derived ordering', () => {
  it('orders producers before consumers', async () => {
    mountEmptyReads(mockServer());
    const plan = await managementClient().manifest.plan(fullManifest());
    const at = (target: string, key: string) => {
      const i = plan.actions.findIndex((a) => a.target === target && a.key === key);
      expect(i, `no ${target} action for ${key}`).toBeGreaterThanOrEqual(0);
      return i;
    };

    expect(at('resource', 'root')).toBeLessThan(at('resource', 'docs'));
    expect(at('resource', 'docs')).toBeLessThan(at('scope', 'draft'));
    expect(at('permission', 'read')).toBeLessThan(at('role', 'editor'));
    expect(at('role', 'editor')).toBeLessThan(at('role-grant', 'editor'));
    expect(at('group', 'staff')).toBeLessThan(at('group-role', 'staff'));
    expect(at('user', 'alice')).toBeLessThan(at('group-member', 'alice'));
  });
});

describe('§27.6 rule 2 — validation precedes every request', () => {
  it('refuses a dangling reference before calling', async () => {
    const server = mockServer();
    let reached = 0;
    server.use(http.all(`${BASE_URL}/*`, () => { reached += 1; return HttpResponse.json(EMPTY_PAGE); }));

    await expect(
      managementClient().manifest.plan({
        roles: [{ key: 'editor', name: 'Editor', description: 'Edits', grants: [{ permission: 'ghost' }] }],
      }),
    ).rejects.toThrow(/ghost/);
    expect(reached).toBe(0);
  });

  it('refuses a resource cycle rather than looping', async () => {
    await expect(
      managementClient().manifest.plan({
        resources: [
          { key: 'a', name: 'a', resourceType: 'collection', parent: 'b' },
          { key: 'b', name: 'b', resourceType: 'collection', parent: 'a' },
        ],
      }),
    ).rejects.toThrow(/cycle/);
  });

  it('refuses a duplicate key', async () => {
    await expect(
      managementClient().manifest.plan({
        roles: [
          { key: 'editor', name: 'A', description: 'a' },
          { key: 'editor', name: 'B', description: 'b' },
        ],
      }),
    ).rejects.toThrow(/more than once/);
  });

  // §27.6 rule 1 in its most useful form: exactly the failure you do not want
  // to meet halfway through an apply.
  it('fails in plan when a user must be created with no password', async () => {
    mountEmptyReads(mockServer());
    await expect(
      managementClient().manifest.plan({
        users: [{ key: 'bob', username: 'bob', email: 'bob@example.com' }],
      }),
    ).rejects.toThrow(/initialPassword/);
  });
});

describe('§27.6 rules 3 and 4 — drift and pruning', () => {
  function mountRolesOnly(server: ReturnType<typeof mockServer>, items: unknown[]): void {
    server.use(
      http.get(`${BASE_URL}/api/v1/roles`, () =>
        HttpResponse.json({ items, total: items.length, offset: 0, limit: 200 }),
      ),
      http.get(`${BASE_URL}/api/v1/roles/:id/permissions`, () => HttpResponse.json([])),
      http.get(`${BASE_URL}/api/v1/roles/:id/users`, () => HttpResponse.json([])),
      http.get(`${BASE_URL}/api/v1/roles/:id/groups`, () => HttpResponse.json([])),
    );
    for (const route of ['resources', 'permissions', 'groups', 'users']) {
      server.use(http.get(`${BASE_URL}/api/v1/${route}`, () => HttpResponse.json(EMPTY_PAGE)));
    }
  }

  it('plans nothing against a converged tenant', async () => {
    mountRolesOnly(mockServer(), [roleJson('Editor', 'Edits documents')]);
    const plan = await managementClient().manifest.plan({
      roles: [{ key: 'editor', name: 'Editor', description: 'Edits documents' }],
    });
    expect(isConverged(plan)).toBe(true);
  });

  // A manifest is usually a SUBSET of a tenant's truth, and pruning by default
  // turns "make sure this role exists" into "delete the other forty".
  it('never deletes a role the manifest omits', async () => {
    mountRolesOnly(mockServer(), [roleJson("SomeoneElsesRole", 'Not in the manifest')]);
    const plan = await managementClient().manifest.plan({});
    expect(plan.actions).toEqual([]);
  });

  it('treats a drifted field the manifest states as an update', async () => {
    const server = mockServer();
    server.use(
      http.get(`${BASE_URL}/api/v1/resources`, () =>
        HttpResponse.json({
          items: [resourceJson('documents', null, 'folder')],
          total: 1,
          offset: 0,
          limit: 200,
        }),
      ),
      http.get(`${BASE_URL}/api/v1/resources/:id/scopes`, () => HttpResponse.json([])),
    );
    for (const route of ['permissions', 'roles', 'groups', 'users']) {
      server.use(http.get(`${BASE_URL}/api/v1/${route}`, () => HttpResponse.json(EMPTY_PAGE)));
    }

    const plan = await managementClient().manifest.plan({
      resources: [{ key: 'docs', name: 'documents', resourceType: 'collection' }],
    });
    expect(plan.actions.find((a) => a.target === 'resource')?.change).toBe('update');
  });
});

describe('§27.6 rules 6 and 7 — apply', () => {
  function mountAllWrites(server: ReturnType<typeof mockServer>): void {
    server.use(
      http.post(`${BASE_URL}/api/v1/resources`, () =>
        HttpResponse.json(resourceJson('workspace'), { status: 201 }),
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
      http.post(`${BASE_URL}/api/v1/permissions`, () =>
        HttpResponse.json(
          {
            id: EXAMPLE_ID,
            tenant_id: TENANT_ID,
            action: 'document:read',
            description: 'Read a document',
            created_at: NOW,
            updated_at: NOW,
          },
          { status: 201 },
        ),
      ),
      http.post(`${BASE_URL}/api/v1/roles`, () =>
        HttpResponse.json(roleJson('Editor', 'Edits documents'), { status: 201 }),
      ),
      http.post(`${BASE_URL}/api/v1/roles/:id/permissions`, () => new HttpResponse(null, { status: 204 })),
      http.post(`${BASE_URL}/api/v1/roles/:id/groups`, () => new HttpResponse(null, { status: 204 })),
      http.post(`${BASE_URL}/api/v1/groups`, () =>
        HttpResponse.json(
          {
            id: EXAMPLE_ID,
            tenant_id: TENANT_ID,
            name: 'Staff',
            description: 'All staff',
            metadata: {},
            created_at: NOW,
            updated_at: NOW,
          },
          { status: 201 },
        ),
      ),
      http.post(`${BASE_URL}/api/v1/groups/:id/members`, () => new HttpResponse(null, { status: 204 })),
      http.post(`${BASE_URL}/api/v1/users`, () =>
        HttpResponse.json(
          {
            id: EXAMPLE_ID,
            tenant_id: TENANT_ID,
            username: 'alice',
            email: 'alice@example.com',
            status: 'Active',
            mfa_enabled: false,
            email_verified: false,
            metadata: {},
            created_at: NOW,
            updated_at: NOW,
            failed_login_attempts: 0,
            is_locked: false,
          },
          { status: 201 },
        ),
      ),
    );
  }

  it('creates everything and reports an outcome for every step', async () => {
    const server = mockServer();
    mountEmptyReads(server);
    mountAllWrites(server);

    const report = await managementClient().manifest.apply(fullManifest());
    expect(isComplete(report)).toBe(true);
    expect(report.steps.every((s) => s.outcome.status === 'created')).toBe(true);
  });

  // §27.6 rule 7: there is no transaction across these endpoints, so the
  // report has to say what already happened and what was never tried.
  it('stops at the first failure and says what was not attempted', async () => {
    const server = mockServer();
    mountEmptyReads(server);
    server.use(
      http.post(`${BASE_URL}/api/v1/resources`, () =>
        HttpResponse.json(resourceJson('workspace'), { status: 201 }),
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
      http.post(`${BASE_URL}/api/v1/permissions`, () =>
        HttpResponse.json({ message: 'action already declared' }, { status: 409 }),
      ),
    );

    const report = await managementClient().manifest.apply(fullManifest());
    expect(isComplete(report)).toBe(false);

    const failed = failure(report);
    expect(failed?.action.target).toBe('permission');

    const statuses = report.steps.map((s) => s.outcome.status);
    const at = statuses.indexOf('failed');
    expect(statuses.slice(0, at)).not.toContain('not-attempted');
    expect(statuses.slice(at + 1).every((s) => s === 'not-attempted')).toBe(true);
  });

  it('applies an empty manifest cleanly', async () => {
    mountEmptyReads(mockServer());
    const report = await managementClient().manifest.apply({});
    expect(isComplete(report)).toBe(true);
    expect(report.steps).toEqual([]);
  });
});
