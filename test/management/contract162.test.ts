// Contract 1.62 — the `network` namespace (§36.8, five tests). The change-taking
// SSF form and the "assigned null is none" rule are in contract162Ssf.test.ts.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';

import registry from '../../management-registry.json' with { type: 'json' };
import { AuthError, AuthzError, NetworkError } from '../../src/core/errors.js';
import { ConflictError, NotFoundError, ValidationError } from '../../src/management/errors.js';
import type {
  CreateNetworkReplyProfileRequest,
  NetworkReplyProfile,
  NetworkSegmentResponse,
  ReplaceNetworkPolicyRequest,
  ReplaceNetworkReplyProfileRequest,
  ReplaceNetworkSegmentRequest,
} from '../../src/management/models.js';
import {
  BASE_URL,
  EXAMPLE_ID,
  TENANT_ID,
  capture,
  managementClient,
  mockServer,
  retryingManagementClient,
} from '../managementSupport.js';

const NOW = '2026-10-16T00:00:00Z';
const SEGMENT_ID = '44444444-4444-4444-8444-444444444444';

const segmentJson = (extra: Record<string, unknown> = {}): Record<string, unknown> => ({
  id: SEGMENT_ID,
  tenant_id: TENANT_ID,
  path: '/network/zones/default/staff',
  name: 'staff',
  site_key: 'default',
  kind: 'access',
  vlan_id: 20,
  filter_ids: ['staff-acl'],
  rank: 1,
  enabled: true,
  version: 3,
  created_by: EXAMPLE_ID,
  updated_by: EXAMPLE_ID,
  created_at: NOW,
  updated_at: NOW,
  ...extra,
});

const profileJson = (extra: Record<string, unknown> = {}): Record<string, unknown> => ({
  segment_id: SEGMENT_ID,
  tenant_id: TENANT_ID,
  dictionary: 'axiam-radius-reply/1',
  session_timeout_secs: 3600,
  session_timeout_clamped: false,
  termination_action: 'radius_request',
  idle_timeout_secs: null,
  filter_id: 'staff-acl',
  service_type: 'framed_user',
  version: 2,
  created_by: EXAMPLE_ID,
  updated_by: EXAMPLE_ID,
  created_at: NOW,
  updated_at: NOW,
  ...extra,
});

const policyJson = (extra: Record<string, unknown> = {}): Record<string, unknown> => ({
  tenant_id: TENANT_ID,
  session_timeout_max_secs: 3600,
  version: 0,
  ...extra,
});

// ── §36.8 (1) the surface ───────────────────────────────────────────────────

describe('§36.8 (1) — the surface', () => {
  const OPERATIONS: Array<[string, string, string]> = [
    ['list_segments', 'GET', '/api/v1/network/segments'],
    ['create_segment', 'POST', '/api/v1/network/segments'],
    ['get_segment', 'GET', '/api/v1/network/segments/{id}'],
    ['replace_segment', 'PUT', '/api/v1/network/segments/{id}'],
    ['delete_segment', 'DELETE', '/api/v1/network/segments/{id}'],
    ['list_profiles', 'GET', '/api/v1/network/profiles'],
    ['create_profile', 'POST', '/api/v1/network/profiles'],
    ['get_profile', 'GET', '/api/v1/network/profiles/{segment_id}'],
    ['replace_profile', 'PUT', '/api/v1/network/profiles/{segment_id}'],
    ['delete_profile', 'DELETE', '/api/v1/network/profiles/{segment_id}'],
    ['get_policy', 'GET', '/api/v1/network/policy'],
    ['replace_policy', 'PUT', '/api/v1/network/policy'],
  ];

  it('the registry holds the twelve operations with §36.1 methods and paths', () => {
    const ops = (registry as unknown as {
      namespaces: Record<string, { operations: Record<string, { method: string; path: string }> }>;
    }).namespaces.network!.operations;
    expect(Object.keys(ops).sort()).toEqual(OPERATIONS.map(([n]) => n).sort());
    for (const [name, method, path] of OPERATIONS) {
      expect(ops[name], name).toMatchObject({ method, path });
    }
  });

  it('the twelve exist on the network handle, and no method reaches POST /network/decide', () => {
    const { network } = managementClient();
    const names = [
      'listSegments', 'createSegment', 'getSegment', 'replaceSegment', 'deleteSegment',
      'listProfiles', 'createProfile', 'getProfile', 'replaceProfile', 'deleteProfile',
      'getPolicy', 'replacePolicy',
    ];
    for (const name of names) {
      expect(typeof (network as unknown as Record<string, unknown>)[name], name).toBe('function');
    }
    // The decision route is the registry's `excluded_operations`: nothing on
    // the handle, in the generated source, or in the registry's operations.
    const proto = Object.getOwnPropertyNames(Object.getPrototypeOf(network));
    expect(proto.filter((n) => /decide/i.test(n))).toEqual([]);
    const source = readFileSync(
      fileURLToPath(new URL('../../src/management/ops/network.ts', import.meta.url)),
      'utf8',
    );
    expect(source).not.toContain('/network/decide');
    const excluded = JSON.stringify((registry as unknown as { excluded_operations: unknown }).excluded_operations);
    expect(excluded).toContain('/api/v1/network/decide');
  });

  it('every operation sends the method and path §36.1 names', async () => {
    const server = mockServer();
    const seen: string[] = [];
    server.use(
      http.all(`${BASE_URL}/api/v1/network/*`, ({ request }) => {
        seen.push(`${request.method} ${new URL(request.url).pathname}`);
        const path = new URL(request.url).pathname;
        if (request.method === 'DELETE') return new HttpResponse(null, { status: 204 });
        if (path.endsWith('/policy')) return HttpResponse.json(policyJson());
        if (path.includes('/profiles')) {
          return request.method === 'GET' && !path.match(/profiles\/./)
            ? HttpResponse.json({ items: [], total: 0, offset: 0, limit: 50 })
            : HttpResponse.json(profileJson());
        }
        return request.method === 'GET' && !path.match(/segments\/./)
          ? HttpResponse.json({ items: [], total: 0, offset: 0, limit: 50 })
          : HttpResponse.json(segmentJson());
      }),
    );
    const { network } = managementClient();
    await network.listSegments();
    await network.createSegment({ kind: 'access', site_key: 'default', name: 'staff', vlan_id: 20, rank: 1 });
    await network.getSegment(SEGMENT_ID);
    await network.replaceSegment(SEGMENT_ID, { version: 3, vlan_id: 20, filter_ids: [], enabled: true });
    await network.deleteSegment(SEGMENT_ID, 3);
    await network.listProfiles();
    await network.createProfile({ segment_id: SEGMENT_ID, segment_version: 3, profile: { session_timeout_secs: 3600 } });
    await network.getProfile(SEGMENT_ID);
    await network.replaceProfile(SEGMENT_ID, { version: 2, segment_version: 3, profile: { session_timeout_secs: 3600 } });
    await network.deleteProfile(SEGMENT_ID, 2);
    await network.getPolicy();
    await network.replacePolicy({ session_timeout_max_secs: 3600, version: 0 });
    expect(seen).toEqual([
      'GET /api/v1/network/segments',
      'POST /api/v1/network/segments',
      `GET /api/v1/network/segments/${SEGMENT_ID}`,
      `PUT /api/v1/network/segments/${SEGMENT_ID}`,
      `DELETE /api/v1/network/segments/${SEGMENT_ID}`,
      'GET /api/v1/network/profiles',
      'POST /api/v1/network/profiles',
      `GET /api/v1/network/profiles/${SEGMENT_ID}`,
      `PUT /api/v1/network/profiles/${SEGMENT_ID}`,
      `DELETE /api/v1/network/profiles/${SEGMENT_ID}`,
      'GET /api/v1/network/policy',
      'PUT /api/v1/network/policy',
    ]);
  });
});

// ── §36.8 (2) versions ──────────────────────────────────────────────────────

describe('§36.8 (2) — versions are sent exactly as given', () => {
  it('replace_segment sends version in the body; both deletes send ?version=', async () => {
    const server = mockServer();
    const put = capture(server, 'PUT', `/api/v1/network/segments/${SEGMENT_ID}`, 200, segmentJson());
    const delSegment = capture(server, 'DELETE', `/api/v1/network/segments/${SEGMENT_ID}`, 204);
    const delProfile = capture(server, 'DELETE', `/api/v1/network/profiles/${SEGMENT_ID}`, 204);
    const { network } = managementClient();

    await network.replaceSegment(SEGMENT_ID, { version: 7, vlan_id: 20, filter_ids: [], enabled: true });
    await network.deleteSegment(SEGMENT_ID, 7);
    await network.deleteProfile(SEGMENT_ID, 0);

    expect((put[0]!.json as ReplaceNetworkSegmentRequest).version).toBe(7);
    expect(delSegment[0]!.query).toBe('version=7');
    // `0` is a version too: it is sent, not dropped as falsy.
    expect(delProfile[0]!.query).toBe('version=0');
  });

  it('a delete cannot be called without a version', () => {
    const { network } = managementClient();
    // @ts-expect-error — `version` is required.
    const a: Promise<void> = network.deleteSegment(SEGMENT_ID);
    // @ts-expect-error — `version` is required.
    const b: Promise<void> = network.deleteProfile(SEGMENT_ID);
    // The calls above are never awaited and have no session to send with a
    // missing version; the compile-time check is the assertion.
    a.catch(() => undefined);
    b.catch(() => undefined);
  });

  it('create_profile sends segment_version, replace_profile version and segment_version, replace_policy version', async () => {
    const server = mockServer();
    const post = capture(server, 'POST', '/api/v1/network/profiles', 201, profileJson());
    const put = capture(server, 'PUT', `/api/v1/network/profiles/${SEGMENT_ID}`, 200, profileJson());
    const policy = capture(server, 'PUT', '/api/v1/network/policy', 200, policyJson());
    const { network } = managementClient();

    await network.createProfile({ segment_id: SEGMENT_ID, segment_version: 11, profile: { session_timeout_secs: 600 } });
    await network.replaceProfile(SEGMENT_ID, { version: 5, segment_version: 12, profile: { session_timeout_secs: 600 } });
    await network.replacePolicy({ session_timeout_max_secs: 7200, version: 0 });

    expect(post[0]!.json).toEqual({ segment_id: SEGMENT_ID, segment_version: 11, profile: { session_timeout_secs: 600 } });
    expect((put[0]!.json as ReplaceNetworkReplyProfileRequest).version).toBe(5);
    expect((put[0]!.json as ReplaceNetworkReplyProfileRequest).segment_version).toBe(12);
    expect((policy[0]!.json as ReplaceNetworkPolicyRequest).version).toBe(0);
  });

  it('a 409 to each write is a ConflictError after exactly one request, exposing reason_code', async () => {
    const server = mockServer();
    const stale = { error: 'conflict', message: 'stale', reason_code: 'stale_version' };
    const hits = [
      capture(server, 'POST', '/api/v1/network/segments', 409, stale),
      capture(server, 'PUT', `/api/v1/network/segments/${SEGMENT_ID}`, 409, stale),
      capture(server, 'DELETE', `/api/v1/network/segments/${SEGMENT_ID}`, 409, stale),
      capture(server, 'POST', '/api/v1/network/profiles', 409, stale),
      capture(server, 'PUT', `/api/v1/network/profiles/${SEGMENT_ID}`, 409, stale),
      capture(server, 'DELETE', `/api/v1/network/profiles/${SEGMENT_ID}`, 409, stale),
      capture(server, 'PUT', '/api/v1/network/policy', 409, stale),
    ];
    const { network } = retryingManagementClient();
    const errors = [
      await network.createSegment({ kind: 'access', site_key: 's', name: 'n', vlan_id: 2, rank: 1 }).catch((e: unknown) => e),
      await network.replaceSegment(SEGMENT_ID, { version: 1, vlan_id: 2, filter_ids: [], enabled: true }).catch((e: unknown) => e),
      await network.deleteSegment(SEGMENT_ID, 1).catch((e: unknown) => e),
      await network.createProfile({ segment_id: SEGMENT_ID, segment_version: 1, profile: { session_timeout_secs: 600 } }).catch((e: unknown) => e),
      await network.replaceProfile(SEGMENT_ID, { version: 1, segment_version: 1, profile: { session_timeout_secs: 600 } }).catch((e: unknown) => e),
      await network.deleteProfile(SEGMENT_ID, 1).catch((e: unknown) => e),
      await network.replacePolicy({ session_timeout_max_secs: 600, version: 1 }).catch((e: unknown) => e),
    ];
    for (const err of errors) {
      expect(err).toBeInstanceOf(ConflictError);
      expect((err as ConflictError).reasonCode).toBe('stale_version');
    }
    for (const h of hits) expect(h).toHaveLength(1);
  });

  it('a 409 already_exists / duplicate_vlan is a ConflictError exposing it too; an unknown code is verbatim; none is undefined', async () => {
    const server = mockServer();
    capture(server, 'POST', '/api/v1/network/segments', 409, {
      error: 'already_exists',
      message: 'vlan taken',
      reason_code: 'duplicate_vlan',
    });
    const { network } = managementClient();
    const dup = await network
      .createSegment({ kind: 'access', site_key: 's', name: 'n', vlan_id: 2, rank: 1 })
      .catch((e: unknown) => e);
    expect(dup).toBeInstanceOf(ConflictError);
    expect((dup as ConflictError).reasonCode).toBe('duplicate_vlan');

    server.resetHandlers();
    capture(server, 'POST', '/api/v1/network/segments', 409, { error: 'conflict', message: 'm', reason_code: 'a_newer_code' });
    const unknown = await network
      .createSegment({ kind: 'access', site_key: 's', name: 'n', vlan_id: 2, rank: 1 })
      .catch((e: unknown) => e);
    expect((unknown as ConflictError).reasonCode).toBe('a_newer_code');

    server.resetHandlers();
    capture(server, 'POST', '/api/v1/network/segments', 409, { error: 'conflict', message: 'old server' });
    const absent = await network
      .createSegment({ kind: 'access', site_key: 's', name: 'n', vlan_id: 2, rank: 1 })
      .catch((e: unknown) => e);
    expect(absent).toBeInstanceOf(ConflictError);
    expect((absent as ConflictError).reasonCode).toBeUndefined();
  });
});

// ── §36.8 (3) closed bodies ─────────────────────────────────────────────────

describe('§36.8 (3) — closed bodies', () => {
  it('serialises exactly the keys set; unset optional members are absent, not null', async () => {
    const server = mockServer();
    const postSegment = capture(server, 'POST', '/api/v1/network/segments', 201, segmentJson());
    const putSegment = capture(server, 'PUT', `/api/v1/network/segments/${SEGMENT_ID}`, 200, segmentJson());
    const postProfile = capture(server, 'POST', '/api/v1/network/profiles', 201, profileJson());
    const putPolicy = capture(server, 'PUT', '/api/v1/network/policy', 200, policyJson());
    const { network } = managementClient();

    await network.createSegment({ kind: 'quarantine', site_key: 'default', name: 'q', vlan_id: 99 });
    await network.replaceSegment(SEGMENT_ID, { version: 1, vlan_id: 20, filter_ids: ['a'], enabled: false });
    await network.createProfile({ segment_id: SEGMENT_ID, segment_version: 1, profile: { session_timeout_secs: 600 } });
    await network.replacePolicy({ session_timeout_max_secs: 600, version: 0 });

    expect(Object.keys(postSegment[0]!.json as object).sort()).toEqual(['kind', 'name', 'site_key', 'vlan_id']);
    expect(Object.keys(putSegment[0]!.json as object).sort()).toEqual(['enabled', 'filter_ids', 'version', 'vlan_id']);
    expect(Object.keys(postProfile[0]!.json as object).sort()).toEqual(['profile', 'segment_id', 'segment_version']);
    const profile = (postProfile[0]!.json as CreateNetworkReplyProfileRequest).profile;
    expect(Object.keys(profile)).toEqual(['session_timeout_secs']);
    expect('vlan_id' in profile, 'a profile has no VLAN member').toBe(false);
    expect(Object.keys(putPolicy[0]!.json as object).sort()).toEqual(['session_timeout_max_secs', 'version']);
  });

  it('the replace types cannot be built without their required members', () => {
    // @ts-expect-error — `version` is required.
    const a: ReplaceNetworkSegmentRequest = { vlan_id: 1, filter_ids: [], enabled: true };
    // @ts-expect-error — `segment_version` is required.
    const b: ReplaceNetworkReplyProfileRequest = { version: 1, profile: { session_timeout_secs: 600 } };
    // @ts-expect-error — `version` is required.
    const c: ReplaceNetworkPolicyRequest = { session_timeout_max_secs: 600 };
    // @ts-expect-error — `segment_version` is required.
    const d: CreateNetworkReplyProfileRequest = { segment_id: SEGMENT_ID, profile: { session_timeout_secs: 600 } };
    void [a, b, c, d];
  });
});

// ── §36.8 (4) open decoding and pagination ──────────────────────────────────

describe('§36.8 (4) — open decoding and pagination', () => {
  it('decodes an unknown kind, termination_action and service_type, and a clamped profile', async () => {
    const server = mockServer();
    capture(server, 'GET', `/api/v1/network/segments/${SEGMENT_ID}`, 200, segmentJson({ kind: 'sandbox' }));
    capture(
      server,
      'GET',
      `/api/v1/network/profiles/${SEGMENT_ID}`,
      200,
      profileJson({
        termination_action: 'quiesce',
        service_type: 'callback_login',
        session_timeout_secs: 300,
        session_timeout_clamped: true,
      }),
    );
    const { network } = managementClient();
    const segment: NetworkSegmentResponse = await network.getSegment(SEGMENT_ID);
    const profile: NetworkReplyProfile = await network.getProfile(SEGMENT_ID);
    expect(segment.kind).toBe('sandbox');
    expect(profile.termination_action).toBe('quiesce');
    expect(profile.service_type).toBe('callback_login');
    expect(profile.session_timeout_clamped).toBe(true);
    expect(profile.session_timeout_secs).toBe(300);
  });

  it('both lists return Page<T> with total, and the auto-pager carries search (and site) on every request', async () => {
    const server = mockServer();
    const segmentQueries: URLSearchParams[] = [];
    const profileQueries: URLSearchParams[] = [];
    server.use(
      http.get(`${BASE_URL}/api/v1/network/segments`, ({ request }) => {
        const q = new URL(request.url).searchParams;
        segmentQueries.push(q);
        const offset = Number(q.get('offset') ?? '0');
        return HttpResponse.json({ items: offset < 2 ? [segmentJson()] : [], total: 2, offset, limit: 1 });
      }),
      http.get(`${BASE_URL}/api/v1/network/profiles`, ({ request }) => {
        const q = new URL(request.url).searchParams;
        profileQueries.push(q);
        const offset = Number(q.get('offset') ?? '0');
        return HttpResponse.json({ items: offset < 2 ? [profileJson()] : [], total: 2, offset, limit: 1 });
      }),
    );
    const { network } = managementClient();

    const page = await network.listSegments('hq', { limit: 1, search: 'staff' });
    expect(page.total).toBe(2);
    expect(page.items).toHaveLength(1);
    segmentQueries.length = 0;
    const all = await network.listSegmentsAll('hq', { limit: 1, search: 'staff' });
    expect(all).toHaveLength(2);
    expect(segmentQueries.length).toBeGreaterThan(1);
    for (const q of segmentQueries) {
      expect(q.get('search')).toBe('staff');
      expect(q.get('site')).toBe('hq');
    }

    const profiles = await network.listProfilesAll({ limit: 1, search: 'staff-acl' });
    expect(profiles).toHaveLength(2);
    for (const q of profileQueries) expect(q.get('search')).toBe('staff-acl');

    // With no site, no `site` key at all.
    segmentQueries.length = 0;
    await network.listSegments(undefined, { limit: 1 });
    expect(segmentQueries[0]!.has('site')).toBe(false);
  });
});

// ── §36.8 (5) errors ────────────────────────────────────────────────────────

describe('§36.8 (5) — errors', () => {
  it('403 is AuthzError exposing action and resource_id; 400 ValidationError; 404 NotFoundError; 401 AuthError', async () => {
    const server = mockServer();
    capture(server, 'PUT', `/api/v1/network/profiles/${SEGMENT_ID}`, 403, {
      error: 'authorization_denied',
      message: 'missing permission',
      action: 'network:grant',
      resource_id: SEGMENT_ID,
    });
    capture(server, 'POST', '/api/v1/network/segments', 400, { error: 'validation_error', message: 'vlan_id: out of range' });
    capture(server, 'GET', `/api/v1/network/profiles/${SEGMENT_ID}`, 404, { error: 'not_found', message: 'no' });
    capture(server, 'GET', '/api/v1/network/policy', 401, { error: 'unauthorized', message: 'human only' });
    capture(server, 'POST', '/api/v1/auth/refresh', 401, { error: 'unauthorized' });
    const { network } = managementClient();

    const denied = await network
      .replaceProfile(SEGMENT_ID, { version: 1, segment_version: 1, profile: { session_timeout_secs: 600 } })
      .catch((e: unknown) => e);
    expect(denied).toBeInstanceOf(AuthzError);
    expect(denied).not.toBeInstanceOf(ConflictError);
    expect((denied as AuthzError).action).toBe('network:grant');
    expect((denied as AuthzError).resourceId).toBe(SEGMENT_ID);

    const invalid = await network
      .createSegment({ kind: 'access', site_key: 's', name: 'n', vlan_id: 9999, rank: 1 })
      .catch((e: unknown) => e);
    expect(invalid).toBeInstanceOf(ValidationError);
    expect((invalid as ValidationError).message).toContain('out of range');

    await expect(network.getProfile(SEGMENT_ID)).rejects.toBeInstanceOf(NotFoundError);
    await expect(network.getPolicy()).rejects.toBeInstanceOf(AuthError);
  });

  it('429 and 503 on each of the seven writes are NetworkError after exactly one request', async () => {
    for (const status of [429, 503]) {
      const server = mockServer();
      server.resetHandlers();
      const hits = [
        capture(server, 'POST', '/api/v1/network/segments', status),
        capture(server, 'PUT', `/api/v1/network/segments/${SEGMENT_ID}`, status),
        capture(server, 'DELETE', `/api/v1/network/segments/${SEGMENT_ID}`, status),
        capture(server, 'POST', '/api/v1/network/profiles', status),
        capture(server, 'PUT', `/api/v1/network/profiles/${SEGMENT_ID}`, status),
        capture(server, 'DELETE', `/api/v1/network/profiles/${SEGMENT_ID}`, status),
        capture(server, 'PUT', '/api/v1/network/policy', status),
      ];
      const { network } = retryingManagementClient();
      const errors = [
        await network.createSegment({ kind: 'access', site_key: 's', name: 'n', vlan_id: 2, rank: 1 }).catch((e: unknown) => e),
        await network.replaceSegment(SEGMENT_ID, { version: 1, vlan_id: 2, filter_ids: [], enabled: true }).catch((e: unknown) => e),
        await network.deleteSegment(SEGMENT_ID, 1).catch((e: unknown) => e),
        await network.createProfile({ segment_id: SEGMENT_ID, segment_version: 1, profile: { session_timeout_secs: 600 } }).catch((e: unknown) => e),
        await network.replaceProfile(SEGMENT_ID, { version: 1, segment_version: 1, profile: { session_timeout_secs: 600 } }).catch((e: unknown) => e),
        await network.deleteProfile(SEGMENT_ID, 1).catch((e: unknown) => e),
        await network.replacePolicy({ session_timeout_max_secs: 600, version: 1 }).catch((e: unknown) => e),
      ];
      for (const err of errors) expect(err, `${status}`).toBeInstanceOf(NetworkError);
      for (const h of hits) expect(h, `${status}`).toHaveLength(1);
    }
  });
});
