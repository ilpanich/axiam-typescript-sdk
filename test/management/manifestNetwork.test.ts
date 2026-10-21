// CONTRACT §27.6.2 / §27.9 "Manifest, `network`" (contract 1.62).
//
// A small stateful stand-in for the network routes: it keeps segments,
// profiles and the policy, bumps versions the way §36.3 describes, answers
// `409` with a `reason_code` for a stale version, clamps profile reads to the
// cap and refuses a write above it with the write gate's `403`. Driving the
// real reconciler against it is what lets "apply, then plan is all NoChange"
// be asserted instead of assumed.

import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';

import { NetworkError } from '../../src/core/errors.js';
import { ValidationError } from '../../src/management/errors.js';
import type { ManagementManifest } from '../../src/management/manifest/index.js';
import { changes, failure, isComplete, isConverged } from '../../src/management/manifest/index.js';
import type { NetworkReplyProfile, NetworkSegmentResponse } from '../../src/management/models.js';
import { BASE_URL, EXAMPLE_ID, TENANT_ID, mockServer, retryingManagementClient } from '../managementSupport.js';

const NOW = '2026-10-16T00:00:00Z';

interface StoredProfile {
  segment_id: string;
  stored_timeout: number;
  termination_action: string;
  idle_timeout_secs: number | null;
  filter_id: string | null;
  service_type: string | null;
  version: number;
}

interface Logged {
  method: string;
  path: string;
  query: string;
  body: Record<string, unknown> | undefined;
}

/** The fake tenant's network state and everything done to it. */
class FakeNetwork {
  cap = 3600;
  policyVersion = 0;
  segments = new Map<string, NetworkSegmentResponse>();
  profiles = new Map<string, StoredProfile>();
  log: Logged[] = [];
  /** The next segment write's version bump (so a test can tell versions apart). */
  segmentCreateVersion = 1;
  /** When set, the next matching write answers this instead of working. */
  refuse: { match: (l: Logged) => boolean; status: number; body: Record<string, unknown> } | undefined;
  #n = 0;

  seedSegment(extra: Partial<NetworkSegmentResponse> = {}): NetworkSegmentResponse {
    this.#n += 1;
    const id = `aaaaaaaa-0000-4000-8000-${String(this.#n).padStart(12, '0')}`;
    const segment: NetworkSegmentResponse = {
      id,
      tenant_id: TENANT_ID,
      path: '/network/zones/hq/staff',
      name: 'staff',
      site_key: 'hq',
      kind: 'access',
      vlan_id: 20,
      filter_ids: ['acl-a', 'acl-b'],
      rank: 1,
      enabled: true,
      version: 4,
      created_by: EXAMPLE_ID,
      updated_by: EXAMPLE_ID,
      created_at: NOW,
      updated_at: NOW,
      ...extra,
    };
    this.segments.set(id, segment);
    return segment;
  }

  seedProfile(segmentId: string, extra: Partial<StoredProfile> = {}): void {
    this.profiles.set(segmentId, {
      segment_id: segmentId,
      stored_timeout: 3600,
      termination_action: 'radius_request',
      idle_timeout_secs: null,
      filter_id: null,
      service_type: 'framed_user',
      version: 2,
      ...extra,
    });
  }

  effective(p: StoredProfile): NetworkReplyProfile {
    const secs = Math.min(p.stored_timeout, this.cap);
    return {
      segment_id: p.segment_id,
      tenant_id: TENANT_ID,
      dictionary: 'axiam-radius-reply/1',
      session_timeout_secs: secs,
      session_timeout_clamped: secs < p.stored_timeout,
      termination_action: p.termination_action,
      idle_timeout_secs: p.idle_timeout_secs,
      filter_id: p.filter_id,
      service_type: p.service_type,
      version: p.version,
      created_by: EXAMPLE_ID,
      updated_by: EXAMPLE_ID,
      created_at: NOW,
      updated_at: NOW,
    } as NetworkReplyProfile;
  }

  methods(): string[] {
    return this.log.map((l) => l.method);
  }

  writes(): Logged[] {
    return this.log.filter((l) => l.method !== 'GET');
  }

  install(): void {
    const server = mockServer();
    const conflict = (reason: string, error = 'conflict') =>
      HttpResponse.json({ error, message: reason, reason_code: reason }, { status: 409 });

    server.use(
      http.all(`${BASE_URL}/api/v1/network/*`, async ({ request }) => {
        const url = new URL(request.url);
        const text = await request.text();
        const entry: Logged = {
          method: request.method,
          path: url.pathname.replace('/api/v1/network', ''),
          query: url.search.replace(/^\?/, ''),
          body: text ? (JSON.parse(text) as Record<string, unknown>) : undefined,
        };
        this.log.push(entry);
        if (this.refuse && this.refuse.match(entry)) {
          const { status, body } = this.refuse;
          return HttpResponse.json(body, { status });
        }
        return this.#route(entry, conflict);
      }),
    );
  }

  #route(
    e: Logged,
    conflict: (reason: string, error?: string) => Response,
  ): Response {
    const page = <T>(all: T[]) => {
      const q = new URLSearchParams(e.query);
      const offset = Number(q.get('offset') ?? '0');
      const limit = Number(q.get('limit') ?? '50');
      return HttpResponse.json({ items: all.slice(offset, offset + limit), total: all.length, offset, limit });
    };

    if (e.path === '/policy') {
      if (e.method === 'GET') {
        return HttpResponse.json({ tenant_id: TENANT_ID, session_timeout_max_secs: this.cap, version: this.policyVersion });
      }
      if (e.body!.version !== this.policyVersion) return conflict('stale_version');
      this.cap = e.body!.session_timeout_max_secs as number;
      this.policyVersion += 1;
      return HttpResponse.json({ tenant_id: TENANT_ID, session_timeout_max_secs: this.cap, version: this.policyVersion });
    }

    if (e.path === '/segments' && e.method === 'GET') return page([...this.segments.values()]);
    if (e.path === '/segments' && e.method === 'POST') {
      const b = e.body!;
      for (const s of this.segments.values()) {
        if (s.site_key === b.site_key && s.vlan_id === b.vlan_id) return conflict('duplicate_vlan', 'already_exists');
      }
      const created = this.seedSegment({
        site_key: b.site_key as string,
        kind: b.kind as string,
        name: b.name as string,
        vlan_id: b.vlan_id as number,
        filter_ids: (b.filter_ids as string[] | undefined) ?? [],
        rank: (b.rank as number | undefined) ?? null,
        enabled: (b.enabled as boolean | undefined) ?? true,
        version: this.segmentCreateVersion,
      });
      return HttpResponse.json(created, { status: 201 });
    }
    const segmentId = /^\/segments\/(.+)$/.exec(e.path)?.[1];
    if (segmentId) {
      const segment = this.segments.get(segmentId);
      if (!segment) return HttpResponse.json({ error: 'not_found', message: 'no' }, { status: 404 });
      if (e.method === 'GET') return HttpResponse.json(segment);
      if (e.method === 'PUT') {
        if (e.body!.version !== segment.version) return conflict('stale_version');
        const next = {
          ...segment,
          vlan_id: e.body!.vlan_id as number,
          filter_ids: e.body!.filter_ids as string[],
          enabled: e.body!.enabled as boolean,
          rank: (e.body!.rank as number | undefined) ?? null,
          version: segment.version + 1,
        };
        this.segments.set(segmentId, next);
        return HttpResponse.json(next);
      }
      if (e.method === 'DELETE') {
        this.segments.delete(segmentId);
        this.profiles.delete(segmentId);
        return new HttpResponse(null, { status: 204 });
      }
    }

    if (e.path === '/profiles' && e.method === 'GET') {
      return page([...this.profiles.values()].map((p) => this.effective(p)));
    }
    if (e.path === '/profiles' && e.method === 'POST') {
      const b = e.body!;
      const segment = this.segments.get(b.segment_id as string);
      if (!segment) return HttpResponse.json({ error: 'not_found', message: 'no' }, { status: 404 });
      if (b.segment_version !== segment.version) return conflict('stale_version');
      if (this.profiles.has(segment.id)) return conflict('profile_exists', 'already_exists');
      const p = b.profile as Record<string, unknown>;
      if ((p.session_timeout_secs as number) > this.cap) return this.#aboveCap();
      this.seedProfile(segment.id, {
        stored_timeout: p.session_timeout_secs as number,
        termination_action: (p.termination_action as string | undefined) ?? 'radius_request',
        idle_timeout_secs: (p.idle_timeout_secs as number | undefined) ?? null,
        filter_id: (p.filter_id as string | undefined) ?? null,
        service_type: (p.service_type as string | undefined) ?? null,
        version: 1,
      });
      return HttpResponse.json(this.effective(this.profiles.get(segment.id)!), { status: 201 });
    }
    const profileId = /^\/profiles\/(.+)$/.exec(e.path)?.[1];
    if (profileId) {
      const stored = this.profiles.get(profileId);
      const segment = this.segments.get(profileId);
      if (!stored || !segment) return HttpResponse.json({ error: 'not_found', message: 'no' }, { status: 404 });
      if (e.method === 'GET') return HttpResponse.json(this.effective(stored));
      if (e.method === 'PUT') {
        const b = e.body!;
        if (b.version !== stored.version || b.segment_version !== segment.version) return conflict('stale_version');
        const p = b.profile as Record<string, unknown>;
        if ((p.session_timeout_secs as number) > this.cap) return this.#aboveCap();
        this.seedProfile(profileId, {
          stored_timeout: p.session_timeout_secs as number,
          termination_action: (p.termination_action as string | undefined) ?? 'radius_request',
          idle_timeout_secs: (p.idle_timeout_secs as number | undefined) ?? null,
          filter_id: (p.filter_id as string | undefined) ?? null,
          service_type: (p.service_type as string | undefined) ?? null,
          version: stored.version + 1,
        });
        return HttpResponse.json(this.effective(this.profiles.get(profileId)!));
      }
      if (e.method === 'DELETE') {
        this.profiles.delete(profileId);
        return new HttpResponse(null, { status: 204 });
      }
    }
    return HttpResponse.json({ error: 'not_found', message: `unrouted ${e.method} ${e.path}` }, { status: 404 });
  }

  #aboveCap(): Response {
    return HttpResponse.json(
      {
        error: 'authorization_denied',
        message: `session_timeout_secs is above the tenant's cap of ${this.cap}`,
      },
      { status: 403 },
    );
  }
}

const staff = {
  key: 'staff',
  site: 'hq',
  kind: 'access' as const,
  name: 'staff',
  vlanId: 20,
  rank: 1,
  filterIds: ['acl-a', 'acl-b'],
};

const full = (): ManagementManifest => ({
  network: {
    policy: { sessionTimeoutMaxSecs: 7200 },
    segments: [staff],
    profiles: [{ segment: 'staff', sessionTimeoutSecs: 3600, filterId: 'acl-a', serviceType: 'framed_user' }],
  },
});

function setup(): { net: FakeNetwork; manifest: ReturnType<typeof retryingManagementClient>['manifest'] } {
  const net = new FakeNetwork();
  net.install();
  return { net, manifest: retryingManagementClient().manifest };
}

describe('§27.6.2 — plan', () => {
  it('issues GETs only: get_policy, list_segments and list_profiles, and nothing for the tenant shape', async () => {
    const { net, manifest } = setup();
    const seg = net.seedSegment();
    net.seedProfile(seg.id);

    await manifest.plan(full());

    expect(net.methods().every((m) => m === 'GET')).toBe(true);
    expect(net.log.map((l) => l.path).sort()).toEqual(['/policy', '/profiles', '/segments']);
  });

  it('a manifest without a network section reads and writes nothing of network', async () => {
    const { net, manifest } = setup();
    mockServer().use(
      http.get(`${BASE_URL}/api/v1/*`, () => HttpResponse.json({ items: [], total: 0, offset: 0, limit: 200 })),
    );
    const plan = await manifest.plan({ resources: [] });
    expect(plan.actions).toEqual([]);
    expect(net.log).toEqual([]);
  });

  it('orders the policy, then the segments, then the profiles (a profile after its segment)', async () => {
    const { manifest } = setup();
    const plan = await manifest.plan({
      network: {
        // Stated profile-first and segment-reversed on purpose.
        profiles: [
          { segment: 'b', sessionTimeoutSecs: 600 },
          { segment: 'a', sessionTimeoutSecs: 600 },
        ],
        segments: [
          { key: 'a', site: 'hq', kind: 'access', name: 'a', vlanId: 10, rank: 1 },
          { key: 'b', site: 'hq', kind: 'access', name: 'b', vlanId: 11, rank: 2 },
        ],
        policy: { sessionTimeoutMaxSecs: 3600 },
      },
    });
    expect(plan.actions.map((a) => `${a.target}:${a.key}`)).toEqual([
      'network-policy:network.policy',
      'network-segment:a',
      'network-segment:b',
      'network-profile:a',
      'network-profile:b',
    ]);
  });

  it('the policy is never Create: NoChange when equal, Update when not', async () => {
    const { net, manifest } = setup();
    net.cap = 3600;
    const same = await manifest.plan({ network: { policy: { sessionTimeoutMaxSecs: 3600 } } });
    expect(same.actions.map((a) => a.change)).toEqual(['no-change']);
    const differs = await manifest.plan({ network: { policy: { sessionTimeoutMaxSecs: 600 } } });
    expect(differs.actions.map((a) => a.change)).toEqual(['update']);
  });

  it('a segment whose stated filter_ids are the read\'s names in another order is NoChange (a set), and apply writes nothing', async () => {
    const { net, manifest } = setup();
    net.seedSegment({ filter_ids: ['acl-a', 'acl-b'] });
    const reordered: ManagementManifest = {
      network: { segments: [{ ...staff, filterIds: ['acl-b', 'acl-a'] }] },
    };
    expect(isConverged(await manifest.plan(reordered))).toBe(true);
    await manifest.apply(reordered);
    expect(net.writes()).toEqual([]);
  });

  it('a segment whose kind is stated as access is NoChange against a read of "access", and there is no zones value', async () => {
    const { net, manifest } = setup();
    net.seedSegment();
    const plan = await manifest.plan({ network: { segments: [staff] } });
    expect(plan.actions[0]!.change).toBe('no-change');

    // On an empty tenant the create body carries the wire spelling.
    const empty = setup();
    await empty.manifest.apply({ network: { segments: [staff] } });
    const created = empty.net.writes()[0]!;
    expect(created.method).toBe('POST');
    expect(created.body!.kind).toBe('access');
    expect(JSON.stringify(empty.net.log)).not.toContain('zones');
  });
});

describe('§27.6.2 — apply', () => {
  it('on an empty tenant: create_segment, then create_profile with the new id and the create response\'s version; plan is then all NoChange', async () => {
    const { net, manifest } = setup();
    net.segmentCreateVersion = 9; // not 1, not anything plan could have read

    const report = await manifest.apply(full());

    expect(isComplete(report)).toBe(true);
    const writes = net.writes().map((w) => `${w.method} ${w.path.replace(/\/[0-9a-f-]{36}$/, '/{id}')}`);
    expect(writes).toEqual(['PUT /policy', 'POST /segments', 'POST /profiles']);
    const [, , profileWrite] = net.writes();
    const segmentId = [...net.segments.keys()][0]!;
    expect(profileWrite!.body).toEqual({
      segment_id: segmentId,
      segment_version: 9,
      profile: { session_timeout_secs: 3600, filter_id: 'acl-a', service_type: 'framed_user' },
    });
    // The create sent the stated members, in the stated filter order.
    expect(net.writes()[1]!.body).toEqual({
      kind: 'access',
      site_key: 'hq',
      name: 'staff',
      vlan_id: 20,
      rank: 1,
      filter_ids: ['acl-a', 'acl-b'],
    });

    const again = await manifest.plan(full());
    expect(isConverged(again)).toBe(true);
    expect(changes(again)).toEqual([]);
  });

  it('a segment Update sends the FULL replacement: version as read, stated and carried members, no kind, site_key or name', async () => {
    const { net, manifest } = setup();
    const seg = net.seedSegment({ version: 6, rank: 3, enabled: true, filter_ids: ['acl-a'] });

    await manifest.apply({ network: { segments: [{ ...staff, vlanId: 30, rank: undefined, filterIds: undefined, enabled: undefined }] } });

    const [put] = net.writes();
    expect(put!.method).toBe('PUT');
    expect(put!.path).toBe(`/segments/${seg.id}`);
    // Every unstated member carried from the read; the VLAN is the stated one.
    expect(put!.body).toEqual({ version: 6, vlan_id: 30, filter_ids: ['acl-a'], enabled: true, rank: 3 });
    expect(Object.keys(put!.body!).sort()).toEqual(['enabled', 'filter_ids', 'rank', 'version', 'vlan_id']);
  });

  it('an Update caused by another member sends filter_ids in the order the manifest states', async () => {
    const { net, manifest } = setup();
    net.seedSegment({ filter_ids: ['acl-a', 'acl-b'] });
    await manifest.apply({ network: { segments: [{ ...staff, vlanId: 31, filterIds: ['acl-b', 'acl-a'] }] } });
    expect(net.writes()[0]!.body!.filter_ids).toEqual(['acl-b', 'acl-a']);
  });

  it('a stated null leaves the key out: it is how a replacement clears an optional member', async () => {
    const { net, manifest } = setup();
    const seg = net.seedSegment({ rank: 2 });
    net.seedProfile(seg.id, { idle_timeout_secs: 900, filter_id: 'acl-a' });

    await manifest.apply({
      network: {
        segments: [{ ...staff, rank: null, filterIds: undefined }],
        profiles: [{ segment: 'staff', sessionTimeoutSecs: 3600, idleTimeoutSecs: null }],
      },
    });

    const [segmentPut, profilePut] = net.writes();
    expect('rank' in segmentPut!.body!).toBe(false);
    const profile = (profilePut!.body as { profile: Record<string, unknown> }).profile;
    expect('idle_timeout_secs' in profile).toBe(false);
    // An unstated member is carried from the read.
    expect(profile.filter_id).toBe('acl-a');
    expect(profile.service_type).toBe('framed_user');
    expect(profile.dictionary).toBe('axiam-radius-reply/1');
  });

  it('a segment and its profile changed in one apply: replace_segment then replace_profile, with the replace\'s version as segment_version', async () => {
    const { net, manifest } = setup();
    const seg = net.seedSegment({ version: 4 });
    net.seedProfile(seg.id, { version: 2 });

    await manifest.apply({
      network: {
        segments: [{ ...staff, vlanId: 44 }],
        profiles: [{ segment: 'staff', sessionTimeoutSecs: 1800 }],
      },
    });

    const [segmentPut, profilePut] = net.writes();
    expect(segmentPut!.path).toBe(`/segments/${seg.id}`);
    expect(segmentPut!.body!.version).toBe(4);
    expect(profilePut!.path).toBe(`/profiles/${seg.id}`);
    // Not the 4 plan read: the segment write moved it to 5.
    expect(profilePut!.body!.segment_version).toBe(5);
    expect(profilePut!.body!.version).toBe(2);
  });
});

describe('§27.6.2 item 5 — a 409 is that action\'s failure', () => {
  it('stale_version on a network write: exactly one request, apply stops, the outcome exposes reason_code', async () => {
    const { net, manifest } = setup();
    const seg = net.seedSegment({ version: 4 });
    net.seedProfile(seg.id);
    net.refuse = {
      match: (l) => l.method === 'PUT' && l.path.startsWith('/segments/'),
      status: 409,
      body: { error: 'conflict', message: 'stale', reason_code: 'stale_version' },
    };

    const report = await manifest.apply({
      network: {
        segments: [{ ...staff, vlanId: 44 }],
        profiles: [{ segment: 'staff', sessionTimeoutSecs: 1800 }],
      },
    });

    expect(net.writes()).toHaveLength(1);
    expect(report.steps.map((s) => s.outcome.status)).toEqual(['failed', 'not-attempted']);
    const failed = failure(report)!;
    expect(failed.reasonCode).toBe('stale_version');
    expect(failed.action.target).toBe('network-segment');
    expect(isComplete(report)).toBe(false);
    const outcome = report.steps[0]!.outcome;
    expect(outcome.status === 'failed' && outcome.reasonCode).toBe('stale_version');
  });

  it('already_exists / duplicate_vlan does the same, and a create is never retried', async () => {
    const { net, manifest } = setup();
    net.seedSegment({ name: 'other', vlan_id: 20, site_key: 'hq' });

    const report = await manifest.apply({
      network: {
        segments: [{ ...staff, name: 'fresh', key: 'fresh', vlanId: 20 }],
        profiles: [{ segment: 'fresh', sessionTimeoutSecs: 600 }],
      },
    });

    expect(net.writes()).toHaveLength(1);
    expect(report.steps.map((s) => s.outcome.status)).toEqual(['failed', 'not-attempted']);
    expect(failure(report)!.reasonCode).toBe('duplicate_vlan');
  });

  it('a 409 that names no reason_code is a failure with no reasonCode, not an invented one', async () => {
    const { net, manifest } = setup();
    net.seedSegment({ version: 4 });
    net.refuse = {
      match: (l) => l.method === 'PUT',
      status: 409,
      body: { error: 'conflict', message: 'old server' },
    };
    const report = await manifest.apply({ network: { segments: [{ ...staff, vlanId: 44 }] } });
    const failed = failure(report)!;
    expect(failed.reasonCode).toBeUndefined();
    expect(failed.message).toContain('conflict');
  });
});

describe('§27.6.2 item 3 — judged on the read', () => {
  it('a clamped profile: stating the cap is NoChange; stating more is an Update whose apply meets 403, stops, and is not retried', async () => {
    const { net, manifest } = setup();
    const seg = net.seedSegment();
    // Stored 7200, cap lowered to 3600: the read is {3600, clamped}.
    net.seedProfile(seg.id, { stored_timeout: 7200 });
    net.cap = 3600;

    const atCap: ManagementManifest = {
      network: { segments: [staff], profiles: [{ segment: 'staff', sessionTimeoutSecs: 3600, serviceType: 'framed_user' }] },
    };
    expect(isConverged(await manifest.plan(atCap))).toBe(true);
    await manifest.apply(atCap);
    expect(net.writes()).toEqual([]);

    const above: ManagementManifest = {
      network: {
        segments: [staff, { ...staff, key: 'guest', name: 'guest', vlanId: 21, rank: 2 }],
        profiles: [
          { segment: 'staff', sessionTimeoutSecs: 5000 },
          { segment: 'guest', sessionTimeoutSecs: 600 },
        ],
      },
    };
    const plan = await manifest.plan(above);
    expect(plan.actions.find((a) => a.target === 'network-profile' && a.key === 'staff')!.change).toBe('update');
    expect(net.writes()).toEqual([]);

    const report = await manifest.apply(above);
    // The guest segment was created first (a write), then exactly one profile PUT was refused.
    const profilePuts = net.writes().filter((w) => w.method === 'PUT' && w.path.startsWith('/profiles/'));
    expect(profilePuts).toHaveLength(1);
    const failed = failure(report)!;
    expect(failed.action.target).toBe('network-profile');
    expect(failed.message).toContain("session_timeout_secs is above the tenant's cap of 3600");
    expect(failed.reasonCode).toBeUndefined();
    // The guest profile, later in the plan, was not attempted.
    expect(report.steps.at(-1)!.outcome.status).toBe('not-attempted');
    expect(net.writes().some((w) => w.method === 'POST' && w.path === '/profiles')).toBe(false);
  });

  it('an Update of a clamped profile that does not state its timeout stores the clamped value (§36.3 rule 6)', async () => {
    const { net, manifest } = setup();
    const seg = net.seedSegment();
    net.seedProfile(seg.id, { stored_timeout: 7200, filter_id: null });
    net.cap = 3600;
    // `serviceType` drifts, so an Update is sent; the timeout is stated as the read's own value.
    await manifest.apply({
      network: { segments: [staff], profiles: [{ segment: 'staff', sessionTimeoutSecs: 3600, filterId: 'acl-a' }] },
    });
    const put = net.writes()[0]!;
    expect((put.body!.profile as { session_timeout_secs: number }).session_timeout_secs).toBe(3600);
  });
});

describe('§27.6.2 item 1 — refused before any request', () => {
  const refusals: Array<[string, ManagementManifest, RegExp]> = [
    [
      'two segments with one site, kind and name',
      { network: { segments: [staff, { ...staff, key: 'again' }] } },
      /declared more than once/,
    ],
    [
      'a profile whose segment names no segment spec',
      { network: { segments: [staff], profiles: [{ segment: 'ghost', sessionTimeoutSecs: 600 }] } },
      /no network segment declares/,
    ],
    [
      'two profiles for one segment',
      {
        network: {
          segments: [staff],
          profiles: [
            { segment: 'staff', sessionTimeoutSecs: 600 },
            { segment: 'staff', sessionTimeoutSecs: 900 },
          ],
        },
      },
      /more than one profile/,
    ],
    [
      'a segment that lists one Filter-Id twice',
      { network: { segments: [{ ...staff, filterIds: ['acl-a', 'acl-b', 'acl-a'] }] } },
      /more than once in filterIds/,
    ],
  ];

  for (const [name, manifest, pattern] of refusals) {
    it(`${name}: refused at plan and at apply with zero wire calls`, async () => {
      const { net, manifest: api } = setup();
      const planned = await api.plan(manifest).catch((e: unknown) => e);
      const applied = await api.apply(manifest).catch((e: unknown) => e);
      for (const err of [planned, applied]) {
        expect(err).toBeInstanceOf(NetworkError);
        expect((err as Error).message).toMatch(pattern);
      }
      expect(net.log).toEqual([]);
    });
  }
});

describe('§27.6.2 item 4 — an unknown open-enum value on an unstated member (C162-07)', () => {
  for (const [member, stored] of [
    ['termination_action', { termination_action: 'future' }],
    ['service_type', { service_type: 'future' }],
  ] as const) {
    it(`${member} read as "future" and not stated: plan refuses naming member and value, no non-GET request; stating it resolves`, async () => {
      const { net, manifest } = setup();
      const seg = net.seedSegment();
      net.seedProfile(seg.id, stored as Partial<Parameters<typeof net.seedProfile>[1]>);
      const other: ManagementManifest = {
        network: { segments: [staff], profiles: [{ segment: 'staff', sessionTimeoutSecs: 1800 }] },
      };

      const err = await manifest.plan(other).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(ValidationError);
      expect((err as Error).message).toContain(member);
      expect((err as Error).message).toContain('"future"');
      expect(net.writes()).toEqual([]);

      const stated = member === 'termination_action'
        ? { terminationAction: 'radius_request' as const }
        : { serviceType: 'framed_user' as const };
      const plan = await manifest.plan({
        network: { segments: [staff], profiles: [{ segment: 'staff', sessionTimeoutSecs: 1800, ...stated }] },
      });
      expect(plan.actions.find((a) => a.target === 'network-profile')!.change).toBe('update');
      await manifest.apply({
        network: { segments: [staff], profiles: [{ segment: 'staff', sessionTimeoutSecs: 1800, ...stated }] },
      });
      const put = net.writes().find((w) => w.method === 'PUT' && w.path.startsWith('/profiles/'))!;
      expect(JSON.stringify(put.body)).not.toContain('future');
    });
  }

  it('the same read with nothing that differs is NoChange, with no write', async () => {
    const { net, manifest } = setup();
    const seg = net.seedSegment();
    net.seedProfile(seg.id, { termination_action: 'future' } as never);
    const plan = await manifest.plan({
      network: { segments: [staff], profiles: [{ segment: 'staff', sessionTimeoutSecs: 3600 }] },
    });
    expect(plan.actions.find((a) => a.target === 'network-profile')!.change).toBe('no-change');
    expect(net.writes()).toEqual([]);
  });
});

describe('§27.6.2 item 4 — a stated terminationAction null (C162-08)', () => {
  it('is refused at plan and at apply with zero wire calls', async () => {
    const { net, manifest } = setup();
    const m: ManagementManifest = {
      network: { segments: [staff], profiles: [{ segment: 'staff', sessionTimeoutSecs: 600, terminationAction: null }] },
    };
    for (const run of [() => manifest.plan(m), () => manifest.apply(m)]) {
      const err = await run().catch((e: unknown) => e);
      expect(err).toBeInstanceOf(NetworkError);
      expect((err as Error).message).toMatch(/terminationAction as null/);
    }
    expect(net.log).toEqual([]);
  });
});

describe('§27.6.2 item 6 — pruning', () => {
  it('this SDK offers no pruning: a segment the manifest omits is left alone, the policy is never deleted, no Delete is planned', async () => {
    const { net, manifest } = setup();
    const kept = net.seedSegment({ name: 'kept', vlan_id: 99 });
    net.seedProfile(kept.id);
    const plan = await manifest.plan({ network: { policy: { sessionTimeoutMaxSecs: 3600 }, segments: [] } });
    await manifest.apply({ network: { policy: { sessionTimeoutMaxSecs: 3600 } } });
    expect(plan.actions.map((a) => `${a.target}:${a.change}`)).toEqual(['network-policy:no-change']);
    expect(net.methods().filter((m) => m === 'DELETE')).toEqual([]);
    expect(net.segments.has(kept.id)).toBe(true);
  });
});
