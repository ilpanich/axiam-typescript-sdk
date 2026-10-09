// The `scim_targets` management namespace — CONTRACT.md §31.8's six required
// tests, the read-modify-write helper, and the open-union refusal paths the
// contract 1.58 re-sync added (`assertKnownScimTargetAuth` /
// `assertKnownScimTargetScope`). The credential is generated at run time.

import { http, HttpResponse } from 'msw';
import { afterEach, describe, expect, it } from 'vitest';

import { AuthError, NetworkError } from '../../src/core/errors.js';
import { Sensitive } from '../../src/core/sensitive.js';
import { scimTargetInputFrom } from '../../src/management/checks.js';
import { ConflictError, NotFoundError, ValidationError } from '../../src/management/errors.js';
import {
  KNOWN_SCIM_TARGET_AUTH_TYPES,
  KNOWN_SCIM_TARGET_SCOPE_TYPES,
  assertKnownScimTargetAuth,
  assertKnownScimTargetScope,
  scimTargetInputToWire,
  type ScimTargetAuth,
  type ScimTargetInput,
  type ScimTargetResponse,
  type ScimTargetScope,
} from '../../src/management/models.js';
import {
  BASE_URL,
  TENANT_ID,
  capture,
  managementClient,
  mockServer,
  retryingManagementClient,
} from '../managementSupport.js';
import { assertNoFragment, errorRenderings, freshId, freshSecret, renderings } from '../redaction.js';

const TARGETS = '/api/v1/scim-targets';

afterEach(() => mockServer().resetHandlers());

function targetBody(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: freshId(),
    tenant_id: TENANT_ID,
    name: 'Downstream',
    base_url: 'https://idp.example/scim/v2',
    enabled: true,
    auth: { type: 'bearer' },
    scope: { type: 'all_users' },
    push_groups: false,
    user_name_from: 'username',
    deprovision: 'deactivate',
    created_at: '2026-10-05T00:00:00Z',
    updated_at: '2026-10-05T00:00:00Z',
    state: {
      last_success_at: null,
      last_failure_at: null,
      last_failure_reason: null,
      consecutive_failures: 0,
      dead_lettered_total: 0,
      last_reconciled_at: null,
    },
    ...extra,
  };
}

function input(credential?: string): ScimTargetInput {
  return {
    auth: { type: 'bearer' },
    base_url: 'https://idp.example/scim/v2',
    ...(credential !== undefined ? { credential: new Sensitive(credential) } : {}),
    name: 'Downstream',
    scope: { type: 'all_users' },
  };
}

// ── 1. Redaction ────────────────────────────────────────────────────────────

describe('§31.8 (1) — the credential is on the wire and in no rendering', () => {
  it('redacts the input and the error raised by create, and sends the credential', async () => {
    const server = mockServer();
    const credential = freshSecret();
    const body = input(credential);
    assertNoFragment(renderings(body), credential, 'ScimTargetInput');

    const seen = capture(server, 'POST', TARGETS, 400, { error: 'validation_error', message: 'base_url: refused' });
    const err = await managementClient().scimTargets.create(body).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ValidationError);
    assertNoFragment(errorRenderings(err), credential, 'error');
    expect((seen[0]?.json as Record<string, unknown>).credential === credential, 'not sent').toBe(true);
  });
});

// ── 2. No credential on the response ────────────────────────────────────────

describe('§31.8 (2) — a credential in a response is dropped', () => {
  it('decodes a ScimTargetResponse whose every rendering lacks the value', async () => {
    const server = mockServer();
    const leaked = freshSecret();
    const id = freshId();
    capture(server, 'GET', `${TARGETS}/${id}`, 200, targetBody({ credential: leaked, credential_set: true }));
    const target: ScimTargetResponse = await managementClient().scimTargets.get(id);
    assertNoFragment(renderings(target), leaked, 'ScimTargetResponse');
    expect('credential' in target).toBe(false);
    expect(target.name).toBe('Downstream');
    // @ts-expect-error — ScimTargetResponse declares no credential member.
    void target.credential;
  });
});

// ── 3. Replacement and the omitted credential ───────────────────────────────

describe('§31.8 (3) — update without a credential sends no key; variants keep their shape', () => {
  it('no credential key, then the credential; the four variants serialize with exact keys', async () => {
    const server = mockServer();
    const id = freshId();
    const seen = capture(server, 'PUT', `${TARGETS}/${id}`, 200, targetBody());
    const client = managementClient();
    const credential = freshSecret();

    await client.scimTargets.update(id, input());
    await client.scimTargets.update(id, input(credential));
    expect('credential' in (seen[0]?.json as Record<string, unknown>)).toBe(false);
    expect((seen[1]?.json as Record<string, unknown>).credential === credential, 'not sent').toBe(true);

    // @ts-expect-error — name, base_url, auth and scope are required.
    const incomplete: ScimTargetInput = { name: 'x' };
    void incomplete;

    const shapes: Array<[ScimTargetAuth | ScimTargetScope, unknown]> = [
      [{ type: 'bearer' }, { type: 'bearer' }],
      [
        { type: 'oauth2_client_credentials', client_id: 'axiam', scope: 'scim', token_url: 'https://idp.example/token' },
        { type: 'oauth2_client_credentials', client_id: 'axiam', scope: 'scim', token_url: 'https://idp.example/token' },
      ],
      [{ type: 'all_users' }, { type: 'all_users' }],
      [
        { type: 'groups', group_ids: [TENANT_ID] },
        { type: 'groups', group_ids: [TENANT_ID] },
      ],
    ];
    for (const [value, wire] of shapes) {
      expect(JSON.parse(JSON.stringify(value))).toEqual(wire);
    }
  });
});

// ── 4. Open decoding and pagination ─────────────────────────────────────────

describe('§31.8 (4) — unknown values decode and the pager carries search', () => {
  it('unknown auth.type / deprovision / user_name_from, state null, unseen failure reason', async () => {
    const server = mockServer();
    const odd = targetBody({
      auth: { type: 'mtls', certificate_id: freshId() },
      deprovision: 'archive',
      user_name_from: 'employee_number',
      state: null,
    });
    const failing = targetBody({
      state: {
        last_success_at: null,
        last_failure_at: '2026-10-05T01:00:00Z',
        last_failure_reason: 'a reason this SDK has never seen',
        consecutive_failures: 3,
        dead_lettered_total: 1,
        last_reconciled_at: null,
      },
    });
    const queries: string[] = [];
    server.use(
      http.get(`${BASE_URL}${TARGETS}`, ({ request }) => {
        const url = new URL(request.url);
        queries.push(url.search);
        const offset = Number(url.searchParams.get('offset') ?? '0');
        const items = offset === 0 ? [odd] : offset === 1 ? [failing] : [];
        return HttpResponse.json({ items, total: 2, offset, limit: 1 });
      }),
    );
    const client = managementClient();
    const page = await client.scimTargets.list({ limit: 1, search: 'downstream' });
    expect(page.total).toBe(2);
    expect(page.items[0]?.auth.type).toBe('mtls');
    expect(page.items[0]?.deprovision).toBe('archive');
    expect(page.items[0]?.user_name_from).toBe('employee_number');
    expect(page.items[0]?.state).toBeNull();
    const all = await client.scimTargets.listAll({ limit: 1, search: 'downstream' });
    expect(all[1]?.state?.last_failure_reason).toBe('a reason this SDK has never seen');
    for (const q of queries) expect(q).toContain('search=downstream');

    // An unknown variant decodes but is never sent (§31.2): writing it back
    // is refused before any request.
    const writes = capture(server, 'PUT', `${TARGETS}/${page.items[0]!.id}`, 200, targetBody());
    const back = scimTargetInputFrom(page.items[0]!);
    await expect(client.scimTargets.update(page.items[0]!.id, back)).rejects.toBeInstanceOf(NetworkError);
    expect(writes).toHaveLength(0);
  });
});

// ── 5. No retry ─────────────────────────────────────────────────────────────

describe('§31.8 (5) — no write is retried on 503', () => {
  it('create, update, delete and reconcile: one request each, NetworkError', async () => {
    const server = mockServer();
    const id = freshId();
    const hits = [
      capture(server, 'POST', TARGETS, 503),
      capture(server, 'PUT', `${TARGETS}/${id}`, 503),
      capture(server, 'DELETE', `${TARGETS}/${id}`, 503),
      capture(server, 'POST', `${TARGETS}/${id}/reconcile`, 503),
    ];
    const t = retryingManagementClient().scimTargets;
    const errors = [
      await t.create(input(freshSecret())).catch((e: unknown) => e),
      await t.update(id, input()).catch((e: unknown) => e),
      await t.delete(id).catch((e: unknown) => e),
      await t.reconcile(id).catch((e: unknown) => e),
    ];
    for (const e of errors) expect(e).toBeInstanceOf(NetworkError);
    for (const h of hits) expect(h).toHaveLength(1);
  });
});

// ── 6. Errors and reconcile ─────────────────────────────────────────────────

describe('§31.8 (6) — statuses map, and reconcile is a bodyless 202', () => {
  it('400 / 409 / 409 / 404 / 401 and ScimReconcileAccepted', async () => {
    const server = mockServer();
    const id = freshId();
    const other = freshId();
    capture(server, 'POST', TARGETS, 400, { error: 'validation_error', message: 'credential: required on create' });
    capture(server, 'PUT', `${TARGETS}/${id}`, 409, {
      error: 'conflict',
      message: 'the SCIM target changed since it was read',
    });
    capture(server, 'POST', `${TARGETS}/${other}/reconcile`, 409, { error: 'conflict', message: 'a run holds the claim' });
    capture(server, 'GET', `${TARGETS}/${id}`, 404, { error: 'not_found', message: 'no' });
    capture(server, 'DELETE', `${TARGETS}/${id}`, 401, { error: 'unauthorized', message: 'human only' });
    capture(server, 'POST', '/api/v1/auth/refresh', 401, { error: 'unauthorized' });
    const reconcile = capture(server, 'POST', `${TARGETS}/${id}/reconcile`, 202, { target_id: id, status: 'started' });
    const t = managementClient().scimTargets;

    const invalid = await t.create(input()).catch((e: unknown) => e);
    expect(invalid).toBeInstanceOf(ValidationError);
    expect((invalid as ValidationError).message).toContain('credential');
    await expect(t.update(id, input())).rejects.toBeInstanceOf(ConflictError);
    await expect(t.reconcile(other)).rejects.toBeInstanceOf(ConflictError);
    await expect(t.get(id)).rejects.toBeInstanceOf(NotFoundError);
    await expect(t.delete(id)).rejects.toBeInstanceOf(AuthError);

    const accepted = await managementClient().scimTargets.reconcile(id);
    expect(accepted).toEqual({ target_id: id, status: 'started' });
    expect(reconcile[0]?.text).toBe('');
  });
});

describe('read-modify-write', () => {
  it('a read converts into the replacement body without a credential', () => {
    const target = targetBody() as unknown as ScimTargetResponse;
    const body = scimTargetInputFrom(target);
    expect('credential' in body).toBe(false);
    expect(body.base_url).toBe(target.base_url);
    expect(body.enabled).toBe(true);
    expect(JSON.stringify(scimTargetInputToWire(body)).includes('credential')).toBe(false);
  });
});

describe('§31.2 — the open-union guards', () => {
  it('accept every known tag, null and undefined', () => {
    for (const type of KNOWN_SCIM_TARGET_AUTH_TYPES) {
      expect(() => assertKnownScimTargetAuth({ type } as ScimTargetAuth)).not.toThrow();
    }
    for (const type of KNOWN_SCIM_TARGET_SCOPE_TYPES) {
      expect(() => assertKnownScimTargetScope({ type } as ScimTargetScope)).not.toThrow();
    }
    expect(() => assertKnownScimTargetAuth(null)).not.toThrow();
    expect(() => assertKnownScimTargetScope(undefined)).not.toThrow();
  });

  it('refuse an unknown or non-string tag locally, with NetworkError', () => {
    for (const bad of [{ type: 'mtls' }, { type: 7 }, {}]) {
      expect(() => assertKnownScimTargetAuth(bad as unknown as ScimTargetAuth)).toThrow(NetworkError);
      expect(() => assertKnownScimTargetScope(bad as unknown as ScimTargetScope)).toThrow(NetworkError);
    }
  });

  it('create refuses an unknown scope.type before any request', async () => {
    const server = mockServer();
    const writes = capture(server, 'POST', TARGETS, 201, targetBody());
    const body = { ...input(freshSecret()), scope: { type: 'department' } as unknown as ScimTargetScope };
    await expect(managementClient().scimTargets.create(body)).rejects.toBeInstanceOf(NetworkError);
    expect(writes).toHaveLength(0);
  });
});
