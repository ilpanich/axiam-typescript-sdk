// The `directory` management namespace — CONTRACT.md §30.8's six required
// tests, plus the read-modify-write helper. The bind secret is generated at
// run time: a literal would be a credential in the repository and would let a
// redaction test pass by coincidence.

import { http, HttpResponse } from 'msw';
import { afterEach, describe, expect, it } from 'vitest';

import { AuthError, NetworkError } from '../../src/core/errors.js';
import { Sensitive } from '../../src/core/sensitive.js';
import { ConflictError, NotFoundError, ValidationError } from '../../src/management/errors.js';
import { setDirectoryConfigFrom } from '../../src/management/checks.js';
import {
  setDirectoryConfigToWire,
  updateDirectoryConfigToWire,
  type DirectoryConfig,
  type SetDirectoryConfig,
  type UpdateDirectoryConfig,
} from '../../src/management/models.js';
import {
  BASE_URL,
  TENANT_ID,
  capture,
  managementClient,
  mockServer,
  retryingManagementClient,
} from '../managementSupport.js';
import {
  assertNoFragment,
  errorRenderings,
  exhaustiveErrorRenderings,
  freshId,
  freshSecret,
  renderings,
} from '../redaction.js';

const DIRECTORY = `/api/v1/tenants/${TENANT_ID}/directory`;

afterEach(() => mockServer().resetHandlers());

function configBody(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: freshId(),
    tenant_id: TENANT_ID,
    enabled: true,
    kind: 'active_directory',
    url: 'ldaps://dc.corp.example',
    start_tls: false,
    bind_dn: 'cn=svc,dc=corp',
    base_dn: 'dc=corp',
    user_filter: '(sAMAccountName={username})',
    user_attribute_map: {
      username: 'sAMAccountName',
      email: 'mail',
      display_name: 'displayName',
      external_id: 'objectGUID',
    },
    group_base_dn: null,
    group_filter: null,
    group_member_attribute: 'member',
    group_nesting_depth: 5,
    group_mappings: [],
    sync_interval_secs: 3600,
    jit_provisioning: false,
    trust_anchors_pem: [],
    created_at: '2026-10-04T00:00:00Z',
    updated_at: '2026-10-04T00:00:00Z',
    ...extra,
  };
}

function setBody(bindSecret?: string): SetDirectoryConfig {
  return {
    base_dn: 'dc=corp',
    bind_dn: 'cn=svc,dc=corp',
    ...(bindSecret !== undefined ? { bind_secret: new Sensitive(bindSecret) } : {}),
    enabled: true,
    kind: 'active_directory',
    start_tls: false,
    url: 'ldaps://dc.corp.example',
    user_filter: '(sAMAccountName={username})',
  };
}

// ── 1. Redaction ────────────────────────────────────────────────────────────

describe('§30.8 (1) — the bind secret reaches the wire and no rendering', () => {
  it('redacts it from both bodies and from an error raised by set, and sends it', async () => {
    const server = mockServer();
    const client = managementClient();
    const secret = freshSecret();

    const set = setBody(secret);
    const update: UpdateDirectoryConfig = { bind_secret: new Sensitive(secret) };
    assertNoFragment(renderings(set), secret, 'SetDirectoryConfig');
    assertNoFragment(renderings(update), secret, 'UpdateDirectoryConfig');

    const seen = capture(server, 'PUT', DIRECTORY, 400, {
      error: 'validation_error',
      message: 'url: plaintext LDAP is refused',
    });
    const err = await client.directory.set(set).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ValidationError);
    assertNoFragment(errorRenderings(err), secret, 'error');
    expect((seen[0]?.json as Record<string, unknown>).bind_secret === secret, 'the secret was not sent').toBe(true);
    // The wire conversion is the one place it is unwrapped.
    expect(setDirectoryConfigToWire(set).bind_secret === secret).toBe(true);
  });

  // R-18 (contract 1.59): the 400 above takes the ValidationError path, which
  // never held the request. A 5xx and a dropped connection reach NetworkError,
  // whose cause was the axios error with the serialized body in it.
  it('redacts it from the error raised by set and update on a 5xx and on a transport failure', async () => {
    const server = mockServer();
    const client = managementClient();
    const failures = [
      () => HttpResponse.json({ error: 'internal_error' }, { status: 500 }),
      () => new HttpResponse(null, { status: 503 }),
      () => HttpResponse.error(),
    ];
    for (const respond of failures) {
      const secret = freshSecret();
      server.use(
        http.put(`${BASE_URL}${DIRECTORY}`, respond),
        http.patch(`${BASE_URL}${DIRECTORY}`, respond),
      );
      for (const err of [
        await client.directory.set(setBody(secret)).catch((e: unknown) => e),
        await client.directory.update({ bind_secret: new Sensitive(secret) }).catch((e: unknown) => e),
      ]) {
        expect(err).toBeInstanceOf(NetworkError);
        assertNoFragment(exhaustiveErrorRenderings(err), secret, 'error');
      }
      server.resetHandlers();
    }
  });
});

// ── 2. No secret on the response ────────────────────────────────────────────

describe('§30.8 (2) — a bind_secret in a response is dropped', () => {
  it('decodes a DirectoryConfig whose every rendering lacks the value', async () => {
    const server = mockServer();
    const leaked = freshSecret();
    capture(server, 'GET', DIRECTORY, 200, configBody({ bind_secret: leaked }));

    const config: DirectoryConfig = await managementClient().directory.get();
    assertNoFragment(renderings(config), leaked, 'DirectoryConfig');
    expect('bind_secret' in config).toBe(false);
    expect(config.url).toBe('ldaps://dc.corp.example');
    // ... and the type declares no accessor: this would not compile.
    // @ts-expect-error — DirectoryConfig has no bind_secret member.
    void config.bind_secret;
  });
});

// ── 3. Sparse update ────────────────────────────────────────────────────────

describe('§30.8 (3) — update sends exactly the members it was given', () => {
  it('{enabled:false}; url + bind_secret; and an explicit null', async () => {
    const server = mockServer();
    const seen = capture(server, 'PATCH', DIRECTORY, 200, configBody());
    const client = managementClient();
    const secret = freshSecret();

    await client.directory.update({ enabled: false });
    await client.directory.update({ url: 'ldaps://dc2.corp.example', bind_secret: new Sensitive(secret) });
    await client.directory.update({ group_filter: null });

    expect(seen[0]?.text).toBe('{"enabled":false}');
    const second = seen[1]?.json as Record<string, unknown>;
    expect(Object.keys(second).sort()).toEqual(['bind_secret', 'url']);
    expect(second.bind_secret === secret, 'the secret was not sent').toBe(true);
    expect(seen[2]?.text).toBe('{"group_filter":null}');
    // `undefined` is absent, `null` is a clear.
    expect(JSON.stringify(updateDirectoryConfigToWire({ group_base_dn: undefined }))).toBe('{}');
  });
});

// ── 4. Replacement ──────────────────────────────────────────────────────────

describe('§30.8 (4) — set sends every required member', () => {
  it('decodes both 201 and 200, and absent bind_secret is not sent', async () => {
    const server = mockServer();
    const client = managementClient();
    for (const status of [201, 200]) {
      const seen = capture(server, 'PUT', DIRECTORY, status, configBody());
      const config = await client.directory.set(setBody());
      expect(config.enabled).toBe(true);
      const sent = seen.at(-1)?.json as Record<string, unknown>;
      for (const required of ['enabled', 'kind', 'url', 'start_tls', 'bind_dn', 'base_dn', 'user_filter']) {
        expect(required in sent, `${required} missing`).toBe(true);
      }
      expect('bind_secret' in sent, 'absent keeps the stored secret').toBe(false);
      server.resetHandlers();
    }
    // The replacement type cannot be built without its required members.
    // @ts-expect-error — `url` (and six more) are required.
    const incomplete: SetDirectoryConfig = { enabled: true };
    void incomplete;
  });
});

// ── 5. No retry ─────────────────────────────────────────────────────────────

describe('§30.8 (5) — no write is retried on 503', () => {
  it('set, update, delete and link_account: exactly one request each, NetworkError', async () => {
    const server = mockServer();
    const client = retryingManagementClient();
    const put = capture(server, 'PUT', DIRECTORY, 503);
    const patch = capture(server, 'PATCH', DIRECTORY, 503);
    const del = capture(server, 'DELETE', DIRECTORY, 503);
    const link = capture(server, 'POST', `${DIRECTORY}/links`, 503);

    const errors = [
      await client.directory.set(setBody(freshSecret())).catch((e: unknown) => e),
      await client.directory.update({}).catch((e: unknown) => e),
      await client.directory.delete().catch((e: unknown) => e),
      await client.directory.linkAccount({ user_id: freshId() }).catch((e: unknown) => e),
    ];
    for (const e of errors) expect(e).toBeInstanceOf(NetworkError);
    for (const hits of [put, patch, del, link]) expect(hits).toHaveLength(1);
  });

  it('the read MAY be retried (§30.7)', async () => {
    const server = mockServer();
    const hits = capture(server, 'GET', DIRECTORY, 503);
    const client = retryingManagementClient();
    await expect(client.directory.get()).rejects.toBeInstanceOf(NetworkError);
    expect(hits.length).toBeGreaterThan(1);
  });
});

// ── 6. Errors and link_account ──────────────────────────────────────────────

describe('§30.8 (6) — errors map per §2, and link_account sends only the user id', () => {
  it('400 / 409 / 404 / 401 and the five DirectoryLinkResult members', async () => {
    const server = mockServer();
    const client = managementClient();
    capture(server, 'PUT', DIRECTORY, 400, {
      error: 'validation_error',
      message: 'url: changing the connection requires entering the bind secret again',
    });
    capture(server, 'PATCH', DIRECTORY, 409, { error: 'conflict', message: 'opaque_mode' });
    capture(server, 'GET', DIRECTORY, 404, { error: 'not_found', message: 'none' });
    capture(server, 'DELETE', DIRECTORY, 401, { error: 'unauthorized', message: 'human only' });
    capture(server, 'POST', '/api/v1/auth/refresh', 401, { error: 'unauthorized' });

    const invalid = await client.directory.set(setBody()).catch((e: unknown) => e);
    expect(invalid).toBeInstanceOf(ValidationError);
    expect((invalid as ValidationError).message).toContain('bind secret again');
    await expect(client.directory.update({ enabled: true })).rejects.toBeInstanceOf(ConflictError);
    await expect(client.directory.get()).rejects.toBeInstanceOf(NotFoundError);
    await expect(client.directory.delete()).rejects.toBeInstanceOf(AuthError);

    const user = freshId();
    const seen = capture(server, 'POST', `${DIRECTORY}/links`, 200, {
      user_id: user,
      directory_external_id: '3f2a-objectguid',
      webauthn_credentials_deleted: 2,
      certificates_revoked: 1,
      was_already_linked: false,
    });
    const result = await managementClient().directory.linkAccount({ user_id: user });
    expect(seen[0]?.json).toEqual({ user_id: user });
    expect(result).toEqual({
      user_id: user,
      directory_external_id: '3f2a-objectguid',
      webauthn_credentials_deleted: 2,
      certificates_revoked: 1,
      was_already_linked: false,
    });
  });

  it('sync status decodes an unknown result and the first run nulls', async () => {
    const server = mockServer();
    capture(server, 'GET', `${DIRECTORY}/sync-status`, 200, {
      last_result: 'something_new',
      last_attempt_at: null,
      last_full_run_at: null,
      full_required: true,
      has_watermark: false,
    });
    const status = await managementClient().directory.getSyncStatus();
    expect(status.last_result).toBe('something_new');
    expect(status.full_required && !status.has_watermark).toBe(true);
  });
});

describe('read-modify-write', () => {
  it('a read converts into the replacement body without a secret', () => {
    const config = configBody() as unknown as DirectoryConfig;
    const body = setDirectoryConfigFrom(config);
    expect('bind_secret' in body).toBe(false);
    expect(body.url).toBe(config.url);
    expect(body.group_nesting_depth).toBe(5);
    expect(body.sync_interval_secs).toBe(3600);
    expect(body.group_filter).toBeNull();
  });
});
