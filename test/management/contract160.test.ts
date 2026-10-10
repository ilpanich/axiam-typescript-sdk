// Contract 1.60 §27.15's additive members and the `federation.update_config`
// null rule (§34.4: `window_minutes`, `allow_sha1_signatures`,
// `idp_metadata_signing_cert_pem`, note 8). Values are generated at run time.

import { afterEach, describe, expect, it } from 'vitest';

import { Sensitive } from '../../src/core/sensitive.js';
import type { UpdateFederationConfigRequest } from '../../src/management/models.js';
import { TENANT_ID, capture, managementClient, mockServer } from '../managementSupport.js';
import { freshId, freshSecret } from '../redaction.js';

const RULES = '/api/v1/notification-rules';
const CONFIGS = '/api/v1/federation-configs';

afterEach(() => mockServer().resetHandlers());

function ruleBody(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: freshId(),
    tenant_id: TENANT_ID,
    name: 'Lockouts',
    description: 'mail the on-call',
    events: ['user_locked'],
    recipient_emails: ['oncall@example.com'],
    enabled: true,
    window_minutes: 15,
    created_at: '2026-10-05T00:00:00Z',
    updated_at: '2026-10-05T00:00:00Z',
    ...extra,
  };
}

/** A `FederationConfigResponse` as a server before 1.0.0 sends it: no 1.60 members. */
function legacyConfigBody(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: freshId(),
    tenant_id: TENANT_ID,
    provider: 'okta',
    protocol: 'Saml',
    client_id: 'axiam',
    attribute_map: {},
    enabled: true,
    token_exchange: {
      accepted_audiences: [],
      enabled: false,
      max_token_age_secs: 300,
      scope_map: {},
      subject_mapping: 'email',
    },
    provider_kind: 'saml',
    allow_tenant_inheritance: false,
    scopes: [],
    effective_scopes: [],
    allowed_issuer_tenants: [],
    allowed_algorithms: [],
    mints_client_secret: false,
    pkce_required: false,
    has_bundled_mark: false,
    created_at: '2026-10-05T00:00:00Z',
    updated_at: '2026-10-05T00:00:00Z',
    ...extra,
  };
}

/** Not a real certificate: the SDK passes the string through and never parses it. */
function pem(): string {
  return `-----BEGIN CERTIFICATE-----\n${Buffer.from(freshId()).toString('base64')}\n-----END CERTIFICATE-----\n`;
}

describe('§27.15 note 1 — window_minutes is passed through, never clamped', () => {
  it('create sends it as given, create without it sends no key, and a response decodes it', async () => {
    const server = mockServer();
    const seen = capture(server, 'POST', RULES, 201, ruleBody({ window_minutes: 60 }));
    const rules = managementClient().notificationRules;
    const base = {
      description: 'mail the on-call',
      events: ['user_locked'],
      name: 'Lockouts',
      recipient_emails: ['oncall@example.com'],
    };

    const created = await rules.create({ ...base, window_minutes: 60 });
    // Outside 1 … 1440: the server's 400 is the authority, not a client clamp.
    await rules.create({ ...base, window_minutes: 5000 });
    await rules.create({ ...base, window_minutes: 0 });
    await rules.create(base);

    expect((seen[0]?.json as Record<string, unknown>).window_minutes).toBe(60);
    expect((seen[1]?.json as Record<string, unknown>).window_minutes).toBe(5000);
    expect((seen[2]?.json as Record<string, unknown>).window_minutes).toBe(0);
    expect('window_minutes' in (seen[3]?.json as Record<string, unknown>)).toBe(false);
    expect(created.window_minutes).toBe(60);
  });

  it('update sends it only when set (sparse)', async () => {
    const server = mockServer();
    const id = freshId();
    const seen = capture(server, 'PUT', `${RULES}/${id}`, 200, ruleBody({ id, window_minutes: 1440 }));
    const rules = managementClient().notificationRules;

    const updated = await rules.update(id, { window_minutes: 1440 });
    await rules.update(id, { enabled: false });
    expect(seen[0]?.json).toEqual({ window_minutes: 1440 });
    expect(seen[1]?.json).toEqual({ enabled: false });
    expect(updated.window_minutes).toBe(1440);
  });
});

describe('§27.15 notes 6 and 7 — the federation configuration members', () => {
  it('create sends allow_sha1_signatures and idp_metadata_signing_cert_pem only when set', async () => {
    const server = mockServer();
    const seen = capture(server, 'POST', CONFIGS, 201, legacyConfigBody());
    const federation = managementClient().federation;
    const cert = pem();
    const base = {
      client_id: 'axiam',
      client_secret: new Sensitive(freshSecret()),
      protocol: 'Saml',
      provider: 'okta',
    };

    await federation.createConfig({ ...base, allow_sha1_signatures: true, idp_metadata_signing_cert_pem: cert });
    await federation.createConfig(base);

    const set = seen[0]?.json as Record<string, unknown>;
    expect(set.allow_sha1_signatures).toBe(true);
    expect(set.idp_metadata_signing_cert_pem).toBe(cert);
    const unset = seen[1]?.json as Record<string, unknown>;
    expect('allow_sha1_signatures' in unset).toBe(false);
    expect('idp_metadata_signing_cert_pem' in unset).toBe(false);
  });

  it('a response without allow_sha1_signatures (an older server) decodes as false, everywhere', async () => {
    const server = mockServer();
    const id = freshId();
    capture(server, 'GET', `${CONFIGS}/${id}`, 200, legacyConfigBody({ id }));
    capture(server, 'PUT', `${CONFIGS}/${id}`, 200, legacyConfigBody({ id }));
    capture(server, 'POST', CONFIGS, 201, legacyConfigBody({ id }));
    capture(server, 'GET', CONFIGS, 200, { items: [legacyConfigBody({ id })], total: 1, offset: 0, limit: 50 });
    const federation = managementClient().federation;

    const reads = [
      await federation.getConfig(id),
      await federation.updateConfig(id, {}),
      await federation.createConfig({
        client_id: 'axiam',
        client_secret: new Sensitive(freshSecret()),
        protocol: 'Saml',
        provider: 'okta',
      }),
      ...(await federation.listConfigs()).items,
    ];
    for (const config of reads) {
      expect(config.allow_sha1_signatures).toBe(false);
      expect(config.idp_metadata_signing_cert_pem).toBeUndefined();
    }
  });

  it('a response carrying both decodes them as sent, null included', async () => {
    const server = mockServer();
    const id = freshId();
    const other = freshId();
    const cert = pem();
    capture(server, 'GET', `${CONFIGS}/${id}`, 200,
      legacyConfigBody({ id, allow_sha1_signatures: true, idp_metadata_signing_cert_pem: cert }));
    capture(server, 'GET', `${CONFIGS}/${other}`, 200,
      legacyConfigBody({ id: other, allow_sha1_signatures: false, idp_metadata_signing_cert_pem: null }));
    const federation = managementClient().federation;

    const set = await federation.getConfig(id);
    expect(set.allow_sha1_signatures).toBe(true);
    expect(set.idp_metadata_signing_cert_pem).toBe(cert);
    const unset = await federation.getConfig(other);
    expect(unset.allow_sha1_signatures).toBe(false);
    expect(unset.idp_metadata_signing_cert_pem).toBeNull();
  });
});

describe('§27.15 note 8 — update_config: an explicit null clears, an omitted member is left', () => {
  const NULLABLE = [
    'metadata_url',
    'idp_signing_cert_pem',
    'idp_metadata_signing_cert_pem',
    'provider_slug',
    'authorization_endpoint',
    'token_endpoint',
    'userinfo_endpoint',
    'apple_team_id',
    'apple_key_id',
    'button_icon',
  ] as const;

  it('one cleared member: the body is exactly that key, with null (§27.4 rule 5 key-set test)', async () => {
    const server = mockServer();
    const id = freshId();
    const seen = capture(server, 'PUT', `${CONFIGS}/${id}`, 200, legacyConfigBody({ id }));
    const federation = managementClient().federation;

    await federation.updateConfig(id, { idp_metadata_signing_cert_pem: null });
    expect(seen[0]?.text).toBe('{"idp_metadata_signing_cert_pem":null}');
    expect(Object.keys(seen[0]?.json as Record<string, unknown>)).toEqual(['idp_metadata_signing_cert_pem']);

    // Omitted (and `undefined`, which is the same statement) sends nothing.
    await federation.updateConfig(id, {});
    await federation.updateConfig(id, { idp_metadata_signing_cert_pem: undefined, enabled: true });
    expect(seen[1]?.text).toBe('{}');
    expect(seen[2]?.json).toEqual({ enabled: true });
  });

  it('each of the ten nullable members is sent as null when cleared, and only then', async () => {
    const server = mockServer();
    const id = freshId();
    const seen = capture(server, 'PUT', `${CONFIGS}/${id}`, 200, legacyConfigBody({ id }));
    const federation = managementClient().federation;

    for (const member of NULLABLE) {
      const body: UpdateFederationConfigRequest = { [member]: null };
      await federation.updateConfig(id, body);
    }
    NULLABLE.forEach((member, i) => {
      expect(seen[i]?.json, member).toEqual({ [member]: null });
    });

    const cleared = Object.fromEntries(NULLABLE.map((m) => [m, null])) as UpdateFederationConfigRequest;
    await federation.updateConfig(id, cleared);
    expect(Object.keys(seen[NULLABLE.length]?.json as Record<string, unknown>).sort()).toEqual([...NULLABLE].sort());
  });

  it('a value replaces: allow_sha1_signatures and the certificate are sent as given', async () => {
    const server = mockServer();
    const id = freshId();
    const seen = capture(server, 'PUT', `${CONFIGS}/${id}`, 200, legacyConfigBody({ id }));
    const cert = pem();

    await managementClient().federation.updateConfig(id, {
      allow_sha1_signatures: false,
      idp_metadata_signing_cert_pem: cert,
    });
    expect(seen[0]?.json).toEqual({ allow_sha1_signatures: false, idp_metadata_signing_cert_pem: cert });
  });
});
