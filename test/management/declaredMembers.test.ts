// R-20 (contract 1.59 §34.3, review finding F-3; §34.2 P12.1): only declared
// members are kept from a §29 – §32 response, in a known union arm and in an
// unknown one — an unknown arm keeps its discriminator and nothing else.
//
// Before 1.59 the response scrubbers dropped one named key each
// (`private_key_pem`, `bind_secret`, `credential`, `authorization_header`), so
// any other member the type does not declare — `private_key`,
// `bind_secret_set`, `credential_hash`, a member of a nested object, the whole
// body of an unknown `auth` arm — reached the caller and every rendering of
// the result. Every undeclared value here is generated at run time.

import { afterEach, describe, expect, it } from 'vitest';

import { TENANT_ID, capture, managementClient, mockServer } from '../managementSupport.js';
import { assertNoFragment, freshId, freshSecret, renderings } from '../redaction.js';

afterEach(() => mockServer().resetHandlers());

const T = `/api/v1/tenants/${TENANT_ID}`;
const NOW = '2026-10-09T00:00:00Z';

/** Add `extra` (undeclared) members to a copy of `declared`. */
function withExtra(declared: Record<string, unknown>, extra: Record<string, unknown>): Record<string, unknown> {
  return { ...declared, ...extra };
}

function credential(): Record<string, unknown> {
  return {
    id: freshId(),
    tenant_id: TENANT_ID,
    issuer_ca_id: freshId(),
    status: 'active',
    certificate_pem: '-----BEGIN CERTIFICATE-----',
    fingerprint: 'AB:CD',
    serial: '01',
    not_before: NOW,
    not_after: NOW,
    retired_at: null,
    created_at: NOW,
  };
}

function serviceProvider(): Record<string, unknown> {
  return {
    id: freshId(),
    tenant_id: TENANT_ID,
    entity_id: 'https://sp.example',
    display_name: 'SP',
    enabled: true,
    acs_urls: [{ url: 'https://sp.example/acs', binding: 'http_post', index: 0, is_default: true }],
    attribute_mappings: [{ saml_name: 'mail', source: 'email', name_format: null }],
    allowed_groups: [],
    name_id_format: 'persistent',
    sign_responses: true,
    encrypt_assertions: false,
    want_authn_requests_signed: false,
    allow_idp_initiated: false,
    slo_url: null,
    slo_binding: null,
    sp_signing_cert_pem: null,
    sp_encryption_cert_pem: null,
    created_at: NOW,
    updated_at: NOW,
  };
}

function directoryConfig(): Record<string, unknown> {
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
    user_attribute_map: { username: 'sAMAccountName', email: 'mail', display_name: 'displayName', external_id: 'objectGUID' },
    group_base_dn: null,
    group_filter: null,
    group_member_attribute: 'member',
    group_nesting_depth: 5,
    group_mappings: [{ directory_group_dn: 'cn=admins,dc=corp', group_id: freshId() }],
    sync_interval_secs: 3600,
    jit_provisioning: false,
    trust_anchors_pem: [],
    created_at: NOW,
    updated_at: NOW,
  };
}

function scimTarget(auth: Record<string, unknown>, scope: Record<string, unknown>): Record<string, unknown> {
  return {
    id: freshId(),
    tenant_id: TENANT_ID,
    name: 'downstream',
    base_url: 'https://idp.example/scim/v2',
    enabled: true,
    auth,
    scope,
    push_groups: false,
    user_name_from: 'username',
    deprovision: 'deactivate',
    created_at: NOW,
    updated_at: NOW,
    state: {
      last_success_at: null,
      last_failure_at: null,
      last_failure_reason: null,
      consecutive_failures: 0,
      dead_lettered_total: 0,
      last_reconciled_at: null,
    },
  };
}

function ssfStream(): Record<string, unknown> {
  return {
    id: freshId(),
    tenant_id: TENANT_ID,
    receiver_client_id: 'rp-1',
    audience: 'https://rp.example',
    delivery_method: 'push',
    endpoint_url: 'https://rp.example/ssf',
    authorization_header_set: true,
    events_allowed: [],
    events_requested: [],
    events_delivered: [],
    description: null,
    status: 'enabled',
    status_reason: null,
    status_actor: 'receiver',
    subject_format: 'iss_sub',
    transmitter_active: true,
    transmitter_inactive_reason: null,
    last_verification_at: null,
    created_at: NOW,
    updated_at: NOW,
  };
}

describe('R-20 / P12.1 — §29 responses keep only declared members', () => {
  it('SamlIdpCredential: a key under any name is dropped (issue, list, retire, promote)', async () => {
    const server = mockServer();
    const client = managementClient();
    const secret = freshSecret();
    const declared = credential();
    const leaky = withExtra(declared, { private_key: secret, key_der: secret });
    capture(server, 'POST', `${T}/saml/idp-credentials`, 201, leaky);
    capture(server, 'GET', `${T}/saml/idp-credentials`, 200, [leaky]);
    const id = declared.id as string;
    capture(server, 'POST', `${T}/saml/idp-credentials/${id}/retire`, 200, leaky);
    capture(server, 'POST', `${T}/saml/idp-credentials/${id}/promote`, 200, { active: leaky, retired: leaky, signature: secret });

    const issued = await client.saml.issueIdpCredential({ issuer_ca_id: freshId(), slot: 'next' });
    const listed = await client.saml.listIdpCredentials();
    const retired = await client.saml.retireIdpCredential(id);
    const promoted = await client.saml.promoteIdpCredential(id);
    expect(issued).toEqual(declared);
    expect(listed).toEqual([declared]);
    expect(retired).toEqual(declared);
    expect(promoted).toEqual({ active: declared, retired: declared });
    for (const value of [issued, listed, retired, promoted]) assertNoFragment(renderings(value), secret, 'SAML credential');
  });

  it('SamlIdpInfo, SamlServiceProvider (nested acs_urls / attribute_mappings, page envelope) and SamlSpMetadataDraft', async () => {
    const server = mockServer();
    const client = managementClient();
    const secret = freshSecret();
    const info = {
      tenant_id: TENANT_ID,
      entity_id: 'https://iam.example',
      metadata_url: 'https://iam.example/md',
      sso_url: 'https://iam.example/sso',
      slo_url: 'https://iam.example/slo',
      saml_available: true,
      saml_idp_enabled: true,
      metadata_served: true,
      active_credential_id: null,
      next_credential_id: null,
    };
    capture(server, 'GET', `${T}/saml/idp`, 200, withExtra(info, { private_key_pem: secret }));
    const sp = serviceProvider();
    const leakySp = {
      ...sp,
      shared_secret: secret,
      acs_urls: [{ ...(sp.acs_urls as Record<string, unknown>[])[0], token: secret }],
      attribute_mappings: [{ ...(sp.attribute_mappings as Record<string, unknown>[])[0], token: secret }],
    };
    capture(server, 'GET', `${T}/saml/service-providers/${sp.id as string}`, 200, leakySp);
    capture(server, 'GET', `${T}/saml/service-providers`, 200, { items: [leakySp], total: 1, offset: 0, limit: 50, cursor: secret });
    const { id: _id, tenant_id: _t, created_at: _c, updated_at: _u, ...input } = sp;
    const draft = { service_provider: input, signing_certificate_fingerprint: null, encryption_certificate_fingerprint: null, warnings: [] };
    capture(server, 'POST', `${T}/saml/parse-sp-metadata`, 200, {
      ...draft,
      service_provider: { ...input, private_key_pem: secret },
      raw_xml: secret,
    });

    const gotInfo = await client.saml.getIdp();
    const gotSp = await client.saml.getServiceProvider(sp.id as string);
    const page = await client.saml.listServiceProviders();
    const gotDraft = await client.saml.parseSpMetadata({ metadata_url: 'https://sp.example/metadata' });
    expect(gotInfo).toEqual(info);
    expect(gotSp).toEqual(sp);
    expect(page).toEqual({ items: [sp], total: 1, offset: 0, limit: 50 });
    expect(gotDraft).toEqual(draft);
    for (const value of [gotInfo, gotSp, page, gotDraft]) assertNoFragment(renderings(value), secret, 'SAML response');
  });
});

describe('R-20 / P12.1 — §30 responses keep only declared members', () => {
  it('DirectoryConfig drops bind_secret_set, nested user_attribute_map / group_mappings extras; link and sync status too', async () => {
    const server = mockServer();
    const client = managementClient();
    const secret = freshSecret();
    const declared = directoryConfig();
    capture(server, 'GET', `${T}/directory`, 200, {
      ...declared,
      bind_secret: secret,
      bind_secret_set: secret,
      user_attribute_map: { ...(declared.user_attribute_map as Record<string, unknown>), password: secret },
      group_mappings: [{ ...(declared.group_mappings as Record<string, unknown>[])[0], bind_secret: secret }],
    });
    const link = {
      user_id: freshId(),
      directory_external_id: 'guid',
      was_already_linked: false,
      webauthn_credentials_deleted: 0,
      certificates_revoked: 0,
    };
    capture(server, 'POST', `${T}/directory/links`, 200, withExtra(link, { password_hash: secret }));
    const sync = { full_required: false, has_watermark: true, last_attempt_at: null, last_full_run_at: null, last_result: null };
    capture(server, 'GET', `${T}/directory/sync-status`, 200, withExtra(sync, { bind_secret: secret }));

    const config = await client.directory.get();
    const linked = await client.directory.linkAccount({ user_id: link.user_id });
    const status = await client.directory.getSyncStatus();
    expect(config).toEqual(declared);
    expect(linked).toEqual(link);
    expect(status).toEqual(sync);
    for (const value of [config, linked, status]) assertNoFragment(renderings(value), secret, 'directory response');
  });
});

describe('R-20 / P12.1 — §31 responses keep only declared members, in every union arm', () => {
  it('known arms keep their declared members, an unknown arm only its type; credential_hash and state extras dropped', async () => {
    const server = mockServer();
    const client = managementClient();
    const secret = freshSecret();
    const oauth = { type: 'oauth2_client_credentials', token_url: 'https://idp.example/token', client_id: 'axiam', scope: null };
    const groups = { type: 'groups', group_ids: [freshId()] };
    const known = scimTarget(oauth, groups);
    const unknown = scimTarget({ type: 'mtls' }, { type: 'by_attribute' });
    capture(server, 'GET', `/api/v1/scim-targets/${known.id as string}`, 200, {
      ...known,
      credential_hash: secret,
      auth: { ...oauth, client_secret: secret },
      scope: { ...groups, filter: secret },
      state: { ...(known.state as Record<string, unknown>), last_response_body: secret },
    });
    capture(server, 'GET', `/api/v1/scim-targets/${unknown.id as string}`, 200, {
      ...unknown,
      auth: { type: 'mtls', client_key_pem: secret, client_id: secret },
      scope: { type: 'by_attribute', attribute: secret },
    });
    capture(server, 'GET', '/api/v1/scim-targets', 200, { items: [{ ...known, credential: secret }], total: 1, offset: 0, limit: 50, debug: secret });
    const accepted = { target_id: known.id, status: 'started' };
    capture(server, 'POST', `/api/v1/scim-targets/${known.id as string}/reconcile`, 202, withExtra(accepted, { credential: secret }));

    const gotKnown = await client.scimTargets.get(known.id as string);
    const gotUnknown = await client.scimTargets.get(unknown.id as string);
    const page = await client.scimTargets.list();
    const gotAccepted = await client.scimTargets.reconcile(known.id as string);
    expect(gotKnown).toEqual(known);
    expect(gotUnknown).toEqual(unknown);
    expect(gotUnknown.auth).toEqual({ type: 'mtls' });
    expect(page).toEqual({ items: [known], total: 1, offset: 0, limit: 50 });
    expect(gotAccepted).toEqual(accepted);
    for (const value of [gotKnown, gotUnknown, page, gotAccepted]) assertNoFragment(renderings(value), secret, 'SCIM response');
  });
});

describe('R-20 / P12.1 — §32 responses keep only declared members', () => {
  it('SsfStream drops any undeclared member, on get and on a page', async () => {
    const server = mockServer();
    const client = managementClient();
    const secret = freshSecret();
    const declared = ssfStream();
    capture(server, 'GET', `${T}/ssf/streams/${declared.id as string}`, 200, withExtra(declared, { authorization_header: secret, header_value: secret }));
    capture(server, 'GET', `${T}/ssf/streams`, 200, { items: [withExtra(declared, { push_token: secret })], total: 1, offset: 0, limit: 50, trace: secret });

    const stream = await client.ssf.getStream(declared.id as string);
    const page = await client.ssf.listStreams();
    expect(stream).toEqual(declared);
    expect(page).toEqual({ items: [declared], total: 1, offset: 0, limit: 50 });
    for (const value of [stream, page]) assertNoFragment(renderings(value), secret, 'SSF response');
  });
});
