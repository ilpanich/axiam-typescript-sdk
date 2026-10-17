/**
 * Local checks the generated §27 surface runs before any I/O, and the
 * hand-written conveniences around the generated models (contract 1.54–1.57).
 *
 * The generator (`scripts/gen-management.mjs`, `PRECHECKS`) emits a call to a
 * check here at the top of an operation; nothing here performs I/O. The
 * read-modify-write helpers are §27.4 rule 5's recommended form for the
 * `replace`-style updates of §29, §30, §31 and §32: turn a read result back into
 * the replacement body, every member carried over, so changing one field and
 * sending it back preserves the rest.
 */

import { ValidationError } from './errors.js';
import type {
  DirectoryConfig,
  ParseSamlSpMetadata,
  SamlServiceProvider,
  SamlServiceProviderInput,
  ScimTargetInput,
  ScimTargetResponse,
  SetDirectoryConfig,
  SsfStream,
  SsfStreamInput,
} from './models.js';

/**
 * §29.2: `ParseSamlSpMetadata` is **exactly one** of `metadata_xml` and
 * `metadata_url`. Both or neither is a local {@link ValidationError} (status
 * 400, no request made) — never a request the server refuses.
 *
 * `null` and `undefined` both count as "not set".
 *
 * @internal — called by the generated `saml.parseSpMetadata`.
 */
export function assertParseSpMetadataExactlyOne(body: ParseSamlSpMetadata): void {
  const hasXml = body?.metadata_xml !== undefined && body?.metadata_xml !== null;
  const hasUrl = body?.metadata_url !== undefined && body?.metadata_url !== null;
  if (hasXml === hasUrl) {
    const field = hasXml ? 'metadata_xml' : 'metadata_url';
    const message = hasXml
      ? 'set exactly one of metadata_xml and metadata_url, not both (CONTRACT.md §29.2)'
      : 'set exactly one of metadata_xml and metadata_url (CONTRACT.md §29.2)';
    throw new ValidationError('saml.parse_sp_metadata', 400, `saml.parse_sp_metadata: ${message}`, [
      { field, message },
    ]);
  }
}

/**
 * A `saml.parseSpMetadata` request for the server to fetch the SP's metadata
 * from `url` (`https` only, through the server's SSRF guard).
 */
export function parseSpMetadataFromUrl(url: string): ParseSamlSpMetadata {
  return { metadata_url: url };
}

/** A `saml.parseSpMetadata` request carrying the SP's metadata document itself (at most 512 KiB). */
export function parseSpMetadataFromXml(xml: string): ParseSamlSpMetadata {
  return { metadata_xml: xml };
}

/**
 * Read-modify-write for `saml.updateServiceProvider` (§29.2, §27.4 rule 5):
 * every member of `sp` carried over, by name — so a member the SDK does not
 * model (`sign_assertions`, or anything a newer server adds) is **not** sent
 * back.
 */
export function samlServiceProviderInputFrom(sp: SamlServiceProvider): SamlServiceProviderInput {
  return {
    acs_urls: sp.acs_urls.map((a) => ({ ...a })),
    allow_idp_initiated: sp.allow_idp_initiated,
    allowed_groups: [...sp.allowed_groups],
    attribute_mappings: sp.attribute_mappings.map((m) => ({ ...m })),
    display_name: sp.display_name,
    enabled: sp.enabled,
    encrypt_assertions: sp.encrypt_assertions,
    entity_id: sp.entity_id,
    name_id_format: sp.name_id_format,
    sign_responses: sp.sign_responses,
    slo_binding: sp.slo_binding ?? null,
    slo_url: sp.slo_url ?? null,
    sp_encryption_cert_pem: sp.sp_encryption_cert_pem ?? null,
    sp_signing_cert_pem: sp.sp_signing_cert_pem ?? null,
    want_authn_requests_signed: sp.want_authn_requests_signed,
  };
}

/**
 * Read-modify-write for `ssf.updateStream` (§32.2): the **plain converter**.
 * `authorization_header` is left absent — absent keeps the stored header (unless
 * the update moves `endpoint_url` to another origin, §32.3 rule 5) — and so is
 * `clear_authorization_header`.
 *
 * `events_requested` is always sent, as read — `[]` stays `[]`, because omitting
 * it would reset a receiver's narrowing to every allowed event — and
 * `expected_updated_at` is the `updated_at` of the read, **the server's own
 * string** (contract 1.61, 1.62, §32.2): the replacement lands only if nobody
 * wrote the stream since, else `409` — reload, then retry. Delete it from the
 * body to fall back to the server's version-at-request.
 *
 * **The caller's duty (contract 1.62, §32.2).** This function cannot know that
 * you are about to lower `events_allowed`, so it does not cut
 * `events_requested`: if you lower the ceiling on the result you MUST cut
 * `events_requested` to the new `events_allowed` yourself, or the server answers
 * `400` for a request outside the ceiling. Remember the three meanings of
 * `events_requested` on an update — **absent** resets the stream to every event
 * of `events_allowed` (widening what the receiver narrowed), **`[]`** is stored
 * as the receiver's "none", a list is stored as given and refused (`400`)
 * outside `events_allowed` — and that a stream written since you read it
 * (the receiver included) is `409`. {@link ssfStreamInputWith} is the form that
 * takes the changes and does the cut for you.
 */
export function ssfStreamInputFrom(stream: SsfStream): SsfStreamInput {
  return {
    audience: stream.audience,
    delivery_method: stream.delivery_method,
    description: stream.description ?? null,
    endpoint_url: stream.endpoint_url ?? null,
    events_allowed: [...stream.events_allowed],
    events_requested: [...stream.events_requested],
    expected_updated_at: stream.updated_at,
    receiver_client_id: stream.receiver_client_id,
    status: stream.status,
    status_reason: stream.status_reason ?? null,
    subject_format: stream.subject_format,
  };
}

/**
 * The **change-taking** read-modify-write form for `ssf.updateStream`
 * (contract 1.62, §32.2): `(stream, changes) → SsfStreamInput`.
 *
 * It applies `changes` over what was read and returns the replacement body:
 *
 * - `events_requested` and `expected_updated_at` are sent **as read** — an `[]`
 *   stays `[]`, and the timestamp is the stream's own `updated_at` string, byte
 *   for byte, never re-rendered — so the replacement lands only on the version
 *   you read (a write made since, the receiver's included, is `409`: reload,
 *   then retry) and a receiver's narrowing is not widened.
 * - When `changes` names `events_allowed` and not `events_requested`,
 *   `events_requested` is **cut to the new `events_allowed`**: the entries of
 *   the read list that are in the new ceiling, in their order. An
 *   `events_requested` named in `changes` is sent as given — the server judges
 *   it (`400` outside `events_allowed`).
 *
 * The three meanings of `events_requested` on an update still hold for what you
 * name: **absent** resets the stream to every event of `events_allowed`, **`[]`**
 * is stored as the receiver's "none", a list is stored as given. To reset
 * deliberately, name `events_requested: null` — the key is then left out of the
 * body. Likewise `expected_updated_at: null` is "none": the key is left out and
 * the replacement is conditional only on the version the server reads during the
 * request. A member of `changes` whose value is `undefined` is not a change.
 *
 * `authorization_header` and `clear_authorization_header` are left absent unless
 * `changes` names them (absent keeps the stored header, §32.3 rule 5).
 *
 * @param stream - The stream as `ssf.getStream` returned it.
 * @param changes - The members to change, applied over the read.
 */
export function ssfStreamInputWith(
  stream: SsfStream,
  changes: Partial<SsfStreamInput> = {},
): SsfStreamInput {
  const body: SsfStreamInput = ssfStreamInputFrom(stream);
  const named = Object.entries(changes).filter(([, v]) => v !== undefined);
  const record = body as unknown as Record<string, unknown>;
  for (const [key, value] of named) record[key] = value;

  const names = new Set(named.map(([key]) => key));
  if (names.has('events_allowed') && !names.has('events_requested')) {
    const ceiling = new Set<string>(body.events_allowed);
    body.events_requested = (stream.events_requested as string[]).filter((e) =>
      ceiling.has(e),
    ) as SsfStreamInput['events_requested'];
  }
  // An assigned null is "none" (§27.11 rule 5): the key is left out, which for
  // `events_requested` is the reset the caller named.
  if (body.events_requested === null) delete body.events_requested;
  if (body.expected_updated_at === null) delete body.expected_updated_at;
  return body;
}

/**
 * Read-modify-write for `scimTargets.update` (§31.2). `credential` is left
 * absent — absent keeps the stored one, unless the write moves its URL or
 * changes `auth.type` (§31.3 rule 2), when the caller must supply it again.
 *
 * `expected_updated_at` is the `updated_at` of the read (contract 1.60, §31.3
 * rule 4): the replacement lands only if nobody wrote the target since, else
 * `409` — reload, then retry. Delete it from the body to fall back to the
 * server's last-writer-wins.
 */
export function scimTargetInputFrom(target: ScimTargetResponse): ScimTargetInput {
  return {
    auth: { ...target.auth },
    base_url: target.base_url,
    deprovision: target.deprovision,
    enabled: target.enabled,
    expected_updated_at: target.updated_at,
    name: target.name,
    push_groups: target.push_groups,
    scope: { ...target.scope } as ScimTargetInput['scope'],
    user_name_from: target.user_name_from,
  };
}

/**
 * Read-modify-write for `directory.set` (§30.2). `bind_secret` is left absent —
 * absent keeps the stored secret, unless the write moves the connection
 * (`url`, `start_tls`, `bind_dn` or `trust_anchors_pem`, §30.3 rule 2), when
 * the caller must supply it again: the SDK holds no copy.
 */
export function setDirectoryConfigFrom(config: DirectoryConfig): SetDirectoryConfig {
  return {
    base_dn: config.base_dn,
    bind_dn: config.bind_dn,
    enabled: config.enabled,
    group_base_dn: config.group_base_dn ?? null,
    group_filter: config.group_filter ?? null,
    group_mappings: config.group_mappings.map((m) => ({ ...m })),
    group_member_attribute: config.group_member_attribute,
    group_nesting_depth: config.group_nesting_depth,
    jit_provisioning: config.jit_provisioning,
    kind: config.kind,
    start_tls: config.start_tls,
    sync_interval_secs: config.sync_interval_secs,
    trust_anchors_pem: [...config.trust_anchors_pem],
    url: config.url,
    user_attribute_map: { ...config.user_attribute_map },
    user_filter: config.user_filter,
  };
}
