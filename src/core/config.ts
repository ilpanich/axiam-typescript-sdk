// AxiamClientOptions — shared client configuration (CONTRACT.md §5/§6/§6.1).
//
// tenantSlug or tenantId is required at construction time per §5; there is
// no default tenant. customCa is the sole TLS escape hatch (§6) — there is
// no insecure/skip-verification option anywhere in this SDK.
//
// clientCert/clientKey (§6.1) configure a client identity for mutual TLS
// (mTLS). They NEVER relax server verification — they are an ADDITIVE client
// credential, kept on a separate code path from server-CA trust so CI's
// TLS-bypass lint gates are never tripped. mTLS is a Node-only capability
// (browsers cannot present a client certificate from JS); the browser build
// validates the PEM shape then ignores it, exactly as it already ignores
// customCa.

import { Sensitive } from './sensitive.js';

/**
 * Configuration for {@link AxiamClient}, passed as its constructor's first
 * argument.
 *
 * @remarks
 * Either `tenantSlug` or `tenantId` MUST be provided — AXIAM is
 * multi-tenant and has no default tenant, so construction throws when both
 * are omitted (CONTRACT.md §5). `customCa` is the sole TLS escape hatch
 * (CONTRACT.md §6); there is no option to disable certificate verification.
 */
export interface AxiamClientOptions {
  /** Base URL of the AXIAM server, e.g. "https://iam.example.com". */
  baseUrl: string;
  /** Human-readable tenant identifier. At least one of tenantSlug/tenantId is required at runtime. */
  tenantSlug?: string;
  /** Tenant UUID. At least one of tenantSlug/tenantId is required at runtime. */
  tenantId?: string;
  /**
   * Human-readable organization identifier (CONTRACT.md §5). Optional at
   * construction, but the server REQUIRES an org context on login — a tenant
   * slug is only unique *within* an organization — so a client that omits both
   * `orgSlug` and `orgId` will fail login with a 400/401. Forwarded as
   * `org_slug` in the login body. Mutually exclusive with {@link orgId}
   * (if both are given, `orgId` wins, mirroring how `tenantSlug`/`tenantId`
   * resolve).
   */
  orgSlug?: string;
  /**
   * Organization UUID (CONTRACT.md §5). Optional at construction (see
   * {@link orgSlug}). When supplied it is forwarded as `org_id` on login and
   * used to build the `refresh` body; otherwise the resolved organization UUID
   * is decoded from the authenticated session's access-token `org_id` claim
   * after the first successful login. Mutually exclusive with {@link orgSlug}.
   */
  orgId?: string;
  /** PEM-encoded custom CA certificate, for self-signed/dev environments (§6). */
  customCa?: string;
  /**
   * PEM-encoded client-certificate chain for mutual TLS (§6.1). Presented to
   * the server to authenticate an IoT device / service account. MUST be
   * provided together with {@link AxiamClientOptions.clientKey}. Node only —
   * ignored in the browser (browsers cannot present a client certificate from
   * JS). Presenting a client certificate NEVER relaxes server verification.
   */
  clientCert?: string;
  /**
   * PEM-encoded private key (PKCS#8 or PKCS#1) matching {@link
   * AxiamClientOptions.clientCert} (§6.1). Secret material: it is passed
   * straight to the Node TLS stack and is never retained on a public property,
   * logged, or serialized (§7). MUST be provided together with `clientCert`.
   * Node only — ignored in the browser.
   */
  clientKey?: string;
  /** Connection timeout in milliseconds. Defaults to DEFAULT_CONNECT_TIMEOUT_MS. */
  connectTimeoutMs?: number;
  /** Request timeout in milliseconds. Defaults to DEFAULT_REQUEST_TIMEOUT_MS. */
  requestTimeoutMs?: number;
}

export const DEFAULT_CONNECT_TIMEOUT_MS = 10_000;
export const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;

/** PEM header that must appear in a certificate chain (§6/§6.1). */
export const CERT_PEM_MARKER = '-----BEGIN CERTIFICATE-----';

/**
 * PEM header for a private key — PKCS#8 (`BEGIN PRIVATE KEY`), PKCS#1
 * (`BEGIN RSA PRIVATE KEY`), or an EC key (`BEGIN EC PRIVATE KEY`) (§6.1).
 */
const PRIVATE_KEY_PEM_RE = /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/;

/**
 * A validated mTLS client identity (§6.1). The private key is held behind
 * {@link Sensitive} so it can never leak through a debug/log/serialize path
 * (§7); call `key.expose()` only at the point of handing it to the TLS stack.
 */
export interface ClientIdentity {
  /** PEM certificate chain (not secret). */
  cert: string;
  /** PEM private key, redaction-wrapped (§7). */
  key: Sensitive<string>;
}

/**
 * Validate the §6.1 client-certificate options and, when configured, return
 * the resolved identity. Throws at construction time (consistent with §6's
 * PEM-only rule) when:
 *   - exactly one of clientCert/clientKey is present (they are all-or-nothing);
 *   - clientCert is not a PEM certificate chain;
 *   - clientKey is not a PEM private key.
 *
 * Returns `undefined` when neither is configured. This validation runs on
 * every persona (including the browser, which then ignores the identity) so
 * construction fails fast and identically everywhere.
 */
export function resolveClientIdentity(options: {
  clientCert?: string;
  clientKey?: string;
}): ClientIdentity | undefined {
  const hasCert = options.clientCert !== undefined;
  const hasKey = options.clientKey !== undefined;
  if (hasCert !== hasKey) {
    throw new Error(
      'clientCert and clientKey must be provided together for mutual TLS ' +
        '(one was given without the other) (CONTRACT.md §6.1).',
    );
  }
  if (!hasCert || !hasKey) {
    return undefined;
  }
  if (!options.clientCert!.includes(CERT_PEM_MARKER)) {
    throw new Error(
      'clientCert must be a PEM-encoded certificate chain (expected to contain ' +
        '"-----BEGIN CERTIFICATE-----") (CONTRACT.md §6.1).',
    );
  }
  if (!PRIVATE_KEY_PEM_RE.test(options.clientKey!)) {
    throw new Error(
      'clientKey must be a PEM-encoded private key (expected to contain ' +
        '"-----BEGIN PRIVATE KEY-----" or "-----BEGIN RSA PRIVATE KEY-----") ' +
        '(CONTRACT.md §6.1).',
    );
  }
  return { cert: options.clientCert!, key: new Sensitive(options.clientKey!) };
}
