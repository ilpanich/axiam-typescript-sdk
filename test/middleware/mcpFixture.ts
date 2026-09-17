// CONTRACT.md §28.9's fixture — ONE configuration, shared by all five
// required tests so that a divergence between this SDK and a port shows up as
// a different expected value rather than as a different test.
//
// Every constant below is quoted verbatim from §28.9. Nothing here is derived
// at runtime on purpose: the whole point is that `metadataPath`,
// `metadataUrl` and the four challenge vectors are written down, so a test
// fails when the implementation stops producing them rather than when both
// drift together.

import type { ProtectedResourceMetadataOptions } from '../../src/middleware/mcpCore.js';

/** §28.9's configuration, as its table spells it. */
export const FIXTURE: ProtectedResourceMetadataOptions = {
  resource: 'https://mcp.example.com/mcp',
  authorizationServers: ['https://axiam.example.com'],
  scopesSupported: ['mcp:read', 'mcp:tools'],
  bearerMethodsSupported: ['header'], // the default
  resourceDocumentation: 'https://mcp.example.com/docs',
};

/** The path §28.3's derivation produces for the fixture's resource. */
export const METADATA_PATH = '/.well-known/oauth-protected-resource/mcp';

/** {@link METADATA_PATH} resolved against the resource's scheme and authority. */
export const METADATA_URL = `https://mcp.example.com${METADATA_PATH}`;

/**
 * The guard's expected audience — **equal to the resource**, and a different
 * string from {@link METADATA_URL}. §28.5 rule 3 compares each against its own
 * counterpart; an implementation that compared one against the other would
 * reject every correct configuration.
 */
export const EXPECTED_AUDIENCE = 'https://mcp.example.com/mcp';

/** §28.4's four normative test vectors, as exact strings. */
export const VECTORS = {
  /** Vector 1 — the request carried no credential, so no `error` is named. */
  noCredential: `Bearer resource_metadata="${METADATA_URL}"`,
  /** Vector 2 — a credential was presented and rejected. */
  invalidToken: `Bearer error="invalid_token", resource_metadata="${METADATA_URL}"`,
  /** Vector 3 — a `no_grant` denial on a route that named a scope. */
  insufficientScope: `Bearer error="insufficient_scope", scope="mcp:tools", resource_metadata="${METADATA_URL}"`,
  /** Vector 4 — all four parameters, for an application building its own 400. */
  allFour: `Bearer error="invalid_request", error_description="The access token is malformed", scope="mcp:read mcp:tools", resource_metadata="${METADATA_URL}"`,
} as const;
