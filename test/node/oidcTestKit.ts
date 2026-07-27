// Shared fixtures for the CONTRACT.md §12 OIDC/SSO tests.
//
// One place to build: an EdDSA key pair + JWKS handler, a discovery document
// whose endpoints all point at the mocked origin, an ID token with arbitrary
// (deliberately broken) claims/headers, and a NodeSession-backed OidcClient.
//
// JWT fixtures live HERE, never under src/ — CI's token-leak gate fails the
// build if a JWT-shaped ("eyJ"-prefixed) string appears anywhere in dist/.

import { exportJWK, SignJWT, generateKeyPair, type JWK } from 'jose';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { createNodeSession, type NodeSession } from '../../src/node/session.js';
import { createOidcClient, DISCOVERY_PATH, OidcClient } from '../../src/node/oidc.js';
import type { OidcConfiguration } from '../../src/node/oidcTypes.js';

export const BASE_URL = 'https://axiam-oidc.test';
export const TENANT_ID = '11111111-2222-3333-4444-555555555555';
export const ORG_ID = '66666666-7777-8888-9999-aaaaaaaaaaaa';
export const CLIENT_ID = 'axiam-rp';
export const CLIENT_SECRET = 'rp-secret-value';
export const REDIRECT_URI = 'https://app.example.com/auth/callback';
export const JWKS_URI = `${BASE_URL}/oauth2/jwks`;
export const TOKEN_ENDPOINT = `${BASE_URL}/oauth2/token`;
export const INTROSPECT_ENDPOINT = `${BASE_URL}/oauth2/introspect`;
export const REVOKE_ENDPOINT = `${BASE_URL}/oauth2/revoke`;
export const ISSUER = 'https://iam.example.com';

/** A discovery document pointing every endpoint at the mocked origin. */
export function discoveryDocument(overrides: Partial<OidcConfiguration> = {}): OidcConfiguration {
  return {
    issuer: ISSUER,
    authorization_endpoint: `${BASE_URL}/oauth2/authorize`,
    token_endpoint: TOKEN_ENDPOINT,
    userinfo_endpoint: `${BASE_URL}/oauth2/userinfo`,
    jwks_uri: JWKS_URI,
    revocation_endpoint: REVOKE_ENDPOINT,
    introspection_endpoint: INTROSPECT_ENDPOINT,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['EdDSA'],
    scopes_supported: ['openid', 'profile', 'email'],
    token_endpoint_auth_methods_supported: ['client_secret_post'],
    claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'nonce'],
    grant_types_supported: ['authorization_code', 'client_credentials', 'refresh_token'],
    ...overrides,
  };
}

/** An EdDSA signing key plus its published JWK. */
export interface SigningKey {
  privateKey: CryptoKey;
  kid: string;
  jwk: JWK;
}

/** Generate an Ed25519 key pair and the JWK the JWKS endpoint should publish for it. */
export async function generateSigningKey(kid: string): Promise<SigningKey> {
  const { privateKey, publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
  const jwk = await exportJWK(publicKey);
  jwk.kid = kid;
  jwk.alg = 'EdDSA';
  return { privateKey, kid, jwk };
}

/** Claims/header knobs for {@link signIdToken} — each maps to one §12.4 rule. */
export interface IdTokenOptions {
  issuer?: string;
  audience?: string | string[];
  azp?: string;
  nonce?: string | null;
  subject?: string;
  expiresInSec?: number;
  issuedAtSec?: number;
  notBeforeSec?: number;
  /** `kid` written into the header — defaults to the signing key's own. */
  kid?: string;
  extraClaims?: Record<string, unknown>;
}

/** Sign an ID token with the given (possibly deliberately wrong) claims. */
export async function signIdToken(key: SigningKey, options: IdTokenOptions = {}): Promise<string> {
  const nowSec = Math.floor(Date.now() / 1000);
  const claims: Record<string, unknown> = {
    nonce: options.nonce === null ? undefined : (options.nonce ?? 'test-nonce'),
    ...(options.azp !== undefined ? { azp: options.azp } : {}),
    ...options.extraClaims,
  };
  let builder = new SignJWT(claims)
    .setProtectedHeader({ alg: 'EdDSA', kid: options.kid ?? key.kid })
    .setSubject(options.subject ?? 'user-1')
    .setIssuer(options.issuer ?? ISSUER)
    .setAudience(options.audience ?? CLIENT_ID)
    .setIssuedAt(options.issuedAtSec ?? nowSec)
    .setExpirationTime(nowSec + (options.expiresInSec ?? 3600));
  if (options.notBeforeSec !== undefined) {
    builder = builder.setNotBefore(options.notBeforeSec);
  }
  return builder.sign(key.privateKey);
}

/** Build an unsigned `alg: none` JWT — the §12.4 rule 1 "must be rejected outright" case. */
export function unsignedIdToken(claims: Record<string, unknown>): string {
  const encode = (value: unknown): string =>
    Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
  return `${encode({ alg: 'none', kid: 'any' })}.${encode(claims)}.`;
}

/** A `TokenResponse` wire body. */
export function tokenResponse(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    access_token: 'access-token-value',
    token_type: 'Bearer',
    expires_in: 900,
    ...overrides,
  };
}

/** State shared with the msw handlers so tests can assert call counts / captured requests. */
export interface OidcMockState {
  discoveryCalls: number;
  jwksCalls: number;
  tokenCalls: number;
  /** Form bodies posted to `/oauth2/token`, in order. */
  tokenForms: URLSearchParams[];
  /** `tenant_id` query values seen on `/oauth2/token`, in order. */
  tokenTenantIds: (string | null)[];
  /** `Content-Type` headers seen on `/oauth2/token`, in order. */
  tokenContentTypes: (string | null)[];
}

export function createMockState(): OidcMockState {
  return {
    discoveryCalls: 0,
    jwksCalls: 0,
    tokenCalls: 0,
    tokenForms: [],
    tokenTenantIds: [],
    tokenContentTypes: [],
  };
}

/** The discovery handler, counting calls. */
export function discoveryHandler(state: OidcMockState, document = discoveryDocument()) {
  return http.get(`${BASE_URL}${DISCOVERY_PATH}`, () => {
    state.discoveryCalls += 1;
    return HttpResponse.json(document);
  });
}

/** The JWKS handler, counting calls. */
export function jwksHandler(state: OidcMockState, keys: JWK[]) {
  return http.get(JWKS_URI, () => {
    state.jwksCalls += 1;
    return HttpResponse.json({ keys });
  });
}

/** A `/oauth2/token` handler recording the request and replying with `body`. */
export function tokenHandler(
  state: OidcMockState,
  responder: (form: URLSearchParams) => Response | Promise<Response>,
) {
  return http.post(TOKEN_ENDPOINT, async ({ request }) => {
    state.tokenCalls += 1;
    state.tokenTenantIds.push(new URL(request.url).searchParams.get('tenant_id'));
    state.tokenContentTypes.push(request.headers.get('content-type'));
    const form = new URLSearchParams(await request.text());
    state.tokenForms.push(form);
    return responder(form);
  });
}

/** A fresh msw server with no handlers — tests add what they need. */
export function createServer(): ReturnType<typeof setupServer> {
  return setupServer();
}

/** Build a NodeSession + OidcClient pair against the mocked origin. */
export function createClient(
  options: { clientSecret?: string; tenantId?: string; discoveryTtlMs?: number; clockSkewSec?: number } = {},
): { session: NodeSession; oidc: OidcClient } {
  const session = createNodeSession({ baseUrl: BASE_URL, tenantId: TENANT_ID, orgId: ORG_ID });
  const oidc = createOidcClient(session, {
    clientId: CLIENT_ID,
    ...(options.clientSecret !== undefined ? { clientSecret: options.clientSecret } : {}),
    ...(options.tenantId !== undefined ? { tenantId: options.tenantId } : {}),
    ...(options.discoveryTtlMs !== undefined ? { discoveryTtlMs: options.discoveryTtlMs } : {}),
    ...(options.clockSkewSec !== undefined ? { clockSkewSec: options.clockSkewSec } : {}),
  });
  return { session, oidc };
}
