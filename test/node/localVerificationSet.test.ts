// CONTRACT.md §10.1 "Minimum local-verification set" — the complete required
// negative-test set, asserted against BOTH local-verification entry points:
// the JWKS verifier (`verifyAccessToken`) and the §10 guard the Express /
// Fastify middleware and the §11 helpers all funnel through
// (`authenticateRequest`).
//
// §10.1 exists because SEC-071 and SEC-080 were the same defect found twice:
// each SDK verified a *different subset* of the token and each subset looked
// complete in isolation. These tests are the stated complete set, so a future
// change that quietly drops one rule fails here rather than in production.

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { exportJWK, generateKeyPair, SignJWT, type JWTPayload } from 'jose';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { AuthError } from '../../src/core/index.js';
import {
  CLOCK_SKEW_LEEWAY_SEC,
  createVerifier,
  JWKS_PATH,
  resetTenantComparandWarningForTests,
} from '../../src/node/jwks.js';
import { authenticateRequest, type VerifiableSession } from '../../src/middleware/verifyCore.js';

const BASE_URL = 'https://axiam-101.test';
const KID = 'sec-101-kid';
const TENANT = 'tenant-alpha';

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const now = () => Math.floor(Date.now() / 1000);

/** Publish an Ed25519 JWKS at the org-wide endpoint; return the signing key. */
async function serveJwks(): Promise<CryptoKey> {
  const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
  const jwk = await exportJWK(publicKey);
  jwk.kid = KID;
  jwk.alg = 'EdDSA';
  server.use(http.get(`${BASE_URL}${JWKS_PATH}`, () => HttpResponse.json({ keys: [jwk] })));
  return privateKey;
}

/** Sign `payload` as a normal EdDSA AXIAM access token. */
function sign(key: CryptoKey, payload: JWTPayload): Promise<string> {
  return new SignJWT(payload).setProtectedHeader({ alg: 'EdDSA', kid: KID }).sign(key);
}

/** A payload that satisfies every §10.1 rule, before a test breaks one of them. */
function goodPayload(): JWTPayload {
  return {
    sub: 'user-1',
    tenant_id: TENANT,
    iss: 'https://iam.example.com',
    aud: 'axiam:user',
    scope: 'read write',
    exp: now() + 3600,
  };
}

function session(overrides: Partial<VerifiableSession> = {}): VerifiableSession {
  return {
    jwksVerifier: createVerifier(BASE_URL),
    tenantHeaderValue: TENANT,
    ...overrides,
  };
}

/**
 * Assert that BOTH local-verification entry points reject `token` — the raw
 * verifier and the middleware guard. §10.1's whole point is that no entry
 * point may implement a subset.
 */
async function bothEntryPointsReject(token: string, s: VerifiableSession = session()) {
  await expect(
    s.jwksVerifier.verifyAccessToken(token, {
      expectedTenantId: s.tenantHeaderValue,
      expectedIssuer: s.expectedIssuer,
      expectedAudience: s.expectedAudience,
    }),
  ).rejects.toThrow();
  await expect(authenticateRequest(s, token)).rejects.toBeInstanceOf(AuthError);
}

describe('CONTRACT.md §10.1 minimum local-verification set', () => {
  it('accepts a token that satisfies every rule (control)', async () => {
    const key = await serveJwks();
    const token = await sign(key, goodPayload());

    const identity = await authenticateRequest(
      session({ expectedIssuer: 'https://iam.example.com', expectedAudience: 'axiam:user' }),
      token,
    );

    expect(identity).toEqual({ userId: 'user-1', tenantId: TENANT, roles: ['read', 'write'] });
  });

  // Rule 1 — signature, alg pinned to EdDSA before key lookup.
  it('rejects alg: none without consulting a key (rule 1)', async () => {
    await serveJwks();
    // Hand-rolled: jose refuses to *produce* an unsecured JWS, so build the
    // three segments directly. Note the kid names a real published key — the
    // point is that the `alg` header alone must sink it.
    const b64 = (o: unknown) =>
      Buffer.from(JSON.stringify(o)).toString('base64url');
    const token = `${b64({ alg: 'none', kid: KID })}.${b64(goodPayload())}.`;

    await bothEntryPointsReject(token);
  });

  it('rejects an HS256-signed token bearing the EdDSA key id (rule 1)', async () => {
    await serveJwks();
    const token = await new SignJWT(goodPayload())
      .setProtectedHeader({ alg: 'HS256', kid: KID })
      .sign(new TextEncoder().encode('irrelevant-shared-secret-32-bytes!!'));

    await bothEntryPointsReject(token);
  });

  it('rejects a token whose signature does not verify (rule 1)', async () => {
    await serveJwks();
    const { privateKey: attacker } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    const token = await sign(attacker, goodPayload());

    await bothEntryPointsReject(token);
  });

  // Rule 2 — exp REQUIRED.
  it('rejects an expired token (rule 2)', async () => {
    const key = await serveJwks();
    const token = await sign(key, { ...goodPayload(), exp: now() - 3600 });

    await bothEntryPointsReject(token);
  });

  it('rejects a token with NO exp claim — a permanent credential (rule 2)', async () => {
    const key = await serveJwks();
    const { exp: _dropped, ...noExp } = goodPayload();
    const token = await sign(key, noExp);

    await bothEntryPointsReject(token);
  });

  it('rejects a token with a non-numeric exp (rule 2)', async () => {
    const key = await serveJwks();
    const token = await sign(key, { ...goodPayload(), exp: 'tomorrow' as unknown as number });

    await bothEntryPointsReject(token);
  });

  // Rule 3 — nbf honoured when present.
  it('rejects a token whose nbf is in the future (rule 3)', async () => {
    const key = await serveJwks();
    const token = await sign(key, { ...goodPayload(), nbf: now() + 3600 });

    await bothEntryPointsReject(token);
  });

  it('accepts a token with no nbf at all (rule 3 — absent nbf is valid)', async () => {
    const key = await serveJwks();
    const token = await sign(key, goodPayload());

    await expect(authenticateRequest(session(), token)).resolves.toMatchObject({
      userId: 'user-1',
    });
  });

  // Rule 4 — tenant_id REQUIRED and asserted.
  it('rejects a validly-signed token minted for a DIFFERENT tenant (rule 4)', async () => {
    const key = await serveJwks();
    const token = await sign(key, { ...goodPayload(), tenant_id: 'tenant-beta' });

    await bothEntryPointsReject(token);
  });

  it('rejects a token with no tenant_id claim (rule 4)', async () => {
    const key = await serveJwks();
    const { tenant_id: _dropped, ...noTenant } = goodPayload();
    const token = await sign(key, noTenant);

    await bothEntryPointsReject(token);
  });

  it('fails closed when the relying party has NO configured tenant (rule 4)', async () => {
    const key = await serveJwks();
    const token = await sign(key, goodPayload());

    // "There was nothing to compare against, so there was nothing to check"
    // is the SEC-080 defect — it must reject, not pass.
    await expect(
      authenticateRequest(session({ tenantHeaderValue: '' }), token),
    ).rejects.toBeInstanceOf(AuthError);
    await expect(
      createVerifier(BASE_URL).verifyAccessToken(token, {
        expectedTenantId: undefined as unknown as string,
      }),
    ).rejects.toThrow();
  });

  // Rule 5 — iss checked only when configured.
  it('rejects an issuer mismatch when an expected issuer is configured (rule 5)', async () => {
    const key = await serveJwks();
    const token = await sign(key, { ...goodPayload(), iss: 'https://evil.example.com' });

    await bothEntryPointsReject(token, session({ expectedIssuer: 'https://iam.example.com' }));
  });

  it('does not check iss when no expected issuer is configured (rule 5)', async () => {
    const key = await serveJwks();
    const token = await sign(key, { ...goodPayload(), iss: 'https://anything.example.com' });

    await expect(authenticateRequest(session(), token)).resolves.toMatchObject({
      userId: 'user-1',
    });
  });

  // Rule 6 — aud checked only when configured.
  it('rejects an audience mismatch when an expected audience is configured (rule 6)', async () => {
    const key = await serveJwks();
    const token = await sign(key, { ...goodPayload(), aud: 'axiam:m2m' });

    await bothEntryPointsReject(token, session({ expectedAudience: 'axiam:user' }));
  });

  it('rejects a token with no aud when an expected audience is configured (rule 6)', async () => {
    const key = await serveJwks();
    const { aud: _dropped, ...noAud } = goodPayload();
    const token = await sign(key, noAud);

    await bothEntryPointsReject(token, session({ expectedAudience: 'axiam:user' }));
  });

  it('accepts an array-form aud that contains the expected value (rule 6)', async () => {
    const key = await serveJwks();
    const token = await sign(key, { ...goodPayload(), aud: ['axiam:user', 'other'] });

    await expect(
      authenticateRequest(session({ expectedAudience: 'axiam:user' }), token),
    ).resolves.toMatchObject({ userId: 'user-1' });
  });

  // Rule 7 — named, bounded clock skew.
  it('exposes the clock skew as a named 60 s constant (rule 7)', () => {
    expect(CLOCK_SKEW_LEEWAY_SEC).toBe(60);
  });

  it('tolerates an exp that has just passed, within the named skew (rule 7)', async () => {
    const key = await serveJwks();
    const token = await sign(key, { ...goodPayload(), exp: now() - 5 });

    await expect(authenticateRequest(session(), token)).resolves.toMatchObject({
      userId: 'user-1',
    });
  });

  // The §10.1 raw primitive — allowed to exist, must not be the guard.
  describe('verifySignatureOnlyUnchecked (§10.1 raw primitive)', () => {
    it('accepts a token with no exp and a foreign tenant — hence the name', async () => {
      const key = await serveJwks();
      const { exp: _dropped, ...noExp } = goodPayload();
      const token = await sign(key, { ...noExp, tenant_id: 'tenant-beta' });

      const claims = await createVerifier(BASE_URL).verifySignatureOnlyUnchecked(token);
      expect(claims.tenant_id).toBe('tenant-beta');

      // ...and the same token is rejected by the guard entry point.
      await expect(authenticateRequest(session(), token)).rejects.toBeInstanceOf(AuthError);
    });

    it('still rejects a bad signature', async () => {
      await serveJwks();
      const { privateKey: attacker } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
      const token = await sign(attacker, goodPayload());

      await expect(
        createVerifier(BASE_URL).verifySignatureOnlyUnchecked(token),
      ).rejects.toThrow();
    });
  });
});

// §13.4 observation 6 — slug-vs-UUID tenant comparand.
//
// AXIAM tokens carry the tenant UUID in `tenant_id`, but this SDK's client is
// commonly configured with a tenant slug. A guard handed that slug rejects 100%
// of traffic — fail-closed and safe, but it presents as "every token is
// invalid" with nothing pointing at the cause.
describe('§13.4 observation 6 — slug-vs-UUID comparand diagnostic', () => {
  const UUID_TENANT = '11111111-2222-3333-4444-555555555555';

  beforeEach(() => resetTenantComparandWarningForTests());

  /** Capture `console.warn` for the duration of `body`. */
  async function warningsFrom(body: () => Promise<void>): Promise<string[]> {
    const seen: string[] = [];
    const original = console.warn;
    console.warn = (...args: unknown[]) => void seen.push(args.map(String).join(' '));
    try {
      await body();
    } finally {
      console.warn = original;
    }
    return seen;
  }

  it('names the actual cause when the guard is configured with a slug', async () => {
    const key = await serveJwks();
    const token = await sign(key, { ...goodPayload(), tenant_id: UUID_TENANT });

    const warnings = await warningsFrom(async () => {
      await expect(
        authenticateRequest(session({ tenantHeaderValue: 'acme-tenant' }), token),
      ).rejects.toBeInstanceOf(AuthError);
    });

    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain('acme-tenant');
    expect(warnings[0]).toContain('not a UUID');
  });

  it('warns once per process, so bad tokens are not a log-flood lever', async () => {
    const key = await serveJwks();
    const token = await sign(key, { ...goodPayload(), tenant_id: UUID_TENANT });
    const s = session({ tenantHeaderValue: 'acme-tenant' });

    const warnings = await warningsFrom(async () => {
      for (let i = 0; i < 5; i += 1) {
        await expect(authenticateRequest(s, token)).rejects.toBeInstanceOf(AuthError);
      }
    });

    expect(warnings).toHaveLength(1);
  });

  it('stays silent on a genuine cross-tenant rejection', async () => {
    const key = await serveJwks();
    const token = await sign(key, { ...goodPayload(), tenant_id: UUID_TENANT });

    const warnings = await warningsFrom(async () => {
      await expect(
        authenticateRequest(
          session({ tenantHeaderValue: '99999999-8888-7777-6666-555555555555' }),
          token,
        ),
      ).rejects.toBeInstanceOf(AuthError);
    });

    expect(warnings).toEqual([]);
  });

  it('does not change the verification outcome', async () => {
    const key = await serveJwks();
    const token = await sign(key, { ...goodPayload(), tenant_id: UUID_TENANT });

    const warnings = await warningsFrom(async () => {
      const claims = await authenticateRequest(session({ tenantHeaderValue: UUID_TENANT }), token);
      expect(claims.tenantId).toBe(UUID_TENANT);
    });

    expect(warnings).toEqual([]);
  });
});

