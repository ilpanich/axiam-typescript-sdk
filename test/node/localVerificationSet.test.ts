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
  verifyCertificateBinding,
  verifyTokenBinding,
  certificateThumbprintS256,
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

// CONTRACT.md §10.1 rule 8 — "subject of the decision" (§15.3.1).
//
// Rules 1-7 ask whether the token is good; rule 8 asks whether it is the token
// the decision is about. SEC-085 satisfied all seven and was still an
// authentication bypass, because the PHP guard routed a failed verification
// into a second, successful one against the application's own session.
//
// This SDK is structurally safe from that shape — `VerifiableSession` carries a
// verifier and a tenant, not a logged-in session, so there is no second
// credential in scope for the guard to substitute. These tests pin that
// property rather than assume it, which is the guardrail §15.3.1 asks for: they
// fail if anyone ever threads a client session into the guard's inputs.
describe('CONTRACT.md §10.1 rule 8 — the decision is about the caller token', () => {
  it('rejects a failed caller token and consults no other credential', async () => {
    const key = await serveJwks();
    const good = await sign(key, goodPayload());
    const expired = await sign(key, { ...goodPayload(), exp: now() - 3600 });

    // A verifier that would happily succeed for a DIFFERENT token. If the guard
    // ever fell back to another credential, this is what it would reach for.
    const seen: string[] = [];
    const recording = {
      async verifyAccessToken(token: string, expectations: unknown) {
        seen.push(token);
        return createVerifier(BASE_URL).verifyAccessToken(token, expectations as never);
      },
    };

    await expect(
      authenticateRequest({ ...session(), jwksVerifier: recording as never }, expired),
    ).rejects.toBeInstanceOf(AuthError);

    expect(seen).toEqual([expired]);
    expect(seen).not.toContain(good);
  });

  it('exposes no session or refresh surface on the guard input', () => {
    // The shape of the bug: PHP's guard could reach a stateful session through
    // the client it held. Keep the guard's input free of anything like that.
    const keys = Object.keys(session());
    for (const forbidden of ['session', 'tokenManager', 'refresh', 'accessToken', 'client']) {
      expect(keys).not.toContain(forbidden);
    }
  });
});


// ---------------------------------------------------------------------------
// §10.1 rule 9 — sender-constrained (certificate-bound) access tokens
// (contract 1.15, RFC 8705 §3 / RFC 7800).
//
// Three negatives and one positive. The POSITIVE is the one that matters most:
// rule 9 must not become "every caller must present a certificate", which
// would break every deployment that does not use mTLS at all.
// ---------------------------------------------------------------------------

describe('§10.1 rule 9 — sender-constrained tokens', () => {
  /** A real 43-character base64url x5t#S256, and a different one. */
  const THUMBPRINT = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
  const OTHER_THUMBPRINT = 'bWluZS1ub3QteW91cnMtdGhpcy1pcy00My1jaGFyc18';

  it('accepts an unbound token with OR without a certificate', () => {
    // The regression test that keeps rule 9 from becoming a certificate mandate.
    expect(() => verifyCertificateBinding({}, undefined)).not.toThrow();
    expect(() => verifyCertificateBinding({}, THUMBPRINT)).not.toThrow();
  });

  it('accepts a bound token presented with its own certificate', () => {
    expect(() =>
      verifyCertificateBinding({ cnf: { 'x5t#S256': THUMBPRINT } }, THUMBPRINT),
    ).not.toThrow();
  });

  it('rejects a bound token presented with no certificate', () => {
    expect(() => verifyCertificateBinding({ cnf: { 'x5t#S256': THUMBPRINT } }, undefined)).toThrow(
      /no client certificate was presented/,
    );
  });

  it('rejects a bound token presented with a different certificate', () => {
    expect(() =>
      verifyCertificateBinding({ cnf: { 'x5t#S256': THUMBPRINT } }, OTHER_THUMBPRINT),
    ).toThrow(/bound to a different client certificate/);
  });

  // The subtle one. A cnf naming a confirmation method this SDK cannot check
  // is an UNVERIFIABLE constraint, never NO constraint — read the other way, a
  // sender-constrained token silently degrades to a bearer token the day a
  // newer AXIAM issues a confirmation this SDK predates.
  it('rejects, rather than ignores, a cnf naming an unimplemented method', () => {
    const dpopish = { cnf: { jkt: '0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I' } } as never;
    expect(() => verifyCertificateBinding(dpopish, undefined)).toThrow(/cannot verify/);
    expect(() => verifyCertificateBinding(dpopish, THUMBPRINT)).toThrow(/cannot verify/);
  });

  it('carries the cnf claim through a real verifyAccessToken round trip', async () => {
    const key = await serveJwks();
    const token = await sign(key, { ...goodPayload(), cnf: { 'x5t#S256': THUMBPRINT } });
    const claims = await createVerifier(BASE_URL).verifyAccessToken(token, {
      expectedTenantId: TENANT,
    });
    expect(claims.cnf?.['x5t#S256']).toBe(THUMBPRINT);
    // verifyAccessToken deliberately does NOT apply rule 9 — it has no
    // transport to ask. The caller applies it with the thumbprint its TLS
    // layer gives it.
    expect(() => verifyCertificateBinding(claims, THUMBPRINT)).not.toThrow();
    expect(() => verifyCertificateBinding(claims, undefined)).toThrow();
  });

  // -------------------------------------------------------------------------
  // Rule 9 extended for DPoP (contract 1.16)
  // -------------------------------------------------------------------------

  const JKT = '0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I';
  const OTHER_JKT = 'sBjflhaR2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

  // The positive regression test, and the one this change is most likely to
  // break: an unbound token must still pass with no certificate and no proof.
  // The likeliest wrong implementation of rule 9 demands evidence from
  // everybody.
  it('accepts an unbound token with no proofs at all', () => {
    expect(() => verifyTokenBinding({})).not.toThrow();
    expect(() => verifyTokenBinding({}, {})).not.toThrow();
    expect(() =>
      verifyTokenBinding({}, { certificateThumbprint: THUMBPRINT, dpopThumbprint: JKT }),
    ).not.toThrow();
  });

  it('accepts a DPoP-bound token presented with the matching key', () => {
    expect(() =>
      verifyTokenBinding({ cnf: { jkt: JKT } }, { dpopThumbprint: JKT }),
    ).not.toThrow();
  });

  it('rejects a DPoP-bound token with no proof or the wrong key', () => {
    expect(() => verifyTokenBinding({ cnf: { jkt: JKT } })).toThrow(/no verified DPoP proof/);
    expect(() =>
      verifyTokenBinding({ cnf: { jkt: JKT } }, { dpopThumbprint: OTHER_JKT }),
    ).toThrow(/different DPoP key/);
  });

  // Both named is a CONJUNCTION. An operator who turned on two constraints
  // asked for two; satisfying the more convenient one is not compliance. Each
  // half is asserted to fail alone because "check whichever we can" is the
  // likeliest wrong implementation.
  it('requires both proofs when the cnf names both methods', () => {
    const both = { cnf: { 'x5t#S256': THUMBPRINT, jkt: JKT } };

    expect(() =>
      verifyTokenBinding(both, { certificateThumbprint: THUMBPRINT, dpopThumbprint: JKT }),
    ).not.toThrow();

    expect(() => verifyTokenBinding(both, { certificateThumbprint: THUMBPRINT })).toThrow();
    expect(() => verifyTokenBinding(both, { dpopThumbprint: JKT })).toThrow();
  });

  // An empty cnf names nothing checkable and is refused, not read as unbound.
  // Over gRPC this is also how proto3 delivers an empty CnfClaim message,
  // which is why §10.3 rule 3 spells it out separately.
  it('refuses an empty cnf rather than reading it as unbound', () => {
    expect(() => verifyTokenBinding({ cnf: {} })).toThrow(/no method this SDK can verify/);
  });

  // The narrow entry point refuses a DPoP-bound token rather than ignoring the
  // jkt it cannot check — the refusal is what lets it stay in the API without
  // becoming a downgrade path.
  it('refuses a DPoP-bound token from the certificate-only entry point', () => {
    const dpopBound = { cnf: { jkt: JKT } };
    expect(() => verifyCertificateBinding(dpopBound, undefined)).toThrow(/cannot verify/);
    expect(() => verifyCertificateBinding(dpopBound, THUMBPRINT)).toThrow(/cannot verify/);
  });

  it('refuses a both-bound token from the certificate-only entry point', () => {
    expect(() =>
      verifyCertificateBinding({ cnf: { 'x5t#S256': THUMBPRINT, jkt: JKT } }, THUMBPRINT),
    ).toThrow(/both must hold/);
  });

  it('computes an unpadded base64url thumbprint', async () => {
    const der = new Uint8Array(512).fill(0x42);
    const tp = await certificateThumbprintS256(der);
    expect(tp).toHaveLength(43);
    expect(tp).not.toContain('=');
    expect(tp).not.toMatch(/[+/]/);
    expect(await certificateThumbprintS256(der)).toBe(tp);
  });
});
