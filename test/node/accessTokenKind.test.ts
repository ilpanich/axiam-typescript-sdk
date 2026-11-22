// CONTRACT.md §10.1 rules 10–12 (contract 1.68; N14): the access-token path
// refuses every token AXIAM signs with the same key that is NOT an access token
// — the MFA challenge, the MFA setup token, the WebAuthn ceremony state and the
// back-channel logout token. Each case below is an otherwise-valid token for the
// configured tenant, signed by the one JWKS key, with no `aud`, against a
// verifier configured with NO expected audience (rule 6's default) — exactly the
// configuration in which the Rust SDK admitted an MFA challenge as its user.

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT, type JWK, type JWTHeaderParameters } from 'jose';
import type { Request, Response } from 'express';
import { createVerifier, JWKS_PATH } from '../../src/node/jwks.js';
import { authenticateRequest } from '../../src/middleware/verifyCore.js';
import { axiamMiddleware, type AxiamRequest } from '../../src/middleware/express.js';

const BASE_URL = 'https://axiam-access-token-kind.test';
const TENANT = '11111111-1111-1111-1111-111111111111';
const USER = '22222222-2222-2222-2222-222222222222';
const NIL_UUID = '00000000-0000-0000-0000-000000000000';
const KID = 'the-only-key';

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledFrame: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

let privateKey: CryptoKey;
let publicJwk: JWK;

beforeAll(async () => {
  const pair = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
  privateKey = pair.privateKey;
  publicJwk = await exportJWK(pair.publicKey);
  publicJwk.kid = KID;
  publicJwk.alg = 'EdDSA';
});

/**
 * A ONE-key JWKS: the shape in which a kid-less header used to fall back to
 * "the only key in the set".
 */
function serveJwks(): void {
  server.use(http.get(`${BASE_URL}${JWKS_PATH}`, () => HttpResponse.json({ keys: [publicJwk] })));
}

interface MintOptions {
  header?: Partial<JWTHeaderParameters> & Record<string, unknown>;
  /** When true, the header carries no `kid` at all. */
  noKid?: boolean;
  claims?: Record<string, unknown>;
  sub?: string;
}

async function mint(options: MintOptions = {}): Promise<string> {
  const header: JWTHeaderParameters = {
    alg: 'EdDSA',
    ...(options.noKid ? {} : { kid: KID }),
    ...(options.header ?? {}),
  } as JWTHeaderParameters;
  return new SignJWT({ tenant_id: TENANT, ...(options.claims ?? {}) })
    .setProtectedHeader(header)
    .setSubject(options.sub ?? USER)
    .setIssuer('https://axiam.example')
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(privateKey);
}

async function verify(token: string): Promise<unknown> {
  return createVerifier(BASE_URL).verifyAccessToken(token, { expectedTenantId: TENANT });
}

describe('§10.1 rules 10–12 — access-token kind (N14)', () => {
  describe('negative — each refused', () => {
    it('rule 10: typ JWT is refused', async () => {
      serveJwks();
      await expect(verify(await mint({ header: { typ: 'JWT' } }))).rejects.toThrow();
    });

    it('rule 10: typ axiam-mfa-challenge+jwt is refused', async () => {
      serveJwks();
      await expect(verify(await mint({ header: { typ: 'axiam-mfa-challenge+jwt' } }))).rejects.toThrow();
    });

    it('rule 10: typ axiam-webauthn-state+jwt is refused', async () => {
      serveJwks();
      await expect(verify(await mint({ header: { typ: 'axiam-webauthn-state+jwt' } }))).rejects.toThrow();
    });

    it('rule 10: typ logout+jwt is refused', async () => {
      serveJwks();
      await expect(verify(await mint({ header: { typ: 'logout+jwt' } }))).rejects.toThrow();
    });

    it('rule 12: a header with no kid is refused against a one-key JWKS (no single-key fallback)', async () => {
      serveJwks();
      await expect(verify(await mint({ noKid: true, header: { typ: 'at+jwt' } }))).rejects.toThrow();
    });

    it('rule 12: the MFA challenge shape (no kid, no typ, no aud) is refused', async () => {
      serveJwks();
      await expect(
        verify(await mint({ noKid: true, claims: { purpose: 'mfa_challenge' } })),
      ).rejects.toThrow();
    });

    it('rule 11: purpose "mfa_challenge" with typ at+jwt and a valid kid is refused', async () => {
      serveJwks();
      await expect(
        verify(await mint({ header: { typ: 'at+jwt' }, claims: { purpose: 'mfa_challenge' } })),
      ).rejects.toThrow();
    });

    it('rule 11: a purpose claim is refused whatever its value, null included', async () => {
      serveJwks();
      await expect(
        verify(await mint({ header: { typ: 'at+jwt' }, claims: { purpose: null } })),
      ).rejects.toThrow();
    });

    it('rule 11: the WebAuthn shape (nil sub, purpose webauthn_authenticate_discoverable) is refused', async () => {
      serveJwks();
      await expect(
        verify(
          await mint({
            sub: NIL_UUID,
            header: { typ: 'at+jwt' },
            claims: { purpose: 'webauthn_authenticate_discoverable' },
          }),
        ),
      ).rejects.toThrow();
    });

    it('the §10 guard (authenticateRequest) refuses a purpose token too', async () => {
      serveJwks();
      const session = { jwksVerifier: createVerifier(BASE_URL), tenantHeaderValue: TENANT };
      await expect(
        authenticateRequest(session, await mint({ claims: { purpose: 'mfa_challenge' } })),
      ).rejects.toThrow();
    });

    it('the Express middleware answers 401 for an MFA-challenge-shaped token', async () => {
      serveJwks();
      const session = { jwksVerifier: createVerifier(BASE_URL), tenantHeaderValue: TENANT };
      const token = await mint({ noKid: true, claims: { purpose: 'mfa_challenge' } });
      const req = { headers: { authorization: `Bearer ${token}` } } as unknown as Request;
      const res: Partial<Response> = {};
      res.status = vi.fn().mockReturnValue(res);
      res.json = vi.fn().mockReturnValue(res);
      const next = vi.fn();
      await axiamMiddleware(session)(req, res as Response, next);
      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(401);
      expect((req as AxiamRequest).axiamUser).toBeUndefined();
    });
  });

  describe('positive — each verifies', () => {
    it.each(['at+jwt', 'AT+JWT', 'application/at+jwt'])('typ %s verifies', async (typ) => {
      serveJwks();
      const claims = (await verify(await mint({ header: { typ } }))) as { sub: string };
      expect(claims.sub).toBe(USER);
    });

    it('a token with no typ that passes every other rule verifies', async () => {
      serveJwks();
      const claims = (await verify(await mint())) as { sub: string };
      expect(claims.sub).toBe(USER);
    });
  });
});
