/**
 * CONTRACT.md §21.7.2 — DPoP proof verification, all ten checks.
 *
 * Each check gets a negative test, because §21.7.2's whole premise is that a
 * verifier missing one of them still reports success. A suite that only proved
 * a good proof passes would not distinguish this module from `return true`.
 */
import { createHash } from 'node:crypto';
import { exportJWK, generateKeyPair, SignJWT, type JWK } from 'jose';
import { beforeEach, describe, expect, it } from 'vitest';
import { AuthError } from '../../src/core/index.js';
import {
  accessTokenHash,
  canonicalHtu,
  DPOP_IAT_LEEWAY_SEC,
  InMemoryJtiStore,
  jwkThumbprintS256,
  verifyDpopProof,
} from '../../src/node/dpop.js';

const METHOD = 'POST';
const URI = 'https://rs.example.com/v1/things';
const TOKEN = 'eyJhbGciOiJFZERTQSJ9.e30.sig';

let store: InMemoryJtiStore;
beforeEach(() => {
  store = new InMemoryJtiStore();
});

async function ed25519(): Promise<{ priv: CryptoKey; jwk: JWK }> {
  const { privateKey, publicKey } = await generateKeyPair('EdDSA', {
    crv: 'Ed25519',
    extractable: true,
  });
  return { priv: privateKey as CryptoKey, jwk: await exportJWK(publicKey) };
}

interface ProofOverrides {
  alg?: string;
  typ?: string;
  claims?: Record<string, unknown>;
  jwkOverride?: JWK;
}

let jtiCounter = 0;
async function makeProof(
  priv: CryptoKey,
  jwk: JWK,
  o: ProofOverrides = {},
): Promise<string> {
  const claims: Record<string, unknown> = {
    htm: METHOD,
    htu: URI,
    iat: Math.floor(Date.now() / 1000),
    jti: `jti-${++jtiCounter}`,
    ath: accessTokenHash(TOKEN),
    ...(o.claims ?? {}),
  };
  for (const [k, v] of Object.entries(o.claims ?? {})) {
    if (v === undefined) delete claims[k];
  }
  return new SignJWT(claims)
    .setProtectedHeader({ alg: o.alg ?? 'EdDSA', typ: o.typ ?? 'dpop+jwt', jwk: o.jwkOverride ?? jwk })
    .sign(priv);
}

/** Splice a new header onto an existing proof, leaving its signature intact. */
function spliceHeader(proof: string, header: Record<string, unknown>): string {
  const parts = proof.split('.');
  return [
    Buffer.from(JSON.stringify(header)).toString('base64url'),
    parts[1],
    parts[2],
  ].join('.');
}

const base = () => ({ httpMethod: METHOD, httpUri: URI, accessToken: TOKEN, jtiStore: store });

describe('§21.7.2 DPoP proof verification', () => {
  // -------------------------------------------------------------------------
  // The happy path
  // -------------------------------------------------------------------------

  it('verifies a well-formed proof and returns its thumbprint', async () => {
    const { priv, jwk } = await ed25519();
    const jkt = await verifyDpopProof(await makeProof(priv, jwk), base());
    // Returning the thumbprint rather than `true` is what lets a guard pass a
    // value onward that could only have come from a verified proof.
    expect(jkt).toBe(jwkThumbprintS256(jwk as Record<string, unknown>));
    expect(jkt).toHaveLength(43);
  });

  it('strips query and fragment from both sides of htu', async () => {
    const { priv, jwk } = await ed25519();
    await expect(
      verifyDpopProof(await makeProof(priv, jwk), {
        ...base(),
        httpUri: `${URI}?page=2#frag`,
      }),
    ).resolves.toBeTypeOf('string');
  });

  it('accepts all three permitted algorithms', async () => {
    for (const [alg, opts] of [
      ['ES256', {}],
      ['PS256', { modulusLength: 2048 }],
      ['EdDSA', { crv: 'Ed25519' }],
    ] as const) {
      const { privateKey, publicKey } = await generateKeyPair(alg, {
        ...opts,
        extractable: true,
      });
      const jwk = await exportJWK(publicKey);
      const proof = await makeProof(privateKey as CryptoKey, jwk, { alg });
      await expect(verifyDpopProof(proof, base())).resolves.toBeTypeOf('string');
    }
  });

  // -------------------------------------------------------------------------
  // One negative test per check
  // -------------------------------------------------------------------------

  // Without pinning typ, any other JWT signed by the same key — an access
  // token, an ID token — is replayable as a proof.
  it('check 1: refuses a proof without the dpop+jwt typ', async () => {
    const { priv, jwk } = await ed25519();
    await expect(verifyDpopProof(await makeProof(priv, jwk, { typ: 'JWT' }), base())).rejects.toThrow(
      /typ/,
    );
  });

  it('check 1: compares typ case-insensitively', async () => {
    const { priv, jwk } = await ed25519();
    await expect(
      verifyDpopProof(await makeProof(priv, jwk, { typ: 'DPoP+JWT' }), base()),
    ).resolves.toBeTypeOf('string');
  });

  // The public-key-as-HMAC-secret attack, run for real. The attacker holds no
  // private key: they take the *public* key out of an observed proof, use its
  // raw bytes as an HMAC secret, sign their own proof with HS256, and embed
  // the same public jwk. A verifier that reads `alg` from the header computes
  // HMAC with that public key, gets a match, and reports success.
  it('check 2: never believes the header alg', async () => {
    const { jwk } = await ed25519();
    const secret = Buffer.from(jwk.x!, 'base64url');

    const forged = await new SignJWT({
      htm: METHOD,
      htu: URI,
      iat: Math.floor(Date.now() / 1000),
      jti: 'forged-jti',
      ath: accessTokenHash(TOKEN),
    })
      .setProtectedHeader({ alg: 'HS256', typ: 'dpop+jwt', jwk })
      .sign(secret);

    // The forgery is internally consistent — HMAC with the embedded key does
    // verify. Proving that first is what makes the rejection meaningful.
    const { jwtVerify } = await import('jose');
    await expect(jwtVerify(forged, secret, { algorithms: ['HS256'] })).resolves.toBeTruthy();

    await expect(verifyDpopProof(forged, base())).rejects.toThrow(AuthError);
  });

  it('check 2: refuses an unpermitted key type', async () => {
    const { priv, jwk } = await ed25519();
    const proof = await makeProof(priv, jwk);
    const spliced = spliceHeader(proof, {
      typ: 'dpop+jwt',
      jwk: { kty: 'EC', crv: 'P-521', x: 'AA', y: 'AA' },
    });
    await expect(verifyDpopProof(spliced, base())).rejects.toThrow(/not permitted/);
  });

  it('check 3: refuses a proof with no jwk, or one signed by a different key', async () => {
    const { priv, jwk } = await ed25519();
    const proof = await makeProof(priv, jwk);

    await expect(verifyDpopProof(spliceHeader(proof, { typ: 'dpop+jwt' }), base())).rejects.toThrow(
      /public 'jwk'/,
    );

    // Signed by a DIFFERENT key than the one it embeds.
    const other = await ed25519();
    const forged = await makeProof(other.priv, jwk);
    await expect(verifyDpopProof(forged, base())).rejects.toThrow(/signature or claims/);
  });

  // RFC 9449 §4.3. Checked against the RAW header JSON, because many JWK
  // libraries silently drop these members when parsing into a public-key type
  // — the check would then pass because the library hid the evidence.
  it('check 4: refuses private key material in the jwk', async () => {
    const { priv, jwk } = await ed25519();
    const proof = await makeProof(priv, jwk);
    for (const member of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']) {
      const spliced = spliceHeader(proof, {
        typ: 'dpop+jwt',
        jwk: { ...jwk, [member]: 'c2VjcmV0' },
      });
      await expect(verifyDpopProof(spliced, base())).rejects.toThrow(/private key material/);
    }
  });

  it('check 5: refuses a proof minted for another method', async () => {
    const { priv, jwk } = await ed25519();
    const proof = await makeProof(priv, jwk, { claims: { htm: 'GET' } });
    await expect(verifyDpopProof(proof, base())).rejects.toThrow(/htm/);
  });

  it('check 6: refuses a proof minted for another URI', async () => {
    const { priv, jwk } = await ed25519();
    const proof = await makeProof(priv, jwk, {
      claims: { htu: 'https://rs.example.com/v1/other' },
    });
    await expect(verifyDpopProof(proof, base())).rejects.toThrow(/htu/);
  });

  // A normalising comparison is where two unequal URIs become equal. Only
  // query and fragment come off; case, default ports and trailing slashes are
  // left exactly as they are.
  it('check 6: compares htu without normalisation', () => {
    expect(canonicalHtu('https://a.example/p?q=1#f')).toBe('https://a.example/p');
    expect(canonicalHtu('https://A.example/P')).not.toBe(canonicalHtu('https://a.example/p'));
    expect(canonicalHtu('https://a.example:443/p')).not.toBe(canonicalHtu('https://a.example/p'));
    expect(canonicalHtu('https://a.example/p/')).not.toBe(canonicalHtu('https://a.example/p'));
  });

  // Both directions. A proof from the future is as suspect as a stale one: it
  // is how a one-sided skew allowance becomes a long-lived proof.
  it('check 7: refuses a stale or future proof', async () => {
    const { priv, jwk } = await ed25519();
    const nowSec = Math.floor(Date.now() / 1000);

    const stale = await makeProof(priv, jwk, {
      claims: { iat: nowSec - DPOP_IAT_LEEWAY_SEC - 5 },
    });
    await expect(verifyDpopProof(stale, base())).rejects.toThrow(/freshness window/);

    const future = await makeProof(priv, jwk, {
      claims: { iat: nowSec + DPOP_IAT_LEEWAY_SEC + 5 },
    });
    await expect(verifyDpopProof(future, base())).rejects.toThrow(/freshness window/);
  });

  // Freshness bounds the window; the jti guard is what makes the window
  // unusable. Without this the same proof works repeatedly for a full minute.
  it('check 8: refuses a replayed proof', async () => {
    const { priv, jwk } = await ed25519();
    const proof = await makeProof(priv, jwk);
    await expect(verifyDpopProof(proof, base())).resolves.toBeTypeOf('string');
    await expect(verifyDpopProof(proof, base())).rejects.toThrow(/replay/);
  });

  // The jti claim is a mutation, so it runs last. Claiming it earlier would
  // let an attacker burn arbitrary jti values out of the store using proofs
  // that were never going to verify — turning the replay guard into a
  // denial-of-service surface against legitimate proofs.
  it('check 8: claims the jti only after every other check passes', async () => {
    const { priv, jwk } = await ed25519();
    const doomed = await makeProof(priv, jwk, { claims: { htm: 'GET', jti: 'precious' } });

    await expect(verifyDpopProof(doomed, base())).rejects.toThrow(/htm/);

    // That jti is still unused, so a genuine proof carrying it still works.
    expect(store.claim('precious', Date.now() + 60_000)).toBe(true);
  });

  // Without ath, a proof captured on one request can be re-aimed at a
  // different token held by the same key.
  it('check 9: refuses a proof aimed at another token', async () => {
    const { priv, jwk } = await ed25519();
    const proof = await makeProof(priv, jwk, {
      claims: { ath: accessTokenHash('some.other.token') },
    });
    await expect(verifyDpopProof(proof, base())).rejects.toThrow(/ath/);
  });

  it('check 9: refuses a proof with no ath at all', async () => {
    const { priv, jwk } = await ed25519();
    const proof = await makeProof(priv, jwk, { claims: { ath: undefined } });
    await expect(verifyDpopProof(proof, base())).rejects.toThrow(AuthError);
  });

  // This is the step that ties the proof to the token; the other nine are what
  // make the proof mean anything.
  it('check 10: refuses a proof by the wrong key', async () => {
    const { priv, jwk } = await ed25519();
    const other = await ed25519();
    await expect(
      verifyDpopProof(await makeProof(priv, jwk), {
        ...base(),
        expectedJkt: jwkThumbprintS256(other.jwk as Record<string, unknown>),
      }),
    ).rejects.toThrow(/cnf\.jkt/);
  });

  // -------------------------------------------------------------------------
  // Thumbprint and framing
  // -------------------------------------------------------------------------

  // The RFC's own worked example. A thumbprint implementation that is
  // self-consistent but wrong agrees with itself on every round trip, so the
  // only useful test is against a published vector.
  it('matches the RFC 7638 appendix A vector', () => {
    expect(
      jwkThumbprintS256({
        kty: 'RSA',
        n:
          '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt' +
          'VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6' +
          '4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD' +
          'W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9' +
          '1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH' +
          'aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
        e: 'AQAB',
      }),
    ).toBe('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
  });

  // kid/use/alg/x5c are excluded by the spec — which is exactly what makes the
  // thumbprint stable across two different encodings of the same key.
  it('ignores members outside the RFC 7638 set', async () => {
    const { jwk } = await ed25519();
    const decorated = { ...jwk, kid: 'abc', use: 'sig', alg: 'EdDSA', x5c: ['zz'] };
    expect(jwkThumbprintS256(decorated as Record<string, unknown>)).toBe(
      jwkThumbprintS256(jwk as Record<string, unknown>),
    );
  });

  it('hashes ath over the token ASCII exactly as it travelled', () => {
    expect(accessTokenHash(TOKEN)).toBe(
      createHash('sha256').update(TOKEN, 'ascii').digest('base64url'),
    );
  });

  // RFC 9449 §4.2 makes exactly one the rule. Rejecting beats picking the
  // first, which is how a verifier and a downstream parser end up reading
  // different proofs.
  it('refuses a header carrying two proofs', async () => {
    const { priv, jwk } = await ed25519();
    const proof = await makeProof(priv, jwk);
    await expect(verifyDpopProof(`${proof},${proof}`, base())).rejects.toThrow(
      /exactly one proof/,
    );
  });

  it('refuses malformed proofs without throwing something other than AuthError', async () => {
    for (const junk of ['', 'not-a-jwt', 'a.b', 'a.b.c.d', '!!!.###.$$$']) {
      await expect(verifyDpopProof(junk, base())).rejects.toThrow(AuthError);
    }
  });
});
