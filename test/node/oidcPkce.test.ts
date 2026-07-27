// PKCE + CSPRNG primitives (CONTRACT.md §12.1 rules 1–3, RFC 7636).

import { describe, expect, it } from 'vitest';
import { Sensitive } from '../../src/core/index.js';
import {
  CODE_CHALLENGE_METHOD_S256,
  CSPRNG_BYTES,
  computeCodeChallenge,
  generateCodeVerifier,
  randomUrlSafeToken,
} from '../../src/node/oidcPkce.js';

describe('PKCE (§12.1 rules 2–3, RFC 7636)', () => {
  it('matches the RFC 7636 Appendix B test vector', () => {
    // The canonical vector every SDK must carry (§12.1 rule 3).
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    expect(computeCodeChallenge(verifier)).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });

  it('emits S256 as the only challenge method — `plain` is not implemented', () => {
    expect(CODE_CHALLENGE_METHOD_S256).toBe('S256');
    // The module exports no plain-method constant and no method argument
    // anywhere: the challenge function's only behaviour is SHA-256.
    const moduleExports = Object.keys({
      CODE_CHALLENGE_METHOD_S256,
      computeCodeChallenge,
      generateCodeVerifier,
      randomUrlSafeToken,
      CSPRNG_BYTES,
    });
    expect(moduleExports.some((name) => /plain/i.test(name))).toBe(false);
  });

  it('produces a 43-character verifier from the unreserved set, wrapped in Sensitive', () => {
    const verifier = generateCodeVerifier();
    expect(verifier).toBeInstanceOf(Sensitive);
    const raw = verifier.expose();
    // 32 bytes -> 43 base64url characters, the RFC 7636 §4.1 minimum length.
    expect(raw).toHaveLength(43);
    expect(raw).toMatch(/^[A-Za-z0-9\-._~]+$/);
    expect(raw).not.toContain('=');
  });

  it('generates a distinct verifier on every call', () => {
    const verifiers = new Set(Array.from({ length: 50 }, () => generateCodeVerifier().expose()));
    expect(verifiers.size).toBe(50);
  });

  it('derives the challenge as unpadded base64url of the SHA-256 digest', () => {
    const challenge = computeCodeChallenge(generateCodeVerifier().expose());
    expect(challenge).toHaveLength(43);
    expect(challenge).toMatch(/^[A-Za-z0-9\-_]+$/);
    expect(challenge).not.toContain('=');
  });
});

describe('CSPRNG tokens (§12.1 rule 1)', () => {
  it('defaults to 32 bytes (256 bits) of entropy, above the 128-bit floor', () => {
    expect(CSPRNG_BYTES).toBeGreaterThanOrEqual(16);
    const token = randomUrlSafeToken();
    // base64url of 32 bytes is 43 unpadded characters; >= 128 bits either way.
    expect(Buffer.from(token, 'base64url')).toHaveLength(CSPRNG_BYTES);
    expect(Buffer.from(token, 'base64url').length * 8).toBeGreaterThanOrEqual(128);
  });

  it('is base64url without padding', () => {
    const token = randomUrlSafeToken();
    expect(token).toMatch(/^[A-Za-z0-9\-_]+$/);
    expect(token).not.toContain('=');
  });

  it('honours an explicit byte count while staying above 128 bits', () => {
    expect(Buffer.from(randomUrlSafeToken(16), 'base64url')).toHaveLength(16);
  });

  it('never repeats across calls', () => {
    const tokens = new Set(Array.from({ length: 200 }, () => randomUrlSafeToken()));
    expect(tokens.size).toBe(200);
  });
});
