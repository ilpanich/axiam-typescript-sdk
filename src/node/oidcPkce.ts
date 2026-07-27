// PKCE + CSPRNG primitives for the OIDC relying-party flow
// (CONTRACT.md §12.1 "oidc_begin inputs and construction", RFC 7636).
//
// Node's `node:crypto` covers everything needed — CSPRNG, SHA-256 and
// base64url — so §12 adds NO new runtime dependency (plan §6 criterion 4).
// This module is deliberately tiny, pure and synchronous: `oidc_begin`
// performs no network I/O (§12.1), and every value here is derived locally.
//
// S256 ONLY. `plain` is not implemented, not reachable, and not configurable:
// there is no code path in this SDK that can emit
// `code_challenge_method=plain`.

import { createHash, randomBytes } from 'node:crypto';
import { Sensitive } from '../core/index.js';

/**
 * The only PKCE code-challenge method this SDK emits (RFC 7636 §4.2,
 * CONTRACT.md §12.1 rule 3). `plain` is intentionally absent.
 */
export const CODE_CHALLENGE_METHOD_S256 = 'S256';

/**
 * Entropy, in bytes, of a generated `state` / `nonce` / `code_verifier`.
 *
 * §12.1 rule 1 requires at least 16 bytes (128 bits) and RECOMMENDS 32;
 * rule 2 RECOMMENDS 32 bytes for the verifier, which base64url-encodes to
 * exactly 43 characters — the minimum RFC 7636 §4.1 length, drawn only from
 * the unreserved set `[A-Za-z0-9-._~]`.
 */
export const CSPRNG_BYTES = 32;

/**
 * Generate a URL-safe random token: `bytes` CSPRNG bytes, base64url-encoded
 * **without** padding (RFC 4648 §5 — Node's `'base64url'` encoding never
 * emits `=`).
 *
 * Used for both `state` and `nonce`, which §12.3 rule 2 classes as
 * **non-secret**: they are returned as plain strings, are echoed through the
 * browser's address bar by construction, and are safe to log.
 */
export function randomUrlSafeToken(bytes: number = CSPRNG_BYTES): string {
  return randomBytes(bytes).toString('base64url');
}

/**
 * Generate a fresh PKCE `code_verifier` (RFC 7636 §4.1): 32 CSPRNG bytes
 * base64url-encoded without padding, i.e. 43 characters from the unreserved
 * set.
 *
 * Returned already wrapped in {@link Sensitive} — §12.5 makes the verifier
 * secret **for its whole lifetime**, including while it sits in the
 * `AuthorizationRequest` handed back to the caller and in any
 * `OidcStateStore` entry.
 */
export function generateCodeVerifier(): Sensitive<string> {
  return new Sensitive(randomUrlSafeToken(CSPRNG_BYTES));
}

/**
 * Derive the PKCE `code_challenge` from a verifier:
 * `BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))`, unpadded
 * (RFC 7636 §4.2, CONTRACT.md §12.1 rule 3).
 *
 * The verifier is hashed as ASCII exactly as the RFC specifies. Verified
 * against the RFC 7636 Appendix B test vector in
 * `test/node/oidcPkce.test.ts`, which every SDK must carry (§12.1 rule 3).
 *
 * The challenge is a one-way digest and is **not** secret — it travels in the
 * authorization URL — so it is returned as a plain string.
 */
export function computeCodeChallenge(codeVerifier: string): string {
  return createHash('sha256').update(codeVerifier, 'ascii').digest('base64url');
}
