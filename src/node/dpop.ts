/**
 * DPoP proof verification — CONTRACT.md §21.7.2 (RFC 9449), contract 1.16.
 *
 * The resource-server half of DPoP: given the `DPoP` header a caller
 * presented, decide whether it proves possession for *this* request and *this*
 * access token, and return the key thumbprint that {@link verifyTokenBinding}
 * then matches against the token's `cnf.jkt`.
 *
 * ## Why this lives in the SDK
 *
 * §21.7.2 is a ten-check list, and the contract is blunt about partial
 * implementations: *"Partial verification is worse than none, because it
 * produces a guard that reports success."* Nine of the ten look optional until
 * someone builds an attack out of the one that was skipped, so they belong in
 * one audited place rather than in every application guarding an endpoint.
 *
 * The two most often missing, and what they cost:
 *
 * - **`typ`** — without pinning it to `dpop+jwt`, any *other* JWT signed by the
 *   same key (an access token, an ID token) is replayable as a proof.
 * - **`ath`** — without it, a proof captured on one request can be re-aimed at
 *   a different token held by the same key. `ath` binds the proof to the token
 *   rather than merely to the key.
 *
 * ## The algorithm comes from the key, never from the header
 *
 * `alg: none` and RSA-public-key-as-HMAC-secret are the same bug wearing
 * different clothes: *the token told the verifier how to check the token*.
 * This module derives the expected algorithm from the embedded key's
 * `kty`/`crv` and passes that one algorithm to the verifier. The header's `alg`
 * is never consulted — not compared, not read.
 *
 * @module
 */
import { createHash, timingSafeEqual } from 'node:crypto';
import { importJWK, jwtVerify, type JWK } from 'jose';
import { AuthError } from '../core/index.js';

/**
 * §21.7.2 check 7 — the `iat` acceptance window, applied in **both**
 * directions. RFC 9449 recommends a small window without fixing a number; 60 s
 * is the contract's RECOMMENDED value. Named, because a bare `60` three call
 * frames deep is a number nobody ever revisits.
 */
export const DPOP_IAT_LEEWAY_SEC = 60;

/**
 * RFC 9449 §4.3 — private key material that must never appear in a proof's
 * embedded public `jwk`. `k` is the symmetric-key member: its presence means
 * the "public key" is a shared secret.
 */
const PRIVATE_JWK_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'] as const;

/**
 * RFC 7638 §3.2 — the members that participate in a thumbprint, per key type,
 * in the lexicographic order they must be serialised in.
 */
const THUMBPRINT_MEMBERS: Record<string, readonly string[]> = {
  RSA: ['e', 'kty', 'n'],
  EC: ['crv', 'kty', 'x', 'y'],
  OKP: ['crv', 'kty', 'x'],
};

function b64urlEncode(raw: Uint8Array): string {
  return Buffer.from(raw).toString('base64url');
}

/** Constant-time string comparison that does not leak length via early exit. */
function constantTimeEquals(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

/**
 * §21.7.2 check 8 — single-use `jti` tracking.
 *
 * One method, and its contract is the point: {@link claim} must be atomic. A
 * `has()`-then-`add()` pair read as two calls is a race that two concurrent
 * replays of the same proof can both win.
 */
export interface JtiStore {
  /**
   * Record `jti` as used until `expiresAtMs`.
   *
   * @returns `true` if this is the first sighting, `false` if it is a replay.
   */
  claim(jti: string, expiresAtMs: number): boolean | Promise<boolean>;
}

/**
 * A {@link JtiStore} for a single process.
 *
 * **Per-process, therefore per-worker.** Four cluster workers give an attacker
 * four chances to replay a proof inside its freshness window, and a restart
 * clears the window entirely. Any deployment running more than one process
 * needs a shared store (Redis, memcached, a database table).
 */
export class InMemoryJtiStore implements JtiStore {
  readonly #seen = new Map<string, number>();

  claim(jti: string, expiresAtMs: number): boolean {
    const now = Date.now();
    // Prune inline. Entries only ever live for the freshness window, so this
    // stays small without a background sweeper.
    if (this.#seen.size > 128) {
      for (const [k, v] of this.#seen) if (v <= now) this.#seen.delete(k);
    }
    const existing = this.#seen.get(jti);
    if (existing !== undefined && existing > now) return false;
    this.#seen.set(jti, expiresAtMs);
    return true;
  }
}

/**
 * RFC 7638 SHA-256 thumbprint of a JWK — the `jkt`.
 *
 * Only the members RFC 7638 names for the key type take part, serialised as
 * compact JSON with lexicographically sorted keys. Members outside that set
 * (`kid`, `use`, `alg`, `x5c`) are excluded by the spec, which is what makes
 * the thumbprint stable across two encodings of the same key.
 */
export function jwkThumbprintS256(jwk: Record<string, unknown>): string {
  const kty = jwk['kty'];
  if (typeof kty !== 'string' || !(kty in THUMBPRINT_MEMBERS)) {
    throw new AuthError(`DPoP proof jwk has an unsupported kty: ${String(kty)}`);
  }
  const canonical: Record<string, string> = {};
  for (const member of THUMBPRINT_MEMBERS[kty]!) {
    const value = jwk[member];
    if (typeof value !== 'string' || value === '') {
      throw new AuthError(`DPoP proof jwk is missing the required member '${member}'`);
    }
    canonical[member] = value;
  }
  // JSON.stringify over a key list gives both the member filter and the
  // ordering RFC 7638 requires, with no whitespace.
  const serialized = JSON.stringify(canonical, THUMBPRINT_MEMBERS[kty] as string[]);
  return b64urlEncode(createHash('sha256').update(serialized, 'utf8').digest());
}

/**
 * The `ath` claim value for `accessToken` — RFC 9449 §4.2.
 *
 * base64url-unpadded SHA-256 over the token's **ASCII** bytes, i.e. over the
 * compact JWT string exactly as it travelled in the `Authorization` header,
 * not over anything decoded out of it.
 */
export function accessTokenHash(accessToken: string): string {
  return b64urlEncode(createHash('sha256').update(accessToken, 'ascii').digest());
}

/**
 * The `htu` comparison form — §21.7.2 check 6.
 *
 * Query and fragment removed, and **nothing else**. No case folding, no
 * default-port elision, no percent-decoding, no trailing-slash fixing: a
 * normalising comparison is precisely where two unequal URIs become equal, and
 * an attacker who finds such a pair can aim a proof at an endpoint it was not
 * minted for.
 */
export function canonicalHtu(uri: string): string {
  const hash = uri.indexOf('#');
  const withoutFragment = hash === -1 ? uri : uri.slice(0, hash);
  const query = withoutFragment.indexOf('?');
  return query === -1 ? withoutFragment : withoutFragment.slice(0, query);
}

/**
 * §21.7.2 check 2 — derive the algorithm from the key itself.
 *
 * This function is why the proof header's `alg` is never read: the key's own
 * type determines how a signature over it can be checked, and that is not a
 * matter the presenter gets an opinion on.
 */
function expectedAlg(jwk: Record<string, unknown>): string {
  const { kty, crv } = jwk as { kty?: string; crv?: string };
  if (kty === 'RSA') return 'PS256';
  if (kty === 'EC' && crv === 'P-256') return 'ES256';
  if (kty === 'OKP' && crv === 'Ed25519') return 'EdDSA';
  throw new AuthError(
    `DPoP proof key type is not permitted by CONTRACT.md §21.7.2 ` +
      `(kty=${String(kty)}, crv=${String(crv)}; permitted: ES256, EdDSA, PS256)`,
  );
}

/**
 * The proof's header as **raw JSON**.
 *
 * §21.7.2 check 4 insists the private-material check run against this rather
 * than a parsed key object, because many JWK libraries quietly drop `d`/`p`/`q`
 * when parsing into a public-key type — the check would then pass by virtue of
 * the library having hidden the evidence.
 */
function rawHeader(proof: string): Record<string, unknown> {
  const segments = proof.split('.');
  if (segments.length !== 3) {
    throw new AuthError('DPoP proof is not a compact JWS with three segments');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(segments[0]!, 'base64url').toString('utf8'));
  } catch {
    throw new AuthError('DPoP proof header is not valid base64url JSON');
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new AuthError('DPoP proof header is not a JSON object');
  }
  return parsed as Record<string, unknown>;
}

/** Inputs to {@link verifyDpopProof}. Every one feeds a check that cannot be made without it. */
export interface DpopVerifyOptions {
  /** The request method, e.g. `'POST'`. */
  httpMethod: string;
  /** The full request URI. Query and fragment are stripped here, so passing it with a query string is expected. */
  httpUri: string;
  /** The access token from the `Authorization` header, exactly as it arrived — hashed for `ath`. */
  accessToken: string;
  /** Replay guard. Required; see {@link InMemoryJtiStore} and its deployment caveat. */
  jtiStore: JtiStore;
  /** The token's `cnf.jkt`, when the caller has it. Supplying it performs check 10 here. */
  expectedJkt?: string | undefined;
  /** The `iat` window, both directions. Defaults to {@link DPOP_IAT_LEEWAY_SEC}. */
  leewaySeconds?: number | undefined;
  /** Override for the current time in ms, for tests. */
  nowMs?: number | undefined;
}

/**
 * Verify a DPoP proof against this request — all ten §21.7.2 checks.
 *
 * Returns the proof key's RFC 7638 thumbprint (`jkt`) on success. Feed it to
 * {@link verifyTokenBinding} as `dpopThumbprint`; returning it rather than a
 * bare `true` is deliberate, so the value a guard passes onward could only have
 * come from a proof that actually verified.
 *
 * There is no "just check the signature" mode, because that is exactly the
 * partial verification the contract calls worse than none.
 *
 * @throws {AuthError} on any failing check.
 */
export async function verifyDpopProof(
  proof: string,
  options: DpopVerifyOptions,
): Promise<string> {
  const {
    httpMethod,
    httpUri,
    accessToken,
    jtiStore,
    expectedJkt,
    leewaySeconds = DPOP_IAT_LEEWAY_SEC,
    nowMs,
  } = options;

  if (typeof proof !== 'string' || proof === '') {
    throw new AuthError('DPoP proof is missing or empty');
  }
  // RFC 9449 §4.2 makes exactly one proof the rule. Rejecting beats picking
  // the first, which is how a verifier and a downstream parser end up reading
  // different proofs.
  if (proof.includes(',') || /\s/.test(proof.trim())) {
    throw new AuthError('DPoP header must carry exactly one proof');
  }

  const header = rawHeader(proof);

  // Check 1 — typ. First, because it is what stops any other JWT signed by the
  // same key from standing in as a proof.
  const typ = header['typ'];
  if (typeof typ !== 'string' || typ.toLowerCase() !== 'dpop+jwt') {
    throw new AuthError(`DPoP proof typ header must be 'dpop+jwt', got ${String(typ)}`);
  }

  // Check 3 (first half) — the header carries a public jwk.
  const jwk = header['jwk'];
  if (typeof jwk !== 'object' || jwk === null || Array.isArray(jwk)) {
    throw new AuthError("DPoP proof header must carry a public 'jwk'");
  }
  const jwkRecord = jwk as Record<string, unknown>;

  // Check 4 — no private material, tested against the raw header JSON.
  const leaked = PRIVATE_JWK_MEMBERS.filter((m) => m in jwkRecord);
  if (leaked.length > 0) {
    throw new AuthError(
      `DPoP proof jwk carries private key material (${leaked.join(', ')}) — RFC 9449 §4.3`,
    );
  }

  // Check 2 — algorithm from the key, never from the header.
  const alg = expectedAlg(jwkRecord);

  // Check 3 (second half) — the signature verifies under that key.
  // jose v6 returns a WebCrypto CryptoKey for asymmetric JWKs; it dropped the
  // `KeyLike` alias that used to name this.
  let key: Awaited<ReturnType<typeof importJWK>>;
  try {
    key = await importJWK(jwkRecord as JWK, alg);
  } catch (err) {
    throw new AuthError(`DPoP proof jwk is not a usable public key: ${String(err)}`);
  }

  let claims: Record<string, unknown>;
  try {
    // Single-element allowlist derived above — never the header's alg, never a
    // wildcard. `clockTolerance` is irrelevant here: this call verifies the
    // signature, and check 7 below is the sole authority on freshness.
    const result = await jwtVerify(proof, key, { algorithms: [alg] });
    claims = result.payload as Record<string, unknown>;
  } catch (err) {
    throw new AuthError(`DPoP proof signature or claims are invalid: ${String(err)}`);
  }

  // Check 5 — htm.
  const htm = claims['htm'];
  if (typeof htm !== 'string' || htm !== httpMethod) {
    throw new AuthError(
      `DPoP proof htm ${String(htm)} does not match request method ${httpMethod}`,
    );
  }

  // Check 6 — htu, with query and fragment stripped from BOTH sides and
  // nothing else touched.
  const htu = claims['htu'];
  const expectedHtu = canonicalHtu(httpUri);
  if (typeof htu !== 'string' || canonicalHtu(htu) !== expectedHtu) {
    throw new AuthError(`DPoP proof htu ${String(htu)} does not match request URI ${expectedHtu}`);
  }

  // Check 7 — iat freshness, both directions. A proof from the future is as
  // suspect as a stale one: it is how a one-sided skew allowance becomes a
  // long-lived proof.
  const iat = claims['iat'];
  if (typeof iat !== 'number' || !Number.isFinite(iat)) {
    throw new AuthError('DPoP proof iat must be a number');
  }
  const nowSec = (nowMs ?? Date.now()) / 1000;
  if (Math.abs(nowSec - iat) > leewaySeconds) {
    throw new AuthError(`DPoP proof iat is outside the ${leewaySeconds}s freshness window`);
  }

  // Check 9 — ath ties the proof to this specific access token.
  const ath = claims['ath'];
  if (typeof ath !== 'string' || ath === '') {
    throw new AuthError('DPoP proof is missing the ath claim');
  }
  if (!constantTimeEquals(ath, accessTokenHash(accessToken))) {
    throw new AuthError('DPoP proof ath does not match the presented access token');
  }

  // Check 10 — the thumbprint that ties the proof to the token's cnf.
  const jkt = jwkThumbprintS256(jwkRecord);
  if (expectedJkt !== undefined && !constantTimeEquals(jkt, expectedJkt)) {
    throw new AuthError("DPoP proof key does not match the token's cnf.jkt");
  }

  // Check 8 — jti single-use. LAST on purpose: claiming a jti is a mutation,
  // and doing it before the cheap checks would let an attacker burn arbitrary
  // jti values out of the store with proofs that were never going to verify.
  const jti = claims['jti'];
  if (typeof jti !== 'string' || jti === '') {
    throw new AuthError('DPoP proof is missing a non-empty jti');
  }
  if (!(await jtiStore.claim(jti, (iat + leewaySeconds) * 1000))) {
    throw new AuthError('DPoP proof jti has already been used (replay)');
  }

  return jkt;
}
