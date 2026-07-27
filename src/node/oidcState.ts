// OidcStateStore + MemoryOidcStateStore (CONTRACT.md §12.3 rule 1).
//
// STRICTLY OPTIONAL. The nine §12 operations never touch a store: `oidcBegin`
// and `oidcExchange` are stateless by contract, and the caller normally keeps
// `state`/`nonce`/`code_verifier` in its own HTTP session. This store exists
// for the framework glue (`middleware/oidcLogin*`), where a login and its
// callback are two separate HTTP requests with nothing but a `state` value
// linking them.
//
// Semantics mirror the server's `federation_login_state` table exactly:
// 10-minute TTL, single-use consume. That symmetry is deliberate — a reader
// who knows the server side already knows this class.

import { Sensitive } from '../core/index.js';

/**
 * The tuple an {@link OidcStateStore} holds for one in-flight login.
 *
 * @remarks
 * `codeVerifier` stays {@link Sensitive} while stored (§12.5: the verifier is
 * secret for its whole lifetime, "including … in any `OidcStateStore` entry"),
 * so `JSON.stringify()`ing an entry — e.g. into a Redis-backed store — emits
 * `"[SENSITIVE]"` rather than the verifier. A store implementation that needs
 * to persist the value must call `expose()` explicitly and is then responsible
 * for protecting it at rest.
 */
export interface OidcStateEntry {
  /** The `state` value this entry is keyed by. Not a secret (§12.3 rule 2). */
  state: string;
  /** The `nonce` to check the ID token's `nonce` claim against. Not a secret (§12.3 rule 2). */
  nonce: string;
  /** The PKCE verifier for the matching authorization request (§12.5 secret). */
  codeVerifier: Sensitive<string>;
  /** The `redirect_uri` that was sent on the authorization request and must be replayed on exchange. */
  redirectUri: string;
  /** Optional application-owned data, e.g. the page the user was heading to before login. */
  returnTo?: string;
}

/**
 * Optional server-side store for in-flight `oidcBegin` state
 * (CONTRACT.md §12.3 rule 1).
 *
 * @remarks
 * Implement this to back the login/callback handlers with your own storage
 * (Redis, a database, an encrypted cookie). Two invariants are normative:
 *
 * 1. **Single-use.** {@link consume} MUST return the entry *and delete it
 *    atomically*, so a replayed callback cannot reuse a `state`.
 * 2. **Expiry.** An entry older than 10 minutes MUST NOT be returned.
 */
export interface OidcStateStore {
  /** Persist an entry, keyed by its `state`, starting its TTL now. */
  save(entry: OidcStateEntry): Promise<void>;
  /**
   * Atomically fetch **and remove** the entry for `state`. Returns
   * `undefined` when the state is unknown, already consumed, or expired —
   * three cases a caller MUST treat identically (as a failed login), because
   * distinguishing them leaks whether a `state` ever existed.
   */
  consume(state: string): Promise<OidcStateEntry | undefined>;
}

/**
 * The contract-mandated TTL for stored login state: 10 minutes, matching the
 * server's `federation_login_state` row lifetime (D-22, §12.3 rule 1).
 */
export const OIDC_STATE_TTL_MS = 600_000;

/**
 * In-memory reference implementation of {@link OidcStateStore} (§12.3 rule 1).
 *
 * @remarks
 * Per-instance (never process-global), single-use, 10-minute TTL. Expired
 * entries are dropped lazily on {@link consume} and swept opportunistically on
 * {@link save}, so no timer is held and the store needs no shutdown hook — a
 * long-lived `setInterval` would keep a Node process alive and would be a
 * surprising side effect for a library.
 *
 * Suitable for a single-process app and for tests. A multi-instance deployment
 * needs a shared store (Redis, database) — implement {@link OidcStateStore}
 * yourself for that; nothing in the SDK assumes this class.
 *
 * @example
 * ```ts
 * const store = new MemoryOidcStateStore();
 * await store.save({ state, nonce, codeVerifier, redirectUri });
 * const entry = await store.consume(state);   // returns the entry
 * const again = await store.consume(state);   // undefined — single-use
 * ```
 */
export class MemoryOidcStateStore implements OidcStateStore {
  readonly #entries = new Map<string, { entry: OidcStateEntry; expiresAt: number }>();
  readonly #ttlMs: number;

  /**
   * @param ttlMs entry lifetime in milliseconds. Defaults to
   *   {@link OIDC_STATE_TTL_MS} (10 minutes) and is **clamped to it**: a
   *   shorter TTL is honoured (useful in tests), a longer one is reduced,
   *   because §12.3 rule 1 fixes 10 minutes as the maximum.
   */
  constructor(ttlMs: number = OIDC_STATE_TTL_MS) {
    this.#ttlMs = Math.min(ttlMs, OIDC_STATE_TTL_MS);
  }

  /** Number of unexpired entries currently held. Intended for tests and metrics. */
  get size(): number {
    this.#sweep();
    return this.#entries.size;
  }

  /** Persist `entry` under its own `state`, expiring `ttlMs` from now. */
  async save(entry: OidcStateEntry): Promise<void> {
    this.#sweep();
    this.#entries.set(entry.state, { entry, expiresAt: Date.now() + this.#ttlMs });
  }

  /**
   * Atomically return and delete the entry for `state`. Deletion happens
   * before the expiry check, so even an expired hit is removed rather than
   * left to accumulate — and a second call can never return the same entry
   * twice regardless of timing (JavaScript's single-threaded event loop makes
   * this get-then-delete pair genuinely atomic; a store backed by real
   * concurrency must use an atomic primitive such as Redis `GETDEL`).
   */
  async consume(state: string): Promise<OidcStateEntry | undefined> {
    const held = this.#entries.get(state);
    if (!held) {
      return undefined;
    }
    this.#entries.delete(state);
    if (held.expiresAt <= Date.now()) {
      return undefined;
    }
    return held.entry;
  }

  /** Drop every expired entry. Lazy housekeeping — no background timer. */
  #sweep(): void {
    const now = Date.now();
    for (const [state, held] of this.#entries) {
      if (held.expiresAt <= now) {
        this.#entries.delete(state);
      }
    }
  }
}
