// CONTRACT.md §10.4 — the optional session-revocation feed poller (contract
// 1.44; AXIAM threats T-39 and T-143).
//
// WHAT THIS NARROWS, AND WHAT IT IS NOT
//
// An AXIAM access token is self-contained and valid for up to fifteen minutes,
// and the §10 guard verifies it locally. A logout, a role removal or an
// account disable therefore does not reach a token already in a caller's hands
// until it expires — §10.2 records that, and the documented answer has been
// "route the decision through gRPC introspection instead", which is correct and
// costs a round trip PER REQUEST.
//
// A deployment may publish `GET /oauth2/revocations`: the base64url-unpadded
// SHA-256 of every session id revoked within the last access-token lifetime. A
// guard that polls it rejects a revoked session within ONE POLL INTERVAL
// instead, for one cacheable fetch per interval.
//
// It is NOT A CONTROL, and every rule below follows from that:
//
//   * Default off. Nothing polls unless a caller attaches one.
//   * Never on the request path. `isRevoked` answers from the cached set and,
//     at most, starts a refresh whose result the NEXT caller sees.
//   * Never fail closed. An unreachable feed, a non-200, a body that does not
//     parse, an `alg` this build does not know — every one behaves exactly as
//     no feed at all. Not as an empty list: an empty list asserts that nothing
//     has been revoked, which is a guard silently honouring no revocations
//     while appearing to honour them.
//   * It only ever rejects. Every §10.1 rule runs first and still decides.
//   * A token with no `sid` is never matched. There is no session behind a
//     client-credentials token, an RPT or a token exchange, and hashing `jti`
//     instead would match nothing while looking like it worked.

import { createHash } from 'node:crypto';

/**
 * The only digest the feed publishes, and the only one this poller accepts.
 *
 * A document naming anything else is treated as unusable — exactly as an
 * unreachable feed is — rather than as a list of entries that happen not to
 * match. Silently matching nothing is how a guard ends up reporting that it
 * honours revocations while honouring none.
 */
const SUPPORTED_ALG = 'SHA-256';

/** The shortest interval a caller may configure (§10.4 rule 2), in ms. */
export const MIN_POLL_INTERVAL_MS = 15_000;

/** The default interval, and the one §10.4 recommends, in ms. */
export const DEFAULT_POLL_INTERVAL_MS = 30_000;

/**
 * The largest number of entries kept in the cache (§10.4 rule 2).
 *
 * The server bounds the document by its own revocation rate over one token
 * lifetime, so this is defence against a server that stops doing so — a cache
 * with no ceiling is an allocation an unauthenticated endpoint controls.
 * Overflow drops the WHOLE set rather than truncating it: a truncated set is a
 * guard that admits some revoked sessions and reports none, which is worse
 * than one that admits all of them and says the feed is unusable.
 */
export const MAX_ENTRIES = 100_000;

/** Options for {@link RevocationFeed}. */
export interface RevocationFeedOptions {
  /** Poll interval in milliseconds. Clamped to {@link MIN_POLL_INTERVAL_MS}. */
  pollIntervalMs?: number;
  /** Injected for tests. Defaults to `globalThis.fetch`. */
  fetchImpl?: typeof fetch;
  /** Injected for tests. Defaults to `Date.now`. */
  now?: () => number;
}

/**
 * A poller for one deployment's revocation feed.
 *
 * Share one instance across the guards that should poll once between them,
 * rather than once each.
 */
export class RevocationFeed {
  readonly #feedUrl: string;
  readonly #pollIntervalMs: number;
  readonly #fetchImpl: typeof fetch;
  readonly #now: () => number;

  /**
   * `undefined` means "never successfully fetched", which is NOT the same as
   * an empty set — and is why this is not a bare `Set`.
   */
  #entries: Set<string> | undefined;
  #lastAttempt: number | undefined;
  /** Collapses a burst of stale-cache callers into one fetch. */
  #inFlight: Promise<void> | undefined;

  constructor(baseUrl: string, options: RevocationFeedOptions = {}) {
    this.#feedUrl = new URL('/oauth2/revocations', baseUrl).toString();
    this.#pollIntervalMs = Math.max(
      options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS,
      MIN_POLL_INTERVAL_MS,
    );
    this.#fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
    this.#now = options.now ?? Date.now;
  }

  /**
   * The feed entry for a `sid`, as the server computes it.
   *
   * Base64url without padding over the claim's EXACT string — never a parsed
   * and re-rendered UUID, or the answer depends on this SDK's parser rather
   * than on the feed.
   */
  static entryFor(sid: string): string {
    return createHash('sha256').update(sid, 'utf8').digest('base64url');
  }

  /**
   * Has this session been revoked, as far as this poller knows?
   *
   * `false` whenever the answer is not a confident yes — a feed never fetched,
   * unreachable, malformed, or simply not listing this session. The caller
   * admits the request in all of those cases, which is §10.4 rule 3 and is the
   * whole reason the feature is safe to turn on.
   *
   * Never blocks on the network beyond the first call: once the cache is warm,
   * a stale cache starts a refresh and this answers from what it currently
   * has.
   */
  async isRevoked(sid: string): Promise<boolean> {
    await this.#refreshIfStale();
    return this.#entries?.has(RevocationFeed.entryFor(sid)) ?? false;
  }

  /** Fetch now, whatever the interval says. For tests, and for warming. */
  async refresh(): Promise<void> {
    this.#inFlight ??= this.#doRefresh().finally(() => {
      this.#inFlight = undefined;
    });
    await this.#inFlight;
  }

  async #refreshIfStale(): Promise<void> {
    const last = this.#lastAttempt;
    if (last !== undefined && this.#now() - last < this.#pollIntervalMs) {
      return;
    }
    await this.refresh();
  }

  async #doRefresh(): Promise<void> {
    this.#lastAttempt = this.#now();
    const fetched = await this.#fetchOnce();
    if (fetched !== undefined) {
      this.#entries = fetched;
    }
    // On failure the previous set is deliberately left in place: a blip must
    // not un-revoke a session the guard already knows about.
  }

  /**
   * One fetch. `undefined` for every kind of failure, which the caller treats
   * identically — see the file header on why "unusable" must not collapse into
   * "empty".
   */
  async #fetchOnce(): Promise<Set<string> | undefined> {
    try {
      const response = await this.#fetchImpl(this.#feedUrl, { method: 'GET' });
      if (!response.ok) {
        return undefined;
      }
      const document: unknown = await response.json();
      if (typeof document !== 'object' || document === null) {
        return undefined;
      }
      const { alg, revoked } = document as { alg?: unknown; revoked?: unknown };
      if (alg !== SUPPORTED_ALG) {
        return undefined;
      }
      if (!Array.isArray(revoked) || revoked.length > MAX_ENTRIES) {
        return undefined;
      }
      return new Set(revoked.filter((e): e is string => typeof e === 'string'));
    } catch {
      return undefined;
    }
  }
}
