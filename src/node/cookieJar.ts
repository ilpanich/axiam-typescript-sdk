// tough-cookie jar + axios wiring (CONTRACT.md §4, D-09).
//
// AXIAM delivers access/refresh tokens exclusively via httpOnly Set-Cookie
// (RESEARCH.md Area 3 — login/refresh response bodies carry NO token
// fields). A Node persona therefore needs an explicit, per-client-instance
// cookie jar so httpOnly cookies persist across requests, and the only way
// to obtain the token values is to read them back out of that jar by name.
//
// Cookie names/paths mirror the server's CSRF/cookie middleware exactly
// (crates/axiam-api-rest/src/middleware/csrf.rs) and the already-shipped
// Rust SDK (the Rust SDK's src/token/manager.rs).

import { CookieJar } from 'tough-cookie';
import { HttpCookieAgent, HttpsCookieAgent } from 'http-cookie-agent/http';
import type { AxiosInstance } from 'axios';
import type { NodeTlsOptions } from '../rest/session.js';

/** The `axiam_access` cookie name (httpOnly, path `/`). */
export const ACCESS_COOKIE = 'axiam_access';
/** The `axiam_refresh` cookie name (httpOnly, path-scoped to `/api/v1/auth/refresh`). */
export const REFRESH_COOKIE = 'axiam_refresh';
/** The `axiam_csrf` cookie name (JS-readable, path `/`). */
export const CSRF_COOKIE = 'axiam_csrf';

/** Construct a fresh, per-client-instance cookie jar (§4 — never process-global). */
export function createJar(): CookieJar {
  return new CookieJar();
}

/**
 * Attach jar-aware agents to an axios instance so the jar persists
 * `Set-Cookie` responses across requests and replays them on subsequent
 * requests to the same origin/path (§4). Mutates and returns the same
 * instance.
 *
 * The agents are constructed HERE rather than via `axios-cookiejar-support`'s
 * `wrapper()`, which used to do it. That wrapper is a thin convenience layer:
 * all cookie handling lives in `http-cookie-agent`'s agents, which it builds
 * for you inside a request interceptor — and that interceptor is hostile to
 * any other agent. It THROWS
 *
 *     axios-cookiejar-support does not support for use with other http(s).Agent.
 *
 * when it finds an `httpsAgent` it did not create, and otherwise replaces it.
 * Since `createSession` attaches an `https.Agent` whenever `customCa` or a
 * §6.1 client certificate is configured, the Node persona could never use
 * either: with TLS material configured every request threw, and there was no
 * seam to pass CA/cert/key through the wrapper's own agent construction.
 *
 * Building the agent ourselves closes that: ONE `HttpsCookieAgent` that is
 * both jar-aware and TLS-configured. Cookie behaviour is unchanged — it is
 * the same agent class the wrapper was constructing, just with the TLS
 * options merged in.
 *
 * @param tls §6/§6.1 TLS material, or undefined for the default trust store.
 *            Never carries `rejectUnauthorized`: strict server verification
 *            is not negotiable (§6).
 */
export function wrapAxios(
  instance: AxiosInstance,
  jar: CookieJar,
  tls?: NodeTlsOptions,
): AxiosInstance {
  // `http-cookie-agent`'s .d.ts resolves tough-cookie through the CJS
  // condition while this file resolves it through the ESM one, so TypeScript
  // sees two structurally identical CookieJar declarations with separate
  // private fields and refuses the assignment. It is the same class at
  // runtime (one tough-cookie install, one instance). Narrow the cast to the
  // jar itself rather than loosening either signature.
  type AgentCookieOptions = NonNullable<ConstructorParameters<typeof HttpCookieAgent>[0]['cookies']>;
  const cookies = { jar } as unknown as AgentCookieOptions;
  instance.defaults.httpAgent = new HttpCookieAgent({ cookies });
  instance.defaults.httpsAgent = new HttpsCookieAgent({ cookies, ...(tls ?? {}) });
  return instance;
}

/**
 * Read a single cookie's value out of the jar by name, for the given URL.
 * This is the ONLY token-source path (RESEARCH.md Area 3 — no JSON-body
 * fallback exists on the wire).
 */
export async function extractCookieValue(
  jar: CookieJar,
  url: string,
  name: string,
): Promise<string | undefined> {
  const cookies = await jar.getCookies(url);
  return cookies.find((c) => c.key === name)?.value;
}
