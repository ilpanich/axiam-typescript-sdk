// MCP resource-server helpers (CONTRACT.md §28, RFC 9728 + RFC 6750) — the
// ONE §28 implementation both the Express and Fastify surfaces are built on,
// mirroring how `verifyCore.ts` is the one §10 verification path and
// `authzCore.ts` the one §11 decision path.
//
// §28.0: this SDK implements the RESOURCE SERVER's half and nothing else.
// AXIAM is the authorization server and implements none of §28; the MCP
// client's half (parsing a challenge, fetching a document, deciding whether to
// trust the authorization server it names) is deliberately not in this
// contract version, for the same reason §20.3 stops at parsing.
//
// **No operation here performs network I/O**, so §16 (retry) and §9
// (single-flight refresh) do not apply and nothing in this module touches the
// SDK client's own session. All three operations are pure local computation,
// like `oidcBegin` (§12.1) and `umaParseChallenge` (§20.5).
//
// **Nothing here is a source of truth about a token.** The document is a claim
// a resource server publishes about itself; the challenge is a hint it gives a
// caller that already failed. Whether a request is authorized stays §10.1's
// and §11's decision, unchanged and unreachable from here.

import type { Request as ExpressRequest, Response as ExpressResponse, Router } from 'express';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { ReasonCode } from '../core/authz.js';
import { ValidationError } from '../management/errors.js';
import { extractCredential } from './cookieHeader.js';

/**
 * RFC 9728 §3.1's well-known prefix — the segment inserted between a
 * resource's authority and its path to reach the document that describes it.
 */
export const PROTECTED_RESOURCE_METADATA_PREFIX = '/.well-known/oauth-protected-resource';

/**
 * The three hosts §28.2 rule 2 lets an `http` URL use, and the only ones.
 *
 * They are AXIAM's RFC 8252 §7.3 loopback hosts, reused verbatim. There is
 * deliberately no flag, environment variable or debug build that widens this:
 * a resource server reachable over plaintext on a routable host publishes an
 * identifier an attacker can impersonate.
 */
const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(['127.0.0.1', '[::1]', 'localhost']);

/** RFC 6750 §3.1's three error codes — the complete vocabulary a challenge may name (§28.4). */
export type BearerChallengeError = 'invalid_request' | 'invalid_token' | 'insufficient_scope';

const BEARER_CHALLENGE_ERRORS: ReadonlySet<string> = new Set<BearerChallengeError>([
  'invalid_request',
  'invalid_token',
  'insufficient_scope',
]);

// ---------------------------------------------------------------------------
// Refusals (§28.2, §28.4, §28.5) — always `ValidationError`, never a new type
// ---------------------------------------------------------------------------

/**
 * Raise §28's refusal.
 *
 * §28.6 pins the error taxonomy: "§28's refusals are `ValidationError`; no new
 * type". This SDK's {@link ValidationError} is §27.4 rule 7's sub-type of
 * `NetworkError`, so `status` names the HTTP code an AXIAM server would answer
 * with for the same rejected field — **400** — even though no server was asked
 * and no request was made. `operation` names the §28 operation that refused,
 * the way a management refusal names `users.get`.
 */
function refuse(operation: string, field: string, message: string): never {
  throw new ValidationError(operation, 400, `${field}: ${message} (CONTRACT.md §28)`, [
    { field, message },
  ]);
}

// ---------------------------------------------------------------------------
// Character classes (RFC 6749 Appendix A) — §28.2 rule 5, §28.4
// ---------------------------------------------------------------------------

/** `NQCHAR`: `%x21` / `%x23`–`%x5B` / `%x5D`–`%x7E`. No space, no `"`, no `\`, no control, no non-ASCII. */
function isNqchar(code: number): boolean {
  return code === 0x21 || (code >= 0x23 && code <= 0x5b) || (code >= 0x5d && code <= 0x7e);
}

/** `NQSCHAR`: `NQCHAR` plus the space (`%x20`). */
function isNqschar(code: number): boolean {
  return code === 0x20 || isNqchar(code);
}

function isAll(value: string, predicate: (code: number) => boolean): boolean {
  for (let i = 0; i < value.length; i += 1) {
    if (!predicate(value.charCodeAt(i))) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Absolute-URI parsing (§28.2 rules 1, 2, 3, 7)
// ---------------------------------------------------------------------------

/**
 * `scheme://authority[path][?query][#fragment]`, matched against the caller's
 * string exactly as given.
 *
 * Deliberately not `new URL()`: that parser *normalises* — it lowercases the
 * host, resolves `..` segments, appends a path to an authority-only URL and
 * re-encodes. §28.2 forbids adjusting a value to make it pass, and §28.3
 * derives the document's own path from this string, so what is validated must
 * be what was written.
 */
const ABSOLUTE_URI = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?#]*)([^?#]*)(\?[^#]*)?(#[\s\S]*)?$/;

/** The pieces of an absolute URI, sliced out of the caller's string without normalisation. */
interface ParsedUri {
  /** The scheme, verbatim (compared case-insensitively, stored as written). */
  scheme: string;
  /** The authority, verbatim — `userinfo@host:port` included. */
  authority: string;
  /** The path component: empty, or starting with `/`. A trailing slash is preserved. */
  path: string;
  /** True when the string carried a `?`, even an empty one. */
  hasQuery: boolean;
  /** True when the string carried a `#`, even an empty one. */
  hasFragment: boolean;
}

function parseAbsoluteUri(raw: string): ParsedUri | undefined {
  const match = ABSOLUTE_URI.exec(raw);
  if (!match) return undefined;
  const authority = match[2] ?? '';
  if (authority === '') return undefined;
  return {
    scheme: match[1] ?? '',
    authority,
    path: match[3] ?? '',
    hasQuery: match[4] !== undefined,
    hasFragment: match[5] !== undefined,
  };
}

/**
 * The host inside an authority: `userinfo@` stripped, port stripped, an IPv6
 * literal's brackets kept (so `[::1]` compares as §28.2 rule 2 spells it).
 *
 * Stripping `userinfo` is what makes `http://localhost@evil.example.com/` a
 * refusal rather than a loopback pass — the host there is `evil.example.com`.
 */
function hostOf(authority: string): string {
  const at = authority.lastIndexOf('@');
  const hostport = at >= 0 ? authority.slice(at + 1) : authority;
  if (hostport.startsWith('[')) {
    const close = hostport.indexOf(']');
    return close < 0 ? hostport : hostport.slice(0, close + 1);
  }
  const colon = hostport.indexOf(':');
  return colon < 0 ? hostport : hostport.slice(0, colon);
}

/** How much of §28.2 rule 1 a particular member is held to — rule 7 and §28.4's `resource_metadata` relax two parts of it. */
interface UriPolicy {
  /** `true` for `resource_documentation` (§28.2 rule 7) and `resource_metadata` (§28.4): a page for a human may be parameterised. */
  allowQuery: boolean;
  /** `true` for the same two members, for the same reason. */
  allowFragment: boolean;
}

const IDENTIFIER: UriPolicy = { allowQuery: false, allowFragment: false };
const LOCATOR: UriPolicy = { allowQuery: true, allowFragment: true };

/**
 * §28.2 rules 1 and 2, applied to one member. Returns the parse so a caller
 * that needs the path (§28.3) does not parse twice.
 */
function requireAbsoluteUri(
  operation: string,
  field: string,
  raw: unknown,
  policy: UriPolicy,
): ParsedUri {
  if (typeof raw !== 'string' || raw === '') {
    refuse(operation, field, 'must be a non-empty absolute URI');
  }
  const parsed = parseAbsoluteUri(raw);
  if (!parsed) {
    refuse(
      operation,
      field,
      `must be an absolute URI with a scheme and an authority, not ${JSON.stringify(raw)}`,
    );
  }
  if (parsed.hasQuery && !policy.allowQuery) {
    refuse(operation, field, 'must carry no query — §28.3 derives the metadata path from it');
  }
  if (parsed.hasFragment && !policy.allowFragment) {
    refuse(operation, field, 'must carry no fragment');
  }
  const scheme = parsed.scheme.toLowerCase();
  if (scheme === 'https') return parsed;
  if (scheme === 'http' && LOOPBACK_HOSTS.has(hostOf(parsed.authority).toLowerCase())) {
    return parsed;
  }
  refuse(
    operation,
    field,
    `must use https — http is accepted only on 127.0.0.1, [::1] or localhost, and ${JSON.stringify(raw)} is neither`,
  );
}

function requireList(operation: string, field: string, value: unknown): readonly unknown[] {
  if (!Array.isArray(value)) refuse(operation, field, 'must be a list');
  return value;
}

// ---------------------------------------------------------------------------
// §28.1 / §28.2 — `protectedResourceMetadata`
// ---------------------------------------------------------------------------

/**
 * The RFC 9728 §2 document, carrying **at most** the five members §28.2
 * permits, in that order, and no others.
 *
 * Member names are the wire names, because this object serializes to the
 * document byte for byte. RFC 9728 defines further members; §28.2 forbids
 * emitting them in this contract version — a member one SDK emits and ten do
 * not is a divergence the cross-SDK review would have to reconcile.
 *
 * Two members are **omitted rather than emitted empty or `null`**:
 * `scopes_supported` when the caller passed no scopes, and
 * `resource_documentation` when the caller passed none.
 */
export interface ProtectedResourceMetadataDocument {
  /** The resource identifier this server publishes for itself — the string an RFC 8707 `resource` parameter carries and the `aud` the guard checks. */
  readonly resource: string;
  /** The issuer identifiers of the authorization servers that guard this resource. At least one, each verbatim. */
  readonly authorization_servers: readonly string[];
  /** The scope tokens this resource server understands, in the caller's order. Omitted when the caller passed none. */
  readonly scopes_supported?: readonly string[];
  /** Always `["header"]` in this contract version — §10's guard reads a bearer credential from the `Authorization` header alone. */
  readonly bearer_methods_supported: readonly string[];
  /** A human-readable documentation page. Omitted when the caller passed none; never `null`. */
  readonly resource_documentation?: string;
}

/**
 * The arguments of §28.1's `protected_resource_metadata`, as one options
 * object — this SDK's idiom for a constructor with five inputs, and the shape
 * `RequireAccessOptions` and `OidcLoginOptions` already use. The canonical
 * order is preserved in the declaration so a port author can read the two
 * side by side.
 */
export interface ProtectedResourceMetadataOptions {
  /** The resource identifier. Absolute, `https` (or `http` on a loopback host), with no query and no fragment. A trailing slash is significant. */
  resource: string;
  /** The issuer identifiers of the authorization servers guarding it — at least one, no duplicates, no query, no fragment. */
  authorizationServers: readonly string[];
  /** The scope tokens this resource server understands. Order is preserved, duplicates are refused, and an empty list omits the member. */
  scopesSupported: readonly string[];
  /** Defaults to `["header"]`, and `["header"]` is the only accepted value in this contract version. */
  bearerMethodsSupported?: readonly string[];
  /** Optional documentation page for a human. May carry a query and a fragment; omitted from the document when absent. */
  resourceDocumentation?: string;
}

/**
 * What {@link protectedResourceMetadata} returns: the document, the path it is
 * served at, and the URL that path resolves to.
 *
 * {@link ProtectedResourceMetadata.metadataUrl} exists so that the guard's
 * `resourceMetadataUrl` option is fed from the helper that derived it rather
 * than retyped — retyping is how the two come to disagree, and a challenge
 * pointing at a document that is not this resource server's is worse than no
 * challenge at all.
 */
export interface ProtectedResourceMetadata {
  /** The RFC 9728 §2 document, ready to serialize. */
  readonly document: ProtectedResourceMetadataDocument;
  /** The absolute path the document is served at, derived from the resource per §28.3 — never chosen. */
  readonly metadataPath: string;
  /** {@link ProtectedResourceMetadata.metadataPath} resolved against the resource's scheme and authority. Feed this to the guard's `resourceMetadataUrl`. */
  readonly metadataUrl: string;
}

/**
 * `protectedResourceMetadata(options)` (CONTRACT.md §28.1) — build and
 * validate the RFC 9728 protected-resource metadata document this server
 * publishes about itself, and derive the path and URL it is served at.
 *
 * @remarks
 * **Validation happens here and it refuses; it never repairs.** Every §28.2
 * rule is checked before any route exists and before any request is served,
 * and a violation throws `ValidationError`. Nothing is normalised, trimmed,
 * lowercased or re-encoded to make it pass: a value that needs adjusting is a
 * configuration mistake an operator fixes in one line, and a helper that
 * quietly fixed it would publish a document describing a resource server that
 * does not exist.
 *
 * **Nothing in the document may come from a request** (§28.2 rule 8). Both
 * `resource` and `authorizationServers` are configuration; this SDK offers no
 * option to build either from the `Host` header, the `Forwarded`/`X-Forwarded-*`
 * family or the request URL, because a document assembled from the request is
 * a document an attacker can point at an authorization server of their
 * choosing — the whole handshake redirected with one header.
 *
 * @example
 * ```ts
 * const metadata = protectedResourceMetadata({
 *   resource: 'https://mcp.example.com/mcp',
 *   authorizationServers: ['https://axiam.example.com'],
 *   scopesSupported: ['mcp:read', 'mcp:tools'],
 * });
 * metadata.metadataPath; // '/.well-known/oauth-protected-resource/mcp'
 * metadata.metadataUrl;  // 'https://mcp.example.com/.well-known/oauth-protected-resource/mcp'
 * ```
 *
 * @throws ValidationError when any §28.2 rule is violated.
 */
export function protectedResourceMetadata(
  options: ProtectedResourceMetadataOptions,
): ProtectedResourceMetadata {
  const op = 'protectedResourceMetadata';

  // Rule 1 + rule 2.
  const resource = options.resource;
  const parsed = requireAbsoluteUri(op, 'resource', resource, IDENTIFIER);

  // Rule 3 + rule 4: at least one entry, each an issuer verbatim, no duplicates.
  const servers = requireList(op, 'authorization_servers', options.authorizationServers);
  if (servers.length === 0) {
    refuse(
      op,
      'authorization_servers',
      'must name at least one authorization server — a document that names none answers none of the question the client asked',
    );
  }
  const seenServers = new Set<string>();
  const authorizationServers: string[] = [];
  for (const entry of servers) {
    requireAbsoluteUri(op, 'authorization_servers', entry, IDENTIFIER);
    const issuer = entry as string;
    if (seenServers.has(issuer)) {
      refuse(op, 'authorization_servers', `duplicate entry ${JSON.stringify(issuer)}`);
    }
    seenServers.add(issuer);
    authorizationServers.push(issuer);
  }

  // Rule 5: NQCHAR tokens, order preserved, duplicates refused, empty omits.
  const scopes = requireList(op, 'scopes_supported', options.scopesSupported);
  const seenScopes = new Set<string>();
  const scopesSupported: string[] = [];
  for (const scope of scopes) {
    if (typeof scope !== 'string' || scope === '' || !isAll(scope, isNqchar)) {
      refuse(
        op,
        'scopes_supported',
        `${JSON.stringify(scope)} is not a scope token — one or more NQCHAR (no space, no '"', no '\\', no control character, no non-ASCII)`,
      );
    }
    if (seenScopes.has(scope)) refuse(op, 'scopes_supported', `duplicate scope ${JSON.stringify(scope)}`);
    seenScopes.add(scope);
    scopesSupported.push(scope);
  }

  // Rule 6: exactly ["header"].
  const methods = requireList(
    op,
    'bearer_methods_supported',
    options.bearerMethodsSupported ?? ['header'],
  );
  if (methods.length !== 1 || methods[0] !== 'header') {
    refuse(
      op,
      'bearer_methods_supported',
      `must be exactly ["header"] in this contract version — §10's guard reads a bearer credential from the Authorization header alone, so ${JSON.stringify(methods)} would describe behaviour this SDK does not have`,
    );
  }

  // Rule 7: absolute URL, query and fragment permitted, omitted when absent.
  const documentation = options.resourceDocumentation;
  if (documentation !== undefined) {
    requireAbsoluteUri(op, 'resource_documentation', documentation, LOCATOR);
  }

  // §28.2 fixes the member order. Insertion order is what `JSON.stringify`
  // emits, so the conditional spreads sit where the omitted members belong.
  const document: ProtectedResourceMetadataDocument = Object.freeze({
    resource,
    authorization_servers: Object.freeze(authorizationServers) as readonly string[],
    ...(scopesSupported.length > 0
      ? { scopes_supported: Object.freeze(scopesSupported) as readonly string[] }
      : {}),
    bearer_methods_supported: Object.freeze(['header']) as readonly string[],
    ...(documentation !== undefined ? { resource_documentation: documentation } : {}),
  });

  const metadataPath = deriveMetadataPath(parsed.path);
  return Object.freeze({
    document,
    metadataPath,
    metadataUrl: `${parsed.scheme}://${parsed.authority}${metadataPath}`,
  });
}

/**
 * §28.3's derivation: RFC 9728 §3.1 inserts the well-known segment between the
 * authority and the path. An empty path and a bare `/` both reach the root
 * form; anything else is appended, **trailing slash included** — it is part of
 * the identifier a client compares, and two resources that differ only by it
 * are two resources.
 */
function deriveMetadataPath(resourcePath: string): string {
  if (resourcePath === '' || resourcePath === '/') return PROTECTED_RESOURCE_METADATA_PREFIX;
  return PROTECTED_RESOURCE_METADATA_PREFIX + resourcePath;
}

// ---------------------------------------------------------------------------
// §28.4 — `bearerChallenge`
// ---------------------------------------------------------------------------

/** The arguments of §28.1's `bearer_challenge`, in canonical order. */
export interface BearerChallengeOptions {
  /** The document's URL — the one parameter that is always present. May carry a query and a fragment. */
  resourceMetadataUrl: string;
  /** One of RFC 6750 §3.1's three codes, or absent when the request carried no authentication information at all. */
  error?: BearerChallengeError;
  /**
   * A human-readable description, for an application building **its own**
   * challenge for its own 400.
   *
   * The SDK's guards never set it: expired, not yet valid, wrong tenant, wrong
   * audience, bad signature, `alg` confusion, an unsatisfiable `cnf`, a revoked
   * `sid` — §28.4 makes all of them `invalid_token`, indistinguishably. Every
   * distinction a 401 draws for an unauthenticated stranger is an oracle.
   */
  errorDescription?: string;
  /** The scope the route asked for, verbatim — one or more tokens joined by a single space. */
  scope?: string;
}

/**
 * `bearerChallenge(options)` (CONTRACT.md §28.4) — build the **value** of a
 * `WWW-Authenticate` header, never the whole header line and never a map. The
 * caller sets the header.
 *
 * @remarks
 * Parameters appear in a fixed order — `error`, `error_description`, `scope`,
 * `resource_metadata` — separated by exactly `, `. `resource_metadata` is
 * always present; the other three are omitted when not given.
 *
 * **Every value is quoted and no value is ever escaped.** RFC 6750 §3 restricts
 * each parameter to a character set that cannot contain `"` or `\`, so a value
 * needing an escape is a value that does not belong in a challenge: this
 * function refuses it rather than escaping, truncating or stripping it. A
 * challenge is built from the code's own constants and a route's own
 * configuration, so an invalid one is a programming error, not a runtime
 * condition to degrade around.
 *
 * @example
 * ```ts
 * bearerChallenge({ resourceMetadataUrl: metadata.metadataUrl });
 * // Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
 *
 * bearerChallenge({ resourceMetadataUrl: metadata.metadataUrl, error: 'insufficient_scope', scope: 'mcp:tools' });
 * // Bearer error="insufficient_scope", scope="mcp:tools", resource_metadata="https://…/mcp"
 * ```
 *
 * @throws ValidationError when any parameter is outside RFC 6750's syntax.
 */
export function bearerChallenge(options: BearerChallengeOptions): string {
  const op = 'bearerChallenge';
  const params: string[] = [];

  if (options.error !== undefined) {
    if (!BEARER_CHALLENGE_ERRORS.has(options.error)) {
      refuse(
        op,
        'error',
        `must be one of invalid_request, invalid_token, insufficient_scope — RFC 6750 §3.1 defines no others, and ${JSON.stringify(options.error)} is not among them`,
      );
    }
    params.push(`error="${options.error}"`);
  }

  if (options.errorDescription !== undefined) {
    const description = options.errorDescription;
    if (typeof description !== 'string' || description === '' || !isAll(description, isNqschar)) {
      refuse(
        op,
        'error_description',
        'must be one or more NQSCHAR (no \'"\', no \'\\\', no control character, no non-ASCII) — a value needing an escape does not belong in a challenge',
      );
    }
    params.push(`error_description="${description}"`);
  }

  if (options.scope !== undefined) {
    const scope = options.scope;
    if (typeof scope !== 'string' || scope === '') {
      refuse(op, 'scope', 'must be one or more scope tokens joined by a single space');
    }
    for (const token of scope.split(' ')) {
      if (token === '' || !isAll(token, isNqchar)) {
        refuse(
          op,
          'scope',
          `${JSON.stringify(scope)} is not a space-joined list of scope tokens — no leading, trailing or doubled space, and no empty token`,
        );
      }
    }
    params.push(`scope="${scope}"`);
  }

  const url = options.resourceMetadataUrl;
  requireAbsoluteUri(op, 'resource_metadata', url, LOCATOR);
  if (!isAll(url, isNqchar)) {
    refuse(
      op,
      'resource_metadata',
      'must carry no \'"\', no \'\\\', no space and no control character — a correctly encoded URL cannot, so one that does has not been encoded',
    );
  }
  params.push(`resource_metadata="${url}"`);

  return `Bearer ${params.join(', ')}`;
}

// ---------------------------------------------------------------------------
// §28.5 — the `resourceMetadataUrl` guard option
// ---------------------------------------------------------------------------

/**
 * The two guard settings §28.5 reads. Satisfied structurally by
 * `VerifiableSession`, which is where an integrator actually sets them; taken
 * as its own shape so `serveProtectedResourceMetadata` can cross-check a guard
 * without depending on the verification core.
 */
export interface McpGuardConfig {
  /** §10.1 row 6's expected audience, under the name this SDK already gives it. §28 adds no second audience option. */
  expectedAudience?: string;
  /** §28.5's option: the URL of this resource server's metadata document. Setting it is what turns §28 on. */
  resourceMetadataUrl?: string;
}

/**
 * The §28 challenge values a guard emits, all built once at guard-construction
 * time so that an invalid one is a startup failure rather than a surprise on
 * the 401 path.
 *
 * `undefined` where {@link McpGuardConfig.resourceMetadataUrl} is unset, which
 * is how "§28 is off" stays byte-for-byte indistinguishable from "§28 is
 * absent" (§28.5 rule 1).
 */
export interface McpGuardChallenges {
  /** §28.4 vector 1 — the request carried **no** authentication information, so RFC 6750 §3 says not to name an error. */
  readonly noCredential: string;
  /** §28.4 vector 2 — a credential was presented and rejected. The only thing the 401 ever says about why. */
  readonly invalidToken: string;
  /** §28.4 vector 3 — present only where the route named a scope; emitted on a `no_grant` denial and nowhere else. */
  readonly insufficientScope?: string;
  /** The document's path, exempted from authentication by the §10 guard (§28.3 rule 2). */
  readonly metadataPath: string;
}

/**
 * Validate a guard's §28 configuration and precompute the challenges it will
 * emit. Called by every guard factory at construction time — route-setup time,
 * never per-request.
 *
 * @remarks
 * Returns `undefined` when `resourceMetadataUrl` is unset: §28 is opt-in, and
 * with the option absent the guard behaves exactly as it did before §28
 * existed — no header on any response, no status changed, no body changed.
 *
 * **`expectedAudience` is mandatory once `resourceMetadataUrl` is set**, and
 * the refusal names both options. A resource server that publishes "tokens for
 * me carry this `aud`" and then does not check `aud` has published a claim it
 * does not honour, and a token minted for a *different* resource server opens
 * it. That is the confusion RFC 8707 exists to prevent, so this is a refusal
 * rather than a warning.
 *
 * @param guard - the session the guard was built from.
 * @param operation - the guard factory's name, so the refusal says which guard refused.
 * @param scope - the route's `scope` argument, where it has one (§28.5 rule 5).
 * @throws ValidationError when `resourceMetadataUrl` is set without an expected audience, or when either it or `scope` is outside §28.4's syntax.
 */
export function mcpGuardChallenges(
  guard: McpGuardConfig,
  operation: string,
  scope?: string,
): McpGuardChallenges | undefined {
  const resourceMetadataUrl = guard.resourceMetadataUrl;
  if (resourceMetadataUrl === undefined) return undefined;

  if (guard.expectedAudience === undefined || guard.expectedAudience === '') {
    refuse(
      operation,
      'resourceMetadataUrl',
      'requires expectedAudience to be set on the same session (CONTRACT.md §28.5 rule 2) — announcing a resource identifier obliges this server to check that an inbound token\'s `aud` is that identifier, and a resource server that announces itself without checking is opened by a token minted for somebody else',
    );
  }

  const parsed = requireAbsoluteUri(operation, 'resourceMetadataUrl', resourceMetadataUrl, LOCATOR);
  return Object.freeze({
    noCredential: bearerChallenge({ resourceMetadataUrl }),
    invalidToken: bearerChallenge({ resourceMetadataUrl, error: 'invalid_token' }),
    ...(scope !== undefined
      ? {
          insufficientScope: bearerChallenge({
            resourceMetadataUrl,
            error: 'insufficient_scope',
            scope,
          }),
        }
      : {}),
    metadataPath: parsed.path === '' ? '/' : parsed.path,
  });
}

/**
 * Pick between §28.4's first two vectors for a 401: `invalid_token` when the
 * request carried a credential, no `error` at all when it carried none.
 *
 * §28.4 is explicit that the absent `error` is not an oversight — RFC 6750 §3
 * says a resource server SHOULD NOT name an error code when the request
 * carried no authentication information, because no credential is not a bad
 * credential, and a client has to be able to tell the two apart.
 *
 * @internal
 */
export function challengeFor401(
  challenges: McpGuardChallenges,
  cookieHeader: string | undefined,
  authorizationHeader: string | undefined,
): string {
  return extractCredential(cookieHeader, authorizationHeader)
    ? challenges.invalidToken
    : challenges.noCredential;
}

/**
 * §28.5 rule 5: the one class of 403 that carries a challenge, and only it.
 *
 * A `no_grant` denial on a route that named a scope means *ask for more*,
 * which is exactly what a challenge invites a client to do. A `denied_by_rule`
 * denial means *an administrator has already decided*, and challenging on it
 * sends an MCP client all the way around the authorization loop to arrive at
 * the identical 403. An absent or unrecognised `reason_code` — an older server,
 * a value this SDK predates — is not eligible either: §11 rule 9 requires an
 * unknown code to leave the outcome alone, and the outcome here is a
 * header-free 403.
 *
 * @internal
 */
export function challengeFor403(
  challenges: McpGuardChallenges | undefined,
  reasonCode: string | undefined,
): string | undefined {
  if (!challenges?.insufficientScope) return undefined;
  return reasonCode === ReasonCode.NO_GRANT ? challenges.insufficientScope : undefined;
}

/**
 * Is this request the unauthenticated `GET` of the metadata document?
 *
 * §28.3 rule 2 requires the document to be reachable with no credential of any
 * kind, and requires the SDK to exempt the path explicitly where the §10 guard
 * is applied globally — which is the normal Express `app.use(...)` and Fastify
 * `preHandler` arrangement. A document that 401s cannot start the handshake it
 * exists to start: the client would be holding a 401 and being told to go read
 * a page that answers 401.
 *
 * The exemption is derived from `resourceMetadataUrl`, so it exists only where
 * §28 is configured and covers exactly the one path that option names.
 *
 * @internal
 */
export function isMetadataDocumentRequest(
  challenges: McpGuardChallenges | undefined,
  method: string | undefined,
  url: string | undefined,
): boolean {
  if (!challenges || typeof url !== 'string') return false;
  const verb = (method ?? '').toUpperCase();
  if (verb !== 'GET' && verb !== 'HEAD') return false;
  const end = url.search(/[?#]/);
  return (end < 0 ? url : url.slice(0, end)) === challenges.metadataPath;
}

// ---------------------------------------------------------------------------
// §28.3 — `serveProtectedResourceMetadata`
// ---------------------------------------------------------------------------

/**
 * The framework object `serveProtectedResourceMetadata` registers on — §10's
 * table, unchanged: an Express application or router, or a Fastify instance.
 */
export type McpMetadataApp = Router | FastifyInstance;

/**
 * `serveProtectedResourceMetadata(app, metadata, guard?)` (CONTRACT.md §28.3) —
 * register the one `GET` route that serves the document, on the framework's
 * own router, and return the same metadata value so the guard's
 * `resourceMetadataUrl` can be fed from it.
 *
 * @remarks
 * **The path is derived, not chosen**, and **exactly one route is registered.**
 * The root form is not also registered for a resource that has a path: a
 * deployment fronting two resources would then have two helpers competing for
 * the same root path and registration order would decide the loser. A
 * deployment fronting several resources calls this once per resource, and the
 * derived paths cannot collide because each comes from its own resource.
 *
 * The response is `200` with `Content-Type: application/json`, the document as
 * its body, `Cache-Control: public, max-age=3600` and
 * `Access-Control-Allow-Origin: *` — the last because an MCP client running in
 * a browser cannot read the document without it, and it is safe precisely
 * because the response is identical for every caller. It carries no
 * `Access-Control-Allow-Credentials`, which would be asking a browser to attach
 * the user's cookies to a request that has no use for them. Nothing is read
 * from the request, so there is no `Set-Cookie` and no per-caller content, and
 * §3a does not apply: it is a `GET`, and §3a is scoped to state-changing
 * methods and cookie-sourced credentials.
 *
 * **Serving it needs no route ordering.** Where the §10 guard is mounted
 * globally it exempts this exact path itself, from the `resourceMetadataUrl`
 * it was configured with — so the route works whether it is registered before
 * or after the guard, and on Fastify, where a `preHandler` hook applies
 * regardless of registration order.
 *
 * @param app - an Express application/router, or a Fastify instance. Register on the application root: a router mounted under a prefix would serve the document at a path the derived URL does not name.
 * @param metadata - the value {@link protectedResourceMetadata} returned.
 * @param guard - optionally, the session the §10 guard is built from. Passing it is what lets this SDK apply §28.5 rule 3 — see below.
 *
 * @throws ValidationError when `guard` is given and its `resourceMetadataUrl`
 * is not exactly the document's `metadataUrl`, or its `expectedAudience` is not
 * exactly the document's `resource`.
 *
 * Both comparisons are simple string equality (RFC 3986 §6.2.1): no
 * normalisation, no case folding of the host, no trailing-slash tolerance. A
 * trailing slash that differs between the document and the guard is a real
 * misconfiguration that will make a real client's `aud` check fail, and
 * startup is a better place to hear about it than a support ticket. Note that
 * the two strings compared are *different* strings — the resource is
 * `https://mcp.example.com/mcp` and the metadata URL is
 * `https://mcp.example.com/.well-known/oauth-protected-resource/mcp` — so each
 * is compared against its own counterpart.
 *
 * Where the guard is configured in another process this SDK can see only one
 * side and checks nothing; omit the argument there and configure both from one
 * constant, which is what `metadataUrl` is for.
 *
 * @example
 * ```ts
 * const metadata = protectedResourceMetadata({
 *   resource: 'https://mcp.example.com/mcp',
 *   authorizationServers: ['https://axiam.example.com'],
 *   scopesSupported: ['mcp:read', 'mcp:tools'],
 * });
 * const session = {
 *   ...baseSession,
 *   expectedAudience: metadata.document.resource,
 *   resourceMetadataUrl: metadata.metadataUrl,
 * };
 *
 * app.use(axiamMiddleware(session));
 * serveProtectedResourceMetadata(app, metadata, session);
 * ```
 */
export function serveProtectedResourceMetadata(
  app: McpMetadataApp,
  metadata: ProtectedResourceMetadata,
  guard?: McpGuardConfig,
): ProtectedResourceMetadata {
  const op = 'serveProtectedResourceMetadata';

  if (guard) {
    if (guard.resourceMetadataUrl !== metadata.metadataUrl) {
      refuse(
        op,
        'resourceMetadataUrl',
        `is ${JSON.stringify(guard.resourceMetadataUrl)} but this document is published at ${JSON.stringify(metadata.metadataUrl)} — the challenge would point at a document that is not this resource server's`,
      );
    }
    if (guard.expectedAudience !== metadata.document.resource) {
      refuse(
        op,
        'expectedAudience',
        `is ${JSON.stringify(guard.expectedAudience)} but this document announces ${JSON.stringify(metadata.document.resource)} — the document would announce one identifier while the guard checked \`aud\` against another, so every token the flow produced would be refused`,
      );
    }
  }

  // Serialized once: the response is identical for every caller (§28.3 rule 4),
  // so there is nothing per-request to build.
  const body = JSON.stringify(metadata.document);

  if (isFastify(app)) {
    // Fastify appends `; charset=utf-8` to any `*json*` content type that
    // carries no charset parameter, and offers no supported way to suppress
    // it short of writing to `reply.raw` and losing every `onSend` hook. The
    // media type is still `application/json`, which is what §28.3 rule 1 pins
    // and what a client parses; the Express surface emits the bare form.
    app.get(metadata.metadataPath, async (_request: FastifyRequest, reply: FastifyReply) =>
      reply
        .code(200)
        .header('content-type', 'application/json')
        .header('cache-control', 'public, max-age=3600')
        .header('access-control-allow-origin', '*')
        .send(body),
    );
    return metadata;
  }

  app.get(metadata.metadataPath, (_req: ExpressRequest, res: ExpressResponse) => {
    // `res.setHeader`/`res.end` rather than `res.type`/`res.json`: Express
    // appends `; charset=utf-8` to a content type set through its own helper,
    // and §28.3 rule 1 pins the header to `application/json`.
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.end(body);
  });
  return metadata;
}

/**
 * Tell a Fastify instance from an Express application/router.
 *
 * `addHook` is the discriminator: Fastify has it and Express has nothing of
 * the kind, so this never depends on how either library spells `get`.
 */
function isFastify(app: McpMetadataApp): app is FastifyInstance {
  return typeof (app as Partial<FastifyInstance>).addHook === 'function';
}
