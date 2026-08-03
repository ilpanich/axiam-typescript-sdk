# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security — BREAKING

- **The §10 route guard now applies the complete CONTRACT §10.1 "minimum
  local-verification set".** §10.1 is a new normative section written because
  `SEC-071` and `SEC-080` were the same defect found independently in two SDKs:
  each verified a *different subset* of the token, and each subset looked
  complete in isolation. This SDK was audited against the stated complete set
  for the first time; two rules were missing and are now enforced. Every §10 /
  §11 surface routes through one call — `axiamMiddleware` (Express),
  `axiamPlugin` (Fastify), `requireAuth`/`requireAccess`/`requireRole`, and the
  NestJS `AxiamGuard` all consume the identity `authenticateRequest` injects,
  and none verifies anything itself.

  This **tightens acceptance** and is therefore breaking, as §10.1 requires it
  to be called out. A token minted by the AXIAM server is unaffected — it
  always carries `exp` and never a future `nbf` — but a guard fed tokens from
  another signer sharing the organization JWKS may start rejecting what it used
  to accept. That is the intent.

  - **`exp` is now REQUIRED (rule 2).** `jose` validates `exp` only
    `if (payload.exp !== undefined)`, so a token minted with **no** `exp` at
    all — a permanent credential — previously verified. `requiredClaims:
    ['exp']` is now passed explicitly. (A present-but-non-numeric `exp` was
    already rejected by `jose`'s own type check.) This is precisely the
    SEC-080 shape.
  - **Clock skew is now a named, bounded constant (rule 7).** `jose` defaults
    `clockTolerance` to `0`; the guard now passes the exported
    `CLOCK_SKEW_LEEWAY_SEC` at the contract's RECOMMENDED 60 seconds, applied
    to both `exp` and `nbf`. It is deliberately not operator-configurable, so
    it can never be widened to an unbounded value. Note this makes the `exp`
    check 60 s *more* tolerant than before.
  - `Verifier.verifyAccessToken(token)` gains a **required second argument**,
    `AccessTokenExpectations`, carrying the tenant it must assert (rule 4) plus
    the optional issuer/audience expectations. Callers that invoked the
    verifier directly must pass it; consumers using `axiamMiddleware` /
    `axiamPlugin` are unaffected, since the middleware builds it from the
    session.
  - `nbf` (rule 3), the `alg`-pinned signature check (rule 1) and the
    `tenant_id` assertion (rule 4) were already correct and are unchanged:
    `jose` honours `nbf` when present; `algorithms: ['EdDSA']` is checked
    against the JWS protected header *before* `jose` invokes the remote key-set
    resolver, so `alg: none` and an HS-signed token bearing an EdDSA `kid` are
    both rejected without a key lookup; and `authenticateRequest` already
    compared `tenant_id` against the session's configured tenant. Rule 4 is now
    additionally enforced inside `verifyAccessToken` itself, so a
    caller-supplied `Verifier` implementation cannot be the only thing standing
    between a cross-tenant token and the application.

### Added

- **Conditional issuer/audience expectations (CONTRACT §10.1 rules 5 and 6).**
  New `AxiamClientOptions.expectedIssuer` and
  `AxiamClientOptions.expectedAudience`, surfaced on `SharedSession` /
  `VerifiableSession` and consumed by the §10 guard. Both are optional and
  unset by default — the rules are explicitly conditional on configuration, and
  the SDK never hardcodes an expected issuer. When set, a mismatch is rejected,
  and the corresponding claim additionally becomes required (an absent `aud`
  does not "contain" the expected audience).
- **`Verifier.verifySignatureOnlyUnchecked(token)`** — the §10.1 raw
  signature-only primitive, for integrators deliberately implementing their own
  policy. No `exp` requirement, no `nbf`/`tenant_id`/`iss`/`aud` check. The
  `Unchecked` suffix is the contract's reference spelling, chosen so the
  omission is obvious at the call site. It is not, and must not become, the
  documented guard entry point.
- `assertTenantClaim` and `CLOCK_SKEW_LEEWAY_SEC` are exported from
  `axiam-sdk/node` and `axiam-sdk/middleware`, so a consumer writing their own
  guard on top of `Verifier` applies the same policy the middleware does.
- `test/node/localVerificationSet.test.ts` — the complete §10.1 required
  negative-test set, asserted against **both** local-verification entry points
  (the verifier and the middleware guard): expired; no `exp`; non-numeric
  `exp`; future `nbf`; different tenant; no `tenant_id`; no configured tenant;
  `alg: none`; HS-signed token bearing the EdDSA `kid`; foreign signature; plus
  issuer-mismatch and audience-mismatch cases for the newly-configurable
  expectations, and proof that the raw primitive waves through exactly what the
  guard rejects.
- CONTRACT.md in this repository is re-synced with the upstream
  `ilpanich/axiam` copy: §10.1 is vendored verbatim.

### Added

- Add `verifyWebhook` webhook-signature verifier (CONTRACT.md §13, T-145), reachable from the
  Node-only `axiam-sdk/node` subpath. Verifies the server's Stripe-style signed-timestamp
  `X-Axiam-Signature: t=<unix>,v1=<hex>` scheme — HMAC-SHA256 over `<timestamp>.<raw_body>`,
  compared in **constant time** (`crypto.timingSafeEqual` over the decoded MAC bytes, never `==`
  on hex strings), with a two-sided 300s-default freshness window (rejects a future-dated `t=` as
  well as a stale one) and a `now` injection seam for tests. Accepts the raw body as
  `Buffer`/`Uint8Array`/string only — re-serializing parsed JSON before verifying breaks the MAC,
  documented in the README alongside the Express `express.raw()`/`verify`-callback workaround.
  Failures raise a typed `WebhookVerifyError` with a stable `reason` code that never surfaces the
  expected or computed signature.

### Fixed

- Repin `amqplib` from the mis-pinned `^2.0.1` to `^0.10.9`, matching the vendored
  `@types/amqplib` range (SEC-078, an SDK-Q06 regression). Add a `npm ls amqplib` CI gate so a
  future pin that can't resolve, or that drifts out of the range the bundled types are built
  against, fails the build instead of surfacing later as a silent install or type mismatch.

## [1.0.0-alpha23] - 2026-08-02

### Fixed

- Make customCa and §6.1 client certificates usable in the Node persona

## [1.0.0-alpha21] - 2026-07-30

### Added

- Add OIDC/SSO relying-party helpers (CONTRACT §12)

### Changed

- Re-sync vendored CONTRACT.md to contract 1.6
- Add regression coverage for CSRF resync after refresh (05b9b8f)
- Bump bufbuild/buf-action from 1.4.0 to 1.5.0
- Bump coverallsapp/github-action from 2.3.6 to 2.3.8
- Bump jsdom from 29.1.1 to 30.0.0
- Bump the minor-patch group with 2 updates
- Re-sync vendored CONTRACT.md to contract 1.5

### Fixed

- Resync CSRF token after refresh, both explicit and reactive (H8 SDK bench)

## [1.0.0-alpha19] - 2026-07-25

### Changed

- Bump fast-uri

## [1.0.0-alpha18] - 2026-07-24

### Changed

- Bump github/codeql-action from 3 to 4 (#19)
- Bump actions/checkout from 7.0.0 to 7.0.1 (#20)
- Bump actions/setup-node from 6.4.0 to 7.0.0 (#21)
- Ratchet vitest thresholds toward current levels (#23)

## [1.0.0-alpha16] - 2026-07-22

### Added

- Add UserInfoService/GetUserInfo (getUserInfo, CONTRACT §1.1)

### Changed

- Vendor userinfo.proto + CONTRACT 1.3 (§1.1 gRPC userinfo)

## [1.0.0-alpha15] - 2026-07-21

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha12.

## [1.0.0-alpha12] - 2026-07-19

### Fixed

- Supply organization context for login/refresh (CONTRACT §5.1) (#18)

## [1.0.0-alpha11] - 2026-07-18

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha10.

## [1.0.0-alpha10] - 2026-07-18

### Changed

- Add organization context to client options (login + refresh) (#17)

## [Unreleased]

### Added

- OIDC / SSO relying-party helpers (CONTRACT.md §12, adopting contract 1.4): nine new
  operations on a Node-only `OidcClient` reachable from the `axiam-sdk/node` subpath —
  `oidcDiscover`, `oidcBegin`, `oidcExchange`, `oidcRefresh`, `loginClientCredentials`,
  `introspect`, `revoke`, `ssoStart`, `ssoComplete` — giving a backend everything it needs
  to offer "Login with AXIAM" (authorization code + PKCE), to authenticate itself as a
  service account, to introspect/revoke tokens, and to drive the server's upstream-IdP
  federation endpoints. PKCE is **S256-only** (`plain` is not implemented) with the RFC 7636
  Appendix B vector covered by a unit test; `state`/`nonce` are 256-bit CSPRNG values; the
  discovery document is cached per normalized origin (TTL ≥ 5 min) with concurrent callers
  sharing a single in-flight fetch. Every returned `id_token` is validated in full before an
  `OidcTokenSet` is constructed (`EdDSA` only, `kid`-selected Ed25519 signature against the
  document's `jwks_uri`, exact-match `iss`, `aud`/`azp`, ≤ 60 s clock skew, constant-time
  `nonce`), and any failure raises `AuthError` with a stable `reason` code while discarding
  the whole token set. `oidcRefresh` runs under the existing single-flight refresh guard
  (CONTRACT.md §9) and stays distinct from the cookie-session `refresh()`; `ssoComplete`
  goes through the §4 cookie jar, since its session arrives as `Set-Cookie`. They reuse the
  existing transport, error mapper, `Sensitive<T>` wrapper and JWKS verifier — no new runtime
  dependency (`node:crypto` covers CSPRNG, SHA-256 and base64url).
- `OidcStateStore` interface plus an opt-in `MemoryOidcStateStore` reference implementation
  (10-minute TTL, single-use `consume(state)`, mirroring the server's `federation_login_state`
  semantics). The core operations remain fully usable without one: `oidcBegin`/`oidcExchange`
  never store `state`, `nonce` or `code_verifier` inside the SDK — the caller owns that state
  (CONTRACT.md §12.3 rule 1).
- "Login with AXIAM" framework glue on the `axiam-sdk/middleware` subpath:
  `oidcLoginHandlers(options)` returning `{ login, callback }` Express handlers, and
  `oidcLoginPlugin(options)` registering the same two routes in Fastify. Both are thin
  adapters over one shared `beginOidcLogin`/`completeOidcLogin` core, with identical failure
  mapping (400 malformed callback, 401 authentication failure, 503 AXIAM unreachable — never
  a silent success).
- `OAuthProtocolError`, an `AuthError` **sub-type** carrying `error` and `errorDescription`
  with `message` set to `"<error>: <error_description>"`, raised for an `OAuth2ErrorResponse`
  body from `/oauth2/*` (a `400` from the token endpoint, or a `401` from
  introspect/revoke). Both endpoint-qualified rows are transcribed in the central error
  mapper. `instanceof AuthError` keeps matching it, so this is additive, not breaking. A
  `401` from `/oauth2/*` no longer enters the single-flight refresh guard — a
  client-credential failure is not a session expiry (CONTRACT.md §12.3 rule 3).
- The CONTRACT.md §2 error taxonomy (`AxiamError`, `AuthError`, `AuthzError`,
  `NetworkError`, `OAuthProtocolError`) and the `Sensitive<T>` wrapper are now exported from
  the root/`axiam-sdk/rest` entry, so `catch (e) { e instanceof AuthError }` works without
  reaching into a subpath (previously they were reachable only via `axiam-sdk/amqp`).
- `createJwksVerifier(jwksUri)` alongside the existing `createVerifier(baseUrl)`, and a
  `verifyIdToken` method on the verifier both share: one verifier, one cached remote key set,
  serving both the §10 middleware's access-token path and the §12.4 ID-token path.
- Runnable `examples/express-oidc-login.ts` and a README section covering all nine
  operations, the caller-owns-state contract, and the ID-token checklist.

### Changed

- Vendored `CONTRACT.md` re-synced to contract version 1.4 (§12 OIDC/SSO relying-party
  helpers, the `OAuthProtocolError` taxonomy sub-type, and the two endpoint-qualified
  HTTP-status rows). Conformance statement updated to §1–§12.

- gRPC `getUserInfo` operation (CONTRACT.md §1.1, adopting contract 1.3): new
  `UserInfoGrpcClient.getUserInfo()` on the `axiam-sdk/grpc` subpath, calling
  `axiam.v1.UserInfoService/GetUserInfo` (vendored `proto/axiam/v1/userinfo.proto`).
  It is the low-latency, gRPC-only counterpart of the server's REST
  `/oauth2/userinfo` endpoint (no REST form in the SDK vocabulary) and returns a
  typed `UserInfo { sub, tenantId, orgId, email?, preferredUsername? }` — `email`
  is populated only with the `email` scope and `preferredUsername` only with the
  `profile` scope, matching the server's OIDC scope gating. Reuses the existing
  gRPC channel, auth + `x-tenant-id` metadata interceptor, and single-flight
  refresh guard (CONTRACT.md §9): a `UNAUTHENTICATED` response drives exactly one
  refresh + one retry, and calling it with no token raises `AuthError` client-side
  without a wire call (CONTRACT.md §1.1). The vendored `CONTRACT.md` is updated to
  contract version 1.3.
- Client-certificate / mutual-TLS (mTLS) support (CONTRACT.md §6.1): new optional
  `clientCert` / `clientKey` PEM options on `AxiamClientOptions` (and the
  `AuthzGrpcClient` constructor options). When configured, the client identity is
  presented on **both** the REST transport (Node `https.Agent` `{ cert, key }`) and the
  gRPC channel (`createSsl(rootCerts, privateKey, certChain)`) of the same client.
  Strict server verification is never relaxed — `rejectUnauthorized` stays at its secure
  default and the client-cert path is kept separate from server-CA trust. The two options
  are all-or-nothing and PEM-validated at construction (throwing on a one-of or non-PEM
  value); the private key is held behind `Sensitive<T>` and never logged or serialized
  (§7). Node-only: browsers validate the PEM shape then ignore it, as with `customCa`.

## [1.0.0-alpha2] - 2026-07-16

### Added

- Declarative authorization helpers (CONTRACT.md §11): `requireAuth`,
  `requireAccess`, `requireRole` (Express `RequestHandler`s) and
  `requireAuthHook`, `requireAccessHook`, `requireRoleHook` (Fastify
  `preHandler` hooks), exported from the existing `axiam-sdk/middleware`
  subpath. `requireAccess`/`requireAccessHook` resolve the checked resource
  from a literal string, `fromParam(name)`, or a `(req) => string` resolver,
  and call `checkAccess` with `subjectId` set to the *authenticated request's*
  user id — never the SDK client's own service-account identity. Error
  mapping: 401 unauthenticated, 403 denied, 400 unresolvable resource, 503
  `authz_unavailable` on any transport failure (fail closed, never a silent
  allow); no decision caching.
- `VerifiableSession` extended (as `AuthzVerifiableSession`) with an optional
  `authzClient` (any `{ checkAccess(...) }`, satisfied by `AxiamClient`) —
  `requireAccess`/`requireAccessHook` throw synchronously at construction if
  it is not configured.
- Optional `axiam-sdk/nestjs` subpath (Tier 2 of CONTRACT.md §11):
  `@RequireAuth()`, `@RequireAccess(action, resource, opts?)`,
  `@RequireRole(...roles)` metadata decorators plus an `AxiamGuard`
  (`CanActivate`) that enforces them via `Reflector`, reusing the same §11
  primitives (resource resolution, error mapping, no decision caching) as
  the Express/Fastify guards. `@nestjs/common`/`@nestjs/core` are optional
  peer dependencies.

## [1.0.0-alpha] - 2026-07-15

First alpha release of the official TypeScript client SDK for AXIAM. This is an
early, pre-production preview published to npm for evaluation and feedback — the
public API may still change before the beta and stable releases.

### Added

- REST client covering the AXIAM API surface (authentication, authorization
  checks, tenant/user/role/resource management).
- gRPC client (`@grpc/grpc-js`) for low-latency authorization checks; proto
  stubs are generated at build time and bundled, so consumers need no `buf`.
- Dual ESM/CJS builds with a browser-safe entry point (no Node-only transports
  leak into the browser bundle).
- Middleware helper for guarding server routes.
- Strict TLS by default with no certificate-verification bypass surface.
- Token-leak protection: no JWT-shaped values in built output.
- Fully documented public API (TSDoc) and published type declarations.

[1.0.0-alpha]: https://github.com/ilpanich/axiam-typescript-sdk/releases/tag/v1.0.0-alpha
