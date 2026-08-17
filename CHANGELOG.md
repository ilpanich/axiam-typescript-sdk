# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **§8b transport security is now enforced, not just documented.** `consume()`
  and `reactorServe()` both called `amqp.connect(url)` with no scheme check and
  no TLS options, while their own doc comments stated that the URL "must be
  `amqps://` (§8b) — there is no verification-skip switch and no plaintext
  fallback". A plaintext `amqp://` URL connected without complaint, so signed
  but readable authorization requests, audit events and reactor replies could
  cross the wire in cleartext with nothing in the SDK objecting.

  Both entry points now validate the URL **before** opening a socket and refuse
  every scheme but `amqps://` (rules 1 and 5). Documented-but-unenforced is the
  worst of the three states: it reads as a guarantee at review time and behaves
  as an invitation at runtime.

### Added

- **A CA bundle and client identity for the broker connection (§8b rules 2 and
  3).** Both entry points take an optional `tls` option carrying `caCert` (a
  privately issued broker certificate — the common in-cluster case, and why
  rule 2 is a MUST) and `clientCert`/`clientKey` for mutual TLS. Rule 2 was
  previously unimplementable here: there was no way to supply a CA at all.

  The certificate/key pair is validated by the same §6.1 helper the REST and
  gRPC transports use, so half an identity is refused before dialling on every
  transport this SDK speaks rather than once per protocol.

  There is still deliberately no verification-skip option under any name
  (rule 4). `amqplib` would accept `rejectUnauthorized` in its socket options,
  which is why the SDK constructs that object itself from the three fields
  above rather than forwarding a caller-supplied one.

- `assertAmqpsUrl()` and `buildAmqpConnectOptions()`, exported from
  `axiam-sdk/amqp`, so a broker URL can be validated at config-load time rather
  than at first connect.

## [1.0.0-alpha25] - 2026-08-16

### Added

- Ship the CONTRACT.md §22 reactor runtime (R2.5) (#60)
- Extend §10.1 rule 9 for DPoP and implement §21.7.2 (#58)
- SubjectTokenType is required (contract 1.13)
- §15.7 — external-IdP subject tokens at the exchange (X4)
- Wire §20.3 challenge emission into the §11 guards, plus the example pair (#52)
- §20 — UMA 2.0 Protection API and ticket grant
- Report clamped settings via §19 ConfigClampedEvent (contract 1.9)
- §16 retry, §17 memo, §18 close(), §19 telemetry (D5) (#47)
- Device grant, token exchange, logout helpers; re-vendor (D6)

### Changed

- Re-vendor CONTRACT.md 1.19, openapi.json and proto/ from main (R5.8) (#59)
- Contract 1.15 — §10.1 rule 9, sender-constrained access tokens (#57)
- Add the §20.7 required timeout assertion
- Retire the "measured residual" justification (contract 1.14)
- Re-sync to contract 1.14 (#302 closed)
- Bump the minor-patch group with 3 updates
- Bump github/codeql-action from 4.37.4 to 4.37.6

### Fixed

- Re-export the §20 types from the middleware entry point
- Re-export the §12.7/§14/§15 types from the middleware entry point

## [Unreleased]

### Added

- **CONTRACT.md §22 — Reactors (AMQP extension actors).** New `src/amqp/reactor/`
  and `reactorServe(config, handler)`, exported from `axiam-sdk/amqp`: it consumes
  the server-declared per-reactor queue, verifies every event (§8 v2 —
  `key_version`, MAC, ±300 s freshness, nonce seen-set) *before* user code sees
  it, dispatches to a handler returning `allow()` / `deny()` / `mutate()`, then
  signs and publishes the reply. Also ships the event registry with its
  mutable-field allow-lists, the strictest-wins `failure_policy` composition
  (§22.8), `AbortSignal`-driven §18 drain, and `examples/reactor/`.

  **§8's HMAC now runs in both directions**, and TypeScript has *two* ways to
  produce a MAC that never verifies with no other symptom. The first is shared
  with every SDK: a reactor body signs `hmac_signature` as **`null`**, where
  `AuthzRequest` and `AuditEventMessage` omit it. The second is ours alone —
  `Date.prototype.toISOString()` always emits three fractional digits, while the
  server's `chrono` emits none on a whole second, so a reply timestamped
  `…T12:00:00.000Z` is re-serialized server-side as `…T12:00:00Z` and its
  signature fails. `toChronoRfc3339()` is the fix; the runtime always uses it and
  a test pins both branches. Both quirks are pinned by the server-generated
  vectors in `testdata/reactor_v2_reference_vectors.json` — same master key,
  tenant and derived subkey as the §8 fixture, so one loader serves both.

  Three behaviours are structural rather than documented. The runtime **declares
  no topology**: the `ReactorChannel` seam has no `assertQueue`/`assertExchange`/
  `bindQueue` at all, and a test drives the whole of `reactorServe` against a
  fake channel that *does* offer them, asserting none is ever called (§22.1). It
  **fails closed on its own errors**: a throwing handler, an unparseable body or
  an expired window publishes *nothing*, so the operator's `failure_policy`
  decides rather than a synthesized `allow` from inside the library (§22.10
  rule 2). And it **does not filter a patch** — one forbidden key rejects the
  whole patch server-side, and pruning it would leave the author believing a
  field was set (§22.4 rule 1).

  §22.7's hot-path exclusion is honoured by absence: `authz.check`,
  `authz.check_batch` and `token.introspect` appear in no constant, no registry
  row and no example.

  Not shipped, deliberately: a typed client for the §22.9 admin CRUD endpoints.
  That subsection is informative, and §22.9 specifically warns against
  re-deriving `PUT` merge semantics or the `failure_policy` re-derivation
  client-side — so the right surface is the server's.

- **CONTRACT.md §21.7.2 DPoP proof verification (RFC 9449).** New `src/node/dpop.ts`
  implements all ten checks and returns the proof key's RFC 7638 thumbprint, so a
  value passed on to rule 9 could only have come from a proof that verified.
  `InMemoryJtiStore` covers check 8 for a single process; the `JtiStore` interface
  is a required option, not an optional one, because there is no safe default
  that skips replay tracking.

  Two design points worth knowing: the algorithm is derived from the embedded
  `jwk` and the header's `alg` is **never read** (the test runs the real
  public-key-as-HMAC-secret forgery and asserts it verifies under HS256 before
  asserting this module refuses it), and the `jti` is claimed **last**, after
  every other check passes, so a stream of invalid proofs cannot burn `jti`
  values out of the store and deny service to valid ones.

- **CONTRACT.md §10.1 rule 9 extended for DPoP (contract 1.16/1.17).**
  `CnfClaim` gains `jkt` (RFC 9449 §6.1), and a new `verifyTokenBinding(claims, proofs)` applies the full
  ten-row rule against a certificate thumbprint, a verified DPoP key
  thumbprint, or **both**. A `cnf` naming both methods is a **conjunction** —
  satisfying only the more convenient one is not compliance — and a `cnf`
  naming nothing this SDK can check (including an *empty* one) is refused
  rather than read as unbound.

  `verifyCertificateBinding` remains as the narrower entry point for transports that can only
  produce a certificate, and now **refuses** a DPoP-bound or both-bound token
  rather than ignoring the half it cannot check.

  New example: `examples/sender-constrained-guard.ts`.

  Not a breaking change: an unbound token is still accepted with no certificate
  and no proof, asserted directly by the first test in the new group.

- **CONTRACT.md §10.1 rule 9 — sender-constrained (certificate-bound) access tokens**
  (contract 1.15, RFC 8705 §3 / RFC 7800). A token carrying `cnf` is **not** a bearer
  token; accepting one without proving the caller holds the named key converts it back
  into one.
  - `AxiamClaims.cnf` / `CnfClaim` — the decoded confirmation claim.
  - `verifyCertificateBinding(claims, presentedThumbprint)` — the rule. Throws on a
    bound token with no certificate, with a *different* certificate, or with a `cnf`
    naming a confirmation method this SDK cannot check.
  - `certificateThumbprintS256(der)` — RFC 8705 §3.1 `x5t#S256`: base64url, **unpadded**,
    SHA-256 over the DER certificate. Node only.

  **Not a breaking change, and it does not make certificates mandatory.** An *unbound*
  token is still accepted with or without a certificate — asserted directly, because the
  likeliest wrong implementation of this rule is one that starts demanding certificates
  from every caller.

  `verifyAccessToken` deliberately does **not** apply rule 9: it has no transport to ask
  for a peer certificate. Call `verifyCertificateBinding` with the thumbprint your TLS
  layer gives you (`TLSSocket.getPeerCertificate().raw`), or a value a *trusted*
  terminating proxy forwarded — never a caller-settable header, which would make the
  mechanism decorative.

  A `cnf` naming an unimplemented method is **rejected**, never read as "unconstrained":
  read the other way, a sender-constrained token silently degrades to a bearer token the
  day a newer AXIAM issues a confirmation this SDK predates.

- **CONTRACT.md §21** — the FAPI 2.0 posture as an SDK sees it: client-registration
  fields, RFC 9207 `iss` on authorization responses, and the discovery additions. Only
  rule 9 above is normative for this SDK.

### Changed

- **Re-sync vendored `CONTRACT.md`, `openapi.json` and `proto/` to contract 1.19**
  (upstream **R5.8**). The vendored copies had been pinned at the 1.15-era artifacts and
  drifted three contract revisions behind `ilpanich/axiam@main`. All five files are now
  byte-identical to upstream, and `proto/axiam/v1/reactor.proto` (contract 1.18 §22, the
  AMQP reactor protocol) is vendored here for the first time.

- **CONTRACT.md §11.2 rule 9 — the gRPC decision reads `reason`, not `deny_reason`**
  (**SDK-Q10**, contract 1.19). `CheckAccessResponse` gains `reason` (proto field 4,
  explicit presence) carrying the same string the REST decision body has always called
  `reason`; `deny_reason` (field 2) is now `[deprecated = true]` and is removed at AXIAM
  2.0. The mirrored `WireCheckAccessResponse` gains an optional `reason` and marks
  `deny_reason` `@deprecated`, and the decision mapper reads `reason`, falling back to
  `deny_reason` only when `reason` is **absent on a refusal** — which is exactly what a
  pre-SDK-Q10 server sends. `AccessDecision` still exposes one `reason`, so this is not a
  breaking change for callers and nothing changes on the wire today.

  **Known residual, deliberately not taken here:** contract 1.19 also relaxes gRPC
  `subject_id` to optional (an *empty* value meaning "the subject in the verified token").
  `CheckAccessRequest.subjectId` stays required — relaxing it is a breaking signature move
  and belongs in its own change. The type's doc comment now records the gap.


### Changed

- **Re-sync vendored `CONTRACT.md` to contract 1.14** — documentation only, no code change.
  §20.2 rule 6 (a permission ticket MUST NOT be retried) cited a "measured residual
  (ilpanich/axiam#302) … roughly 1 in 640" as its second reason. That residual is closed: the
  server now decides the ticket race with a transaction its storage engine arbitrates plus a
  redemption nonce read back after the commit. **The rule is unchanged, and this SDK's
  behaviour is unchanged** — `uma_exchange_ticket` stays excluded from every automatic retry
  path. What changed is the reasoning: the first reason (a spent ticket makes the retry
  useless) always stood alone, and the second now rests on what an SDK can actually know —
  it is talking to a server whose storage engine it cannot attest, and the guarantee is
  conditional on that engine being persistent.
- **BREAKING (contract 1.13): `TokenExchangeParams.subjectTokenType` is now required.** It
  shipped optional, defaulting to `ACCESS_TOKEN_TYPE` when omitted — which satisfied §15.7's
  "never inspect the subject token" while leaving the rule it serves unenforced: an optional
  field with a default *is* a default the SDK applies whenever the caller says nothing. §15.1
  now makes it required.

  TypeScript is one of the languages that can refuse the call outright, so it does: omitting
  the field is a **compile error**, not a runtime one. A `@ts-expect-error` test asserts that,
  so reintroducing the default would fail the build rather than pass silently.

  **Migration** — one line, naming what you were previously getting by silence:

  ```ts
  const exchanged = await oidc.tokenExchange({
    subjectToken: new Sensitive(userToken),
    subjectTokenType: ACCESS_TOKEN_TYPE, // <- add this
    scopes: ['orders:read'],
  });
  ```

  This closes a gap rather than opening one: `subject_token_type` has always been required *on
  the wire*, and the SDK was covering for that with a constant which stopped being the only
  legal value when X4 landed. For a caller who actually held a refresh token, the old default
  traded the `invalid_request` that names the type for a generic `invalid_grant`.

### Added

- **§15.7 external-IdP subject tokens (X4).** `tokenExchange` can now exchange a token minted
  by a trusted external IdP — a partner's Entra, Okta or Keycloak — for an AXIAM token scoped
  to what the resolved AXIAM user may actually do. No new operation: the same method, plus
  `TokenExchangeParams.subjectTokenType` and the exported `JWT_TOKEN_TYPE` constant alongside
  the existing `ACCESS_TOKEN_TYPE`.

  **The type is the caller's to name, never the SDK's to guess.** §15.7 forbids inspecting the
  subject token to pick it, because which kind of token you hold is something only you know and
  a wrong guess is the difference between a request that is refused and one that is silently
  reinterpreted. A JWT-shaped subject token does **not** change what is sent, which is asserted
  by a test. (This shipped with an `ACCESS_TOKEN_TYPE` default; contract 1.13 removed it — see
  *Changed* above.)

  Also asserted: an `actorToken` alongside an external subject token surfaces `invalid_request`
  with no retry and no request rewriting; a refused refresh or ID token type is never retried as
  a different type; the one normative description — `the subject token's issuer is not
  configured for token exchange`, meaning *fix the AXIAM trust config* rather than *fix your
  token* — reaches the caller intact; and nothing re-exchanges an exchanged token, which both
  server paths refuse because exchanges do not compose.

  New `examples/external-token-exchange.ts` runs the partner-token → AXIAM-token exchange at an
  API gateway, including the one error branch worth telling apart.

  `CONTRACT.md` and `openapi.json` re-synced from `ilpanich/axiam@main` (contract 1.10 → 1.12
  plus §15.7), which also brings contract 1.11's lifted §12.6 deferral, contract 1.12's
  `/oauth2/*` error rows dispatching on the `error` field at any status, and the
  `TokenExchangeTrust` schemas behind the X4 provider configuration.

- **§20.3 challenge emission wired into the §11 guards.** `RequireAccessOptions.umaChallenge`
  takes a new `UmaChallenger` (realm, `asUri`, PAT, minter); on denial `requireAccess`
  (Express) and `requireAccessHook` (Fastify) mint a permission ticket for the action just
  refused and set `WWW-Authenticate: UMA` alongside the 403. `CheckOutcome`'s `denied` arm
  gained an optional `challenge`.

  **Opt-in by construction.** Emitting a challenge means minting a credential, so a guard
  that did it by default would turn every unauthorized request into a Protection API call.
  And **failure is not escalation**: if minting fails the denial still surfaces as a plain
  403, because a caller who was going to be refused is refused either way and an outage must
  not turn a deny into a 500 — still less into an allow.

  The minter is taken as a *function* (`UmaTicketMinter`) rather than an `OidcClient`, because
  the middleware core is shared with the browser build and that build has no Protection API
  client. For the same reason the header is formatted inline rather than imported from the
  Node-only `umaChallengeHeader` — it is four literals and a template, and the import would
  drag the whole OIDC entry point into the browser bundle.

- **A runnable UMA example pair**: [`examples/uma-resource-server.ts`](examples/uma-resource-server.ts)
  mints a PAT, registers a resource and guards a route with the challenger;
  [`examples/uma-client.ts`](examples/uma-client.ts) catches the refusal, parses the
  challenge, **makes the trust decision about `asUri` explicitly**, exchanges the ticket and
  retries with the RPT. The client half exists partly to show what §20.3 is protecting: the
  `asUri` is chosen by the server you just failed against, and the example refuses to redeem
  against a host that is not the issuer it already trusts.

- **§20 UMA 2.0 — Protection API and ticket grant (contract 1.10).** New methods on
  `OidcClient`: `umaRegisterResource` / `umaReadResource` / `umaUpdateResource` /
  `umaDeleteResource` / `umaListResources`, `umaRequestTicket`, `umaExchangeTicket`, plus the
  `WWW-Authenticate: UMA` challenge helpers `umaParseChallenge` and `umaChallengeHeader`.

  Two behaviours are load-bearing rather than incidental, and both are asserted by counting
  requests. **`umaExchangeTicket` never retries** — the one documented exception to the §16
  retry policy, because a ticket is consumed before the request is evaluated, so a retry
  cannot succeed and under concurrency is exactly the second redemption that
  ilpanich/axiam#302's measured residual describes. And **`umaParseChallenge` does not
  exchange the ticket it parsed**: the `as_uri` names an authorization server the client has
  not chosen to trust.

  The PAT is an explicit parameter on every Protection API call rather than being taken from
  the client's session, because that session is usually a *user* session and a ticket binds
  to a `client_id`.

  `access_denied` on the ticket grant arrives as **403** (UMA 2.0 §3.3.6), unlike RFC 8628's,
  which is a 400. It is mapped to `OAuthProtocolError` by a mapper local to this grant rather
  than by widening §2's endpoint-qualified rows — an ordinary REST 403 still maps to
  `AuthzError`, unchanged.

- **§19 `ConfigClampedEvent` (contract 1.9).** A clamped setting is now reported at
  construction rather than applied silently — currently the §17.1 rule 2 memo TTL. Clamping
  is right; clamping *silently* is not: an operator who set a 60-second TTL believes their
  staleness bound is 60 seconds, and it is five. Nothing is emitted for a value already
  within its limit, or for the disabled default.

### Added

- **§16 bounded read-only retry policy.** `checkAccess`/`can`/`batchCheck` now retry under
  the contract's normative table: 3 attempts, 200 ms base, 5 s cap, **full jitter** over
  `[0, backoff]`, `Retry-After` honored as a floor. Both non-deterministic inputs are
  injectable, so the tests pin the jitter fraction to 0 and 1 to prove the range instead of
  sleeping.
- **§18 `AxiamClient.close()`**, idempotent, with use-after-close rejecting rather than
  silently reconnecting. It does **not** log out and never reaches the network: the
  server-side session outlives the client object, and a `close()` that logged out would end
  every user's session on each deploy.
- **§19 telemetry hooks** — `telemetryHook` on `AxiamClientOptions`, plus the `TelemetryEvent`
  union and `examples/telemetry-hook.ts` with the OpenTelemetry mapping. A hook that throws
  cannot fail the operation that fired it, and no event payload can carry a token. One
  request pair per *attempt*, not per logical call, so callers can count real wire calls.
- **§17 decision memo — opt-in, off by default.** `decisionMemoTtlMs`, clamped to 5000 ms.
  Allows and denies memoized identically, failures never memoized, cleared on any credential
  change. **Reads-your-own-writes is not guaranteed.**
- `retryEnabled` (§16.6), default on. No knob for the attempt cap, base or delay cap: §16.1
  forbids raising them.

### Fixed

- **`withRetry` was never called by any production path.** It was exported, unit-tested and
  green, but `checkAccess` did not route through it — so this SDK performed **no read-only
  retries at all** while appearing to, leaving §11.2 rule 5 silently unmet. A tested helper
  nobody calls is worse than an absent one: the passing tests are what stop anyone looking.
  The §16 conformance tests now assert through the public `checkAccess` surface.
- **`Retry-After` replaced the backoff instead of flooring it.** `retryAfterMs ?? backoff(n)`
  meant a `Retry-After: 0` retried immediately, defeating the policy — exactly what §16.1's
  "floor, never a ceiling" forbids. Now `Math.max(jittered, retryAfterMs)`.
- **Partial jitter replaced with full jitter.** The old `base + 0–20%` keeps every client's
  retries clustered around the same instant, which causes the thundering herd retries are
  meant to prevent.
- The §19 request pair now carries the real attempt number. An earlier draft emitted every
  pair as attempt 1, which would have made a retried call indistinguishable from a single
  slow one — caught by the conformance test asserting `[1, 2]`.

### Changed

- Re-vendored `CONTRACT.md` at **1.8.1**. `openapi.json` unchanged — docs-only contract revs.
- `RetryOptions.maxAttempts` removed: §16.1 fixes the cap at 3 and forbids raising it.
  `withRetry`'s callback now receives the attempt number.

## [1.0.0-alpha24] - 2026-08-04

### Added

- Enforce the full CONTRACT §10.1 local-verification set

### Changed

- Bump fast-uri
- Device (mTLS) tokens now carry aud=axiam:m2m (#44)
- Service accounts can use login_client_credentials (#43)
- Bump github/codeql-action from 4 to 4.37.4
- Bump amqplib from 0.10.9 to 2.0.1
- Bump the minor-patch group with 4 updates
- Pin CONTRACT §10.1 rule 8 against regression (§15.3.1) (#39)
- Bump postcss from 8.5.17 to 8.5.25
- Bump find-my-way from 9.6.0 to 9.7.0

### Fixed

- Diagnose the slug-vs-UUID tenant comparand (§13.4 observation 6) (#36)
- Repin amqplib to real 0.10.x + add verifyWebhook helper (SEC-078, T-145)

## [Unreleased]

### Added

- **CONTRACT §10.1 rule-8 regression tests (§15.3.1).** Rule 8 — "the decision is
  about the caller's credential and no other" — was enforced only by inspection
  here. SEC-085 satisfied rules 1–7 and was still an authentication bypass, so
  the absence of a guardrail is the condition that let it survive three reviews.

  This SDK is structurally safe from that shape: `VerifiableSession` carries a
  verifier and a tenant, **not a logged-in session**, so there is no second
  credential in scope for the guard to substitute. The new tests pin that
  property rather than assume it — one asserts the verifier is invoked with the
  caller's token and nothing else, the other asserts the guard's input exposes
  no `session`/`client`/`refresh`/`accessToken` surface. They fail if anyone
  ever threads a stateful client session into the guard's inputs, which is
  precisely how the PHP bug became reachable.

### Fixed

- **Slug-vs-UUID tenant comparand now diagnoses itself (§13.4 observation 6).**
  AXIAM access tokens carry the tenant **UUID** in `tenant_id`, but this SDK's
  client is commonly configured with a tenant **slug**. A guard handed that slug
  rejects 100% of traffic — fail-closed and safe, but it presents as "every token
  is invalid" with nothing pointing at the cause. `assertTenantClaim` now emits a
  single `console.warn` naming the real problem. It fires **once per process**,
  only when the configured value is not UUID-shaped while the claim is, and
  strictly *after* the rejection is decided — so it cannot be used as a log-flood
  lever and does not alter the verification outcome. A genuine cross-tenant
  rejection (UUID vs UUID) stays silent.

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
