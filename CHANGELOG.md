# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Re-vendored the AXIAM contract artifacts at contract 1.36.** `CONTRACT.md`,
  `openapi.json` and `management-registry.json` are byte-identical copies of the
  `sdks/` sources in [`ilpanich/axiam`](https://github.com/ilpanich/axiam)
  (ilpanich/axiam#396). `proto/` and `opaque-test-vectors.json` did not change
  in 1.36 and are untouched. No SDK code changes with them; the three entries
  below are why not.

- **§5.2.2 rule 4 is new, and is an errata rather than a wire change.** The
  server now scopes every *self-service* endpoint to `principal_tenant_id`
  rather than to the acting tenant — `GET`/`PUT /users/{own id}`, that user's
  `mfa-methods`, `POST /users/{own id}/reset-mfa`, `POST /auth/mfa/enroll` and
  `/confirm`, `POST /auth/webauthn/register/start` and `/finish`, `POST
  /users/me/resend-verification`, the §25 account export and erasure for the
  caller's own id, and `GET /oauth2/userinfo`. Each of those answered `404` for
  an organization-level caller that had switched to another tenant and now
  succeeds. No request or response field is added, so nothing here is a wire
  change.

  The rule also forbids the obvious workaround: an SDK MUST NOT clear or rewrite
  the acting-tenant header for those calls, because that header is what makes
  the **administrative** form of the same endpoints reach the tenant the caller
  asked for — stripping it would break reading another tenant's user in order to
  fix reading your own. This SDK was audited for such a workaround and has none:
  `X-Tenant-ID` is set in one axios request interceptor in
  `src/rest/session.ts`, whose only exception is the §3A foreign-host check; no
  endpoint is special-cased.

- **Issue #395 is settled: the acting-tenant header is `X-Axiam-Tenant`**, and
  §5.2, §5.2.2 and §5.2.3 now name it. The note under 1.0.0-beta05 below
  recorded the contract and the server disagreeing on it; they no longer do, and
  the name this SDK documents was already the server's — checked against the
  vendored contract rather than assumed. §5 rule 2's *unconditional*
  `X-Tenant-ID` is deliberately **not** renamed, and the contract now carries a
  note saying why it must not be: it names the client's *constructor* tenant, so
  folding it into `X-Axiam-Tenant` would override the acting tenant on every
  request an organization-level principal made after a switch. Every existing §5
  rule 2 send is left exactly as it was.

- **`openapi.json` gains `/api/v1/auth/me`, `/api/v1/auth/password/change` and
  `/api/v1/admin/bootstrap`.** All three were always served and always normative
  in `CONTRACT.md`; they were missing from the generated document only because
  their handlers were never listed in its `paths(…)`. `management-registry.json`
  changes only in its `spec_digest` and by one new exclusion entry —
  `operation_count` stays **155**, bootstrap being excluded on the §27.0
  boundary — so §27 code generation must produce no diff. Re-ran `node
  scripts/gen-management.mjs` to confirm it produces none.

## [1.0.0-beta05] - 2026-08-30

### Added

- Contract 1.35, carrying 1.34 — service-account RBAC, principal tenant, tenant scope

- **Contract 1.35, which carries contract 1.34 with it.** Nothing had been
  fanned out since 1.33, so this re-vendors `CONTRACT.md`, `openapi.json` and
  `management-registry.json` across both revisions. The registry still holds
  155 operations across 24 namespaces — 1.35 changed only its `spec_digest` —
  so the eight §27 operations below arrived with 1.34 and are new here
  regardless.

- **§27: service accounts as RBAC principals** (contract 1.34) — eight
  generated operations: `roles.listServiceAccounts`,
  `roles.assignToServiceAccount`, `roles.unassignFromServiceAccount`,
  `groups.listServiceAccounts`, `groups.addServiceAccount`,
  `groups.removeServiceAccount`, `serviceAccounts.listRoles` and
  `serviceAccounts.listGroups`. `unassignFromServiceAccount` takes the same
  optional `resourceId` query parameter as the user and group unassign calls:
  omitting it removes the *global* grant specifically, not every grant of that
  role.

- **§5.2.2: the acting tenant and the principal tenant are different things**
  (contract 1.34). `AxiamUserInfo` gains `tenantId`, `principalTenantId`,
  `principalTenantSlug` and `orgId`. Absent means equal — a server older than
  1.34 omits them and cannot switch the acting tenant either, so
  `principalTenantId` falls back to `tenantId` rather than to `undefined`.
  Read `orgId` from the session instead of resolving a slug through `GET
  /api/v1/organizations`, which is `super-admin`-only.

- **§5.2.3: tenant-scoped role assignments** (contract 1.35). `tenant_scope`
  appears on the three assignment request bodies and on the assignment objects
  the read paths return, and `AxiamUserInfo.reachableTenantIds` reports a
  narrowed principal's reach. Omitted means unrestricted, which is what every
  assignment written before the field existed already meant.

### Changed

- **One mapper for the login user object, instead of three.** `auth.ts`,
  `accountLifecycle.ts` and `opaque.ts` each carried their own copy of the
  wire-to-`AxiamUserInfo` mapping, two of them annotated "same reading as
  `auth.ts`". Contract 1.34 turned that duplication into a hazard — five more
  fields, and a copy forwarding three of them is a bug nothing catches — so
  they now share `userInfoFromWire`.

### Fixed

- **A registration record for your own password was sealed against the wrong
  tenant.** CONTRACT.md §5.2.2 rule 2: the caller's credentials live in the
  tenant the *account* lives in, not whichever tenant the client is currently
  pointed at, and a record sealed against the acting tenant is refused with
  "the OPAQUE session was issued for a different tenant".

  `opaqueEnrollment` had one behaviour for a function documented for three
  callers — user creation, change-password and reset completion — and only the
  first of those wants the acting tenant. It keeps that behaviour, which is
  correct for creating *another* account; the new `opaqueEnrollmentForSelf`
  seals against `principalTenantId` and is what a self-service password change
  must call.

  The two collapse to the same request for every ordinary principal, so this
  only bit an organization-level account that had switched tenant — which is
  why it survived every test written against an ordinary one.

- **An empty `tenant_scope` is no longer put on the wire.** The server refuses
  `[]` with `400`: an assignment reaching no tenant is a grant that does not
  exist rather than a restriction. Optionality alone did not prevent it —
  `JSON.stringify` drops `undefined` but keeps `[]`, and `[]` is exactly what
  collecting into an array produces for "no tenants named". The three
  assignment operations now normalise the body before sending.

### Note on `X-Tenant-ID` vs `X-Axiam-Tenant`

CONTRACT.md §5.2.2 and §5.2.3 name the acting-tenant header `X-Tenant-ID`, but
the AXIAM server reads **`X-Axiam-Tenant`** (`ACTIVE_TENANT_HEADER` in
`crates/axiam-api-rest/src/extractors/auth.rs`), as do its own tests, the admin
UI, and the `openapi.json` vendored alongside that contract. The server never
reads `X-Tenant-ID` at all.

Documentation updated here for §5.2.3 rule 4 therefore names
`X-Axiam-Tenant`, because a tenant switch sent under the other name is not
refused — it is ignored, and the request quietly acts on the principal's own
tenant instead. The discrepancy has been reported upstream; this SDK's existing
`X-Tenant-ID` sends are left as they are, being out of scope for a contract
re-vendor.

## [1.0.0-beta04] - 2026-08-28

### Changed

- Re-vendor contract 1.33, pin CodeQL by digest, record why npm needs no second attestation

- Vendor contract 1.32 — §5.2.1 organization-level sign-in

- **CONTRACT 1.32 — signing in an organization-level principal (§5.2.1).**
  `CONTRACT.md`, `openapi.json` and `management-registry.json` re-vendored from
  the AXIAM server.

  No code change was needed here, and that is the point worth recording. §5.2.1
  adds two rules; this SDK already satisfied both:

  - Naming no tenant resolves the organization's own reserved scope on
    `/auth/login`, `/auth/opaque/login/start`, `/auth/opaque/register/start`
    and `/auth/webauthn/authenticate/discoverable/start`. The reserved tenant's
    slug is `organization`, so `new AxiamClient({ tenantSlug: 'organization',
    orgSlug })` reaches it through the ordinary constructor.
  - An SDK **MUST NOT** send an empty-string slug. `tenantSlug: ''` is refused
    at construction (§5 — there is no default tenant), so no client exists from
    which one could be serialized, and `buildLoginBody` omits an identifier it
    was not given.

  Both are now pinned by tests in `test/rest/orgContext.test.ts` rather than
  left as a property of falsy checks. The rule has teeth: sending `""` breaks
  organization-level sign-in on all four routes, and on
  `/auth/opaque/login/start` it does so before the tenant's OPAQUE mode is
  read — the `404` of §23.4 rule 10 never arrives, so the client has no
  fallback and sign-in fails even where OPAQUE is disabled.

## [1.0.0-beta02] - 2026-08-28

### Added

- Contract 1.31 — list search, the truthful resend, organization scope

- Declarative manifests, plan/apply, and the §27.7 forms

- Generate the §27 surface — 146 operations, 24 namespaces

- **CONTRACT 1.31 — the AXIAM server PR #383 surface.** `CONTRACT.md`,
  `openapi.json` and `management-registry.json` re-vendored, and the six things
  they describe implemented.

  - **`search` on all twenty paginated management operations** (§27.4 rule 4).
    A third field on `PageRequest`, not a third argument on twenty generated
    `list` methods:

    ```ts
    await client.users.list({ limit: 50, search: 'ada' });
    await client.users.listAll({ limit: 200, search: 'ada' });
    ```

    Putting it on the page request is what makes `listAll` carry the term across
    the whole walk. A walk that filtered its first request and not the rest
    returns the matches followed by the unfiltered tail, which from the caller's
    side looks like a server bug.

    The server applies it **before** `offset`/`limit`, so `page.total` counts
    matches rather than rows — which is what lets a pager built on it show a page
    count belonging to the result set it is paging. `search: ''` and
    `search: '   '` send no `search` parameter at all, so a box that fires on
    every keystroke does not ask a different question once it is cleared. The
    server's length cap is deliberately **not** copied here: a client-side
    truncation the server would not have made is a silently different query.

  - **`resendOwnVerification()`** (§25.1, §25.7) —
    `POST /api/v1/users/me/resend-verification`, for a caller signed in to the
    account it is asking about. It takes no address, and reports what happened:
    resolves for enqueued, `ConflictError` for already-verified-or-ineligible,
    `NetworkError` for the daily limit.

    `resendVerification` still exists and still resolves whatever happens,
    because it takes an address from an anonymous caller and a truthful answer
    there is an enumeration oracle. Use the new one whenever there is a session —
    a profile page wired to the old one reports success while doing nothing,
    which is the defect the pair exists to separate. This SDK does not fall back
    from one to the other in either direction (§25.7 rule 2).

  - **`AxiamUserInfo.organizationLevel`** (§5.2) — on the `authenticated`
    branch of `LoginResult`. Whether the account holds grants that apply in every
    tenant of its organization. Check it before offering a tenant switch: an
    ordinary tenant principal changing `X-Tenant-ID` gets a `403`. `false`
    against a server older than contract 1.31, which is the safe reading of
    absent.

  - **`Tenant.kind` and `TenantKind`** (§27.11) — ordinary tenant or the
    organization's own scope. Absent on a row written before that scope existed.
    Read-only: it is not on `CreateTenantRequest` or `UpdateTenantRequest`.

  - **`MtlsTrustAnchorResponse.trusted_anchors`** (§27.11) — how many CAs the
    live listener now trusts, when it was reloaded. Absent is **not** zero: it
    means there was no listener to ask, which is the case `restart_required:
    true` already reports.

  - **`Certificate.bound_service_account_id`** (§27.11) — the service account a
    certificate authenticates, resolved for a whole page in one query by
    `certificates.list()` and absent from `certificates.get()`. The SDK does not
    issue a second request to fill it in there.

### Changed

- Re-vendor openapi.json and management-registry.json from axiam main (#84)

- Re-vendor the contract artifacts: spec digest + §27.10 posture (#82)

- README, examples, and the CI codegen gate

- Re-vendor CONTRACT.md, openapi.json and the §27 registry

- **Generated management enums are open.** Each is now a literal union with a
  trailing `(string & {})` arm, so a value this SDK's copy of the spec does not
  list reaches a caller as itself rather than being asserted out of existence
  (§27.11 rule 1). The named arms still autocomplete and still narrow; what the
  extra arm removes is the illusion that an exhaustive `switch` over them is
  exhaustive — which is exactly the assumption the next `kind` or `status` the
  server adds would break.

### Fixed

- The search doc linked to an internal symbol

- **`scripts/gen-management.mjs` no longer drops a projected list element.** The
  server answers `GET /api/v1/certificates` with `Certificate` plus one resolved
  graph edge, expressed as an `allOf` of the `$ref` and an anonymous object.
  Read as a whole, that composition has no name, so the registry carried a page
  with no element type and the added field reached no model. The generator now
  takes the base name through the `allOf` and folds the projection's added
  fields onto the base interface as optional. (The registry-side half of this is
  AXIAM PR #386.)

## [1.0.0-alpha44] - 2026-08-25

### Changed

- Re-vendor openapi.json at alpha43 for tenant signing CAs (axiam#379)

- Bump github/codeql-action from 4.37.7 to 4.37.8

- Bump the minor-patch group with 5 updates

- **Re-vendor `openapi.json` at 1.0.0-alpha43** for AXIAM server PR #379, which
  adds **tenant signing CAs**: an intermediate CA created beneath one of the
  organization's CAs and scoped to a single tenant, so a tenant's user, service
  and device certificates chain through a CA that can be revoked, rotated or
  handed to a different operator without redistributing the anchor the rest of
  the estate trusts. `CONTRACT.md` and `proto/` were untouched by that PR and are
  already current.

  This is a specification re-sync with **no SDK surface change**. CA-certificate
  administration is not part of the SDK contract — `CONTRACT.md` §1 maps no
  method onto any `/api/v1/organizations/{org_id}/...` CA route — and this SDK
  models none of the schemas below, so nothing here gains, loses, or changes a
  symbol. The spec is vendored so what this SDK is written against keeps
  describing the server it talks to.

  What moved in the spec:

  - **`POST /api/v1/organizations/{org_id}/tenants/{tenant_id}/signing-cas`**
    (`generate_intermediate`) — create a tenant signing CA under an organization
    CA, with AXIAM generating the key. Returns `GeneratedCaCertificate`; the
    private key comes back exactly once, and not at all under `vault_pki`, where
    it was born inside Vault and no API exports it.
  - **`GET .../signing-cas`** (`list_intermediates`) — a paginated list of one
    tenant's signing CAs.
  - **`POST .../signing-cas/sign-csr`** (`sign_intermediate_csr`) — the BYOK
    counterpart: sign a PKCS#10 CSR produced elsewhere, so the private key never
    reaches AXIAM at all. The response carries no `private_key_pem` because there
    is none to carry.
  - **`CaCertificate` gains two nullable fields** — `tenant_id`, the tenant a CA
    signs for, and `parent_ca_id`, the CA in the organization that signed it.
    Both are absent for an organization-level CA, which is the trust anchor and
    the only kind that existed before this change.
  - **Four new schemas**: `CreateIntermediateCa`, `CreateIntermediateCaRequest`,
    `SignIntermediateCsr` and `SignIntermediateCsrRequest`.

  The spec version moves from **1.0.0-alpha40** to **1.0.0-alpha43**; the
  intervening alpha41 and alpha42 releases changed nothing in it but that string.

## [1.0.0-alpha43] - 2026-08-24

### Added

- Raise the Node floor to 22 and build the newest line (#77)

- **Node 26 is now a CI-built runtime.** The gating matrix runs `build`,
  `typecheck`, the full test suite and the CommonJS-require smoke tests on the
  floor **and** on the newest release line, rather than on one line in the
  middle of the range.

- **`test/core/versionPolicy.test.ts`** — a conformance test for the support
  policy itself. `engines.node`, the `@types/node` pin and the CI `node` matrix
  are three independent declarations of the same fact and nothing compared
  them. Before this test existed all three disagreed at once: `engines` said
  `>=18`, `@types/node` was `^26`, and CI built only 22 — meaning `tsc`
  validated the SDK against APIs no tested runtime provided, while the package
  advertised installation on a runtime nothing built.

- **`examples/version-compatibility.ts`** — a runnable startup preflight
  reporting the running Node against the SDK's declared range, read out of the
  SDK's own `package.json` rather than hardcoded. `engines` is advisory to npm
  and ignored outright under `engine-strict=false`; this makes it assertable.

- **`"./package.json"` in the package `exports` map**, so a consumer can read
  the SDK's `engines` range at runtime. Additive — no existing subpath changes.

- **A "Supported Node versions" section in the README**, stating the two claims
  separately: built against the floor, runs on everything through the newest,
  with a CI leg proving each.

### Changed

- **BREAKING (declared support): `engines.node` raised `>=18` → `>=22`.** Node
  18 reached end of life on 2025-04-30 and Node 20 on 2026-04-30; 22 is the
  oldest line still receiving security fixes. The SDK was never built or
  tested on 18 — this corrects a declaration that had quietly stopped being
  true, rather than dropping a runtime that was working.

  No code change accompanies this: the bundle still targets ES2022. Installs
  on Node 18 or 20 will now emit an `EBADENGINE` warning (or fail under
  `engine-strict=true`).

- **The gating CI matrix is floor + newest (22, 26)** rather than a single
  line. Runtime-independent gates — bundle-grep, the token-leak and TLS-lint
  greps, `npm audit`, the docs gate and the publish dry-run — run once on the
  floor leg rather than twice, mirroring the Rust SDK's
  `if: matrix.toolchain == 'stable'` pattern.

## [1.0.0-alpha41] - 2026-08-24

### Added

- Fall back to /auth/login when mode is optional (§23.4 rule 7)

### Changed

- Re-vendor openapi.json for the vault_pki CA custodian (axiam#368)

- Re-vendor CONTRACT.md 1.29 and openapi.json alpha40

- **Re-vendor `openapi.json`** for AXIAM server PR #368, which adds a third CA
  key custodian, `vault_pki`, having HashiCorp Vault's PKI secrets engine
  generate the CA key inside Vault and sign on AXIAM's behalf. The spec version
  is unchanged at **1.0.0-alpha40**; `CONTRACT.md` and `proto/` are untouched by
  that PR and are already current.

  This is a specification re-sync with **no SDK surface change**. CA-certificate
  administration is not part of the SDK contract — `CONTRACT.md` §1 maps no
  method onto `/api/v1/organizations/{org_id}/ca-certificates`, and this SDK
  models none of the five schemas below — so nothing here gains, loses, or
  changes a symbol. It is vendored so the spec this SDK is written against keeps
  describing the server it talks to.

  What moved in the spec:

  - `CaCertificate` gains a nullable `chain_pem`: the issuers above
    `public_cert_pem`, concatenated PEM, nearest issuer first and the root last.
    Absent for a CA that is its own root, which is every CA AXIAM generated
    before this. Present for a `vault_pki` CA, where it is the only copy of the
    root certificate anything outside Vault will ever see.
  - `CaCertificate.public_cert_pem` is now documented as the certificate that
    *signs*, which under `vault_pki` custody is the intermediate rather than the
    root beneath which it was created. The field itself is unchanged.
  - `GeneratedCaCertificate.private_key_pem` is **no longer required**. Under
    `vault_pki` custody the key is born inside Vault and no API exports it, so
    there is nothing to return. The field is omitted rather than sent as `null`,
    which keeps a client that has always read it working unchanged against every
    custodian that does produce a key.
  - `GeneratedCertificate` gains a nullable `chain_pem`, present only when the
    signer returned one — the `vault_pki` case, where the root's certificate
    exists nowhere a client could fetch it from.
  - `CreateCaCertificate` and `CreateCaCertificateRequest` gain the optional
    `issue_from_root`, `intermediate_subject` and `intermediate_validity_days`.
    All three are `vault_pki`-only and ignored by every other custodian.
    `issue_from_root` defaults to off: a root that signs only one intermediate
    can have that intermediate revoked and replaced without redistributing the
    trust anchor, and a root that signs leaves directly cannot.

- **`loginOpaque()` falls back to `login()` under `opaque_mode: "optional"` —
  CONTRACT.md §23.4 rule 7 (contract 1.29).** `POST /auth/opaque/login/start`
  now returns the tenant's `mode`, and it is the only thing that decides what a
  failed `KE2` means. Under `"optional"` the SDK retries the same credentials
  over `POST /api/v1/auth/login` before reporting anything, and returns that
  call's outcome — its success on success, its error on failure. Under
  `"optional"` an account with no registration record is the ordinary case, not
  an error: every account has none the moment an operator enables OPAQUE and
  acquires one only as its password is next set, so the previous behaviour
  locked out every user of a tenant mid-migration. Under `"required"`, with no
  `mode` field at all (a server older than it), or on an unrecognised value, the
  behaviour is unchanged and fails closed: `AuthError`, no `KE3` sent, and no
  plaintext password on the wire. `404` handling — the tenant has OPAQUE
  disabled, still a `NetworkError` — is untouched.

  `mode` is **not** downgrade protection and is not documented as such: a
  hostile server that wanted the plaintext could answer `404` and get the
  fallback whatever it put there. `required` is what closes that, server-side.

- Re-vendor `CONTRACT.md` at **1.29** and `openapi.json` at **1.0.0-alpha40**.

### Fixed

- Surface a pre-mapped 401 as AuthError, not NetworkError

- **`login()`, `refresh()` and `logout()` reported a `401` as a `NetworkError`
  instead of an `AuthError`.** All three post to a `SKIP_REFRESH` url, so the
  response interceptor maps their `401` to an `AuthError` before `auth.ts`'s
  own `catch` runs. That already-mapped error carries no axios `.response`, so
  the status probe returned `undefined` and the final line wrapped it in
  `NetworkError('<op> request failed')` with the `AuthError` as `cause` — a
  wrong password was reported as a transport failure. `auth.ts` now rethrows an
  already-mapped `AxiamError` unchanged.

  The inconsistency this removes: `verifyMfa()` is *not* a `SKIP_REFRESH` url,
  so the identical `401` already surfaced there as `AuthError`. The same bad
  credential produced two different error classes depending on which endpoint
  saw it, and the README's documented `catch` pattern — `if (err instanceof
  AuthError) { /* re-authenticate */ }` — silently failed to match a failed
  login.

  It also compounded with the §23.4 rule 7 fallback: under `opaque_mode:
  "optional"`, `loginOpaque()` delegates to `login()` and returns its outcome
  verbatim, so a wrong password came back as a `NetworkError` — which the
  README's own fallback guard (`if (!(err instanceof NetworkError)) throw err`)
  treats as "OPAQUE unavailable, try the password path", running a second
  plaintext login for a credential that had already been rejected.

  **Behaviour change for callers** who catch `NetworkError` around `login()`,
  `refresh()` or `logout()` to handle a rejected credential: that now arrives
  as `AuthError`. Catching `AxiamError`, or the `AuthError`/`NetworkError`
  split the README documents, was already correct and is unaffected. Transport
  failures with no response are still `NetworkError` with the same messages.

## [1.0.0-alpha40] - 2026-08-23

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha39.

## [1.0.0-alpha39] - 2026-08-23

### Changed

- Re-vendor CONTRACT.md for the §14.1 anchor repair
- Re-vendor openapi.json at 1.0.0-alpha38

## [1.0.0-alpha38] - 2026-08-22

### Added

- Add WebAuthn (§24), account lifecycle (§25) and PAR (§26)

- **WebAuthn and passkeys — CONTRACT.md §24.** Six relying-party operations on
  `AxiamClient` (`webauthnRegisterStart`/`Finish`,
  `webauthnAuthenticateStart`/`Finish`, `webauthnDiscoverableStart`/`Finish`),
  isomorphic so a Node service completing a ceremony a handset ran is the
  relying party exactly as a browser is. A new `axiam-sdk/browser` subpath adds
  the platform ceremony over `navigator.credentials` —
  `webauthnRegister`/`webauthnLogin`/`webauthnDiscoverableLogin`, feature
  detection, conditional mediation, and the five-outcome error classification.

- **The §24.6a JSON bridge.** `webauthnRequestJson` hands the challenge to any
  platform authenticator API in the JSON form all of them speak, and every
  `*Finish` accepts the platform's response JSON string directly — so an Android
  app passes `requestJson` into `CreatePublicKeyCredentialRequest` and the
  response straight back, with nothing destructured in between.

- **Account lifecycle and MFA enrolment — CONTRACT.md §25.** Nine operations:
  `mfaEnroll`/`mfaConfirm`, `mfaSetupEnroll`/`mfaSetupConfirm`, `verifyEmail`,
  `resendVerification`, `requestPasswordReset`, `confirmPasswordReset`,
  `passwordResetContext`.

- **Pushed authorization requests — CONTRACT.md §26 (RFC 9126).** `oidcPar` on
  `OidcClient`, plus `pushed_authorization_request_endpoint` in the discovery
  document type.

- Examples: `webauthn-browser.ts`, `account-lifecycle.ts`, `par-login.ts`.

### Changed

- Use the shared authenticatorData fixture value

- Re-vendor CONTRACT.md at 1.28

- Re-vendor `CONTRACT.md`. Repairs §14.1's link to the `device_login` heading,
  which dropped a hyphen the em dash leaves behind and so rendered as a link
  that went nowhere; the same heading's other two links were already correct.
  Link target only — no normative change and no contract-version bump.

- Re-vendor `openapi.json` at **1.0.0-alpha38**. The server registered the four
  GDPR data-subject endpoints (`POST /api/v1/account/export`,
  `GET /api/v1/account/export/{token}`, `POST /api/v1/account/delete`,
  `GET /api/v1/auth/account/delete/cancel`), taking the document to 181
  operations across 121 paths. Purely additive, and no SDK surface changes with
  it: nothing in this repo is generated from the spec, so the cross-repo
  artifact-drift gate was the only thing reporting `STALE`.

- **BREAKING — `login()` and `loginOpaque()` gain a third outcome.** A tenant
  that requires MFA answers `403 mfa_setup_required` with a setup token for an
  account that has none. That used to arrive as an `AuthzError`, which told the
  caller they lacked permission to log in when what the server said was
  recoverable and came with the means to recover. It is now
  `{ status: 'mfa_setup_required', setupToken }` on `LoginResult`. Code that
  matches the union exhaustively needs a new arm; code that does not is
  unaffected, and a genuine authorization refusal is still an `AuthzError` —
  the SDK matches on the body's discriminant, not on the status alone.

- The SC#1 bundle-and-grep gate now covers the `axiam-sdk/browser` entry as well
  as `/rest`, rather than trusting a browser-only subpath to stay clean.

## [1.0.0-alpha37] - 2026-08-21

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha34.

## [1.0.0-alpha34] - 2026-08-21

### Added

- Replace SRP-6a with OPAQUE (RFC 9807) — CONTRACT 1.26

### Changed

- Link to the AXIAM platform documentation site

- Re-vendor openapi.json at alpha32 (#69)

- Document OpaqueEnrollment's fields for typedoc

## [1.0.0-alpha33] - 2026-08-21

### Added

- `@axiam/opaque-wasm` as an **optional peer dependency**. An installation that
  never calls the OPAQUE path is not made to carry a WebAssembly module; when it
  is absent, `opaqueAvailable()` resolves to `false` and `loginOpaque` rejects
  with a `NetworkError`, so the documented fallback to `login()` works unchanged.
- `OpaqueUnavailableError`, a `NetworkError` subclass, so a caller can tell "not
  installed" from "the tenant has it disabled" while a caller that only catches
  `NetworkError` needs no special case.

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha31.
- **BREAKING: `loginSrp` becomes `loginOpaque`** — CONTRACT.md §23 is now
  OPAQUE (RFC 9807), and SRP-6a is removed from AXIAM entirely.
  - `loginSrp` → `loginOpaque`, `srpEnrollment` → `opaqueEnrollment`,
    `srpAvailable` → `opaqueAvailable`.
  - `opaqueEnrollment` takes only a password and is **async**: it performs a
    `register/start` round trip, because OPAQUE's envelope is sealed under the
    server's oblivious PRF and there is no offline computation that produces a
    valid record. The SRP version took four arguments including the account's
    canonical username, and passing an email produced a verifier no login could
    satisfy — a mistake that is no longer expressible.
  - `opaqueAvailable` is **async** and can genuinely return `false`.
  - The enrolment object has two fields where `SrpEnrollment` had seven.
- **The protocol is no longer implemented here.** `core/srp.ts` — 419 lines of
  modular exponentiation, `PAD()` and transcript hashing — is replaced by a
  loader around `@axiam/opaque-wasm`. §23.1 forbids an SDK from writing its own.
- Re-vendor `openapi.json` at **1.0.0-alpha32**, matching the server. The
  content was already byte-identical in every path and schema; only
  `info.version` differed, which is what the cross-repo artifact-drift gate
  reports as `STALE`.

### Removed

- The server-proof check. RFC 9807's AKE authenticates the server during the
  handshake, so opening `KE2` *is* the proof it holds the record. §23.3 rule 6
  had to mandate an `M2` comparison in capitals because skipping it kept only
  half the protocol; there is now nothing to skip.
- The group-restart loop. SRP had to guess a group before the server named one
  and re-run the exchange if it guessed wrong; `KE1` does not depend on the KSF,
  so a login is always one round trip.
- `hash-wasm` is no longer needed for the login path.
- `srp-test-vectors.json`, replaced by the smaller `opaque-test-vectors.json` —
  see CONTRACT §23.7 for why the fixture shrank rather than being ported.

### Fixed

- `OpaqueUnavailableError` re-sets its prototype after `super()`. `NetworkError`
  pins its own to survive ES5 transpilation, which silently breaks `instanceof`
  for anything extending it — the subclass would have been indistinguishable
  from its parent, defeating the distinction it exists to draw.

## [1.0.0-alpha31] - 2026-08-20

### Fixed

- Release: `npm publish` is called with an explicit `--tag`, derived from the
  version, so a prerelease publishes under `alpha` instead of being refused.
  npm >= 11 rejects publishing a prerelease with no dist-tag, and the publish
  job upgrades to npm@latest because Trusted Publishing needs >= 11.5.1 — so
  1.0.0-alpha29 and 1.0.0-alpha30 both failed at the pre-publish dry run and
  never reached the registry. The fix landed on main after the alpha30 tag was
  cut, so this is the first release to carry it.

## [1.0.0-alpha30] - 2026-08-20

### Changed

- Added publish environment to NPM publish flow

## [1.0.0-alpha29] - 2026-08-20

### Added

- SRP-6a login client (CONTRACT §23) + npm Trusted Publishing (#66)

## [1.0.0-alpha28] - 2026-08-19

### Changed

- Re-vendor openapi.json at 1.0.0-alpha27 (#65)
- Bump github/codeql-action from 4.37.6 to 4.37.7
- Bump the minor-patch group with 3 updates

## [1.0.0-alpha27] - 2026-08-17

### Added

- §22.14 declarative reactor handler binding — reactorHandlers
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

### Changed

- Stop a doc comment tripping the TLS-bypass gate
- Re-vendor CONTRACT.md 1.23 (§8b rules 7 and 8)
- Re-vendor openapi.json for the SCIM provisioning-token endpoints
- Re-vendor CONTRACT.md 1.22 from the server repo
- Re-vendor `openapi.json` at 1.0.0-alpha27 — the copy was pinned at alpha26 and
  failing the cross-repo artifact-drift gate

### Fixed

- Enforce §8b instead of documenting it
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

### Changed

- Re-vendor CONTRACT.md 1.19, openapi.json and proto/ from main (R5.8) (#59)
- Contract 1.15 — §10.1 rule 9, sender-constrained access tokens (#57)
- Add the §20.7 required timeout assertion
- Retire the "measured residual" justification (contract 1.14)
- Re-sync to contract 1.14 (#302 closed)
- Bump the minor-patch group with 3 updates
- Bump github/codeql-action from 4.37.4 to 4.37.6
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
- Re-vendored `CONTRACT.md` at **1.8.1**. `openapi.json` unchanged — docs-only contract revs.
- `RetryOptions.maxAttempts` removed: §16.1 fixes the cap at 3 and forbids raising it.
  `withRetry`'s callback now receives the attempt number.

### Fixed

- Re-export the §20 types from the middleware entry point
- Re-export the §12.7/§14/§15 types from the middleware entry point
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

## [1.0.0-alpha24] - 2026-08-04

### Added

- Enforce the full CONTRACT §10.1 local-verification set
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
- Repin `amqplib` from the mis-pinned `^2.0.1` to `^0.10.9`, matching the vendored
  `@types/amqplib` range (SEC-078, an SDK-Q06 regression). Add a `npm ls amqplib` CI gate so a
  future pin that can't resolve, or that drifts out of the range the bundled types are built
  against, fails the build instead of surfacing later as a silent install or type mismatch.

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

- Add organization context to client options (login + refresh) (#17)
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
