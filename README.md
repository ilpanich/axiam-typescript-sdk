# axiam-sdk (TypeScript/JavaScript)

[![CI](https://github.com/ilpanich/axiam-typescript-sdk/actions/workflows/sdk-ci-typescript.yml/badge.svg?branch=main)](https://github.com/ilpanich/axiam-typescript-sdk/actions/workflows/sdk-ci-typescript.yml)
[![Coverage Status](https://coveralls.io/repos/github/ilpanich/axiam-typescript-sdk/badge.svg?branch=main)](https://coveralls.io/github/ilpanich/axiam-typescript-sdk?branch=main)
[![npm](https://img.shields.io/npm/v/axiam-sdk.svg)](https://www.npmjs.com/package/axiam-sdk)
[![Docs](https://img.shields.io/badge/docs-TypeDoc-blue.svg)](https://ilpanich.github.io/axiam-typescript-sdk/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Official TypeScript/JavaScript client SDK for [AXIAM](https://github.com/ilpanich/axiam) — Access eXtended Identity and Authorization Management.

**Platform documentation:** <https://ilpanich.github.io/axiam/> — getting started, the authorization model, the OAuth2/OIDC surface, and the operations guides. This README covers the SDK; the site covers the server it talks to.

## Package identity

- **npm package:** `axiam-sdk`
- **Registry:** [npmjs.com/package/axiam-sdk](https://www.npmjs.com/package/axiam-sdk) _(reserved, not yet published)_
- **Source:** [github.com/ilpanich/axiam-typescript-sdk](https://github.com/ilpanich/axiam-typescript-sdk)
- **License:** Apache-2.0
- **Node:** `>=22` — see [Supported Node versions](#supported-node-versions)

## Contract conformance

This SDK conforms to CONTRACT.md §1–§13 and §12.7, §14, §15, §17, §19, §20, §21, §22, §23,
§24, §25, §26, §27 (including §6.1 mTLS client certificates, the §10.1 minimum
local-verification set, the §12 OIDC/SSO relying-party helpers, and the §13
`verifyWebhook` signature verifier).

§27 is implemented **in full**, both halves: the 146-operation imperative surface *and*
the §27.6 declarative manifest with its §27.7 `defineManifest` and decorator forms. The
contract asks an SDK that ships only one half to say which; this one ships both.

§12.7, §14, §15, §22, §24, §25, §26 and §27 are named rather than folded into the range
because they landed after this SDK already claimed §1–§13: widening the range silently
would turn a statement that was true when written into a different claim without anyone
editing it.

### §10.1 minimum local-verification set

`axiamMiddleware` / `axiamPlugin` (and the `requireAuth` / `requireAccess` / `requireRole`
helpers built on them) funnel through `authenticateRequest`, which applies **every** §10.1
rule on every inbound token: EdDSA `alg` pinned before the JWKS is consulted, a REQUIRED
`exp` (`jose` only checks `exp` *if present*, so `requiredClaims: ['exp']` is passed
explicitly), `nbf` honoured when present, `tenant_id` asserted against the session's
configured tenant, `iss`/`aud` checked when configured, all under a named 60-second
`CLOCK_SKEW_LEEWAY_SEC`.

Because the `/oauth2/jwks` trust anchor is **organization-wide**, the session guarding a
resource server must be configured with the tenant **UUID** (`tenantId`), since that is
what the `tenant_id` claim carries. `expectedIssuer` / `expectedAudience` are optional and
unset by default:

```ts
const client = createNodeClient({
  baseUrl: 'https://iam.example.com',
  tenantId: '…-uuid-…',        // §10.1 rule 4 — compared against the tenant_id claim
  expectedAudience: 'axiam:user', // §10.1 rule 6 — optional, recommended
});
app.use(axiamMiddleware(client.session));
```

`verifier.verifySignatureOnlyUnchecked(token)` is the §10.1 raw signature-only primitive,
for integrators implementing their own policy. It checks the signature and nothing else —
never use it to guard a route.

See [`CONTRACT.md`](./CONTRACT.md) for the full cross-language behavioral contract.

## Install

```bash
npm install axiam-sdk
```

## Supported Node versions

| | Version | Why this one |
|---|---|---|
| **Floor** | 22 | The oldest release line still receiving security fixes. Node 18 went EOL 2025-04-30 and Node 20 on 2026-04-30. `engines.node` is `>=22`. |
| **Newest** | 26 | The current release line (out 2026-05, promoted to LTS 2026-10), and the line `@types/node` is pinned to. |

Node 24 (Active LTS) sits between the two and is supported.

**The SDK is built against the floor, and runs on everything up to the newest.**
Those are two different claims, and CI proves each separately: the gating
matrix in `sdk-ci-typescript.yml` runs `build`, `typecheck`, the full test
suite and the CommonJS-require smoke tests on **22 and on 26**. The floor leg
is what stops a Node 24-only built-in from slipping in; the newest leg is what
catches a removal, and is the runtime `tsc` is typechecking against. A line
between two green legs is interpolation, which is why the matrix is two legs
rather than four — the runtime-independent gates (bundle-grep, the token-leak
and TLS-lint greps, `npm audit`, the docs gate and the publish dry-run) run
once, on the floor.

If you are on a newer runtime than the floor you need do nothing: the
published bundle targets ES2022 and is forward-compatible, and the newest leg
is the evidence.

The browser persona (`axiam-sdk/browser`) has no Node floor at all — it needs
a runtime with `fetch`, `crypto.subtle` and `TextEncoder`, which every
currently supported browser has.

`test/core/versionPolicy.test.ts` fails the build if `engines.node`, the
`@types/node` pin and the CI matrix ever stop agreeing. They are three
independent declarations of the same fact and nothing else compares them —
before that test existed, all three disagreed at once.

## Two personas, tree-shaken subpath entries

`axiam-sdk` ships as **one package with two personas**, each reachable through its own
`package.json` subpath so a bundler only pulls in the transport code the caller actually
imports (proven in CI by the SC#1 bundle-and-grep gate — a `/rest`-only browser bundle
never contains `@grpc/grpc-js` or `amqplib`):

| Entry point            | Persona                    | Contents                                                                 |
|-------------------------|-----------------------------|---------------------------------------------------------------------------|
| `axiam-sdk` / `axiam-sdk/rest` | Browser + Node, REST-only  | `AxiamClient`: `login`/`verifyMfa`/`refresh`/`logout`, `can`/`batchCheck` over the FND-04 REST authz endpoint |
| `axiam-sdk/browser`     | Browser only                | The WebAuthn **platform ceremony** — `webauthnRegister`/`webauthnLogin`/`webauthnDiscoverableLogin` over `navigator.credentials` (CONTRACT.md §24.6b). The relying-party operations themselves are on `AxiamClient` in `/rest` and work in Node too. |
| `axiam-sdk/grpc`        | Node only                   | Everything in `/rest` plus `AuthzGrpcClient.checkAccess`/`batchCheck` and `UserInfoGrpcClient.getUserInfo` over gRPC, the Node persona (`createNodeSession`), and the local-JWKS verifier |
| `axiam-sdk/amqp`        | Node only                   | `consume()` — HMAC-verified AMQP audit/authz event consumer (CONTRACT.md §8) |
| `axiam-sdk/node`        | Node only                   | The Node persona (`createNodeSession`/`createNodeClient`, cookie jar + local-JWKS verifier) plus the **OIDC/SSO relying-party helpers** — `OidcClient`, `MemoryOidcStateStore`, PKCE primitives (CONTRACT.md §12) |
| `axiam-sdk/middleware`  | Node only                   | `axiamMiddleware` (Express) / `axiamPlugin` (Fastify) — shared local-JWKS verify core (CONTRACT.md §10) — plus `requireAuth`/`requireAccess`/`requireRole` declarative route guards (CONTRACT.md §11) and the `oidcLoginHandlers`/`oidcLoginPlugin` "Login with AXIAM" routes (CONTRACT.md §12) |
| `axiam-sdk/nestjs`      | Node only, optional         | `@RequireAccess`/`@RequireAuth`/`@RequireRole` metadata decorators + `AxiamGuard` (CONTRACT.md §11, Tier 2) |

**Browser code should only ever import from `axiam-sdk` or `axiam-sdk/rest`.** Importing
`axiam-sdk/grpc`, `axiam-sdk/amqp`, or `axiam-sdk/middleware` pulls in Node-only
dependencies (`@grpc/grpc-js`, `amqplib`, `jose`'s Node crypto, `express`/`fastify` types)
that do not belong in a browser bundle.

## Construction

`tenantSlug` (or `tenantId`) is a non-optional constructor parameter (CONTRACT.md §5) —
there is no default tenant:

```typescript
import { AxiamClient } from 'axiam-sdk';

const client = new AxiamClient({
  baseUrl: 'https://iam.example.com',
  tenantSlug: 'acme',
  // Organization context is required for login/refresh — a tenant slug is only
  // unique within an organization (CONTRACT.md §5.1). Pass orgSlug (or orgId).
  orgSlug: 'acme',
  // customCa is optional — PEM-encoded CA cert for self-signed dev environments (§6)
  // customCa: pemString,
});
```

### mTLS / client certificates (Node only)

For IoT devices and service accounts authenticated by **mutual TLS** (CONTRACT.md §6.1),
pass a PEM client-certificate chain and its PEM private key. The identity is presented on
**both** the REST and gRPC transports of the same client. Presenting a client certificate
**never** relaxes server verification — strict TLS stays on.

```typescript
import { readFileSync } from 'node:fs';
import { AxiamClient } from 'axiam-sdk';

const client = new AxiamClient({
  baseUrl: 'https://iam.example.com',
  tenantSlug: 'acme',
  orgSlug: 'acme', // organization context required for login/refresh (CONTRACT.md §5.1)
  clientCert: readFileSync('device.crt', 'utf8'), // PEM certificate chain
  clientKey: readFileSync('device.key', 'utf8'),  // PEM private key (PKCS#8 or PKCS#1)
  // customCa: readFileSync('ca.crt', 'utf8'),     // optional server-trust CA (§6)
});
```

- `clientCert` and `clientKey` are **all-or-nothing** — providing exactly one throws at
  construction, and each is validated to be PEM-shaped (as `customCa` is).
- The private key is secret material: it is passed straight to the Node TLS stack and is
  never retained on a public property, logged, or serialized (CONTRACT.md §7).
- **Node only.** Browsers cannot present a client certificate from JavaScript, so the
  browser build validates the PEM shape then ignores `clientCert`/`clientKey` — exactly as
  it already ignores `customCa`.

## Usage per persona

### Browser — login + authz (`axiam-sdk` / `axiam-sdk/rest`)

```typescript
import { AxiamClient } from 'axiam-sdk';

const client = new AxiamClient({ baseUrl: 'https://iam.example.com', tenantSlug: 'acme', orgSlug: 'acme' });

const result = await client.login(email, password);
switch (result.status) {
  case 'mfa_required': {
    const code = await promptForMfaCode(result.availableMethods);
    const final = await client.verifyMfa(result.mfaToken, code);
    if (final.status === 'authenticated') console.log(`Authenticated as ${final.user.username}`);
    break;
  }
  case 'authenticated': {
    console.log(`Authenticated as ${result.user.username}`);
    break;
  }
}

// Single access check (REST-backed, browser-safe)
const allowed = await client.can('read', 'doc:1');

// Batch check — results preserve input order
const decisions = await client.batchCheck([
  { action: 'read', resourceId: 'doc:1' },
  { action: 'write', resourceId: 'doc:1' },
]);
```

Tokens arrive exclusively via `httpOnly` `Set-Cookie` — no raw session token is ever
exposed to application code. CSRF forwarding (cookie double-submit, CONTRACT.md §3) and
single-flight refresh (CONTRACT.md §9) are handled automatically.

### Node — gRPC authz (`axiam-sdk/grpc`)

```typescript
import { AuthzGrpcClient, createNodeSession } from 'axiam-sdk/grpc';

const session = createNodeSession({ baseUrl: 'https://iam.example.com', tenantSlug: 'acme' });
const grpcClient = new AuthzGrpcClient(session, { baseUrl: 'https://iam.example.com' });

const decision = await grpcClient.checkAccess({
  tenantId: 'tenant-1',
  subjectId: 'user-1',
  action: 'read',
  resourceId: 'doc:1',
});

grpcClient.close();
```

The gRPC channel is constructed once and reused; `UNAUTHENTICATED` responses transparently
share the same single-flight refresh guard as the REST persona (CONTRACT.md §9).

#### gRPC userinfo (`UserInfoGrpcClient.getUserInfo`, CONTRACT.md §1.1)

`getUserInfo` is a **gRPC-only** operation (contract 1.3) — the low-latency counterpart of
the server's REST `/oauth2/userinfo` endpoint. It takes no arguments; the caller's identity
is derived server-side from the bearer token. It reuses the same channel, auth + `x-tenant-id`
metadata interceptor, and single-flight refresh guard as `AuthzGrpcClient` (a co-located
client built from the same session shares the pooled connection).

```typescript
import { UserInfoGrpcClient, createNodeSession } from 'axiam-sdk/grpc';

const session = createNodeSession({ baseUrl: 'https://iam.example.com', tenantSlug: 'acme' });
// ... after a successful login() on an AxiamClient sharing this session ...
const userInfoClient = new UserInfoGrpcClient(session, { baseUrl: 'https://iam.example.com' });

const info = await userInfoClient.getUserInfo();
// info: { sub, tenantId, orgId, email?, preferredUsername? }
// email is present only with the "email" scope, preferredUsername only with "profile".

userInfoClient.close();
```

Calling `getUserInfo()` with no token present raises `AuthError` client-side, without a wire
call (CONTRACT.md §1.1). A `UNAUTHENTICATED` response drives exactly one refresh + one retry,
identical to `checkAccess`.

### Node — AMQP consumer (`axiam-sdk/amqp`)

```typescript
import { consume, Sensitive } from 'axiam-sdk/amqp';

const signingKey = new Sensitive(Buffer.from(process.env.AXIAM_AMQP_SIGNING_KEY ?? '', 'hex'));

await consume(
  // §8b: amqps:// only, enforced — a plaintext URL is refused before a socket
  // opens, and there is no fallback for it to take.
  'amqps://localhost:5671',
  'axiam.audit.events',
  signingKey,
  async (event) => {
    // Only a verified event ever reaches this closure — HMAC-SHA256
    // signature checked and stripped by the SDK before your handler runs
    // (CONTRACT.md §8). Verification failures are nacked-without-requeue.
    console.log('verified audit event:', event);
  },
  // Optional. The PEM bundle for a privately issued broker certificate — the
  // common in-cluster case (§8b rule 2), and the only TLS knob this SDK has.
  { tls: { caCert: readFileSync('/etc/axiam/broker-ca.pem', 'utf8') } },
);
```

#### Transport security (§8b)

`consume()` and `reactorServe()` both require `amqps://` and enforce it before
any socket is opened. HMAC signing (§8) gives authenticity and replay
protection across broker hops; TLS gives confidentiality. Both are required and
neither substitutes for the other — a signed `AuthzRequest` still names its
subject, resource and action in cleartext on an unencrypted wire.

| Option | Meaning |
|---|---|
| `tls.caCert` | PEM bundle for a privately issued broker certificate. Omit for a publicly issued one (Node's bundled roots verify it). |
| `tls.clientCert` + `tls.clientKey` | Mutual TLS toward the broker. All-or-nothing: half an identity is rejected before dialling. |

There is deliberately no verification-skip option, under any name (§8b rule 4).
A switch like that appears in a dev compose file, works, and travels unchanged
into production, where it turns TLS into an expensive no-op against precisely
the attacker TLS exists to stop. `caCert` covers the legitimate reason people
reach for one.

### Node — reactors, AMQP extension actors (`axiam-sdk/amqp`, CONTRACT.md §22)

A **reactor** is an external process that subscribes to named hook events on the AMQP bus and
answers back — allow, deny, or a field-allow-listed mutation — inside a timeout the server
declared. It is AXIAM's answer to Zitadel Actions and Keycloak SPIs, and the difference is the
whole design: those load third-party code *into* the authorization server, and this keeps it
outside, reachable only through a signed reply schema the server validates before it believes
a word of it.

```typescript
import { Sensitive } from 'axiam-sdk/amqp';
import { REACTOR_EVENTS, allow, deny, mutate, reactorServe } from 'axiam-sdk/amqp';

const signingKey = new Sensitive(Buffer.from(process.env.AXIAM_AMQP_SIGNING_KEY_HEX ?? '', 'hex'));

await reactorServe(
  {
    amqpUrl: 'amqps://reactor:secret@broker.example.com:5671',
    tenantId: '11111111-1111-1111-1111-111111111111',
    reactorId: '99999999-9999-9999-9999-999999999999',
    signingKey, // the tenant's HKDF-derived AMQP subkey, never the master key
  },
  (event) => {
    switch (event.event) {
      // token.pre_issue is mutable — the `ext.` namespace, and nothing else.
      case REACTOR_EVENTS.TOKEN_PRE_ISSUE:
        return mutate({ 'ext.cost_center': '42' });
      // login.post_auth is veto-only, plus step-up.
      case REACTOR_EVENTS.LOGIN_POST_AUTH:
        return deny('embargoed region');
      default:
        return allow();
    }
  },
);
```

#### Binding handlers per event (§22.14)

The `switch` above is the shape every multi-event reactor grows, and its `default:` arm —
`return allow()` — answers on behalf of code that never ran. That is the defect §22.10
rule 2 forbids the *runtime* from committing, relocated into your file where the rule does
not reach it: an operator who set `fail_closed` on the registration has it defeated there.

`reactorHandlers` is §22.14's declarative form, in the spirit of the §11 declarative
authorization helpers:

```typescript
import { REACTOR_EVENTS, reactorHandlers, reactorServe } from 'axiam-sdk/amqp';

await reactorServe(
  options,
  reactorHandlers({
    [REACTOR_EVENTS.TOKEN_PRE_ISSUE]: (event) => mutate({ 'ext.cost_center': '42' }),
    [REACTOR_EVENTS.LOGIN_POST_AUTH]: async (event) => deny('embargoed region'),
  }),
);
```

- **A misspelled event is a compile error**, because the map's key type is
  `ReactorEventName` — and it is re-checked at runtime for JavaScript callers, who get no
  such help. That runtime check is also how the three hot-path operations §22.7 excludes are
  refused: they are in no registry row.
- **An unbound event abstains** — no reply, and the registration's `failure_policy` decides
  (§22.8), exactly as it decides a timeout. Never a synthesized `allow`.
- Several maps may be passed (`reactorHandlers(tokenHandlers, loginHandlers)`) so handlers
  can be split across modules; binding the same event twice throws rather than silently
  overwriting.

It is pure sugar: the value it produces is exactly the `ReactorHandler` `reactorServe`
already takes. It opens nothing, verifies nothing, signs nothing, does not filter a patch,
and a handler's own rejection reaches the runtime unchanged so nothing is published.

See [`examples/reactor/index.ts`](examples/reactor/index.ts) for a complete three-hook reactor
with graceful shutdown and a telemetry hook.

#### The five hookable events, and their allow-lists

| Event | Mutable | Complete allow-list | Default failure policy |
|---|---|---|---|
| `token.pre_issue` | yes | the **`ext.`** namespace only | `fail_open` |
| `login.post_auth` | no | — (veto, or `require_mfa`) | `fail_closed` |
| `user.pre_create` | yes | `username`, `email`, `metadata.` | `fail_closed` |
| `user.pre_update` | yes | `username`, `email`, `metadata.` | `fail_closed` |
| `grant.pre_assign` | no | — (veto only) | `fail_closed` |

An entry ending in `.` is a **namespace prefix** and needs at least one character after the
dot: `ext.` admits `ext.department` and `ext.a.b.c`, and refuses `ext.` itself, `ext`, `extra`,
`external_id` and `evil.ext.department`. So a reactor can never reach `sub`, `aud`, `exp`,
`scope` or any other standard claim — a **correctly signed** reply setting `sub` is refused
exactly as a forged one is.

Registrations that name no `failure_policy` get **the strictest default among their events**,
in either array order — `defaultFailurePolicyFor([...])` computes it, and "take the first
event's default" is specifically what §22.8 forbids, because it lets the order of a JSON array
decide whether an unreachable fraud check passes.

#### `authz.check` is not hookable, and this SDK does not pretend otherwise

`authz.check`, `authz.check_batch` and `token.introspect` are absent from `EVENT_REGISTRY`,
from `REACTOR_EVENTS` and from every example here (§22.7, a normative MUST NOT). A reactor
round-trip is milliseconds; the check path's budget is microseconds. An application that needs
external input on an authorization decision writes a **deny grant**, which the engine
evaluates in the hot path at hot-path cost — and there is deliberately no client-side
interceptor in this SDK offering itself as the reactor equivalent.

#### What the runtime guarantees

- **Both directions are signed.** The server signs the event with the tenant's HKDF-derived
  AMQP subkey; the reactor signs its reply with the same key. An unsigned or stale reply is
  not a weak reply — the server discards it as though the reactor had never answered. Every
  event is verified (`key_version >= 2`, MAC, ±300 s freshness, nonce seen-set) *before* your
  handler is called.
- **Two canonicalization quirks, both of which are silent failures if missed.** First, a
  reactor body signs `hmac_signature` as **`null`**, where §8's own two message types omit it.
  Second — and this one is TypeScript's alone — `Date.prototype.toISOString()` always emits
  three fractional digits, while the server's `chrono` emits none on a whole second; a reply
  timestamped `…T12:00:00.000Z` is re-serialized server-side as `…T12:00:00Z` and its MAC
  fails with no other symptom. `toChronoRfc3339()` is the fix and the runtime always uses it.
  Both are pinned by server-generated vectors rather than by memory — see
  [`testdata/reactor_v2_reference_vectors.json`](testdata/reactor_v2_reference_vectors.json)
  and [`test/amqp/reactor/vectors.test.ts`](test/amqp/reactor/vectors.test.ts).
- **It declares no topology.** No `assertQueue`, no `assertExchange`, no `bindQueue` — the
  server owns all three, and the `ReactorChannel` seam this runtime is written against does
  not even offer them. A reactor that can bind is a reactor that can bind itself to
  `*.token.pre_issue` and read another tenant's issuance events.
- **It fails closed on its own errors.** A handler that throws, a body that will not parse, a
  window that has already closed: each publishes **nothing**, so the registration's
  `failure_policy` decides. Synthesizing an `allow` would override the operator's
  `fail_closed` setting from inside the library. `abstain()` is the explicit form of the same
  thing.
- **It does not filter your patch.** One forbidden key rejects the whole patch server-side;
  pruning it here would leave you believing a field was set when it was dropped. Check
  yourself with `patchFieldAllowed(spec, field)` if you want to know before you send.
- **It honours `timeout_ms`.** The handler runs inside the window the server declared, and a
  reply whose window has closed is abandoned rather than published late.
- **Shutdown drains (§18).** Pass an `AbortSignal`; aborting it cancels the consumer, lets
  every dispatch already running finish — handler, signature, publish — and only then closes
  the channel and connection.

#### Registering a reactor (§22.9)

Registration is a REST admin call, not part of this runtime:

```bash
curl -X POST https://axiam.example.com/api/v1/reactors \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"fraud-check","events":["login.post_auth"],"mode":"intercept","timeout_ms":500}'
```

The response's `id` is what `reactorId` takes, and the server declares the queue.
`timeout_ms` defaults to **500** and is refused outside `1…5000`; the chain's wall-clock
ceiling is **5000 ms** and the per-tenant in-flight cap is **64**. This SDK exposes those as
constants (`DEFAULT_REACTOR_TIMEOUT_MS`, `MAX_REACTOR_TIMEOUT_MS`,
`DEFAULT_REACTOR_MAX_IN_FLIGHT`) but ships **no typed client for the CRUD endpoints** — call
them through the REST client, and let the server validate; §22.9 explicitly warns against
re-deriving `PUT` merge semantics or the `failure_policy` re-derivation client-side.

#### Logging

The `payload`, `patch`, `reason` and `decision` are tenant business data — readable by design,
since a handler that cannot inspect the event cannot decide anything, but this runtime never
logs them at info level and yours should not either (§22.12). The signing key is
`Sensitive<Buffer>`, is never logged at any level, and never appears in an error payload.
`nonce`, `correlation_id` and `hmac_signature` are not secrets and may be logged for
correlation.

### Express middleware (`axiam-sdk/middleware`)

```typescript
import express from 'express';
import { createNodeSession } from 'axiam-sdk/grpc';
import { axiamMiddleware, type AxiamRequest } from 'axiam-sdk/middleware';

const session = createNodeSession({ baseUrl: 'https://iam.example.com', tenantSlug: 'acme' });
const app = express();

app.use(axiamMiddleware(session));

app.get('/protected', (req, res) => {
  const axiamUser = (req as AxiamRequest).axiamUser;
  res.json({ userId: axiamUser?.userId, tenantId: axiamUser?.tenantId, roles: axiamUser?.roles });
});
```

### Fastify plugin (`axiam-sdk/middleware`)

```typescript
import Fastify from 'fastify';
import { createNodeSession } from 'axiam-sdk/grpc';
import { axiamPlugin, type AxiamFastifyRequest } from 'axiam-sdk/middleware';

const session = createNodeSession({ baseUrl: 'https://iam.example.com', tenantSlug: 'acme' });
const app = Fastify();

app.register(axiamPlugin(session));

app.get('/protected', (request, reply) => {
  const axiamUser = (request as AxiamFastifyRequest).axiamUser;
  reply.send({ userId: axiamUser?.userId, tenantId: axiamUser?.tenantId, roles: axiamUser?.roles });
});
```

Both middleware integrations verify the session against a locally-cached JWKS (no
`cookie-parser` / `@fastify/cookie` peer dependency required), inject the authenticated
identity into the request context, and surface `AuthError` as HTTP 401 / `AuthzError` as
HTTP 403 with a standardized JSON error body (CONTRACT.md §10).

### Declarative authorization helpers (`axiam-sdk/middleware`)

CONTRACT.md §11 adds a per-endpoint authorization layer on top of the §10 guard above:
`requireAuth`, `requireAccess`, `requireRole` (Express) and their `*Hook` counterparts
(Fastify). They never extract or verify a token themselves — they read the identity
`axiamMiddleware`/`axiamPlugin` already injected (401 if absent) — and `requireAccess`
additionally needs an authz-capable client on the session (`authzClient`, satisfied by
`AxiamClient.checkAccess`):

```typescript
import { AxiamClient } from 'axiam-sdk/rest';
import { createNodeSession } from 'axiam-sdk/grpc';
import {
  axiamMiddleware,
  fromParam,
  requireAccess,
  requireRole,
  type AuthzVerifiableSession,
} from 'axiam-sdk/middleware';

const session = createNodeSession({ baseUrl: 'https://iam.example.com', tenantSlug: 'acme' });
const authzSession: AuthzVerifiableSession = {
  ...session,
  // Adopts the SAME session, so the cookie jar/refresh guard is shared with axiamMiddleware.
  authzClient: new AxiamClient({ baseUrl: 'https://iam.example.com', tenantSlug: 'acme' }, session),
};

const app = express();
app.use(axiamMiddleware(session));

// action before resource (§1); resource is a literal, `fromParam('id')`, or a `(req) => string` resolver.
app.get('/documents/:id', requireAccess(authzSession, 'read', fromParam('id')), (req, res) => {
  res.json({ documentId: req.params.id });
});

// Local-only (no server round-trip) role check — NOT a substitute for requireAccess.
app.get('/admin', requireRole(session, 'admin'), (_req, res) => res.json({ ok: true }));
```

The Fastify equivalents are `requireAuthHook`/`requireAccessHook`/`requireRoleHook`, each
returning a plain `preHandler` function:

```typescript
import { requireAccessHook, fromParam } from 'axiam-sdk/middleware';

app.get(
  '/documents/:id',
  { preHandler: requireAccessHook(authzSession, 'read', fromParam('id')) },
  async (request) => ({ documentId: (request.params as { id: string }).id }),
);
```

Error mapping (§11.2.5, same `{ error, message }` JSON shape as §10): 401
`authentication_failed` (no authenticated identity on the request), 403
`authorization_denied` (denied by policy), 400 `invalid_request` (the resource id
couldn't be resolved — never a silent allow), 503 `authz_unavailable` on any transport
failure while calling the authz endpoint (fail closed — a network error never allows).
The check is always made for the *authenticated request's* user (`subjectId =
axiamUser.userId`), never the SDK client's own service-account identity, and the decision
is never cached.

#### NestJS (`axiam-sdk/nestjs`, optional)

An optional Tier 2 on top of the same `middleware/authzCore.ts` primitives: metadata
decorators plus an `AxiamGuard` (`CanActivate`) that reads them via `Reflector`.
`@nestjs/common`/`@nestjs/core` are optional peer dependencies, like `express`/`fastify`
above. `AxiamGuard` never extracts or verifies a token itself — mount
`axiamMiddleware`/`axiamPlugin` on the underlying HTTP adapter (Nest runs on top of
Express or Fastify) so `request.axiamUser` is already set:

```typescript
import { APP_GUARD, Reflector } from '@nestjs/core';
import { Controller, Get, Module, Param } from '@nestjs/common';
import { AXIAM_SESSION, AxiamGuard, RequireAccess, RequireRole } from 'axiam-sdk/nestjs';

@Controller('documents')
class DocumentsController {
  @RequireAccess('read', { param: 'id' })
  @Get(':id')
  getDocument(@Param('id') id: string) {
    return { documentId: id };
  }

  @RequireRole('admin')
  @Get()
  listDocuments() {
    return { message: 'admin-only listing' };
  }
}

@Module({
  controllers: [DocumentsController],
  providers: [
    { provide: AXIAM_SESSION, useValue: authzSession },
    // AxiamGuard is a plain class with no Nest decorators of its own (this SDK's
    // tsconfig does not enable experimentalDecorators) — wire it via a factory provider.
    { provide: APP_GUARD, useFactory: (r: Reflector) => new AxiamGuard(r, authzSession), inject: [Reflector] },
  ],
})
class AppModule {}
```

See `examples/nestjs-app.ts` for a complete, compiling example (including the
`axiamMiddleware` wiring `AxiamGuard` depends on).

More runnable examples (all compiling under `tsc --noEmit -p examples/tsconfig.json`) live
in `examples/` at the package root.

## OIDC / SSO relying-party helpers (`axiam-sdk/node`, CONTRACT.md §12)

Everything a backend needs to offer **"Login with AXIAM"** — authorization code + PKCE
against AXIAM's own OIDC provider — plus service-account M2M login, token
introspection/revocation, and the upstream-IdP federation endpoints. Node-only: PKCE uses
`node:crypto` and ID-token validation uses `jose`, so these deliberately do not hang off the
browser-safe `AxiamClient` (a `/rest` browser bundle stays free of Node code, proven by CI).

```typescript
import { createNodeSession, createOidcClient, MemoryOidcStateStore } from 'axiam-sdk/node';

// One session carries the cookie jar (§4), TLS config (§6) and refresh guard (§9)
// that the OIDC client reuses rather than duplicating.
const session = createNodeSession({ baseUrl: 'https://iam.example.com', tenantId, orgId });

const oidc = createOidcClient(session, {
  clientId: 'my-web-app',
  clientSecret: process.env.AXIAM_CLIENT_SECRET, // omit for a public client
});
```

### The nine operations

| Operation | Wire call | Notes |
|-----------|-----------|-------|
| `oidcDiscover()` | `GET /.well-known/openid-configuration` | Cached per origin, TTL ≥ 5 min, concurrent calls share one fetch |
| `oidcBegin({ configuration, redirectUri, scope?, extraParams? })` | *none — pure local computation* | CSPRNG `state`/`nonce` (256-bit) + PKCE **S256** challenge; returns `{ url, state, nonce, codeVerifier }` |
| `oidcExchange({ code, codeVerifier, nonce, redirectUri, tenantId?, configuration? })` | `POST /oauth2/token?tenant_id=…` | `grant_type=authorization_code`; validates the ID token in full before returning |
| `oidcRefresh({ refreshToken, scope?, tenantId?, configuration? })` | `POST /oauth2/token?tenant_id=…` | `grant_type=refresh_token`, under the §9 single-flight guard. **Distinct from `AxiamClient.refresh()`**, which drives the cookie-session path |
| `loginClientCredentials({ scope?, tenantId?, adoptAsCredential?, configuration? })` | `POST /oauth2/token?tenant_id=…` | Service-account M2M login; no `openid` scope, no ID token. `adoptAsCredential: true` uses the token as the session's bearer credential |
| `introspect({ token, tokenTypeHint?, tenantId?, configuration? })` | `POST /oauth2/introspect?tenant_id=…` | RFC 7662; requires a `clientSecret` |
| `revoke({ token, tokenTypeHint?, tenantId?, configuration? })` | `POST /oauth2/revoke?tenant_id=…` | RFC 7009; returns `void` and is **idempotent** — a `200` for an unknown token is success |
| `ssoStart({ federationConfigId, redirectUri, tenantId?/tenantSlug?, orgId?/orgSlug? })` | `POST /api/v1/auth/federation/oidc/start` | Upstream-IdP SSO step 1; returns `{ authorizeUrl, state, expiresInSecs }` |
| `ssoComplete({ state, code })` | `POST /api/v1/auth/federation/oidc/callback` | Step 2; the session arrives as `Set-Cookie`, so it needs the cookie-jar-backed Node session |

Wire details worth knowing: the token/introspection/revocation endpoints are
**form-encoded** (not JSON) and take `tenant_id` as a **required query parameter** in **UUID**
form — a slug-only client raises `AuthError` client-side rather than sending a slug. Client
authentication is `client_secret_post` (never HTTP Basic). Endpoint URLs always come from the
discovery document, never hardcoded.

### The caller owns the login state

`oidcBegin` and `oidcExchange` store **nothing** — no `state`, `nonce` or `code_verifier` in
the SDK, in process-global state, or in any implicit cache. You keep them (typically in your
own HTTP session) and pass `nonce` + `codeVerifier` back into `oidcExchange`:

```typescript
// 1. login route
const configuration = await oidc.oidcDiscover();
const request = oidc.oidcBegin({ configuration, redirectUri, scope: 'openid profile email' });
req.session.oidc = { state: request.state, nonce: request.nonce, verifier: request.codeVerifier };
res.redirect(request.url);

// 2. callback route — check the returned `state` matches, then exchange
const tokens = await oidc.oidcExchange({
  code: String(req.query.code),
  codeVerifier: req.session.oidc.verifier,
  nonce: req.session.oidc.nonce,
  redirectUri,
});
console.log(tokens.idClaims?.sub);   // validated ID-token subject
```

`MemoryOidcStateStore` is an optional, opt-in reference store for that bookkeeping (10-minute
TTL, single-use `consume(state)` — mirroring the server's own `federation_login_state`
semantics). It is single-process; use a shared store (Redis, a database) behind a load
balancer by implementing `OidcStateStore` yourself. The core operations never require one.

### Framework glue

```typescript
import { oidcLoginHandlers } from 'axiam-sdk/middleware';

const { login, callback } = oidcLoginHandlers({
  client: oidc,
  store: new MemoryOidcStateStore(),
  redirectUri: 'https://app.example.com/auth/callback',
  scope: 'openid profile email',
  // Establishing YOUR app session is your decision — the SDK validates the login
  // and hands you the token set.
  onSuccess: (tokens) => establishMySession(String(tokens.idClaims?.sub)),
});

app.get('/auth/login', login);       // 302 -> AXIAM /oauth2/authorize
app.get('/auth/callback', callback); // consume state -> exchange -> validate ID token
```

Fastify gets the same flow as a plugin: `fastify.register(oidcLoginPlugin({ …, loginPath,
callbackPath }))`. Both are thin adapters over the shared `beginOidcLogin`/`completeOidcLogin`
core, so they cannot drift. Failure mapping is identical: `400` malformed callback, `401`
authentication failure (unknown/expired/replayed state, IdP error, ID-token failure, OAuth2
protocol error), `503` when AXIAM is unreachable — never a silent success.

The login handler reads an optional `?returnTo=` and stores it with the login state.
**Validate or allowlist that value in your application** if you accept it from user input —
an unchecked redirect target is an open-redirect vector, and the SDK cannot know which
destinations your app considers safe.

### ID-token validation (always on)

Every ID token is validated before `oidcExchange` returns, per CONTRACT.md §12.4:
`alg` must be exactly `EdDSA` (`none` and everything else rejected, checked from the header
*before* any signature work); the Ed25519 signature must verify against the key selected by
`kid` from the document's `jwks_uri` (one JWKS re-fetch on an unknown `kid`, then fail);
`iss` must equal the discovery document's `issuer` by exact string comparison; `aud` must
contain the `client_id` (with `azp` required when there are multiple audiences); `exp`/`iat`/
`nbf` must hold within at most 60 s of clock skew; and the `nonce` claim must match the
`oidcBegin` nonce (constant-time). Any failure raises `AuthError` with a stable
`reason` code — `invalid_alg`, `unknown_kid`, `invalid_signature`, `invalid_issuer`,
`invalid_audience`, `token_expired`, `nonce_mismatch` — and **discards the entire token set**;
the access and refresh tokens from that response never reach the caller. There is no option
to disable or skip this.

```typescript
try {
  const tokens = await oidc.oidcExchange({ code, codeVerifier, nonce, redirectUri });
} catch (err) {
  if (err instanceof OAuthProtocolError) {
    console.error(err.error, err.errorDescription);   // e.g. "invalid_grant", "code expired"
  } else if (err instanceof AuthError) {
    console.error(err.reason);                        // e.g. "nonce_mismatch"
  }
}
```

`access_token`, `refresh_token`, `id_token`, `client_secret` and `code_verifier` are all
`Sensitive<T>` (CONTRACT.md §12.5) — they redact to `[SENSITIVE]` in `toString()`,
`JSON.stringify()` and `console.log`. `state` and `nonce` are not secrets and stay plain
strings.

See `examples/express-oidc-login.ts` for a complete, runnable example.

## OPAQUE (CONTRACT.md §23)

`loginOpaque` proves the password without sending it. What crosses the wire is
a blinded group element and a MAC, neither useful without the account's
registration record **and** the tenant's OPRF seed.

```ts
const result = await client.loginOpaque('alice', 'correct horse battery staple');
```

It takes the same arguments as `login` and returns the same `LoginResult`, MFA
branch included, so switching a tenant to OPAQUE needs no change to how the
result is handled.

### Falling back — and when not to

Fall back to `login()` when the tenant does not offer OPAQUE, or when this
installation cannot perform it. Both are a `NetworkError`, deliberately **not**
an `AuthError`, so neither can be mistaken for a bad password:

```ts
let result;
try {
  result = await client.loginOpaque(user, password);
} catch (err) {
  if (!(err instanceof NetworkError)) throw err;   // <- not a fallback case
  result = await client.login(user, password);
}
```

The `if` is the important line. **Any other error is a failed login**, and
retrying it over `login()` yourself would hand the plaintext to a server that
just failed to prove it holds the record.

One case is handled for you. `login/start` returns the tenant's `mode`, and when
it is `"optional"` — the mid-migration state, where accounts acquire a
registration record only as their passwords are next set — a failed exchange is
not yet a verdict on the credentials, so `loginOpaque` retries over
`POST /api/v1/auth/login` itself and returns that call's outcome (CONTRACT.md
§23.4 rule 7). Under `"required"`, and against a server too old to send `mode`
at all, it fails closed exactly as before. `mode` is **not** downgrade
protection: a hostile server that wanted the plaintext could answer `404` and
get the fallback above regardless. `required` is what closes that, server-side,
by refusing `/auth/login` for every principal in the tenant.

### What this buys, and what it does not

OPAQUE closes holes TLS 1.3 does not:

- a TLS-terminating reverse proxy, ingress controller, CDN or service mesh sees
  every plaintext password today; under OPAQUE it sees a blinded group element;
- an accidental request-body log, a heap dump or a crash reporter can no longer
  capture a plaintext password, because the server never has one;
- **a stolen record database is not offline-crackable on its own.** Recovering a
  password additionally requires the tenant's OPRF seed, encrypted at rest
  separately. This is the property SRP could not offer, and the main reason
  AXIAM replaced it.

It does **not** protect against a compromised AXIAM server, and in a browser it
does not protect against AXIAM serving malicious JavaScript.

### Enrolment

The server cannot build a record — it never sees the plaintext — so one has to
be sent with any request that sets a password:

```ts
const opaque = await client.opaqueEnrollment(newPassword);
// send `opaque` as the request body's `opaque` field
```

One argument, where the SRP verifier this replaces took four. There is no
`identity` — a record binds to a credential identifier the server chooses, so
enrolling against an email can no longer produce something no login can satisfy,
and a later rename cannot invalidate it — and no group or KDF, because the
server names them in its `register/start` response and this call honours what
it names.

It is `async` because that response has to be fetched: OPAQUE's envelope is
sealed under the server's oblivious PRF, so there is no offline computation that
produces a valid record. The SRP verifier needed no network at all.

### This SDK does not implement OPAQUE

CONTRACT.md §23.1 forbids it. SRP was hand-written eleven times because it is
modular arithmetic every language has; OPAQUE needs an oblivious PRF,
`hash_to_curve`, `expand_message_xmd`, an envelope construction and a
three-message AKE. `core/srp.ts` — 419 lines of it — is replaced by a loader
around `@axiam/opaque-wasm`, the WebAssembly build of the same implementation
the AXIAM server links and every other SDK binds.

### Runtime requirements

`@axiam/opaque-wasm` is an **optional peer dependency**:

```bash
npm install @axiam/opaque-wasm
```

Optional, because an installation that never touches the OPAQUE path should not
be made to carry a WebAssembly module. When it is absent, `opaqueAvailable()`
resolves to `false` and `loginOpaque` rejects with a `NetworkError` — reporting
rather than throwing at login time is what §23.1 asks of an SDK whose native
artifact did not load, and it is why the fallback above works unchanged.

```ts
if (!(await client.opaqueAvailable())) {
  // use login() — this installation cannot do OPAQUE
}
```

It is imported lazily and memoized, so a consumer who never calls OPAQUE does
not pay the wasm payload at module-load time, and two concurrent logins do not
instantiate it twice.

### Cost

`loginOpaque` runs the tenant's key-stretching function: Argon2id at 19 MiB and
t=2 by default, tens to hundreds of milliseconds of synchronous work. That cost
is the point — it is what makes a stolen record expensive to attack even by
someone holding the OPRF seed. In a browser, consider a Web Worker.

## WebAuthn and passkeys (CONTRACT.md §24)

A passkey ceremony is **two exchanges stacked**: one with an *authenticator*,
which needs a platform API, and one with *AXIAM*, which is four ordinary JSON
round trips. This SDK splits along that seam, and where you import from tells
you which half you get.

| | Where | Runs in |
|---|---|---|
| The six relying-party operations | `AxiamClient`, from `axiam-sdk` / `axiam-sdk/rest` | **Browser and Node** |
| The ceremony (`navigator.credentials`) | `axiam-sdk/browser` | Browser only |

The Node half is not a consolation prize. A service completing a ceremony that
ran on a handset — an Android app, an iOS app, a hardware client — is the
relying party, exactly as a browser is, and it never touches
`navigator.credentials`.

### The browser: three calls

```ts
import { AxiamClient } from 'axiam-sdk/rest';
import {
  isWebauthnSupported,
  webauthnRegister,
  webauthnLogin,
  webauthnDiscoverableLogin,
  classifyWebauthnError,
  webauthnErrorMessage,
} from 'axiam-sdk/browser';

const client = new AxiamClient({ baseUrl, orgSlug: 'globex', tenantSlug: 'acme' });

// Enrol, for a user who is already signed in.
if (isWebauthnSupported()) {
  await webauthnRegister(client, 'Alice’s laptop', 'platform');
}

// Passkey as a SECOND factor, continuing a password login.
const result = await client.login(email, password);
if (result.status === 'mfa_required' && result.availableMethods.includes('webauthn')) {
  await webauthnLogin(client, result.mfaToken);   // client is authenticated after this
}

// Passkey with NO username at all.
await webauthnDiscoverableLogin(client);
```

`isWebauthnSupported()` is a query, not a try/catch: hide the button rather than
offer one that throws. Ceremony failures classify into five outcomes, and
`already_registered` is the one worth separating — it means the authenticator
already holds a credential for this account and refused to mint a second, so the
remedy is a different device rather than another attempt:

```ts
try {
  await webauthnRegister(client, name, kind);
} catch (err) {
  const failure = classifyWebauthnError(err);   // 'cancelled' | 'already_registered' | …
  showBanner(webauthnErrorMessage(failure));
}
```

`cancelled` covers **both** an explicit refusal and a silent timeout. The
WebAuthn spec deliberately refuses to distinguish them, because telling a website
which one happened leaks whether an authenticator was present — so the copy for
it does not accuse anyone of cancelling, and you should not try to recover the
distinction by timing the call.

Passkey autofill (conditional mediation) is a flag, and everything about it
degrades quietly:

```ts
if (await isConditionalMediationAvailable()) {
  const abort = new AbortController();
  void webauthnDiscoverableLogin(client, undefined, { conditional: true, signal: abort.signal })
    .catch(() => {/* abandoned, not failed */});
}
```

That promise may never settle — the user simply may not pick a passkey — so
abandon it on navigation and never show an error for a prompt nobody engaged
with.

### Anywhere else: the JSON bridge

Every platform authenticator API speaks the same WebAuthn **JSON form** — Android's
Credential Manager takes `requestJson` and returns `registrationResponseJson`;
browsers use `parseCreationOptionsFromJSON()` and `credential.toJSON()`. So the
SDK hands you the challenge as that JSON and takes the platform's answer back as
that JSON, from any runtime:

```ts
import { webauthnRequestJson } from 'axiam-sdk/rest';

const { challenge, stateToken } = await client.webauthnDiscoverableStart();
const requestJson = webauthnRequestJson(challenge);   // → give this to the platform

// …the platform runs the ceremony and hands back a JSON string…
await client.webauthnDiscoverableFinish(stateToken, responseJson);
```

Nothing is destructured on the way through, which matters: the response is the
input to a signature check over bytes this SDK did not produce, and re-encoding
base64url "to be safe" is the most common way to break a ceremony that was
otherwise correct.

### What the SDK does not do, on purpose

**It never adjusts an option.** The server generates the challenge and chooses
`residentKey`, `userVerification`, the attestation conveyance, the exclusion list
and the timeout; this SDK passes all of it to the authenticator unchanged and
posts the answer back unchanged. Not because those fields are hard — because they
are not, and that is the hazard: relaxing `userVerification` to `"preferred"`
because a CI authenticator kept prompting weakens a ceremony the server believes
it configured, and the server cannot detect it, since an assertion produced under
weaker options is a valid assertion.

The single exception is the `authenticatorAttachment` hint, and only when you
pass one. It selects which authenticator the user is prompted for; without it, a
user reaching for a security key gets asked for Touch ID.

**It never emulates an authenticator.** A "credential" held in process memory is
not a second factor. Where no platform API is reachable, the JSON bridge is the
answer and it is a complete one.

**There is no user private key anywhere in this API.** The private half never
leaves the authenticator — that is the property the whole mechanism rests on.

### Two error rows that are not the generic mapping

- A **`403` on `webauthnRegisterFinish`** is the tenant's attestation policy
  refusing *this authenticator* — an AAGUID that is not allow-listed, a missing
  FIDO certification, a revoked status — not a permission problem with the user.
  The server's message is surfaced verbatim, because it is the only way the person
  holding the key learns that a different one would work.
- A **`503` on `webauthnRegisterStart`** means the attestation policy requires
  attestation and the FIDO metadata service has no usable snapshot. It is a server
  configuration state, not a transient failure, and it is deliberately **not**
  retried: retrying changes nothing and delays a message an operator needs.

## Account lifecycle and MFA enrolment (CONTRACT.md §25)

§1 locks the *middle* of an account's life — `login`, `verifyMfa`, `refresh`,
`logout` all assume an account that already exists, is verified, and already has
its second factor. These nine operations are how it gets there.

```ts
// Voluntary TOTP enrolment, by a signed-in user. Two calls, deliberately: the
// human step in the middle is not something a helper can wait for, and one that
// returned after mfaEnroll would report MFA as enabled when it is not.
const enrolment = await client.mfaEnroll();
renderQr(enrolment.totpUri.expose());
await client.mfaConfirm(codeTypedByUser);       // → true once the factor is live
```

`secretBase32` and `totpUri` are both `Sensitive`, and the URI is the one that
matters: it *is* `otpauth://…?secret=…`, so it contains the secret it sits next
to. Wrapping only the secret would have wrapped nothing — the URI is the field
that actually reaches a log, because it is the field you hand to a QR renderer.

### `login()` has a third outcome

**This is a breaking change** (contract 1.28). The server has always been able to
answer `POST /api/v1/auth/login` with `403 mfa_setup_required` and a setup token,
meaning "this tenant requires MFA, this account has none, here is how to finish".
It used to reach you as an `AuthzError` — which told you that you lacked
permission to log in, when what the server said was recoverable and came with the
means to recover.

```ts
switch (result.status) {
  case 'authenticated':
    break;
  case 'mfa_required':
    await client.verifyMfa(result.mfaToken, code);
    break;
  case 'mfa_setup_required': {                    // ← new
    const enrolment = await client.mfaSetupEnroll(result.setupToken);
    renderQr(enrolment.totpUri.expose());
    await client.mfaSetupConfirm(result.setupToken, codeTypedByUser);
    break;                                        // this completes the login
  }
}
```

If you match `LoginResult` exhaustively, this is the edit you need. A genuine
authorization refusal is still an `AuthzError`: the SDK matches on the body's own
discriminant, not on the `403` alone.

### Email verification and password reset

```ts
await client.verifyEmail(tokenFromLink, tenantId);
await client.resendVerification(email, tenantId);

await client.requestPasswordReset({ email });
```

`requestPasswordReset` resolves **whether or not the address exists**, and this
SDK exposes no way to tell the difference. That is not an omission to improve on:
any signal distinguishing them — including one inferred from timing — turns the
endpoint into the account enumeration oracle its uniform response exists to
prevent.

Setting the new password takes one extra call on any tenant that might have
OPAQUE enabled (§23), because the client has to build a registration record and
cannot know the parameters before it has a token to ask with:

```ts
const context = await client.passwordResetContext(token);
await client.confirmPasswordReset({
  token,
  newPassword,
  tenantId,
  ...(context.opaque ? { opaque: await client.opaqueEnrollment(newPassword) } : {}),
});
```

The context discloses no identity — an unauthenticated endpoint that confirmed
which account a token belongs to would be an oracle worth not having — and a
`404` covers unknown, expired and already-consumed without distinguishing them.

## Device authorization grant (`axiam-sdk/node`, CONTRACT.md §14)

RFC 8628 — signing in a device that cannot show a browser: a TV, a CLI, a headless
commissioning tool.

```ts
const tokens = await oidc.deviceLogin({
  onUserCode: (auth) => {
    // Called BEFORE the first poll. Display it however the device can —
    // screen, QR code, e-ink panel. The SDK never prints it for you.
    console.log(`visit ${auth.verificationUri} and enter ${auth.userCode}`);
  },
});
```

`deviceAuthorize` and `devicePoll` are also public, for an application driving its own
loop. The polling rules are where implementations go wrong, so they are worth stating:

- **`slow_down` raises the interval permanently.** An SDK that backs off for one round and
  returns to the original interval will be told to slow down again, forever.
- **`access_denied` and `expired_token` stay distinct.** A human said no, versus nobody
  answered — the only information the device can act on.
- **Polling stops at `expires_in`**, even if the server has not yet said `expired_token`.
- **A `5xx` mid-poll is not terminal.** A server restart must not lose a grant the user has
  already approved.

`deviceCode` is `Sensitive`; `userCode` deliberately is not — it exists to be read aloud,
and wrapping it would defeat the one thing it is for.

Per §14.3 rule 4, `deviceLogin` **returns** the token set rather than adopting it. See
[`examples/device-login.ts`](examples/device-login.ts).

## Token exchange (`axiam-sdk/node`, CONTRACT.md §15)

RFC 8693 — a service holding a user's token exchanging it for a *narrower* one before
calling the next service.

```ts
const exchanged = await oidc.tokenExchange({
  subjectToken: new Sensitive(userToken),
  subjectTokenType: ACCESS_TOKEN_TYPE, // required (§15.1), no default
  scopes: ['orders:read'],
  audience: 'orders-service',
});
```

Most of what this method does is refuse to be helpful, and each refusal is deliberate:

- **No default `actorToken`.** Omitting it asks for *impersonation*; the SDK will not
  quietly substitute the client's own session token and turn that into a delegation.
- **No auto-narrowing after `invalid_scope`.** The server refuses rather than silently
  narrowing precisely so the caller finds out here.
- **No refresh token, ever** — `ExchangedToken` has no such field, so there is nothing to
  synthesise. Re-run the exchange.
- **No adoption.** The issued token is handed onward in one call; adopting it would
  silently re-privilege every later call this client makes. A MUST NOT, where
  `loginClientCredentials` adoption is a MAY.

See [`examples/token-exchange.ts`](examples/token-exchange.ts).

### External-IdP subject tokens (CONTRACT.md §15.7)

The same method exchanges a token minted by a **trusted external IdP** — a partner's
Entra, Okta or Keycloak — for an AXIAM token scoped to what the resolved AXIAM user may
actually do. There is no separate operation:

```ts
const exchanged = await oidc.tokenExchange({
  subjectToken: new Sensitive(partnerToken),
  subjectTokenType: JWT_TOKEN_TYPE, // named, never guessed
  scopes: ['read:orders'],
  audience: 'https://orders.internal',
});
```

- **`subjectTokenType` is yours to state, and is required** (§15.1). The SDK never decodes
  the subject token to pick it, and never overrides what you named. There is no default —
  omitting it does not compile, because a default would be the SDK choosing for you.
- **No actor token.** Delegation across a trust boundary is unsupported in v1; sending one
  is `invalid_request`, which the SDK will not work around by dropping it and re-sending.
- **One refusal is distinguishable.** `invalid_grant` whose description is `the subject
  token's issuer is not configured for token exchange` means *fix the AXIAM trust
  configuration*. Every other `invalid_grant` means *fix your token*, and is deliberately
  generic.
- **Forward the result as-is.** It carries an `ext_exchange` claim naming the partner
  issuer; never strip it, and never read it as an authorization input. It also cannot be
  exchanged again — exchanges do not compose.

See [`examples/external-token-exchange.ts`](examples/external-token-exchange.ts) and the
operator guide, `docs/api/federated-token-exchange.md`.

## Pushed authorization requests (`axiam-sdk/node`, CONTRACT.md §26)

PAR (RFC 9126) moves the authorization request off the browser. Instead of
putting `scope`, `redirect_uri`, `state` and the PKCE challenge into a URL the
user agent carries, the client POSTs them straight to AXIAM over an
authenticated back channel and puts an opaque `request_uri` in the redirect.
What travels through the browser is then a random string that cannot be edited
into meaning something else.

Required for a FAPI 2.0 client: `profile: "fapi2"` refuses a registration that
does not set `require_par`, so such a client cannot authorize any other way.

```ts
const configuration = await oidc.oidcDiscover();
const request = oidc.oidcBegin({ configuration, redirectUri, scope: 'openid profile' });

const pushed = await oidc.oidcPar({ request, redirectUri, scope: 'openid profile', configuration });

redirect(pushed.authorizationUrl);
// …on the callback, unchanged by PAR:
const tokens = await oidc.oidcExchange({
  code, redirectUri, nonce: pushed.nonce, codeVerifier: pushed.codeVerifier,
});
```

`oidcBegin` still does the computing — there is no second generator for `state`,
`nonce` and PKCE — and `pushed.codeVerifier` is the one it produced, so there is
exactly one value to keep.

Three things about this that are easy to get wrong:

1. **The endpoint answers `201`, not `200`.** RFC 9126 §2.2 specifies Created,
   and a success predicate written `status === 200` treats every successful push
   as a failure.
2. **The authorization URL carries exactly `client_id` and `request_uri`.** The
   server *refuses* a request that mixes a `request_uri` with inline
   authorization parameters rather than merging them, and re-adding them "for
   compatibility" restores the parameter-confusion attack the refusal prevents:
   an attacker supplies the inline value they want and lets the pushed copy
   satisfy whichever check reads the other one.
3. **`request_uri` is single-use and short-lived.** There is nothing to retry
   with it — the safe recovery is a fresh push, which costs one round trip and
   cannot double-consume anything. `oidcPar` is correspondingly never retried on
   a `5xx` or a transport failure: it is a POST that creates server state.

`invalid_client` on a push has three usual causes: a wrong secret, a secret sent
by a client registered for `tls_client_auth` / `private_key_jwt` /
`self_signed_tls_client_auth` (which is refused, not ignored), or a client
certificate the transport did not present.

## Logout — RP-initiated and back-channel (`axiam-sdk/node`, CONTRACT.md §12.7)

`logoutUrl` builds the redirect; `verifyLogoutToken` validates a token the OP **pushed** to
your back-channel endpoint.

```ts
const url = await oidc.logoutUrl({ idToken });

// …and at your registered backchannel_logout_uri:
const verified = await oidc.verifyLogoutToken(logoutToken);
if (verified.sid) {
  endSession(verified.sid); // that session ONLY
}
```

The verifier is where the security weight sits — the input arrives unsolicited and
instructs you to terminate a session. It checks the signature (same JWKS path, same
`kid`-required discipline as §12.4), `iss`, `aud`, that `events` carries the
back-channel-logout key (**the only thing separating a logout token from an ID token**),
that `nonce` is *absent* (its presence is how an ID token gets replayed as one), that
something is named, and freshness.

It returns `sid`/`sub`/`jti` rather than a bare boolean: you have to know *which* session to
end. **Dedup on `jti` yourself** — delivery is at-least-once, so a valid token legitimately
arrives twice; the SDK has no durable store and an in-memory guard would silently drop a
real second logout after a restart.

See [`examples/logout.ts`](examples/logout.ts).

## UMA 2.0 — Protection API and ticket grant (CONTRACT.md §20)

The resource-server side of User-Managed Access: register what you guard, ask the
authorization server what a caller would need, and redeem the resulting ticket.

The two runnable halves are [`examples/uma-resource-server.ts`](examples/uma-resource-server.ts)
and [`examples/uma-client.ts`](examples/uma-client.ts) — run the first, then the second
against it.

### Making a denial actionable (`axiam-sdk/middleware`)

```ts
import { requireAccess, type UmaChallenger } from 'axiam-sdk/middleware';

const challenger: UmaChallenger = {
  realm: 'invoices',
  asUri: (await oidc.oidcDiscover()).issuer,
  pat, // a client-credentials token carrying `uma_protection` (§20.2 rule 1)
  mint: (token, permissions) => oidc.umaRequestTicket(token, [...permissions]),
};

app.get(
  '/invoices/:id',
  requireAccess(session, 'invoices:read', fromParam('id'), { umaChallenge: challenger }),
  handler,
);
```

Without `umaChallenge` this is an ordinary §11 guard and a denial is a bare 403. With it, the
guard mints a permission ticket for the action it just refused and returns
`WWW-Authenticate: UMA realm=…, as_uri=…, ticket=…` alongside the 403 — so a UMA-aware client
knows where to obtain authority instead of only being told no. The body is unchanged, so a
client that does not speak UMA sees exactly the 403 it saw before. Both `requireAccess`
(Express) and `requireAccessHook` (Fastify) take the option.

**It is opt-in, and that is a design decision rather than an oversight.** Emitting a
challenge means *minting a credential*: a wire call to the Protection API and a live ticket,
produced on a path the caller did not explicitly request. A guard that did that on every
denial by default would turn each unauthorized request into a Protection API call — a
denial-of-service amplifier pointed at your own authorization server.

**Failure is not escalation.** If minting fails — expired PAT, Protection API down, a scope
the resource never declared — the denial still surfaces as a plain 403 with no challenge. A
caller who was going to be refused is refused either way; letting an outage turn a deny into
a 500 would give it a second consequence, and letting it turn into an allow would be a
security bug.

### Consuming the challenge (`axiam-sdk/node`)

```ts
import { umaParseChallenge } from 'axiam-sdk/node';

const challenge = umaParseChallenge(response.headers.get('www-authenticate') ?? '');
if (challenge?.ticket) {
  // Deciding whether to trust challenge.asUri is YOUR call — parsing performed no
  // exchange, deliberately (§20.3): that host was chosen by the server you just
  // failed against.
  const rpt = await oidc.umaExchangeTicket({ ticket: challenge.ticket, claimToken: userToken });
}
```

The rest of the surface — `umaRegisterResource`, the other four `rreg` operations,
`umaRequestTicket`, `umaExchangeTicket` — plus the rules they enforce (a ticket is never
retried, the RPT is never adopted, an update replaces the scope list rather than merging it)
is documented on the generated API docs for `axiam-sdk/node`.

## Webhook signature verification (`axiam-sdk/node`, CONTRACT.md §13)

AXIAM signs every webhook delivery with a Stripe-style signed timestamp:

```
X-Axiam-Signature: t=<unix_seconds>,v1=<hex_lowercase_hmac>
```

where `v1 = HMAC-SHA256(secret_utf8_bytes, "<timestamp>.<raw_body>")`. `verifyWebhook`
recomputes and checks that signature — in constant time, with a two-sided freshness window —
so integrators never hand-roll (or skip) the comparison.

```typescript
import { verifyWebhook, WebhookVerifyError, Sensitive } from 'axiam-sdk/node';

const secret = new Sensitive(process.env.AXIAM_WEBHOOK_SECRET!);

try {
  const { event, id } = verifyWebhook(secret, req.header('X-Axiam-Signature')!, req.rawBody);
  // `event`/`id` come from the verified body's own `event`/`id` fields; `X-Axiam-Delivery`
  // is the at-least-once dedup key — keep a short-lived seen-set, since a retry replays a
  // validly-signed request inside the freshness window.
  console.log('verified webhook:', event, id);
} catch (err) {
  if (err instanceof WebhookVerifyError) {
    res.status(400).end();   // err.reason is a stable code; err.message never
                              // contains the secret or the expected signature
  }
}
```

**The raw body is load-bearing.** `verifyWebhook` MUST receive the *exact* bytes AXIAM sent —
`Buffer`, `Uint8Array`, or the identical raw string — never a `JSON.stringify` of the parsed
body. Re-serializing changes key order/whitespace and silently breaks the MAC; this is the
single most common integration mistake. Most JSON body-parsing middleware discards the raw
bytes by default, so capture them explicitly on the webhook route. With Express,
`express.json()` alone does **not** keep them — use its `verify` callback, or mount
`express.raw({ type: 'application/json' })` on that one route instead:

```typescript
import express from 'express';

app.post(
  '/webhooks/axiam',
  express.json({
    verify: (req, _res, buf) => {
      (req as express.Request & { rawBody: Buffer }).rawBody = buf;
    },
  }),
  (req, res) => {
    const { rawBody } = req as express.Request & { rawBody: Buffer };
    const event = verifyWebhook(secret, req.header('X-Axiam-Signature')!, rawBody);
    // ...
  },
);
```

The freshness window defaults to 300 s and is two-sided — a future-dated `t=` is rejected just
like a stale one — and accepts a `tolerance` override plus a `now` injection seam for tests. A
failure always raises the typed `WebhookVerifyError` (never a generic exception whose message
could leak the expected signature).

## Client quality-of-life (CONTRACT.md §16–§19)

### Retry policy (§16)

Read-only authorization checks — `checkAccess`, `can`, `batchCheck` — retry transient
failures under the contract's normative table: **3 attempts** (1 initial + 2 retries),
200 ms base, 5 s cap, **full jitter** (uniform over `[0, backoff]`), and `Retry-After`
honored as a **floor**.

> **This changed in D5.** The previous policy used a 1000 ms base, an 8 s cap, partial
> jitter, and let `Retry-After` *replace* the backoff — so a `Retry-After: 0` retried
> immediately. Worse, `withRetry` was exported and unit-tested but **never called by
> `checkAccess`**, so this SDK performed no read-only retries at all. Both are fixed, and
> the conformance tests now assert through the public API rather than against the helper.

Only failures that could plausibly succeed on a second attempt are retried — transport
errors, `408`, `429`, `5xx`. A `401` or `403` is an answer, not a transport failure, and is
surfaced after exactly one attempt. Nothing that changes server state is ever retried.

```ts
// Turn it off if you own your own retry layer — you know your deadline, this SDK doesn't.
const client = new AxiamClient({ baseUrl, tenantSlug: 'acme', retryEnabled: false });
```

There is deliberately no knob for the attempt cap, base delay or delay cap: §16.1 forbids
raising them, and eleven SDKs agreeing on one table is the point.

### Deterministic shutdown (§18)

`client.close()` releases the client's local resources. It is idempotent, and any call
afterwards rejects with a `NetworkError` naming the cause rather than silently reconnecting.

**`close()` does not log out.** It never reaches the network. The server-side session
deliberately outlives the client object — that is what lets a process restart and resume —
so a `close()` that logged out would silently end every user's session on each deploy. Call
`logout()` first if ending the session is what you want.

### Telemetry hooks (§19)

Wire metrics without this package depending on any metrics library:

```ts
const client = new AxiamClient({
  baseUrl,
  tenantSlug: 'acme',
  telemetryHook: (event) => {
    if (event.type === 'requestEnd') {
      histogram.record(event.durationMs, { op: event.operation, outcome: event.outcome });
    } else if (event.type === 'retry') {
      counter.add(1, { op: event.operation, attempt: event.attempt });
    }
  },
});
```

- **A hook that throws cannot fail the operation that fired it.** Telemetry is not permitted
  to fail an authorization check.
- **No event payload can carry a token.** `TelemetryEvent` is a closed union with a fixed
  field set — this surface exists to be shipped to a metrics backend.
- **Path templates, not URLs**, so a metric label cannot become a cardinality bomb.

One `requestStart`/`requestEnd` pair is emitted **per attempt**, so you can count real wire
calls. See [`examples/telemetry-hook.ts`](examples/telemetry-hook.ts), including the
OpenTelemetry mapping.

### Decision memo (§17) — opt-in, off by default

An optional TTL-bounded cache for `checkAccess` results. **Disabled by default**, because
§11.2 rule 6's ban on caching authorization decisions is still the default behaviour.

```ts
const client = new AxiamClient({
  baseUrl,
  tenantSlug: 'acme',
  decisionMemoTtlMs: 5000, // 0 = off, which is the default
});
```

**What you are accepting.** The staleness bound is the TTL, in *both* directions: a grant
revoked on the server can still read as allowed for up to the TTL, and a grant just added
can still read as denied for up to the TTL.

> **Reads-your-own-writes is not guaranteed.** An admin UI that grants a role and
> immediately re-checks is the case that breaks, and it breaks silently. If that is your
> workload, leave this off.

The TTL is clamped to 5000 ms rather than rejected. Allows and denies are memoized
identically — asymmetric caching would leak which outcome occurred through latency.
Failures are never memoized: caching a transport error as a deny would turn a blip into a
TTL-long outage. The memo is cleared on `login`, `verifyMfa`, `refresh` and `logout`, since
entries are keyed by subject rather than by session.

## Management API (CONTRACT.md §27)

Everything above assumes a populated tenant. `login` signs a user in,
`checkAccess` asks about a resource, `verifyWebhook` checks a delivery signature — and
none of them can create the user, declare the resource or register the webhook. The
management surface is the part that can: **146 operations across 24 namespaces**,
generated from `management-registry.json`, which is the whole server API minus what other
contract sections own and minus organization creation and deletion (§27.0 keeps those out
of reach of a client library on purpose).

```ts
const page  = await client.users.list({ limit: 50 });
const every = await client.users.listAll({ limit: 200 });
const role  = await client.roles.get(roleId);
await client.roles.assignToUser(roleId, { user_id: userId });
```

Operations hang off **namespace handles** rather than the client. Twenty namespaces have a
`list` and fourteen a `get`, so flattening them would need a disambiguating prefix invented
once per operation — and would bury the eight §1 methods most callers want under five times
as many they do not. Acquiring a handle performs no I/O. `client.management.users` is the
same handle as `client.users`, for call sites that read better with the namespace spelled
out.

Every management call goes through the session's existing axios instance, so it inherits
CSRF forwarding (§3), the cookie jar (§4), the `X-Tenant-ID` header (§5), the TLS policy
(§6), the reactive single-flight refresh the response interceptor already performs (§9),
the retry policy (§16) and telemetry (§19). None of it is reimplemented, and none of it can
be forgotten per-operation.

**Field names are the server's, verbatim** — `resource_type`, `is_global`, `user_id`. A
management surface is read alongside the API docs, and a casing translation layer over 136
generated types is both a lot of code and a class of bug; what you read in `openapi.json`
is what you write here. The hand-curated §1 types (`AccessCheck`) keep their camelCase.

### Five things that bite

**Reads retry; writes never do.** Not even the idempotent-looking ones.
`certificates.generate()` twice mints two certificates; `serviceAccounts.rotateSecret()`
twice invalidates the secret the first call returned and you already stored.

**Seventeen `PUT`s patch, four replace.** A sparse update sends only the fields you set — an
unset field is *absent* from the wire body, not `null`, so it is left unchanged. But
`settings.setOrg()`, `emailConfig.setOrg()`, `webauthnPolicy.set()` and
`caCertificates.setMtlsTrustAnchor()` **replace**: what you omit is not preserved. Their
request types have required fields, so a half-filled one does not typecheck — which is the
point, since sending a subset of `SetOrgSettings` resets the other eighteen.

**Seven calls return a secret exactly once.** Creating a service account or an OAuth2
client, minting a SCIM token, generating a certificate, a CA, a signing CA or a PGP key.
The field is `Sensitive<string>`: `JSON.stringify` gives `"[SENSITIVE]"`, `.expose()` gives
the value. No later `get` returns it again, and the `get` projection has no field where it
was — so nothing tells you it is missing.

**404 means "absent, or not yours."** The server answers 404 for a resource in another
tenant deliberately: a distinguishable "exists but not yours" lets a caller enumerate
another tenant's ids.

```ts
try {
  await client.users.get(id);
} catch (e) {
  if (e instanceof NotFoundError) { /* absent, or another tenant's */ }
  else if (e instanceof ConflictError) { /* 409 — the name is taken */ }
  else if (e instanceof ValidationError) { for (const f of e.fields) { /* 400, per field */ } }
}
```

All three are real subclasses of the §2 types — `NotFoundError` and `ConflictError` extend
`AuthzError`, `ValidationError` extends `NetworkError` — so `e instanceof AuthzError`
written before §27 still catches the first two.

**`orgId` and `tenantId` default from the client**, and are overridable per handle with
`.inOrg(id)` / `.forTenant(id)`. A client built with a *slug* fails locally, with no
request, on any route that needs the UUID — the SDK will not resolve a slug behind your
back.

### Declarative manifests (§27.6, §27.7)

Calling 146 operations one at a time is rarely what an application wants. What it does at
start-up, in a migration, or in a test fixture is assert a shape:

```ts
import { defineManifest, Sensitive } from 'axiam-sdk/rest';

export const desired = defineManifest({
  resources: [
    { key: 'docs', name: 'documents', resourceType: 'collection',
      scopes: [{ key: 'draft', name: 'draft', description: 'Unpublished' }] },
  ],
  permissions: [{ key: 'read', action: 'document:read', description: 'Read a document' }],
  roles: [{ key: 'editor', name: 'Editor', description: 'Edits documents',
            grants: [{ permission: 'read', scopes: ['draft'] }] }],
  groups: [{ key: 'staff', name: 'Staff', description: 'The team', roles: ['editor'] }],
  users: [{ key: 'alice', username: 'alice', email: 'alice@example.com',
            initialPassword: new Sensitive(pw), groups: ['staff'] }],
});

const plan = await client.manifest.plan(desired);   // reads only — no writes
const report = await client.manifest.apply(desired);
```

`defineManifest` keeps the literal key types *and* validates immediately — a dangling
cross-reference throws where the manifest is written, which for a config module is import
time, rather than on the first `plan` against production.

`plan()` issues `GET`s and nothing else. It matches each spec by its natural key — a user's
`username`, a role's `name`, a scope's `name` within its resource — and returns the ordered
actions that would reconcile the tenant.

- **Nothing is ever deleted.** A manifest is usually a *subset* of a tenant's truth, and a
  prune would turn "make sure these three roles exist" into "delete the other forty". There
  is no prune option, deliberately.
- **A field the manifest does not state is never a difference**, so `apply` is safe against
  a tenant that also holds hand-made state.
- **Applying twice converges**: the second plan is all `no-change`. That is what makes
  re-running after a failure safe.
- **There is no transaction** across 146 independent HTTP endpoints, and `ApplyReport` does
  not pretend there is. If step 12 of 30 fails, steps 1–11 have happened; the report says
  which, execution stops rather than continuing blindly, and there is no `rollback` —
  because this SDK could not honour one.

Codebases that already declare their domain with classes get decorators instead:

```ts
@AxiamResource({ key: 'docs', name: 'documents', resourceType: 'collection' })
@AxiamScope({ key: 'draft', name: 'draft', description: 'Unpublished' })
class Documents {}

@AxiamRole({ key: 'editor', name: 'Editor', description: 'Edits documents' })
@AxiamGrant({ permission: 'read', scopes: ['draft'] })
class Editor {}

const shape = collectManifest(Documents, ReadDocument, Editor);
```

TypeScript has two decorator dialects and this SDK's own `tsconfig.json` deliberately
enables neither — so these are dual-protocol plain functions that work under both, and
under neither: `AxiamResource(spec)(Documents)` is exactly what the `@` syntax desugars to.

### Examples

- [`examples/management-basics.ts`](examples/management-basics.ts) — the imperative surface
  and the rules above, one at a time.
- [`examples/management-manifest.ts`](examples/management-manifest.ts) — both declarative
  forms end to end.
- [`examples/device-mtls-provisioning.ts`](examples/device-mtls-provisioning.ts) —
  provisioning an IoT device and its mTLS identity: anchor the CA, create the service
  account, generate the certificate, bind it, then authenticate with it. This is the flow
  §27 exists for; before it, every step but the last had to happen out of band.

### Regenerating

`src/management/models.ts` and `src/management/ops/` are generated and committed. After
re-vendoring `management-registry.json` or `openapi.json`:

```bash
npm run gen-management          # regenerate
npm run gen-management:check    # what CI runs
```

## Error handling

Every persona throws the three CONTRACT.md §2 error types — `AuthError`, `AuthzError`,
`NetworkError` — plus one `AuthError` **sub-type**, `OAuthProtocolError`, for RFC 6749
protocol errors from `/oauth2/*` (its `message` is always `"<error>: <error_description>"`,
and `instanceof AuthError` still matches it):

```typescript
import { AuthError, AuthzError, NetworkError } from 'axiam-sdk';

try {
  await client.can('read', 'doc:1');
} catch (err) {
  if (err instanceof AuthError) {
    // re-authenticate
  } else if (err instanceof AuthzError) {
    // caller lacks permission
  } else if (err instanceof NetworkError) {
    // transport-level failure
  }
}

// OAuth2 protocol errors are AuthError sub-types (CONTRACT.md §2, §12.3 rule 3)
import { OAuthProtocolError } from 'axiam-sdk';

try {
  await oidc.oidcRefresh({ refreshToken });
} catch (err) {
  if (err instanceof OAuthProtocolError && err.error === 'invalid_grant') {
    // the refresh token was revoked or already used — re-authenticate
  }
}
```

## Security notes

- Token-carrying values are wrapped in `Sensitive<T>` — `toString()`/`toJSON()`/
  `util.inspect` all redact to `[SENSITIVE]`; the raw value is only reachable via an
  explicit accessor (CONTRACT.md §7).
- Strict TLS verification is always on; the only server-trust escape hatch is the
  constructor's `customCa` option for self-signed development environments (CONTRACT.md §6).
- Optional mutual TLS (mTLS): a PEM `clientCert`/`clientKey` client identity (Node only) is
  presented on both REST and gRPC without ever relaxing server verification (CONTRACT.md §6.1).
- AMQP messages are HMAC-SHA256 verified before your handler ever sees them; verification
  failures are nacked without requeue (CONTRACT.md §8).
- The OIDC relying-party flow is PKCE **S256**-only (`plain` is not implemented), ID tokens are
  `EdDSA`-only and validated on every exchange with no opt-out, and login state
  (`state`/`nonce`/`code_verifier`) is never stored inside the SDK (CONTRACT.md §12).

## Release / versioning

Tagged releases follow the plain `vX.Y.Z` convention (e.g. `v1.0.0`). CI runs the full
gate suite (build, test, SC#1 bundle-and-grep, CJS-require smoke, token-leak, TLS-lint,
`npm publish --dry-run`) on every pull request, and publishes to npm with
[provenance](https://docs.npmjs.com/generating-provenance-statements) only when a `vX.Y.Z`
tag is pushed from `main` and its version matches `package.json`. The same tag publishes
the TypeDoc API reference to this repo's GitHub Pages site.

## Building from source

The gRPC stubs under `src/gen/` are generated from `proto/` by
[buf](https://buf.build) and are deliberately not committed, so a source build needs the
`buf` CLI on `PATH`:

```bash
npm ci
npm run generate   # buf generate → src/gen (also runs automatically via prebuild)
npm run build
npm test
```

## License

Apache-2.0 — see [`LICENSE`](./LICENSE).
