# axiam-sdk (TypeScript/JavaScript)

[![CI](https://github.com/ilpanich/axiam-typescript-sdk/actions/workflows/sdk-ci-typescript.yml/badge.svg?branch=main)](https://github.com/ilpanich/axiam-typescript-sdk/actions/workflows/sdk-ci-typescript.yml)
[![Coverage Status](https://coveralls.io/repos/github/ilpanich/axiam-typescript-sdk/badge.svg?branch=main)](https://coveralls.io/github/ilpanich/axiam-typescript-sdk?branch=main)
[![npm](https://img.shields.io/npm/v/axiam-sdk.svg)](https://www.npmjs.com/package/axiam-sdk)
[![Docs](https://img.shields.io/badge/docs-TypeDoc-blue.svg)](https://ilpanich.github.io/axiam-typescript-sdk/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Official TypeScript/JavaScript client SDK for [AXIAM](https://github.com/ilpanich/axiam) — Access eXtended Identity and Authorization Management.

## Package identity

- **npm package:** `axiam-sdk`
- **Registry:** [npmjs.com/package/axiam-sdk](https://www.npmjs.com/package/axiam-sdk) _(reserved, not yet published)_
- **Source:** [github.com/ilpanich/axiam-typescript-sdk](https://github.com/ilpanich/axiam-typescript-sdk)
- **License:** Apache-2.0

## Contract conformance

This SDK conforms to CONTRACT.md §1–§11 (including §6.1 mTLS client certificates).

See [`CONTRACT.md`](./CONTRACT.md) for the full cross-language behavioral contract.

## Install

```bash
npm install axiam-sdk
```

## Two personas, tree-shaken subpath entries

`axiam-sdk` ships as **one package with two personas**, each reachable through its own
`package.json` subpath so a bundler only pulls in the transport code the caller actually
imports (proven in CI by the SC#1 bundle-and-grep gate — a `/rest`-only browser bundle
never contains `@grpc/grpc-js` or `amqplib`):

| Entry point            | Persona                    | Contents                                                                 |
|-------------------------|-----------------------------|---------------------------------------------------------------------------|
| `axiam-sdk` / `axiam-sdk/rest` | Browser + Node, REST-only  | `AxiamClient`: `login`/`verifyMfa`/`refresh`/`logout`, `can`/`batchCheck` over the FND-04 REST authz endpoint |
| `axiam-sdk/grpc`        | Node only                   | Everything in `/rest` plus `AuthzGrpcClient.checkAccess`/`batchCheck` over gRPC, the Node persona (`createNodeSession`), and the local-JWKS verifier |
| `axiam-sdk/amqp`        | Node only                   | `consume()` — HMAC-verified AMQP audit/authz event consumer (CONTRACT.md §8) |
| `axiam-sdk/middleware`  | Node only                   | `axiamMiddleware` (Express) / `axiamPlugin` (Fastify) — shared local-JWKS verify core (CONTRACT.md §10) — plus `requireAuth`/`requireAccess`/`requireRole` declarative route guards (CONTRACT.md §11) |
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

### Node — AMQP consumer (`axiam-sdk/amqp`)

```typescript
import { consume, Sensitive } from 'axiam-sdk/amqp';

const signingKey = new Sensitive(Buffer.from(process.env.AXIAM_AMQP_SIGNING_KEY ?? '', 'hex'));

await consume('amqp://localhost:5672', 'axiam.audit.events', signingKey, async (event) => {
  // Only a verified event ever reaches this closure — HMAC-SHA256
  // signature checked and stripped by the SDK before your handler runs
  // (CONTRACT.md §8). Verification failures are nacked-without-requeue.
  console.log('verified audit event:', event);
});
```

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

## Error handling

Every persona throws exactly the three CONTRACT.md §2 error types — `AuthError`,
`AuthzError`, `NetworkError`:

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
