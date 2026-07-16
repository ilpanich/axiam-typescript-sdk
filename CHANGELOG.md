# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
