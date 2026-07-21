// gRPC AuthorizationService client — reused channel, checkAccess/batchCheck
// (D-10/D-13, SC#2 Node half).
//
// The generated ts-proto stubs (`src/gen`, produced by `buf generate` at
// build time — Phase 15 D-01/D-20) are NOT committed and are unavailable in
// this sandbox (no `buf` CLI). Rather than importing from a path that does
// not exist here, this module (a) defines local wire-shape interfaces that
// exactly mirror `proto/axiam/v1/authorization.proto`, and (b) builds the
// gRPC client dynamically via grpc-js's own `makeClientConstructor` (the
// same primitive ts-proto's `outputServices=grpc-js` stubs are built on top
// of) rather than importing a generated class. A buf-enabled build can swap
// `buildAuthorizationServiceClient` below for the real ts-proto-generated
// `AuthorizationServiceClient` from `../gen/...` with NO change to the
// public `AuthzGrpcClient` surface, since both satisfy the same
// `WireAuthorizationServiceClient` shape by construction (same .proto).
// End-to-end wiring against real generated stubs is deferred to a
// buf-enabled CI run (RESEARCH.md D-20; environment note in this plan).

import * as grpc from '@grpc/grpc-js';
import type { AccessDecision, ClientIdentity } from '../core/index.js';
import { AuthError, resolveClientIdentity } from '../core/index.js';
import type { NodeSession } from '../node/session.js';
import { authInterceptor } from './interceptor.js';
import { callWithRefresh } from './callWithRefresh.js';

// Re-exported (not re-declared) so `grpc/index.ts` can still export
// `AccessDecision` from `./client.js` — see `core/authz.ts` for the single
// shared definition (SDK-Q10, C2).
export type { AccessDecision };

// ---------------------------------------------------------------------------
// Wire shapes (proto/axiam/v1/authorization.proto) — mirrored, not imported.
// ---------------------------------------------------------------------------

export interface WireCheckAccessRequest {
  tenant_id: string;
  // `subject_id` is a required (non-`optional`) proto3 field
  // (`proto/axiam/v1/authorization.proto`), unlike `scope` below — the wire
  // contract always carries it, so it stays required here too rather than
  // relaxed to match REST's optional `subjectId` (see `CheckAccessRequest`
  // below for why the two transports differ).
  subject_id: string;
  action: string;
  resource_id: string;
  scope?: string;
}

export interface WireCheckAccessResponse {
  allowed: boolean;
  deny_reason: string;
}

export interface WireBatchCheckAccessRequest {
  requests: WireCheckAccessRequest[];
}

export interface WireBatchCheckAccessResponse {
  results: WireCheckAccessResponse[];
}

// ---------------------------------------------------------------------------
// Wire shapes (proto/axiam/v1/userinfo.proto) — mirrored, not imported.
// ---------------------------------------------------------------------------

/**
 * `axiam.v1.GetUserInfoRequest` — an empty message. Identity is derived
 * entirely server-side from the `authorization: Bearer <token>` metadata
 * (CONTRACT.md §1.1), so the request carries no fields.
 */
export type WireGetUserInfoRequest = Record<string, never>;

export interface WireGetUserInfoResponse {
  sub: string;
  tenant_id: string;
  org_id: string;
  // proto3 `optional` fields — absent on the wire unless the access token
  // carried the gating scope ("email" / "profile" respectively).
  email?: string;
  preferred_username?: string;
}

type UnaryCallback<T> = (error: grpc.ServiceError | null, response?: T) => void;

/**
 * The subset of a ts-proto (`outputServices=grpc-js`) generated
 * `AuthorizationServiceClient` this module needs. The real generated client
 * satisfies this shape exactly (unary Node-callback methods), so a
 * buf-enabled build's generated client is a drop-in replacement here.
 */
export interface WireAuthorizationServiceClient {
  checkAccess(
    request: WireCheckAccessRequest,
    metadata: grpc.Metadata,
    callback: UnaryCallback<WireCheckAccessResponse>,
  ): grpc.ClientUnaryCall;
  batchCheckAccess(
    request: WireBatchCheckAccessRequest,
    metadata: grpc.Metadata,
    callback: UnaryCallback<WireBatchCheckAccessResponse>,
  ): grpc.ClientUnaryCall;
  close(): void;
}

/**
 * The subset of a ts-proto (`outputServices=grpc-js`) generated
 * `UserInfoServiceClient` this module needs. As with
 * {@link WireAuthorizationServiceClient}, the real generated client satisfies
 * this shape exactly (single unary Node-callback method), so a buf-enabled
 * build's generated `UserInfoServiceClient` from `../gen/...` is a drop-in
 * replacement.
 */
export interface WireUserInfoServiceClient {
  getUserInfo(
    request: WireGetUserInfoRequest,
    metadata: grpc.Metadata,
    callback: UnaryCallback<WireGetUserInfoResponse>,
  ): grpc.ClientUnaryCall;
  close(): void;
}

/**
 * Public (camelCase, §1) single access-check request shape.
 *
 * `subjectId` is required here (unlike REST's optional `AccessCheck.subjectId`)
 * because gRPC calls typically originate from a service-mesh caller with no
 * request-scoped JWT to derive a subject from — the caller must pass it
 * explicitly. REST, by contrast, derives the subject from the caller's JWT
 * when `subjectId` is omitted (§5). This mirrors the proto's non-`optional`
 * `subject_id` field (`proto/axiam/v1/authorization.proto`), which is not
 * changed here (SDK-Q10, C2).
 */
export interface CheckAccessRequest {
  tenantId: string;
  subjectId: string;
  action: string;
  resourceId: string;
  scope?: string;
}

function toWireRequest(req: CheckAccessRequest): WireCheckAccessRequest {
  return {
    tenant_id: req.tenantId,
    subject_id: req.subjectId,
    action: req.action,
    resource_id: req.resourceId,
    scope: req.scope,
  };
}

function fromWireResponse(resp: WireCheckAccessResponse): AccessDecision {
  return {
    allowed: resp.allowed,
    reason: resp.deny_reason ? resp.deny_reason : undefined,
  };
}

/**
 * The authenticated caller's OIDC-style identity claims, returned by
 * {@link UserInfoGrpcClient.getUserInfo} (CONTRACT.md §1.1). Public (camelCase,
 * §1) counterpart of the `axiam.v1.GetUserInfoResponse` wire message.
 *
 * `sub`, `tenantId`, and `orgId` are always present. `email` is populated only
 * when the access token carries the `email` scope, and `preferredUsername` only
 * with the `profile` scope — the server gates these exactly as the REST
 * `/oauth2/userinfo` endpoint does.
 */
export interface UserInfo {
  /** Subject (user) UUID. Always present. */
  sub: string;
  /** Tenant UUID. Always present. */
  tenantId: string;
  /** Organization UUID. Always present. */
  orgId: string;
  /** User email — present only with the `email` scope. */
  email?: string;
  /** Preferred username — present only with the `profile` scope. */
  preferredUsername?: string;
}

function fromWireUserInfo(resp: WireGetUserInfoResponse): UserInfo {
  return {
    sub: resp.sub,
    tenantId: resp.tenant_id,
    orgId: resp.org_id,
    // Preserve absence: a missing (scope-gated) claim stays `undefined` rather
    // than becoming an empty string.
    email: resp.email ? resp.email : undefined,
    preferredUsername: resp.preferred_username ? resp.preferred_username : undefined,
  };
}

function promisifyUnary<TReq, TResp>(
  call: (req: TReq, metadata: grpc.Metadata, callback: UnaryCallback<TResp>) => grpc.ClientUnaryCall,
  request: TReq,
): Promise<TResp> {
  return new Promise((resolve, reject) => {
    call(request, new grpc.Metadata(), (error, response) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(response as TResp);
    });
  });
}

/**
 * Build the gRPC channel credentials for `baseUrl` (§6 — TLS is always
 * strict by default; `customCa` is the ONLY certificate escape hatch, never
 * an insecure/skip-verification surface).
 *
 * A plaintext target (`http://`/`grpc://`) is REFUSED by default (X-2): it
 * would silently drop the channel to `createInsecure()`, sending bearer tokens
 * and tenant metadata in cleartext. Callers who genuinely need a local dev
 * plaintext channel must opt in explicitly with `allowInsecure: true`, which
 * emits a `console.warn`. As a convenience the opt-in is required for ANY host
 * (including loopback) — there is no silent path to an insecure channel.
 *
 * When a §6.1 mTLS client identity is configured it is applied to the secure
 * channel via `createSsl(rootCerts, privateKey, certChain)` — the SAME strict
 * verification as the default `createSsl()`, just additionally presenting a
 * client certificate. The identity never affects the plaintext-refusal path.
 */
function buildCredentials(
  baseUrl: string,
  customCa: string | undefined,
  allowInsecure: boolean,
  identity: ClientIdentity | undefined,
): grpc.ChannelCredentials {
  const isSecure = baseUrl.startsWith('https://') || baseUrl.startsWith('grpcs://');
  if (!isSecure) {
    if (!allowInsecure) {
      throw new Error(
        `AXIAM gRPC refuses to open an insecure (plaintext) channel to "${baseUrl}": ` +
          'bearer tokens and tenant metadata would be sent in cleartext. Use an ' +
          'https:// or grpcs:// target, or pass { allowInsecure: true } to opt in ' +
          'explicitly for a trusted local/dev channel (CONTRACT.md §6).',
      );
    }
    // Explicit opt-in only — never reached without allowInsecure.
    // eslint-disable-next-line no-console
    console.warn(
      `AXIAM gRPC: opening an INSECURE (plaintext) channel to "${baseUrl}" because ` +
        'allowInsecure was set. Bearer tokens and tenant metadata are transmitted in ' +
        'cleartext — never use this outside a trusted local/dev environment.',
    );
    return grpc.ChannelCredentials.createInsecure();
  }
  const rootCerts = customCa ? Buffer.from(customCa, 'utf8') : null;
  if (identity) {
    // mTLS (§6.1): present the client cert+key. `rootCerts ?? null` keeps the
    // platform trust store (null = default roots) when no customCa is given;
    // strict server verification is unchanged.
    return grpc.ChannelCredentials.createSsl(
      rootCerts,
      Buffer.from(identity.key.expose(), 'utf8'),
      Buffer.from(identity.cert, 'utf8'),
    );
  }
  if (customCa) {
    return grpc.ChannelCredentials.createSsl(rootCerts);
  }
  // Default: verify against the platform's native trust store.
  return grpc.ChannelCredentials.createSsl();
}

function grpcTarget(baseUrl: string): string {
  const url = new URL(baseUrl);
  return url.port ? `${url.hostname}:${url.port}` : url.hostname;
}

const jsonCodec = <T>() => ({
  serialize: (value: T): Buffer => Buffer.from(JSON.stringify(value)),
  deserialize: (bytes: Buffer): T => JSON.parse(bytes.toString('utf8')) as T,
});

/**
 * Construct a real `AuthorizationServiceClient` over grpc-js's own
 * `makeClientConstructor` primitive (the same primitive ts-proto's
 * `outputServices=grpc-js` codegen target uses under the hood). This
 * transport-level client encodes/decodes with JSON as a build-independent
 * stand-in for the protobuf binary codec a buf-enabled build's generated
 * serializers would use — swap this factory for the generated
 * `AuthorizationServiceClient` once `src/gen` exists (D-20).
 */
export function buildAuthorizationServiceClient(
  baseUrl: string,
  credentials: grpc.ChannelCredentials,
  interceptors: grpc.Interceptor[],
): WireAuthorizationServiceClient {
  const checkAccessCodec = jsonCodec<WireCheckAccessRequest>();
  const checkAccessRespCodec = jsonCodec<WireCheckAccessResponse>();
  const batchCodec = jsonCodec<WireBatchCheckAccessRequest>();
  const batchRespCodec = jsonCodec<WireBatchCheckAccessResponse>();

  const ServiceClientConstructor = grpc.makeClientConstructor(
    {
      checkAccess: {
        path: '/axiam.v1.AuthorizationService/CheckAccess',
        requestStream: false,
        responseStream: false,
        requestSerialize: checkAccessCodec.serialize,
        requestDeserialize: checkAccessCodec.deserialize,
        responseSerialize: checkAccessRespCodec.serialize,
        responseDeserialize: checkAccessRespCodec.deserialize,
      },
      batchCheckAccess: {
        path: '/axiam.v1.AuthorizationService/BatchCheckAccess',
        requestStream: false,
        responseStream: false,
        requestSerialize: batchCodec.serialize,
        requestDeserialize: batchCodec.deserialize,
        responseSerialize: batchRespCodec.serialize,
        responseDeserialize: batchRespCodec.deserialize,
      },
    },
    'axiam.v1.AuthorizationService',
  );

  return new ServiceClientConstructor(grpcTarget(baseUrl), credentials, {
    interceptors,
  }) as unknown as WireAuthorizationServiceClient;
}

export type AuthorizationServiceClientFactory = (
  baseUrl: string,
  credentials: grpc.ChannelCredentials,
  interceptors: grpc.Interceptor[],
) => WireAuthorizationServiceClient;

/**
 * Construct a real `UserInfoServiceClient` the same way
 * {@link buildAuthorizationServiceClient} builds the AuthorizationService
 * client — grpc-js's own `makeClientConstructor` primitive (the primitive
 * ts-proto's `outputServices=grpc-js` codegen sits on top of), with a JSON
 * codec as a build-independent stand-in for the protobuf binary serializers a
 * buf-enabled build would generate. Swap this factory for the generated
 * `UserInfoServiceClient` from `../gen/...` once `src/gen` exists (D-20); it
 * satisfies {@link WireUserInfoServiceClient} by construction (same .proto).
 *
 * grpc-js pools subchannels by target + credentials, so a UserInfoService
 * client built against the same `baseUrl`/credentials as the co-located
 * {@link AuthzGrpcClient} shares the underlying connection rather than opening a
 * redundant one (CONTRACT.md §1.1: reuse the existing channel machinery).
 */
export function buildUserInfoServiceClient(
  baseUrl: string,
  credentials: grpc.ChannelCredentials,
  interceptors: grpc.Interceptor[],
): WireUserInfoServiceClient {
  const reqCodec = jsonCodec<WireGetUserInfoRequest>();
  const respCodec = jsonCodec<WireGetUserInfoResponse>();

  const ServiceClientConstructor = grpc.makeClientConstructor(
    {
      getUserInfo: {
        path: '/axiam.v1.UserInfoService/GetUserInfo',
        requestStream: false,
        responseStream: false,
        requestSerialize: reqCodec.serialize,
        requestDeserialize: reqCodec.deserialize,
        responseSerialize: respCodec.serialize,
        responseDeserialize: respCodec.deserialize,
      },
    },
    'axiam.v1.UserInfoService',
  );

  return new ServiceClientConstructor(grpcTarget(baseUrl), credentials, {
    interceptors,
  }) as unknown as WireUserInfoServiceClient;
}

export type UserInfoServiceClientFactory = (
  baseUrl: string,
  credentials: grpc.ChannelCredentials,
  interceptors: grpc.Interceptor[],
) => WireUserInfoServiceClient;

/**
 * gRPC transport for `AuthorizationService` (`checkAccess`/`batchCheck`,
 * SC#2 Node half), reusing one long-lived client/channel per instance (D-10
 * — never reconstructed per-call) and injecting auth + tenant metadata via
 * the synchronous interceptor on every RPC.
 */
export class AuthzGrpcClient {
  readonly #session: NodeSession;
  readonly #inner: WireAuthorizationServiceClient;

  constructor(
    session: NodeSession,
    options: {
      baseUrl: string;
      customCa?: string;
      allowInsecure?: boolean;
      /** PEM client-certificate chain for mutual TLS (§6.1); pair with `clientKey`. */
      clientCert?: string;
      /** PEM private key for mutual TLS (§6.1); pair with `clientCert`. Secret (§7). */
      clientKey?: string;
    },
    clientFactory: AuthorizationServiceClientFactory = buildAuthorizationServiceClient,
  ) {
    this.#session = session;
    // Validate + resolve the §6.1 identity (throws on one-of/bad-PEM, §6.1) and
    // apply it to the gRPC channel — the SAME identity the REST transport uses.
    const identity = resolveClientIdentity(options);
    const credentials = buildCredentials(
      options.baseUrl,
      options.customCa,
      options.allowInsecure ?? false,
      identity,
    );
    this.#inner = clientFactory(options.baseUrl, credentials, [authInterceptor(session)]);
  }

  /** `CheckAccess` over gRPC (SC#2 Node half). UNAUTHENTICATED triggers exactly one shared-guard refresh + one retry (§9.3). */
  async checkAccess(request: CheckAccessRequest): Promise<AccessDecision> {
    const wireRequest = toWireRequest(request);
    const response = await callWithRefresh(this.#session, () =>
      promisifyUnary(this.#inner.checkAccess.bind(this.#inner), wireRequest),
    );
    return fromWireResponse(response);
  }

  /** `BatchCheckAccess` over gRPC — results preserve input order (§1). */
  async batchCheck(requests: CheckAccessRequest[]): Promise<AccessDecision[]> {
    const wireRequest: WireBatchCheckAccessRequest = { requests: requests.map(toWireRequest) };
    const response = await callWithRefresh(this.#session, () =>
      promisifyUnary(this.#inner.batchCheckAccess.bind(this.#inner), wireRequest),
    );
    return response.results.map(fromWireResponse);
  }

  /** Close the underlying gRPC channel. */
  close(): void {
    this.#inner.close();
  }
}

/**
 * gRPC transport for `axiam.v1.UserInfoService` (`getUserInfo`, CONTRACT.md
 * §1.1) — the low-latency counterpart of the server's REST
 * `GET /oauth2/userinfo` endpoint.
 *
 * Reuses the SAME channel/interceptor/refresh machinery as {@link
 * AuthzGrpcClient}: one long-lived client/channel per instance (D-10 — never
 * reconstructed per-call), the shared auth + `x-tenant-id` interceptor
 * (`authInterceptor(session)`), and this session's single-flight refresh guard
 * via `callWithRefresh`. Built from the same {@link NodeSession}, it shares the
 * pooled subchannel with a co-located `AuthzGrpcClient` (no second connection).
 */
export class UserInfoGrpcClient {
  readonly #session: NodeSession;
  readonly #inner: WireUserInfoServiceClient;

  constructor(
    session: NodeSession,
    options: {
      baseUrl: string;
      customCa?: string;
      allowInsecure?: boolean;
      /** PEM client-certificate chain for mutual TLS (§6.1); pair with `clientKey`. */
      clientCert?: string;
      /** PEM private key for mutual TLS (§6.1); pair with `clientCert`. Secret (§7). */
      clientKey?: string;
    },
    clientFactory: UserInfoServiceClientFactory = buildUserInfoServiceClient,
  ) {
    this.#session = session;
    // Validate + resolve the §6.1 identity (throws on one-of/bad-PEM) and apply
    // it to the gRPC channel — the SAME identity the REST/authz transports use.
    const identity = resolveClientIdentity(options);
    const credentials = buildCredentials(
      options.baseUrl,
      options.customCa,
      options.allowInsecure ?? false,
      identity,
    );
    this.#inner = clientFactory(options.baseUrl, credentials, [authInterceptor(session)]);
  }

  /**
   * `GetUserInfo` over gRPC (CONTRACT.md §1.1). Returns the authenticated
   * caller's identity claims; the request is empty (identity comes from the
   * bearer token in the interceptor-injected metadata).
   *
   * Pre-flight (§1.1.3): with no cached access token this raises `AuthError`
   * client-side, WITHOUT a wire call — the same synchronous cached-token view
   * the auth interceptor reads. A gRPC `UNAUTHENTICATED` response otherwise
   * drives exactly one shared-guard refresh + one retry (§9.3), identical to
   * {@link AuthzGrpcClient.checkAccess}.
   */
  async getUserInfo(): Promise<UserInfo> {
    if (this.#session.tokenManager.cachedAccessToken() === null) {
      throw new AuthError('getUserInfo requires a prior successful login() (no access token present)');
    }
    const response = await callWithRefresh(this.#session, () =>
      promisifyUnary(this.#inner.getUserInfo.bind(this.#inner), {} as WireGetUserInfoRequest),
    );
    return fromWireUserInfo(response);
  }

  /** Close the underlying gRPC channel. */
  close(): void {
    this.#inner.close();
  }
}
