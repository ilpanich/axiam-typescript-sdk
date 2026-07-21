// gRPC getUserInfo (axiam.v1.UserInfoService/GetUserInfo, CONTRACT.md §1.1) +
// interceptor metadata + UNAUTHENTICATED single-flight retry (§9) +
// no-token client-side pre-flight (§1.1.3). Per D-24, all Node unit tests here
// run against a mocked/stubbed transport (no live gRPC server) for determinism.

import * as grpc from '@grpc/grpc-js';
import { CookieJar } from 'tough-cookie';
import { afterEach, describe, expect, it } from 'vitest';
import { AuthError, resetRefreshGuard } from '../../src/core/index.js';
import {
  UserInfoGrpcClient,
  type UserInfoServiceClientFactory,
  type WireGetUserInfoRequest,
  type WireGetUserInfoResponse,
  type WireUserInfoServiceClient,
} from '../../src/grpc/client.js';
import { NodeSession } from '../../src/node/session.js';
import { createSession } from '../../src/rest/session.js';
import { TokenManager } from '../../src/node/tokenManager.js';
import { createVerifier } from '../../src/node/jwks.js';
import { ACCESS_COOKIE } from '../../src/node/cookieJar.js';

const BASE_URL = 'https://axiam-grpc.test';

function serviceError(code: grpc.status): grpc.ServiceError {
  const err = new Error(`grpc error ${code}`) as grpc.ServiceError;
  err.code = code;
  err.details = `grpc error ${code}`;
  err.metadata = new grpc.Metadata();
  return err;
}

interface StubClientOptions {
  /** Metadata captured from every start() call made through the interceptor. */
  capturedMetadata: grpc.Metadata[];
  /**
   * Queue of outcomes for getUserInfo: a `WireGetUserInfoResponse` resolves,
   * a status code rejects with a ServiceError.
   */
  outcomes: Array<WireGetUserInfoResponse | grpc.status>;
}

/** Build a stub WireUserInfoServiceClient honoring the real grpc-js interceptor chain. */
function buildStubClient(options: StubClientOptions): UserInfoServiceClientFactory {
  return (_baseUrl, _credentials, interceptors) => {
    // Route calls through the real grpc-js interceptor chain so the test proves
    // the interceptor actually adds metadata (not just that the client-level
    // code would, in isolation) — mirrors checkAccess.test.ts.
    const runInterceptorChain = (): void => {
      const terminal = new grpc.InterceptingCall({
        start(metadata: grpc.Metadata) {
          options.capturedMetadata.push(metadata);
        },
        sendMessage() {},
        halfClose() {},
        cancelWithStatus() {},
        getPeer: () => 'stub-peer',
        sendMessageWithContext() {},
        startRead() {},
        getAuthContext: () => null,
      });
      let call: grpc.InterceptingCall = terminal;
      for (const interceptor of [...interceptors].reverse()) {
        const inner = call;
        call = interceptor(
          { method_definition: { path: '', requestStream: false, responseStream: false } } as grpc.InterceptorOptions,
          () => inner,
        );
      }
      call.start(new grpc.Metadata());
    };

    const client: WireUserInfoServiceClient = {
      getUserInfo(
        _request: WireGetUserInfoRequest,
        _metadata: grpc.Metadata,
        callback: (error: grpc.ServiceError | null, response?: WireGetUserInfoResponse) => void,
      ): grpc.ClientUnaryCall {
        runInterceptorChain();
        const outcome = options.outcomes.shift();
        if (outcome === undefined) {
          callback(null, { sub: 'u-1', tenant_id: 't-1', org_id: 'o-1' });
        } else if (typeof outcome === 'number') {
          callback(serviceError(outcome));
        } else {
          callback(null, outcome);
        }
        return {} as grpc.ClientUnaryCall;
      },
      close() {},
    };
    return client;
  };
}

async function buildTestSession(withToken = true): Promise<NodeSession> {
  const jar = new CookieJar();
  if (withToken) {
    await jar.setCookie(`${ACCESS_COOKIE}=cached-access-token; Path=/`, BASE_URL);
  }

  const base = createSession({ baseUrl: BASE_URL, tenantSlug: 'acme' });
  const tokenManager = new TokenManager(jar, BASE_URL, base.tenantHeaderValue);
  await tokenManager.syncFromJar();
  const jwksVerifier = createVerifier(BASE_URL);
  return new NodeSession({ baseUrl: BASE_URL, tenantSlug: 'acme' }, base, tokenManager, jwksVerifier, jar);
}

describe('gRPC getUserInfo (CONTRACT.md §1.1)', () => {
  afterEach(() => {
    resetRefreshGuard();
  });

  it('maps a full claim set (sub, tenant_id, org_id, email, preferred_username)', async () => {
    const session = await buildTestSession();
    const capturedMetadata: grpc.Metadata[] = [];
    const factory = buildStubClient({
      capturedMetadata,
      outcomes: [
        {
          sub: 'user-uuid',
          tenant_id: 'tenant-uuid',
          org_id: 'org-uuid',
          email: 'alice@example.com',
          preferred_username: 'alice',
        },
      ],
    });
    const client = new UserInfoGrpcClient(session, { baseUrl: BASE_URL }, factory);

    const info = await client.getUserInfo();

    expect(info).toEqual({
      sub: 'user-uuid',
      tenantId: 'tenant-uuid',
      orgId: 'org-uuid',
      email: 'alice@example.com',
      preferredUsername: 'alice',
    });
  });

  it('leaves scope-gated optionals undefined when absent on the wire', async () => {
    const session = await buildTestSession();
    const capturedMetadata: grpc.Metadata[] = [];
    const factory = buildStubClient({
      capturedMetadata,
      outcomes: [{ sub: 'user-uuid', tenant_id: 'tenant-uuid', org_id: 'org-uuid' }],
    });
    const client = new UserInfoGrpcClient(session, { baseUrl: BASE_URL }, factory);

    const info = await client.getUserInfo();

    expect(info.sub).toBe('user-uuid');
    expect(info.tenantId).toBe('tenant-uuid');
    expect(info.orgId).toBe('org-uuid');
    expect(info.email).toBeUndefined();
    expect(info.preferredUsername).toBeUndefined();
  });

  it('the interceptor adds authorization + x-tenant-id metadata', async () => {
    const session = await buildTestSession();
    const capturedMetadata: grpc.Metadata[] = [];
    const factory = buildStubClient({
      capturedMetadata,
      outcomes: [{ sub: 'u-1', tenant_id: 't-1', org_id: 'o-1' }],
    });
    const client = new UserInfoGrpcClient(session, { baseUrl: BASE_URL }, factory);

    await client.getUserInfo();

    expect(capturedMetadata).toHaveLength(1);
    const md = capturedMetadata[0];
    expect(md.get('authorization')).toEqual(['Bearer cached-access-token']);
    expect(md.get('x-tenant-id')).toEqual(['acme']);
  });

  it('UNAUTHENTICATED once then OK causes exactly one refresh and one retry', async () => {
    const session = await buildTestSession();
    let refreshCalls = 0;
    session.doRefresh = async () => {
      refreshCalls += 1;
      await session.tokenManager.syncFromJar();
    };

    const capturedMetadata: grpc.Metadata[] = [];
    const factory = buildStubClient({
      capturedMetadata,
      outcomes: [
        grpc.status.UNAUTHENTICATED,
        { sub: 'u-1', tenant_id: 't-1', org_id: 'o-1', email: 'a@b.c' },
      ],
    });
    const client = new UserInfoGrpcClient(session, { baseUrl: BASE_URL }, factory);

    const info = await client.getUserInfo();

    expect(info.sub).toBe('u-1');
    expect(info.email).toBe('a@b.c');
    expect(refreshCalls).toBe(1);
    // Original attempt + one retry = 2 interceptor invocations.
    expect(capturedMetadata).toHaveLength(2);
  });

  it('two consecutive UNAUTHENTICATED responses surface AuthError with no third attempt', async () => {
    const session = await buildTestSession();
    let refreshCalls = 0;
    session.doRefresh = async () => {
      refreshCalls += 1;
      await session.tokenManager.syncFromJar();
    };

    const capturedMetadata: grpc.Metadata[] = [];
    const factory = buildStubClient({
      capturedMetadata,
      outcomes: [grpc.status.UNAUTHENTICATED, grpc.status.UNAUTHENTICATED],
    });
    const client = new UserInfoGrpcClient(session, { baseUrl: BASE_URL }, factory);

    await expect(client.getUserInfo()).rejects.toBeInstanceOf(AuthError);

    expect(refreshCalls).toBe(1);
    expect(capturedMetadata).toHaveLength(2);
  });

  it('raises AuthError client-side with no wire call when no token is present (§1.1.3)', async () => {
    const session = await buildTestSession(false);
    const capturedMetadata: grpc.Metadata[] = [];
    let rpcCalls = 0;
    const factory: UserInfoServiceClientFactory = (baseUrl, credentials, interceptors) => {
      const inner = buildStubClient({
        capturedMetadata,
        outcomes: [{ sub: 'u-1', tenant_id: 't-1', org_id: 'o-1' }],
      })(baseUrl, credentials, interceptors);
      return {
        getUserInfo(request, metadata, callback) {
          rpcCalls += 1;
          return inner.getUserInfo(request, metadata, callback);
        },
        close() {
          inner.close();
        },
      };
    };
    const client = new UserInfoGrpcClient(session, { baseUrl: BASE_URL }, factory);

    await expect(client.getUserInfo()).rejects.toBeInstanceOf(AuthError);
    // No wire call was attempted (no RPC invocation, no interceptor run).
    expect(rpcCalls).toBe(0);
    expect(capturedMetadata).toHaveLength(0);
  });
});
