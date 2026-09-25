// gRPC after authenticateDevice() adoption — CONTRACT 1.52 N4.3/N4.5 (C-12).
//
// N4.3 ("On success the token is the credential of every request the
// client makes afterwards: authz, management, self-service, WebAuthn,
// logout, and gRPC") and N4.5 ("Never refreshed, on either transport. A
// REST 401 or a gRPC UNAUTHENTICATED on the device credential is
// AuthError, with no refresh call").
//
// Before this fix: authInterceptor (src/grpc/interceptor.ts) always sends
// `tokenManager.cachedAccessToken()` — the cookie-jar-synced token — never
// the device token authenticateDevice() adopted onto the session, so a
// device-adopted gRPC caller silently rode a stale/absent cookie session
// instead of its own credential. And callWithRefresh (src/grpc/callWithRefresh.ts)
// refreshed on UNAUTHENTICATED unconditionally, but a device credential has
// no refresh token behind it (CONTRACT.md §6.1 rule 6).

import * as grpc from '@grpc/grpc-js';
import { CookieJar } from 'tough-cookie';
import { afterEach, describe, expect, it } from 'vitest';
import { AuthError, resetRefreshGuard, Sensitive } from '../../src/core/index.js';
import {
  AuthzGrpcClient,
  type AuthorizationServiceClientFactory,
  type WireAuthorizationServiceClient,
  type WireBatchCheckAccessRequest,
  type WireBatchCheckAccessResponse,
  type WireCheckAccessRequest,
  type WireCheckAccessResponse,
} from '../../src/grpc/client.js';
import { NodeSession } from '../../src/node/session.js';
import { createSession } from '../../src/rest/session.js';
import { TokenManager } from '../../src/node/tokenManager.js';
import { createVerifier } from '../../src/node/jwks.js';
import { ACCESS_COOKIE } from '../../src/node/cookieJar.js';

const BASE_URL = 'https://axiam-grpc-device.test';

function serviceError(code: grpc.status): grpc.ServiceError {
  const err = new Error(`grpc error ${code}`) as grpc.ServiceError;
  err.code = code;
  err.details = `grpc error ${code}`;
  err.metadata = new grpc.Metadata();
  return err;
}

interface StubClientOptions {
  capturedMetadata: grpc.Metadata[];
  checkAccessOutcomes: Array<'ok' | grpc.status>;
}

/** Build a stub WireAuthorizationServiceClient honoring the real grpc-js interceptor chain (mirrors test/grpc/checkAccess.test.ts). */
function buildStubClient(options: StubClientOptions): AuthorizationServiceClientFactory {
  return (_baseUrl, _credentials, interceptors) => {
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

    const client: WireAuthorizationServiceClient = {
      checkAccess(
        _request: WireCheckAccessRequest,
        _metadata: grpc.Metadata,
        callback: (error: grpc.ServiceError | null, response?: WireCheckAccessResponse) => void,
      ): grpc.ClientUnaryCall {
        runInterceptorChain();
        const outcome = options.checkAccessOutcomes.shift() ?? 'ok';
        if (outcome === 'ok') {
          callback(null, { allowed: true, deny_reason: '' });
        } else {
          callback(serviceError(outcome));
        }
        return {} as grpc.ClientUnaryCall;
      },
      batchCheckAccess(
        request: WireBatchCheckAccessRequest,
        _metadata: grpc.Metadata,
        callback: (error: grpc.ServiceError | null, response?: WireBatchCheckAccessResponse) => void,
      ): grpc.ClientUnaryCall {
        runInterceptorChain();
        callback(null, {
          results: request.requests.map((r) => ({ allowed: r.action !== 'deny-me', deny_reason: '' })),
        });
        return {} as grpc.ClientUnaryCall;
      },
      close() {},
    };
    return client;
  };
}

/** A session as it stands right after a successful authenticateDevice() call: a stale/prior jar cookie coexists with the adopted device token, exactly as rest/session.ts's SharedSession.deviceAccessToken doc describes. */
async function buildDeviceSession(): Promise<NodeSession> {
  const jar = new CookieJar();
  // A cookie session from BEFORE the device login — must never be read by
  // gRPC once a device token is adopted (mirrors the REST-side hazard
  // test/rest/deviceAuth.test.ts's "no stale cookie" describe block covers).
  await jar.setCookie(`${ACCESS_COOKIE}=stale-cookie-session-token; Path=/`, BASE_URL);

  const base = createSession({ baseUrl: BASE_URL, tenantSlug: 'acme' });
  const tokenManager = new TokenManager(jar, BASE_URL, base.tenantHeaderValue);
  await tokenManager.syncFromJar();
  const jwksVerifier = createVerifier(BASE_URL);
  const session = new NodeSession({ baseUrl: BASE_URL, tenantSlug: 'acme' }, base, tokenManager, jwksVerifier, jar);
  session.deviceAccessToken = new Sensitive('device-token-value');
  session.authenticated = true;
  return session;
}

describe('CONTRACT 1.52 N4.3 (C-12) — gRPC sends the device credential after adoption', () => {
  afterEach(() => {
    resetRefreshGuard();
  });

  it('the interceptor sends the device token, not the cookie-jar-synced cached token', async () => {
    const session = await buildDeviceSession();
    const capturedMetadata: grpc.Metadata[] = [];
    const factory = buildStubClient({ capturedMetadata, checkAccessOutcomes: ['ok'] });
    const client = new AuthzGrpcClient(session, { baseUrl: BASE_URL }, factory);

    await client.checkAccess({ tenantId: 't-1', subjectId: 's-1', action: 'read', resourceId: 'r-1' });

    expect(capturedMetadata).toHaveLength(1);
    expect(capturedMetadata[0].get('authorization')).toEqual(['Bearer device-token-value']);
  });
});

describe('CONTRACT 1.52 N4.5 (C-12) — gRPC never refreshes a device credential', () => {
  afterEach(() => {
    resetRefreshGuard();
  });

  it('UNAUTHENTICATED on the device credential surfaces AuthError with no refresh call', async () => {
    const session = await buildDeviceSession();
    let refreshCalls = 0;
    session.doRefresh = async () => {
      refreshCalls += 1;
      await session.tokenManager.syncFromJar();
    };

    const capturedMetadata: grpc.Metadata[] = [];
    const factory = buildStubClient({
      capturedMetadata,
      checkAccessOutcomes: [grpc.status.UNAUTHENTICATED, 'ok'],
    });
    const client = new AuthzGrpcClient(session, { baseUrl: BASE_URL }, factory);

    await expect(
      client.checkAccess({ tenantId: 't-1', subjectId: 's-1', action: 'read', resourceId: 'r-1' }),
    ).rejects.toBeInstanceOf(AuthError);

    expect(refreshCalls).toBe(0);
    // Exactly one attempt: no retry after a refresh that never happened.
    expect(capturedMetadata).toHaveLength(1);
  });

  // I4 twin: the ordinary cookie-session path (no device token adopted)
  // must keep refreshing on UNAUTHENTICATED exactly as it always has.
  it('twin: an ordinary cookie session still refreshes once on UNAUTHENTICATED (I4)', async () => {
    const jar = new CookieJar();
    await jar.setCookie(`${ACCESS_COOKIE}=cached-access-token; Path=/`, BASE_URL);
    const base = createSession({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    const tokenManager = new TokenManager(jar, BASE_URL, base.tenantHeaderValue);
    await tokenManager.syncFromJar();
    const jwksVerifier = createVerifier(BASE_URL);
    const session = new NodeSession({ baseUrl: BASE_URL, tenantSlug: 'acme' }, base, tokenManager, jwksVerifier, jar);

    let refreshCalls = 0;
    session.doRefresh = async () => {
      refreshCalls += 1;
      await session.tokenManager.syncFromJar();
    };

    const capturedMetadata: grpc.Metadata[] = [];
    const factory = buildStubClient({
      capturedMetadata,
      checkAccessOutcomes: [grpc.status.UNAUTHENTICATED, 'ok'],
    });
    const client = new AuthzGrpcClient(session, { baseUrl: BASE_URL }, factory);

    const decision = await client.checkAccess({ tenantId: 't-1', subjectId: 's-1', action: 'read', resourceId: 'r-1' });

    expect(decision.allowed).toBe(true);
    expect(refreshCalls).toBe(1);
    expect(capturedMetadata).toHaveLength(2);
  });
});
