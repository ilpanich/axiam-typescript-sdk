// gRPC validateToken/introspectToken (axiam.v1.TokenService, CONTRACT.md
// §1.1.1, §10.3, contract 1.51) — mirrors the reference (axiam-rust-sdk#115)'s
// tests/grpc_token_test.rs in this SDK's own idiom, and getUserInfo.test.ts's
// stub-client pattern (real grpc-js interceptor chain, no live server, D-24).

import * as grpc from '@grpc/grpc-js';
import { CookieJar } from 'tough-cookie';
import { afterEach, describe, expect, it } from 'vitest';
import { AuthError, resetRefreshGuard, Sensitive } from '../../src/core/index.js';
import {
  TokenGrpcClient,
  type TokenServiceClientFactory,
  type WireIntrospectTokenRequest,
  type WireIntrospectTokenResponse,
  type WireTokenServiceClient,
  type WireValidateTokenRequest,
  type WireValidateTokenResponse,
} from '../../src/grpc/client.js';
import { verifyTokenBinding } from '../../src/node/jwks.js';
import { NodeSession } from '../../src/node/session.js';
import { createSession } from '../../src/rest/session.js';
import { TokenManager } from '../../src/node/tokenManager.js';
import { createVerifier } from '../../src/node/jwks.js';
import { ACCESS_COOKIE } from '../../src/node/cookieJar.js';

const BASE_URL = 'https://axiam-grpc-token.test';

function serviceError(code: grpc.status): grpc.ServiceError {
  const err = new Error(`grpc error ${code}`) as grpc.ServiceError;
  err.code = code;
  err.details = `grpc error ${code}`;
  err.metadata = new grpc.Metadata();
  return err;
}

interface StubOptions {
  capturedMetadata: grpc.Metadata[];
  capturedValidateRequests: WireValidateTokenRequest[];
  capturedIntrospectRequests: WireIntrospectTokenRequest[];
  validateOutcomes: Array<WireValidateTokenResponse | grpc.status>;
  introspectOutcomes: Array<WireIntrospectTokenResponse | grpc.status>;
}

function runInterceptorChain(interceptors: grpc.Interceptor[], sink: grpc.Metadata[]): void {
  const terminal = new grpc.InterceptingCall({
    start(metadata: grpc.Metadata) {
      sink.push(metadata);
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
}

function buildStubClient(options: Partial<StubOptions> = {}): TokenServiceClientFactory {
  const capturedMetadata = options.capturedMetadata ?? [];
  const capturedValidateRequests = options.capturedValidateRequests ?? [];
  const capturedIntrospectRequests = options.capturedIntrospectRequests ?? [];
  const validateOutcomes = options.validateOutcomes ?? [];
  const introspectOutcomes = options.introspectOutcomes ?? [];

  return (_baseUrl, _credentials, interceptors) => {
    const client: WireTokenServiceClient = {
      validateToken(request, _metadata, callback) {
        capturedValidateRequests.push(request);
        runInterceptorChain(interceptors, capturedMetadata);
        const outcome = validateOutcomes.shift();
        if (outcome === undefined) {
          callback(null, { valid: true, subject_id: 's', tenant_id: 't', org_id: 'o', exp: 0, token_type: 'Bearer' });
        } else if (typeof outcome === 'number') {
          callback(serviceError(outcome));
        } else {
          callback(null, outcome);
        }
        return {} as grpc.ClientUnaryCall;
      },
      introspectToken(request, _metadata, callback) {
        capturedIntrospectRequests.push(request);
        runInterceptorChain(interceptors, capturedMetadata);
        const outcome = introspectOutcomes.shift();
        if (outcome === undefined) {
          callback(null, {
            active: true,
            sub: 's',
            tenant_id: 't',
            org_id: 'o',
            iss: 'axiam',
            iat: 0,
            exp: 0,
            jti: 'j',
            scope: '',
            client_id: '',
            token_type: 'Bearer',
            permissions: [],
            ext_exchange_iss: '',
          });
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
    await jar.setCookie(`${ACCESS_COOKIE}=cached-caller-token; Path=/`, BASE_URL);
  }
  const base = createSession({ baseUrl: BASE_URL, tenantSlug: 'acme' });
  const tokenManager = new TokenManager(jar, BASE_URL, base.tenantHeaderValue);
  await tokenManager.syncFromJar();
  const jwksVerifier = createVerifier(BASE_URL);
  return new NodeSession({ baseUrl: BASE_URL, tenantSlug: 'acme' }, base, tokenManager, jwksVerifier, jar);
}

function inspected(): Sensitive<string> {
  return new Sensitive('the-token-under-inspection');
}

describe('gRPC TokenService (CONTRACT.md §1.1.1, §10.3, contract 1.51)', () => {
  afterEach(() => {
    resetRefreshGuard();
  });

  it('an unbound response still validates — the positive regression §10.1 rule 9 requires', async () => {
    const session = await buildTestSession();
    const factory = buildStubClient({
      validateOutcomes: [
        { valid: true, subject_id: 'u1', tenant_id: 't1', org_id: 'o1', exp: 999, token_type: 'Bearer' },
      ],
    });
    const client = new TokenGrpcClient(session, { baseUrl: BASE_URL }, factory);

    const result = await client.validateToken(inspected());

    expect(result.valid).toBe(true);
    expect(result.cnf).toBeUndefined();
    // No transport evidence supplied — verifyTokenBinding must still accept
    // an unbound token, with or without proofs.
    expect(() => verifyTokenBinding({ cnf: result.cnf })).not.toThrow();
  });

  it('a certificate-bound token is not a bearer token — verifyTokenBinding refuses it without evidence', async () => {
    const session = await buildTestSession();
    const factory = buildStubClient({
      validateOutcomes: [
        {
          valid: true,
          subject_id: 'u1',
          tenant_id: 't1',
          org_id: 'o1',
          exp: 999,
          token_type: 'Bearer', // rule 5: certificate-bound is STILL reported "Bearer".
          cnf: { x5t_s256: 'thumbprint-abc', jkt: '' },
        },
      ],
    });
    const client = new TokenGrpcClient(session, { baseUrl: BASE_URL }, factory);

    const result = await client.validateToken(inspected());

    expect(result.tokenType).toBe('Bearer');
    expect(result.cnf).toEqual({ 'x5t#S256': 'thumbprint-abc' });
    // §10.3 rule 2: valid: true is not "usable as presented" — the caller
    // MUST verify possession against its OWN connection. With no evidence,
    // verifyTokenBinding refuses.
    expect(() => verifyTokenBinding({ cnf: result.cnf })).toThrow();
    // With the matching certificate evidence, it is accepted.
    expect(() =>
      verifyTokenBinding({ cnf: result.cnf }, { certificateThumbprint: 'thumbprint-abc' }),
    ).not.toThrow();
    expect(() =>
      verifyTokenBinding({ cnf: result.cnf }, { certificateThumbprint: 'different-thumbprint' }),
    ).toThrow();
  });

  it('an empty CnfClaim is refused, not read as unbound (§10.3 rule 3)', async () => {
    const session = await buildTestSession();
    const factory = buildStubClient({
      validateOutcomes: [
        { valid: true, subject_id: 'u1', tenant_id: 't1', org_id: 'o1', exp: 999, token_type: 'Bearer', cnf: { x5t_s256: '', jkt: '' } },
      ],
    });
    const client = new TokenGrpcClient(session, { baseUrl: BASE_URL }, factory);

    const result = await client.validateToken(inspected());

    // Present but empty — distinct from absent (proto3's rendering of "unset").
    expect(result.cnf).toEqual({});
    expect(() => verifyTokenBinding({ cnf: result.cnf })).toThrow(
      /naming no method this SDK can verify/,
    );
  });

  it("another tenant's token is invalid, not an error (§10.3 rule / §1.1.1 rule 6)", async () => {
    const session = await buildTestSession();
    const factory = buildStubClient({
      validateOutcomes: [{ valid: false, subject_id: '', tenant_id: '', org_id: '', exp: 0, token_type: '' }],
    });
    const client = new TokenGrpcClient(session, { baseUrl: BASE_URL }, factory);

    const result = await client.validateToken(inspected());

    expect(result.valid).toBe(false);
    expect(result.subjectId).toBe('');
    expect(result.cnf).toBeUndefined();
  });

  it('the inspected token is not the caller\'s — the two travel separately', async () => {
    const session = await buildTestSession();
    const capturedMetadata: grpc.Metadata[] = [];
    const capturedValidateRequests: WireValidateTokenRequest[] = [];
    const factory = buildStubClient({
      capturedMetadata,
      capturedValidateRequests,
      validateOutcomes: [{ valid: true, subject_id: 's', tenant_id: 't', org_id: 'o', exp: 0, token_type: 'Bearer' }],
    });
    const client = new TokenGrpcClient(session, { baseUrl: BASE_URL }, factory);

    await client.validateToken(inspected());

    // The caller's OWN token authenticates the call, via the interceptor.
    expect(capturedMetadata[0]!.get('authorization')).toEqual(['Bearer cached-caller-token']);
    // The inspected token travels in the message body, and is a DIFFERENT value.
    expect(capturedValidateRequests[0]!.access_token).toBe('the-token-under-inspection');
    expect(capturedValidateRequests[0]!.access_token).not.toBe('cached-caller-token');
  });

  it('without a caller token there is no wire call (precondition, §1.1 rule 3)', async () => {
    const session = await buildTestSession(false);
    let rpcCalls = 0;
    const inner = buildStubClient({
      validateOutcomes: [{ valid: true, subject_id: 's', tenant_id: 't', org_id: 'o', exp: 0, token_type: 'Bearer' }],
    });
    const factory: TokenServiceClientFactory = (baseUrl, credentials, interceptors) => {
      const innerClient = inner(baseUrl, credentials, interceptors);
      return {
        validateToken(request, metadata, callback) {
          rpcCalls += 1;
          return innerClient.validateToken(request, metadata, callback);
        },
        introspectToken(request, metadata, callback) {
          rpcCalls += 1;
          return innerClient.introspectToken(request, metadata, callback);
        },
        close() {
          innerClient.close();
        },
      };
    };
    const client = new TokenGrpcClient(session, { baseUrl: BASE_URL }, factory);

    await expect(client.validateToken(inspected())).rejects.toBeInstanceOf(AuthError);
    await expect(client.introspectToken(inspected())).rejects.toBeInstanceOf(AuthError);
    expect(rpcCalls).toBe(0);
  });

  it('introspection models every field, including scope/client_id/permissions/ext_exchange_iss, and reads jkt', async () => {
    const session = await buildTestSession();
    const factory = buildStubClient({
      introspectOutcomes: [
        {
          active: true,
          sub: 'user-1',
          tenant_id: 'tenant-1',
          org_id: 'org-1',
          iss: 'https://axiam.example/',
          iat: 1000,
          exp: 2000,
          jti: 'jti-1',
          scope: 'read write',
          client_id: 'client-abc',
          token_type: 'DPoP',
          cnf: { x5t_s256: '', jkt: 'jkt-thumbprint' },
          permissions: [{ resource_id: 'r-1', resource_scopes: ['read'], exp: 1999 }],
          ext_exchange_iss: 'https://other-domain.example/',
        },
      ],
    });
    const client = new TokenGrpcClient(session, { baseUrl: BASE_URL }, factory);

    const result = await client.introspectToken(inspected());

    expect(result).toEqual({
      active: true,
      sub: 'user-1',
      tenantId: 'tenant-1',
      orgId: 'org-1',
      iss: 'https://axiam.example/',
      iat: 1000,
      exp: 2000,
      jti: 'jti-1',
      scope: 'read write',
      clientId: 'client-abc',
      tokenType: 'DPoP',
      cnf: { jkt: 'jkt-thumbprint' },
      permissions: [{ resourceId: 'r-1', resourceScopes: ['read'], exp: 1999 }],
      extExchangeIss: 'https://other-domain.example/',
    });
    // rule 5: token_type "DPoP" alone is not sufficient — decide boundness
    // from cnf. Here cnf does name jkt, so this one genuinely is bound.
    expect(() => verifyTokenBinding({ cnf: result.cnf })).toThrow();
    expect(() => verifyTokenBinding({ cnf: result.cnf }, { dpopThumbprint: 'jkt-thumbprint' })).not.toThrow();
  });

  it('UNAUTHENTICATED refreshes the caller\'s token and retries once', async () => {
    const session = await buildTestSession();
    let refreshCalls = 0;
    session.doRefresh = async () => {
      refreshCalls += 1;
      await session.tokenManager.syncFromJar();
    };
    const capturedMetadata: grpc.Metadata[] = [];
    const factory = buildStubClient({
      capturedMetadata,
      validateOutcomes: [
        grpc.status.UNAUTHENTICATED,
        { valid: true, subject_id: 'u1', tenant_id: 't1', org_id: 'o1', exp: 999, token_type: 'Bearer' },
      ],
    });
    const client = new TokenGrpcClient(session, { baseUrl: BASE_URL }, factory);

    const result = await client.validateToken(inspected());

    expect(result.valid).toBe(true);
    expect(refreshCalls).toBe(1);
    expect(capturedMetadata).toHaveLength(2);
  });
});
