// Entry-point barrels (src/index.ts and the per-subpath index.ts files):
// importing each executes the re-export module and asserts the documented
// public surface is actually reachable from that entry.

import { describe, expect, it } from 'vitest';

describe('barrel entry points', () => {
  it('root (.) re-exports the REST surface', async () => {
    const mod = await import('../src/index.js');
    expect(typeof mod.AxiamClient).toBe('function');
    expect(typeof mod.withRetry).toBe('function');
    expect(typeof mod.SharedSession).toBe('function');
  });

  it('/rest exposes the client, session, retry and interceptor sentinel', async () => {
    const mod = await import('../src/rest/index.js');
    expect(typeof mod.AxiamClient).toBe('function');
    expect(typeof mod.SharedSession).toBe('function');
    expect(typeof mod.withRetry).toBe('function');
    expect(mod.SKIP_REFRESH).toBeDefined();
  });

  it('/rest exposes the §2 error taxonomy including the §12 OAuthProtocolError sub-type', async () => {
    const mod = await import('../src/rest/index.js');
    expect(typeof mod.AxiamError).toBe('function');
    expect(typeof mod.AuthError).toBe('function');
    expect(typeof mod.AuthzError).toBe('function');
    expect(typeof mod.NetworkError).toBe('function');
    expect(typeof mod.OAuthProtocolError).toBe('function');
    expect(typeof mod.Sensitive).toBe('function');
    // The sub-type must stay catchable as an AuthError (contract 1.4 is additive).
    expect(new mod.OAuthProtocolError('invalid_grant', 'nope')).toBeInstanceOf(mod.AuthError);
  });

  it('/node exposes the Node persona builders and helpers', async () => {
    const mod = await import('../src/node/index.js');
    expect(typeof mod.createNodeClient).toBe('function');
    expect(typeof mod.createNodeSession).toBe('function');
    expect(typeof mod.NodeSession).toBe('function');
    expect(typeof mod.TokenManager).toBe('function');
    expect(typeof mod.createVerifier).toBe('function');
    expect(typeof mod.createJar).toBe('function');
    expect(mod.ACCESS_COOKIE).toBeDefined();
  });

  it('/node exposes the §12 OIDC/SSO relying-party surface', async () => {
    const mod = await import('../src/node/index.js');
    // Factory + client class carrying the nine canonical §12.2 operations.
    expect(typeof mod.createOidcClient).toBe('function');
    expect(typeof mod.OidcClient).toBe('function');
    for (const operation of [
      'oidcDiscover',
      'oidcBegin',
      'oidcExchange',
      'oidcRefresh',
      'loginClientCredentials',
      'introspect',
      'revoke',
      'ssoStart',
      'ssoComplete',
    ]) {
      expect(typeof (mod.OidcClient.prototype as unknown as Record<string, unknown>)[operation]).toBe(
        'function',
      );
    }
    // State store, PKCE primitives, ID-token constants, JWKS verifier factory.
    expect(typeof mod.MemoryOidcStateStore).toBe('function');
    expect(mod.OIDC_STATE_TTL_MS).toBe(600_000);
    expect(typeof mod.computeCodeChallenge).toBe('function');
    expect(typeof mod.generateCodeVerifier).toBe('function');
    expect(typeof mod.randomUrlSafeToken).toBe('function');
    expect(mod.CODE_CHALLENGE_METHOD_S256).toBe('S256');
    expect(mod.ID_TOKEN_ALG).toBe('EdDSA');
    expect(mod.MAX_CLOCK_SKEW_SEC).toBe(60);
    expect(typeof mod.createJwksVerifier).toBe('function');
    expect(typeof mod.normalizeOrigin).toBe('function');
    expect(mod.DISCOVERY_PATH).toBe('/.well-known/openid-configuration');
    expect(mod.SSO_START_PATH).toBe('/api/v1/auth/federation/oidc/start');
    expect(mod.SSO_CALLBACK_PATH).toBe('/api/v1/auth/federation/oidc/callback');
    expect(mod.MIN_DISCOVERY_TTL_MS).toBe(300_000);
  });

  it('/grpc exposes the gRPC transport plus the Node persona re-exports', async () => {
    const mod = await import('../src/grpc/index.js');
    expect(typeof mod.AuthzGrpcClient).toBe('function');
    expect(typeof mod.UserInfoGrpcClient).toBe('function');
    expect(typeof mod.authInterceptor).toBe('function');
    expect(typeof mod.callWithRefresh).toBe('function');
    expect(typeof mod.buildAuthorizationServiceClient).toBe('function');
    expect(typeof mod.buildUserInfoServiceClient).toBe('function');
    expect(typeof mod.createNodeClient).toBe('function');
  });

  it('/amqp exposes Sensitive, hmac, messages and the consumer', async () => {
    const mod = await import('../src/amqp/index.js');
    expect(typeof mod.Sensitive).toBe('function');
    expect(typeof mod.signPayload).toBe('function');
    expect(typeof mod.verifyPayload).toBe('function');
    expect(typeof mod.verifyAndDispatch).toBe('function');
    expect(typeof mod.consume).toBe('function');
    expect(mod.HMAC_SIGNED_MESSAGE_TYPES).toContain('AuthzRequest');
  });

  it('/amqp exposes the §22 reactor runtime, and never the hot-path operations', async () => {
    const mod = await import('../src/amqp/index.js');
    expect(typeof mod.reactorServe).toBe('function');
    expect(typeof mod.dispatchReactorDelivery).toBe('function');
    expect(typeof mod.allow).toBe('function');
    expect(typeof mod.deny).toBe('function');
    expect(typeof mod.mutate).toBe('function');
    expect(typeof mod.abstain).toBe('function');
    expect(typeof mod.requireStepUp).toBe('function');
    expect(typeof mod.defaultFailurePolicyFor).toBe('function');
    expect(typeof mod.patchFieldAllowed).toBe('function');
    expect(mod.REACTOR_EXCHANGE).toBe('axiam.reactor.events');
    expect(mod.EVENT_REGISTRY).toHaveLength(5);

    // §22.7 asserted on the enum/list, not on a comment: the three hot-path
    // operations are absent from every event constant this SDK exposes.
    const names = mod.EVENT_REGISTRY.map((spec) => spec.name);
    const constants = Object.values(mod.REACTOR_EVENTS);
    for (const excluded of ['authz.check', 'authz.check_batch', 'token.introspect']) {
      expect(names, `${excluded} must not be hookable (§22.7)`).not.toContain(excluded);
      expect(constants).not.toContain(excluded);
      expect(mod.eventSpec(excluded)).toBeUndefined();
    }
  });

  it('/middleware exposes both framework adapters and the shared core', async () => {
    const mod = await import('../src/middleware/index.js');
    expect(typeof mod.axiamMiddleware).toBe('function');
    expect(typeof mod.axiamPlugin).toBe('function');
    expect(typeof mod.authenticateRequest).toBe('function');
    expect(typeof mod.parseCookieHeader).toBe('function');
    expect(typeof mod.isCsrfValid).toBe('function');
    expect(mod.ACCESS_COOKIE_NAME).toBe('axiam_access');
  });

  it('/middleware exposes the §11 declarative authorization helpers (Express + Fastify)', async () => {
    const mod = await import('../src/middleware/index.js');
    expect(typeof mod.requireAuth).toBe('function');
    expect(typeof mod.requireAccess).toBe('function');
    expect(typeof mod.requireRole).toBe('function');
    expect(typeof mod.requireAuthHook).toBe('function');
    expect(typeof mod.requireAccessHook).toBe('function');
    expect(typeof mod.requireRoleHook).toBe('function');
    expect(typeof mod.fromParam).toBe('function');
    expect(typeof mod.assertAuthzClient).toBe('function');
    expect(typeof mod.evaluateAccess).toBe('function');
    expect(typeof mod.resolveResourceId).toBe('function');
    expect(typeof mod.hasAnyRole).toBe('function');
    expect(typeof mod.ResourceResolutionError).toBe('function');
  });

  it('/middleware exposes the §12 "Login with AXIAM" glue for both frameworks', async () => {
    const mod = await import('../src/middleware/index.js');
    expect(typeof mod.oidcLoginHandlers).toBe('function');
    expect(typeof mod.oidcLoginPlugin).toBe('function');
    expect(typeof mod.beginOidcLogin).toBe('function');
    expect(typeof mod.completeOidcLogin).toBe('function');
    expect(typeof mod.MemoryOidcStateStore).toBe('function');
    expect(mod.OIDC_STATE_TTL_MS).toBe(600_000);
  });
});
