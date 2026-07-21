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
});
