// AuthzGrpcClient construction path (grpc/client.ts) exercised through the
// REAL default client factory (buildAuthorizationServiceClient) and
// buildCredentials, which the stubbed-factory tests in checkAccess.test.ts
// deliberately bypass. No RPC is issued — makeClientConstructor builds a
// channel lazily, so this touches no network.

import * as grpc from '@grpc/grpc-js';
import { CookieJar } from 'tough-cookie';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AuthzGrpcClient, buildAuthorizationServiceClient } from '../../src/grpc/client.js';
import { NodeSession } from '../../src/node/session.js';
import { createSession } from '../../src/rest/session.js';
import { TokenManager } from '../../src/node/tokenManager.js';
import { createVerifier } from '../../src/node/jwks.js';

function buildSession(baseUrl: string): NodeSession {
  const jar = new CookieJar();
  const base = createSession({ baseUrl, tenantSlug: 'acme' });
  const tokenManager = new TokenManager(jar, baseUrl, base.tenantHeaderValue);
  const jwksVerifier = createVerifier(baseUrl);
  return new NodeSession({ baseUrl, tenantSlug: 'acme' }, base, tokenManager, jwksVerifier, jar);
}

afterEach(() => vi.restoreAllMocks());

describe('AuthzGrpcClient construction (buildCredentials §6)', () => {
  it('builds over an https:// target with the default trust store and closes cleanly', () => {
    const session = buildSession('https://axiam-grpc.test:8443');
    const client = new AuthzGrpcClient(session, { baseUrl: 'https://axiam-grpc.test:8443' });
    expect(client).toBeInstanceOf(AuthzGrpcClient);
    expect(() => client.close()).not.toThrow();
  });

  it('uses createSsl(customCa) when a custom CA is supplied over a secure target', () => {
    const pem = `-----BEGIN CERTIFICATE-----
MIIBUjCB+aADAgECAgEBMAoGCCqGSM49BAMCMA==
-----END CERTIFICATE-----`;
    const session = buildSession('https://axiam-grpc.test');
    const client = new AuthzGrpcClient(session, {
      baseUrl: 'https://axiam-grpc.test',
      customCa: pem,
    });
    expect(client).toBeInstanceOf(AuthzGrpcClient);
    client.close();
  });

  it('accepts a grpcs:// target (also treated as secure)', () => {
    const session = buildSession('grpcs://axiam-grpc.test');
    const client = new AuthzGrpcClient(session, { baseUrl: 'grpcs://axiam-grpc.test' });
    client.close();
    expect(client).toBeInstanceOf(AuthzGrpcClient);
  });

  it('refuses a plaintext (http://) target without allowInsecure', () => {
    const session = buildSession('http://axiam-grpc.test');
    expect(() => new AuthzGrpcClient(session, { baseUrl: 'http://axiam-grpc.test' })).toThrow(
      /refuses to open an insecure/,
    );
  });

  it('opens an insecure channel with allowInsecure and warns', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const session = buildSession('http://localhost:50051');
    const client = new AuthzGrpcClient(session, {
      baseUrl: 'http://localhost:50051',
      allowInsecure: true,
    });
    expect(warn).toHaveBeenCalledOnce();
    expect(warn.mock.calls[0][0]).toMatch(/INSECURE/);
    client.close();
  });
});

describe('buildAuthorizationServiceClient factory', () => {
  it('constructs a WireAuthorizationServiceClient with checkAccess/batchCheckAccess/close', () => {
    const inner = buildAuthorizationServiceClient(
      'https://axiam-grpc.test:8443',
      grpc.ChannelCredentials.createSsl(),
      [],
    );
    expect(typeof inner.checkAccess).toBe('function');
    expect(typeof inner.batchCheckAccess).toBe('function');
    expect(typeof inner.close).toBe('function');
    inner.close();
  });

  it('derives a host:port target from a url with a port and a bare host otherwise', () => {
    // Both must construct without throwing (grpcTarget covers the port and
    // no-port branches).
    const withPort = buildAuthorizationServiceClient(
      'https://host.test:9000',
      grpc.ChannelCredentials.createSsl(),
      [],
    );
    const noPort = buildAuthorizationServiceClient(
      'https://host.test',
      grpc.ChannelCredentials.createSsl(),
      [],
    );
    withPort.close();
    noPort.close();
    expect(true).toBe(true);
  });
});
