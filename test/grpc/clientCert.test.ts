// §6.1 mTLS on the gRPC transport: AuthzGrpcClient must pass the client
// cert+key to grpc's createSsl(rootCerts, privateKey, certChain) — the SAME
// strict-verification createSsl, just additionally presenting a client
// identity. No RPC is issued; only the credentials-builder call is inspected.

import * as grpc from '@grpc/grpc-js';
import { CookieJar } from 'tough-cookie';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AuthzGrpcClient } from '../../src/grpc/client.js';
import { NodeSession } from '../../src/node/session.js';
import { createSession } from '../../src/rest/session.js';
import { TokenManager } from '../../src/node/tokenManager.js';
import { createVerifier } from '../../src/node/jwks.js';

const BASE_URL = 'https://axiam-grpc.test:8443';

// Non-secret placeholders: these tests only check that the PEM markers pass
// validation and that cert/key values are forwarded to grpc createSsl — no real
// key material is committed (markers assembled from parts so scanners don't match).
const PEM_BEGIN = '-----BEGIN ';
const PEM_END = '-----END ';
const CERT_PEM = `${PEM_BEGIN}CERTIFICATE-----\nplaceholder-not-a-real-certificate\n${PEM_END}CERTIFICATE-----`;

const KEY_PEM = `${PEM_BEGIN}PRIVATE KEY-----\nplaceholder-marker-validation-only-not-a-real-key\n${PEM_END}PRIVATE KEY-----`;

const CA_PEM = `${PEM_BEGIN}CERTIFICATE-----\nplaceholder-not-a-real-ca-certificate\n${PEM_END}CERTIFICATE-----`;

function buildSession(): NodeSession {
  const jar = new CookieJar();
  const base = createSession({ baseUrl: BASE_URL, tenantSlug: 'acme' });
  const tokenManager = new TokenManager(jar, BASE_URL, base.tenantHeaderValue);
  const jwksVerifier = createVerifier(BASE_URL);
  return new NodeSession({ baseUrl: BASE_URL, tenantSlug: 'acme' }, base, tokenManager, jwksVerifier, jar);
}

afterEach(() => vi.restoreAllMocks());

describe('AuthzGrpcClient mTLS credentials (§6.1)', () => {
  it('passes cert+key to createSsl with null root certs when no customCa is set', () => {
    // Return a real (valid) credentials object regardless of the stub args.
    const realCreds = grpc.ChannelCredentials.createSsl();
    const spy = vi.spyOn(grpc.ChannelCredentials, 'createSsl').mockReturnValue(realCreds);

    const client = new AuthzGrpcClient(buildSession(), {
      baseUrl: BASE_URL,
      clientCert: CERT_PEM,
      clientKey: KEY_PEM,
    });

    expect(spy).toHaveBeenCalledTimes(1);
    const [roots, key, cert] = spy.mock.calls[0];
    expect(roots).toBeNull();
    expect(Buffer.isBuffer(key)).toBe(true);
    expect(Buffer.isBuffer(cert)).toBe(true);
    expect((key as Buffer).toString('utf8')).toContain('PRIVATE KEY');
    expect((cert as Buffer).toString('utf8')).toContain('BEGIN CERTIFICATE');
    client.close();
  });

  it('passes the customCa root certs alongside the client identity when both are set', () => {
    const realCreds = grpc.ChannelCredentials.createSsl();
    const spy = vi.spyOn(grpc.ChannelCredentials, 'createSsl').mockReturnValue(realCreds);

    const client = new AuthzGrpcClient(buildSession(), {
      baseUrl: BASE_URL,
      customCa: CA_PEM,
      clientCert: CERT_PEM,
      clientKey: KEY_PEM,
    });

    const [roots, key, cert] = spy.mock.calls[0];
    expect(Buffer.isBuffer(roots)).toBe(true);
    expect((roots as Buffer).toString('utf8')).toContain('BEGIN CERTIFICATE');
    expect(Buffer.isBuffer(key)).toBe(true);
    expect(Buffer.isBuffer(cert)).toBe(true);
    client.close();
  });

  it('does not pass a private key when no client identity is configured', () => {
    const spy = vi.spyOn(grpc.ChannelCredentials, 'createSsl');
    const client = new AuthzGrpcClient(buildSession(), { baseUrl: BASE_URL });
    // Default secure channel: createSsl() with no client-key/cert arguments.
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy.mock.calls[0].length).toBe(0);
    client.close();
  });

  it('throws when only clientCert is configured (one-of, §6.1)', () => {
    expect(
      () => new AuthzGrpcClient(buildSession(), { baseUrl: BASE_URL, clientCert: CERT_PEM }),
    ).toThrow(/together/);
  });

  it('never relaxes the plaintext-refusal path (identity does not enable insecure)', () => {
    expect(
      () =>
        new AuthzGrpcClient(buildSession(), {
          baseUrl: 'http://axiam-grpc.test',
          clientCert: CERT_PEM,
          clientKey: KEY_PEM,
        }),
    ).toThrow(/refuses to open an insecure/);
  });
});
