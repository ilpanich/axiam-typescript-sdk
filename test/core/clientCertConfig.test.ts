// §6.1 client-certificate (mTLS) config validation: resolveClientIdentity's
// one-of / bad-PEM rejection and its Sensitive-wrapped private key (§7), plus
// createSession surfacing the same validation on the REST path.

import { describe, expect, it } from 'vitest';
import { REDACTED, resolveClientIdentity } from '../../src/core/index.js';
import { createSession } from '../../src/rest/session.js';

const BASE_URL = 'https://axiam-mtls.test';

// These fixtures exercise ONLY the PEM-marker validation in resolveClientIdentity
// (it checks for the header markers, never parsing real key material). The bodies
// are deliberately non-secret placeholders — no real key is committed (a real TLS
// handshake is exercised separately in test/node/mtls.test.ts with runtime-generated
// PKI). Markers are assembled from parts so secret scanners don't match a key block.
const PEM_BEGIN = '-----BEGIN ';
const PEM_END = '-----END ';
const CERT_PEM = `${PEM_BEGIN}CERTIFICATE-----\nplaceholder-not-a-real-certificate\n${PEM_END}CERTIFICATE-----`;

const KEY_PEM = `${PEM_BEGIN}PRIVATE KEY-----\nplaceholder-marker-validation-only-not-a-real-key\n${PEM_END}PRIVATE KEY-----`;

const RSA_KEY_PEM = `${PEM_BEGIN}RSA PRIVATE KEY-----\nplaceholder-marker-validation-only-not-a-real-key\n${PEM_END}RSA PRIVATE KEY-----`;

describe('resolveClientIdentity (§6.1)', () => {
  it('returns undefined when neither cert nor key is configured', () => {
    expect(resolveClientIdentity({})).toBeUndefined();
  });

  it('resolves a PKCS#8 identity and wraps the key in Sensitive (§7)', () => {
    const identity = resolveClientIdentity({ clientCert: CERT_PEM, clientKey: KEY_PEM });
    expect(identity).toBeDefined();
    expect(identity!.cert).toBe(CERT_PEM);
    // Key is redacted through every stringify surface — never leaks (§7).
    expect(String(identity!.key)).toBe(REDACTED);
    expect(JSON.stringify(identity!.key)).toBe(`"${REDACTED}"`);
    // ...but the raw PEM is recoverable through the internal accessor only.
    expect(identity!.key.expose()).toBe(KEY_PEM);
  });

  it('accepts a PKCS#1 (RSA) private key', () => {
    const identity = resolveClientIdentity({ clientCert: CERT_PEM, clientKey: RSA_KEY_PEM });
    expect(identity!.key.expose()).toBe(RSA_KEY_PEM);
  });

  it('throws when only clientCert is provided', () => {
    expect(() => resolveClientIdentity({ clientCert: CERT_PEM })).toThrow(/together/);
  });

  it('throws when only clientKey is provided', () => {
    expect(() => resolveClientIdentity({ clientKey: KEY_PEM })).toThrow(/together/);
  });

  it('throws when clientCert is not a PEM certificate', () => {
    expect(() => resolveClientIdentity({ clientCert: 'not-a-pem', clientKey: KEY_PEM })).toThrow(
      /clientCert must be a PEM-encoded certificate/,
    );
  });

  it('throws when clientKey is not a PEM private key', () => {
    expect(() => resolveClientIdentity({ clientCert: CERT_PEM, clientKey: 'not-a-key' })).toThrow(
      /clientKey must be a PEM-encoded private key/,
    );
  });
});

describe('createSession client-certificate validation (§6.1)', () => {
  it('builds an https agent carrying the client identity under Node', () => {
    const session = createSession({
      baseUrl: BASE_URL,
      tenantSlug: 'acme',
      clientCert: CERT_PEM,
      clientKey: KEY_PEM,
    });
    // The mTLS identity is threaded into the axios instance's https agent.
    expect(session.axios.defaults.httpsAgent).toBeDefined();
  });

  it('rejects a one-of (cert without key) at construction', () => {
    expect(() =>
      createSession({ baseUrl: BASE_URL, tenantSlug: 'acme', clientCert: CERT_PEM }),
    ).toThrow(/together/);
  });

  it('rejects a malformed client key at construction', () => {
    expect(() =>
      createSession({ baseUrl: BASE_URL, tenantSlug: 'acme', clientCert: CERT_PEM, clientKey: 'nope' }),
    ).toThrow(/clientKey must be a PEM-encoded private key/);
  });
});
