// SharedSession construction + host-isolation guard (rest/session.ts):
// tenant resolution (§5), customCa PEM validation and Node https.Agent
// construction (§6), and isForeignHost's fail-closed behavior (3A).

import { describe, expect, it } from 'vitest';
import {
  createSession,
  resolveTenantHeaderValue,
  SharedSession,
} from '../../src/rest/session.js';

const BASE_URL = 'https://axiam-session.test';

// A syntactically-valid self-contained PEM block (never used for a real TLS
// handshake here — createSession only checks the PEM marker and hands it to
// node:https.Agent, which accepts arbitrary CA bytes at construction time).
const FAKE_PEM = `-----BEGIN CERTIFICATE-----
MIIBUjCB+aADAgECAgEBMAoGCCqGSM49BAMCMA==
-----END CERTIFICATE-----`;

describe('resolveTenantHeaderValue (§5)', () => {
  it('prefers tenantSlug', () => {
    expect(resolveTenantHeaderValue({ baseUrl: BASE_URL, tenantSlug: 'acme', tenantId: 'id-1' })).toBe(
      'acme',
    );
  });

  it('falls back to tenantId when no slug is given', () => {
    expect(resolveTenantHeaderValue({ baseUrl: BASE_URL, tenantId: 'id-1' })).toBe('id-1');
  });

  it('throws when neither tenant is provided', () => {
    expect(() => resolveTenantHeaderValue({ baseUrl: BASE_URL })).toThrow(/requires a tenant/);
  });
});

describe('createSession customCa handling (§6)', () => {
  it('rejects a customCa that is not PEM-shaped', () => {
    expect(() =>
      createSession({ baseUrl: BASE_URL, tenantSlug: 'acme', customCa: 'not-a-pem' }),
    ).toThrow(/PEM-encoded certificate/);
  });

  it('builds a session (with an https agent) for a valid PEM customCa under Node', () => {
    const session = createSession({ baseUrl: BASE_URL, tenantSlug: 'acme', customCa: FAKE_PEM });
    expect(session).toBeInstanceOf(SharedSession);
    // The httpsAgent is threaded into the axios instance's defaults.
    expect(session.axios.defaults.httpsAgent).toBeDefined();
  });

  it('builds a session with no https agent when customCa is omitted', () => {
    const session = createSession({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    expect(session.axios.defaults.httpsAgent).toBeUndefined();
  });
});

describe('SharedSession.isForeignHost (3A)', () => {
  const session = createSession({ baseUrl: BASE_URL, tenantSlug: 'acme' });

  it('treats a relative/host-less url as same-origin', () => {
    expect(session.isForeignHost('/api/v1/auth/login')).toBe(false);
  });

  it('treats an undefined url as same-origin', () => {
    expect(session.isForeignHost(undefined)).toBe(false);
  });

  it('treats an absolute same-origin url as same-origin', () => {
    expect(session.isForeignHost(`${BASE_URL}/api/v1/protected`)).toBe(false);
  });

  it('flags an absolute third-party url as foreign', () => {
    expect(session.isForeignHost('https://evil.example.com/steal')).toBe(true);
  });

  it('fails closed (foreign) on a malformed url', () => {
    // 'http://' has a scheme but no host — `new URL()` throws, so the guard's
    // catch branch fails closed (treats it as foreign).
    expect(session.isForeignHost('http://')).toBe(true);
  });
});

describe('createSession request interceptor (§5.2)', () => {
  it('injects X-Tenant-ID on a same-origin request and omits it for a foreign host', async () => {
    const session = createSession({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    const handlers = (
      session.axios.interceptors.request as unknown as {
        handlers: Array<{ fulfilled: (c: Record<string, unknown>) => Record<string, unknown> }>;
      }
    ).handlers;
    const run = handlers[0].fulfilled;

    const sameOrigin = run({ url: '/api/v1/protected', headers: {} }) as {
      headers: Record<string, string>;
    };
    expect(sameOrigin.headers['X-Tenant-ID']).toBe('acme');

    const foreign = run({ url: 'https://evil.example.com/x', headers: {} }) as {
      headers: Record<string, string>;
    };
    expect(foreign.headers['X-Tenant-ID']).toBeUndefined();
  });
});
