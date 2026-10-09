// Error-mapping paths for checkAccess()/batchCheck() over REST — the non-403
// status branch, the batchCheck catch, and the no-response NetworkError
// fallback in authz.ts's mapAuthzError.

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { NetworkError } from '../../src/core/errors.js';
import { AxiamClient } from '../../src/rest/client.js';

const BASE_URL = 'https://axiam.test';
const CHECK = `${BASE_URL}/api/v1/authz/check`;
const BATCH = `${BASE_URL}/api/v1/authz/check/batch`;

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledFrame: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function client(): AxiamClient {
  return new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });
}

describe('authz error mapping', () => {
  it('maps a non-403 error status on checkAccess to a thrown error', async () => {
    server.use(http.post(CHECK, () => HttpResponse.json({ message: 'boom' }, { status: 500 })));
    await expect(client().checkAccess({ action: 'users:read', resourceId: 'r-1' })).rejects.toThrow();
  });

  it('maps a 403 error status on batchCheck to a thrown error (the batch catch path)', async () => {
    server.use(http.post(BATCH, () => HttpResponse.json({ message: 'nope' }, { status: 403 })));
    await expect(client().batchCheck([{ action: 'users:read', resourceId: 'r-1' }])).rejects.toThrow();
  });

  it('maps a network error (no response) to a NetworkError', async () => {
    server.use(http.post(CHECK, () => HttpResponse.error()));
    await expect(client().checkAccess({ action: 'users:read', resourceId: 'r-1' })).rejects.toThrow();
  });

  // Contract 1.59 R-18's path: a transport failure's cause is the sanitized
  // diagnostics, never the axios error with the request (its headers carry
  // the session's CSRF token and bearer, its config the body).
  it('a network error keeps no request in its cause', async () => {
    server.use(http.post(CHECK, () => HttpResponse.error()));
    const err = await client()
      .checkAccess({ action: 'users:read', resourceId: 'r-1' })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(NetworkError);
    const cause = (err as NetworkError).cause as Record<string, unknown>;
    expect(cause).toBeDefined();
    for (const key of ['config', 'request', 'response']) expect(key in cause, `cause.${key}`).toBe(false);
  });
});
