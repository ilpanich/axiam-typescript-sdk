// Contract 1.66, §12.1 rule 12b (#837): a federated sign-in is completed
// through the cookie jar that started it.
//
// Against a REAL loopback HTTP server rather than msw: the jar's Cookie header
// is injected inside the cookie agent's addRequest(), a layer msw never
// reaches, and Set-Cookie does not propagate into a real jar through msw.

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { AuthError } from '../../src/core/index.js';
import { createOidcClient, SSO_CALLBACK_PATH, SSO_START_PATH } from '../../src/node/oidc.js';
import { createNodeSession } from '../../src/node/session.js';
import { CLIENT_ID, ORG_ID, TENANT_ID } from './oidcTestKit.js';

/** A 43-character binding value, the shape the server mints. */
const BINDING = 'fEdBiNdInGvAlUe0123456789abcdefghijklmnopqr';
const BINDING_COOKIE = `axiam_fed_bind=${BINDING}`;

let server: Server;
let baseUrl: string;
const callbackCookies: (string | undefined)[] = [];

beforeAll(async () => {
  server = createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      const path = new URL(req.url ?? '/', 'http://x').pathname;
      if (req.method === 'POST' && path === SSO_START_PATH) {
        res.writeHead(200, {
          'content-type': 'application/json',
          // Plain-http mock: the server's `cookie_secure = false` form.
          'set-cookie': `${BINDING_COOKIE}; Path=/; HttpOnly; SameSite=Strict`,
        });
        res.end(
          JSON.stringify({
            authorize_url: 'https://idp.example.com/authorize?state=abc',
            state: 'abc',
            expires_in_secs: 600,
          }),
        );
        return;
      }
      if (req.method === 'POST' && path === SSO_CALLBACK_PATH) {
        const cookie = req.headers.cookie;
        callbackCookies.push(cookie);
        // As the server does: no matching binding cookie, the uniform 401.
        const bound = (cookie ?? '').split(/;\s*/).includes(BINDING_COOKIE);
        res.writeHead(bound ? 200 : 401, { 'content-type': 'application/json' });
        res.end(
          JSON.stringify(
            bound
              ? {
                  user_id: '99999999-8888-7777-6666-555555555555',
                  session_id: '12121212-3434-5656-7878-909090909090',
                  expires_in: 900,
                  redirect_uri: 'https://app.example.com/after-login',
                }
              : { message: 'unauthorized' },
          ),
        );
        return;
      }
      res.writeHead(404);
      res.end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

function newOidcClient() {
  const session = createNodeSession({ baseUrl, tenantId: TENANT_ID, orgId: ORG_ID });
  return createOidcClient(session, { clientId: CLIENT_ID });
}

describe('federated sign-in cookie binding (§12.1 rule 12b, contract 1.66)', () => {
  it("presents the sso_start binding cookie on the same client's ssoComplete, and not on a second client's", async () => {
    expect(BINDING).toHaveLength(43);
    const oidc = newOidcClient();

    await oidc.ssoStart({
      federationConfigId: 'bbbbbbbb-cccc-dddd-eeee-ffffffffffff',
      redirectUri: 'https://app.example.com/after-login',
    });
    await oidc.ssoComplete({ state: 'abc', code: 'idp-code' });

    // A second, separate client never ran the start: its jar is empty.
    const other = newOidcClient();
    await expect(other.ssoComplete({ state: 'abc', code: 'idp-code' })).rejects.toBeInstanceOf(AuthError);

    expect(callbackCookies).toHaveLength(2);
    expect((callbackCookies[0] ?? '').split(/;\s*/)).toContain(BINDING_COOKIE);
    expect(callbackCookies[1] ?? '').not.toContain('axiam_fed_bind=');
  });
});
