// Express "Login with AXIAM" example — the OIDC relying-party flow
// (CONTRACT.md §12: authorization code + PKCE S256, validated ID token).
//
// Two routes do the whole login:
//   GET /auth/login     -> 302 to AXIAM's /oauth2/authorize
//   GET /auth/callback  -> consumes the state, exchanges the code, validates
//                          the ID token, then establishes THIS app's session
//
// Run: `npx tsx examples/express-oidc-login.ts` with AXIAM_BASE_URL,
// AXIAM_TENANT_ID (a UUID — the token endpoint requires the UUID form, §12.3
// rule 4), AXIAM_CLIENT_ID, AXIAM_CLIENT_SECRET and AXIAM_REDIRECT_URI set.
// Not part of the automated test suite; the compile check
// (`tsc --noEmit -p examples/tsconfig.json`) is the gate.

import express from 'express';
import type { Request, Response } from 'express';
import { createNodeSession, createOidcClient, MemoryOidcStateStore } from 'axiam-sdk/node';
import { oidcLoginHandlers } from 'axiam-sdk/middleware';
import { OAuthProtocolError } from 'axiam-sdk';

const baseUrl = process.env.AXIAM_BASE_URL ?? 'https://localhost:8443';
// A UUID, not a slug: /oauth2/token|introspect|revoke take `tenant_id` as a
// required query parameter and reject a slug (CONTRACT.md §12.3 rule 4).
const tenantId = process.env.AXIAM_TENANT_ID ?? '00000000-0000-0000-0000-000000000000';
const orgId = process.env.AXIAM_ORG_ID ?? '00000000-0000-0000-0000-000000000000';
const clientId = process.env.AXIAM_CLIENT_ID ?? 'my-web-app';
const clientSecret = process.env.AXIAM_CLIENT_SECRET;
const redirectUri = process.env.AXIAM_REDIRECT_URI ?? 'http://127.0.0.1:8080/auth/callback';
const listenAddr = process.env.AXIAM_LISTEN_ADDR ?? '127.0.0.1:8080';

// One session for the whole app: it carries the cookie jar (§4), the TLS
// configuration (§6) and the single-flight refresh guard (§9) that the OIDC
// client reuses rather than duplicating.
const session = createNodeSession({ baseUrl, tenantId, orgId });

const oidc = createOidcClient(session, {
  clientId,
  // Omit for a public client. `introspect`/`revoke` require it (§12.1 note 4).
  ...(clientSecret ? { clientSecret } : {}),
});

// Where the in-flight login state (state / nonce / code_verifier) lives between
// the login redirect and the callback. The SDK stores nothing itself (§12.3
// rule 1). MemoryOidcStateStore is single-process; use a shared store (Redis,
// a database) behind a load balancer.
const store = new MemoryOidcStateStore();

/** This example's stand-in for a real application session store. */
const appSessions = new Map<string, { sub: string; expiresAt: number }>();

const app = express();

const { login, callback } = oidcLoginHandlers({
  client: oidc,
  store,
  redirectUri,
  scope: 'openid profile email',
  // Establishing YOUR session is your decision — the SDK hands you a validated
  // login and stays out of it. `tokens.idClaims` is the already-validated ID
  // token (§12.4); `tokens.accessToken`/`refreshToken` are Sensitive<T> and
  // redact themselves in logs (§12.5).
  onSuccess: (tokens) => {
    const sub = String(tokens.idClaims?.sub ?? 'unknown');
    appSessions.set(sub, { sub, expiresAt: Date.now() + tokens.expiresIn * 1000 });
    console.log(`login complete for ${sub} (access token expires in ${tokens.expiresIn}s)`);
  },
});

// GET /auth/login?returnTo=/dashboard
//
// SECURITY: `returnTo` comes from the query string, so validate or allowlist it
// in a real app before trusting it as a redirect target — an unchecked value is
// an open-redirect vector, and the SDK cannot know which destinations your app
// considers safe.
app.get('/auth/login', login);

// GET /auth/callback?code=…&state=…  (must equal AXIAM_REDIRECT_URI)
app.get('/auth/callback', callback);

app.get('/', (_req: Request, res: Response) => {
  res.type('html').send(
    '<a href="/auth/login?returnTo=/whoami">Login with AXIAM</a>',
  );
});

app.get('/whoami', (_req: Request, res: Response) => {
  res.json({ sessions: [...appSessions.values()] });
});

// ---------------------------------------------------------------------------
// The other §12 operations, for reference
// ---------------------------------------------------------------------------

/**
 * Service-account (machine-to-machine) login: no browser, no ID token.
 * `adoptAsCredential` additionally uses the returned access token as this
 * session's bearer credential for later REST calls.
 */
async function machineToMachineLogin(): Promise<void> {
  if (!clientSecret) {
    console.log('skipping client_credentials — no AXIAM_CLIENT_SECRET set');
    return;
  }
  try {
    const tokens = await oidc.loginClientCredentials({
      scope: 'authz:check',
      adoptAsCredential: true,
    });
    console.log(`m2m token acquired, expires in ${tokens.expiresIn}s`);

    const introspection = await oidc.introspect({ token: tokens.accessToken });
    console.log(`introspection: active=${introspection.active} sub=${introspection.sub ?? '-'}`);

    // Idempotent: a 200 for an unknown or already-revoked token is success.
    await oidc.revoke({ token: tokens.accessToken, tokenTypeHint: 'access_token' });
    console.log('token revoked');
  } catch (err) {
    if (err instanceof OAuthProtocolError) {
      // "<error>: <error_description>", e.g. "invalid_client: …" (§12.3 rule 3).
      console.error(`OAuth2 protocol error: ${err.error} — ${err.errorDescription}`);
      return;
    }
    throw err;
  }
}

/**
 * Federation SSO against an **upstream** IdP (`ssoStart`/`ssoComplete`). The
 * session arrives as `Set-Cookie` on the callback, which is why it must run on
 * a cookie-jar-backed session (§12.1 note 6).
 */
async function upstreamIdpSso(federationConfigId: string): Promise<void> {
  const start = await oidc.ssoStart({
    federationConfigId,
    redirectUri: 'http://127.0.0.1:8080/sso/callback',
  });
  console.log(`redirect the browser to ${start.authorizeUrl} (state valid ${start.expiresInSecs}s)`);
  // …then, on your /sso/callback route, with the state and code the IdP returned:
  // const result = await oidc.ssoComplete({ state, code });
}

const [host, port] = listenAddr.split(':');
app.listen(Number(port), host, () => {
  console.log(`Listening on http://${listenAddr} — open / and click "Login with AXIAM"`);
  void machineToMachineLogin();
  void upstreamIdpSso;
});
