// Pushed Authorization Requests — CONTRACT.md §26 (RFC 9126).
//
// PAR moves the authorization request off the browser. Instead of putting
// `scope`, `redirect_uri`, `state` and the PKCE challenge into a URL the user
// agent carries, the client POSTs them straight to AXIAM over an authenticated
// back channel and puts an opaque `request_uri` in the redirect. What travels
// through the browser is then a random string that cannot be edited into
// meaning something else.
//
// Required for a FAPI 2.0 client: `profile: "fapi2"` refuses a registration
// that does not set `require_par`, so such a client cannot authorize any other
// way (§21.1).

import { createNodeSession, createOidcClient, type PushedAuthorizationRequest } from 'axiam-sdk/node';

const session = createNodeSession({
  baseUrl: 'https://iam.example.com',
  tenantId: '11111111-1111-1111-1111-111111111111',
  orgId: '22222222-2222-2222-2222-222222222222',
});

const oidc = createOidcClient(session, {
  clientId: process.env.AXIAM_CLIENT_ID!,
  clientSecret: process.env.AXIAM_CLIENT_SECRET,
});

const REDIRECT_URI = 'https://app.example.com/auth/callback';
const SCOPE = 'openid profile email';

/**
 * Start a login.
 *
 * `oidcBegin` still does the computing — §26.2 rule 1 forbids a second
 * generator for `state`, `nonce` and PKCE, so `oidcPar` pushes what it
 * produced rather than producing its own.
 */
export async function begin(): Promise<PushedAuthorizationRequest> {
  const configuration = await oidc.oidcDiscover();
  const request = oidc.oidcBegin({ configuration, redirectUri: REDIRECT_URI, scope: SCOPE });

  const pushed = await oidc.oidcPar({
    request,
    redirectUri: REDIRECT_URI,
    scope: SCOPE,
    configuration,
  });

  // Exactly two query parameters: `client_id` and `request_uri`. Not
  // `response_type`, not `scope`, not `state` — the server REFUSES a request
  // carrying both a `request_uri` and any inline authorization parameter
  // rather than merging them, because merging is where parameter confusion
  // lives (§26.2 rule 2). Do not "helpfully" re-add them.
  console.log(`redirect the browser to ${pushed.authorizationUrl}`);

  // Store `state`, `nonce` and `codeVerifier` against the browser session, as
  // you would without PAR. `requestUri` is single-use and short-lived; there
  // is nothing to retry with it if the redirect fails (§26.2 rule 3).
  return pushed;
}

/** Finish the login. Unchanged by PAR — same grant, same verifier, same redirect URI. */
export async function complete(
  pushed: PushedAuthorizationRequest,
  code: string,
  returnedState: string,
): Promise<void> {
  if (returnedState !== pushed.state) {
    throw new Error('state mismatch — abandon this login');
  }

  const tokens = await oidc.oidcExchange({
    code,
    redirectUri: REDIRECT_URI,
    nonce: pushed.nonce,
    // The verifier `oidcBegin` produced, carried through the push. One value,
    // so there is no second place for the two to disagree (§26.2 rule 6).
    codeVerifier: pushed.codeVerifier,
  });

  console.log(`token set acquired, expires in ${tokens.expiresIn}s`);
}
