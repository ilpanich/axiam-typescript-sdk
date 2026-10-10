// Token Exchange (CONTRACT.md §15) — narrowing a user's token before calling
// the next service.
//
// The situation: an API gateway holds a user's access token and needs to call
// an orders service. Forwarding the user's token verbatim over-privileges that
// call and leaves the second hop unable to tell the caller from the user;
// using the gateway's own service credentials has the right privileges but
// loses the user entirely. The exchange gives you both.
//
// Run: npx tsx examples/token-exchange.ts

import { ACCESS_TOKEN_TYPE, createNodeSession, createOidcClient } from '../src/node/index.js';
import { Sensitive } from '../src/core/index.js';

const baseUrl = process.env.AXIAM_BASE_URL ?? 'https://localhost:8443';
const tenantId = process.env.AXIAM_TENANT_ID ?? '11111111-2222-3333-4444-555555555555';
const clientId = process.env.AXIAM_OIDC_CLIENT_ID ?? 'api-gateway';
const clientSecret = process.env.AXIAM_OIDC_CLIENT_SECRET ?? 'gateway-secret';

// The user's token, as it would arrive on an inbound request.
const userToken = process.env.AXIAM_SUBJECT_TOKEN ?? 'the-users-access-token';

const session = createNodeSession({ baseUrl, tenantId });

// Unlike §14's device, an exchanging client is a confidential service and
// authenticates.
const oidc = createOidcClient(session, { clientId, clientSecret });

// Delegation: "the gateway, acting on behalf of the user". Supplying an
// `actorToken` is what makes it delegation; omitting it asks for impersonation
// instead — a different operation with different risk, which the server
// refuses unless this client holds that grant. The SDK will not pick for you
// (§15.2 rule 1).
//
// The actor token must have been issued to THIS client (§15.2 rule 9): the one
// the server accepts is the exchanging client's own client_credentials token,
// whose `sub` — and so the issued token's `act.sub` — is the client's
// `client_id`. A token issued to another client, a console sign-in or a service
// account is answered 400 invalid_request ("actor_token was not issued to the
// exchanging client"), which the SDK surfaces unchanged: it neither retries nor
// quietly drops the actor token. `loginClientCredentials` does not adopt the
// token as this client's session (a MAY the example does not need), and the SDK
// supplies no default — you obtain the actor token and pass it.
const actor = await oidc.loginClientCredentials();

const exchanged = await oidc.tokenExchange({
  subjectToken: new Sensitive(userToken),
  subjectTokenType: ACCESS_TOKEN_TYPE, // required (§15.1): only you know what you hold
  actorToken: actor.accessToken, // the same client's client_credentials token (§15.2 rule 9)
  scopes: ['orders:read'],
  audience: 'orders-service',
});

// Read what you actually got. On success the granted scope may still be
// narrower than requested (§15.2 rule 7) — the client's registration bounds
// it, and assuming the request was honoured verbatim is how a caller ends up
// surprised at the *next* service.
console.log(
  `exchanged for ${exchanged.expiresIn}s, granted scope: ${exchanged.scope ?? '(server default)'}`,
);

// Hand it onward in ONE outbound call. It is not this client's session:
// adopting it would silently re-privilege every later call the gateway makes,
// and the narrowed token would make most of them fail far from here (rule 5).
// There is also no refresh token, ever — re-run the exchange (rule 4).
const authorizationHeader = `Bearer ${exchanged.accessToken.expose()}`;
void authorizationHeader;

// Worth handling explicitly, because each names something an operator must fix
// rather than something to retry:
//
//   unauthorized_client -> this client may not exchange, or may not
//                          impersonate. A registration fact.
//   invalid_request     -> among other things, an actor token that was not
//                          issued to this client (§15.2 rule 9). Fix the token;
//                          do not drop it and re-send as an impersonation.
//   invalid_scope       -> you asked for something the user does not have. Do
//                          NOT re-send with fewer scopes; the server refused
//                          rather than silently narrowing precisely so you
//                          would find out here.
//   invalid_grant       -> subject token bad, expired, or from another tenant.
//                          The server collapses those on purpose.
