// External-IdP token exchange (CONTRACT.md §15.7) — accepting a partner's
// token at an API gateway.
//
// The situation: a partner runs their own IdP (Entra, Okta, Keycloak). Their
// service calls yours carrying THEIR token, which means nothing to your
// services. You present it here and get back an AXIAM token scoped to what the
// resolved AXIAM user may actually do.
//
// This is the same `tokenExchange` as ./token-exchange.ts — §15.7 adds no new
// operation. What differs is what you pass and what the refusals mean:
//
//   - `subjectTokenType` is named explicitly (…:jwt), because only you know
//     what kind of token you are holding.
//   - There is no actor token. Delegation across a trust boundary needs a
//     second trust decision that v1 does not make.
//   - One refusal means "fix the AXIAM trust configuration" and every other
//     one means "fix your token".
//
// The partner's token is EVIDENCE OF AUTHENTICATION, never a grant of
// authorization: their IdP stays the authority on who authenticated, AXIAM
// stays the authority on what they may do here. Nothing in the partner's token
// can widen the result.
//
// Run: npx tsx examples/external-token-exchange.ts

import { createNodeSession, createOidcClient, JWT_TOKEN_TYPE } from '../src/node/index.js';
import { OAuthProtocolError, Sensitive } from '../src/core/index.js';

// The one normative `error_description` (§15.7). It is the ONLY external
// failure given a distinguishable message, and matching on it is explicitly
// allowed.
const ISSUER_NOT_CONFIGURED = "the subject token's issuer is not configured for token exchange";

const baseUrl = process.env.AXIAM_BASE_URL ?? 'https://localhost:8443';
const tenantId = process.env.AXIAM_TENANT_ID ?? '11111111-2222-3333-4444-555555555555';
const clientId = process.env.AXIAM_OIDC_CLIENT_ID ?? 'api-gateway';
const clientSecret = process.env.AXIAM_OIDC_CLIENT_SECRET ?? 'gateway-secret';

// The partner's token, as it would arrive on an inbound request — from an
// Authorization header your gateway is about to stop trusting blindly.
const partnerToken = process.env.PARTNER_SUBJECT_TOKEN ?? 'the-partners-access-token';

const session = createNodeSession({ baseUrl, tenantId });

// The exchanging client is a confidential service and authenticates. It does
// NOT need the `may_impersonate` grant: the evidence here is a trusted IdP's
// signed assertion that the user authenticated, not this client's own say-so
// that it may be them.
const oidc = createOidcClient(session, { clientId, clientSecret });

try {
  const exchanged = await oidc.tokenExchange({
    subjectToken: new Sensitive(partnerToken),

    // Named, not guessed. The SDK never decodes the subject token to pick this
    // (§15.7) — a wrong value is the difference between a request that is
    // refused and one that is silently reinterpreted, so it is yours to state.
    // AXIAM accepts …:jwt or …:access_token for an external issuer, and
    // refuses refresh and ID token types by name.
    subjectTokenType: JWT_TOKEN_TYPE,

    // NO `actorToken`. Delegation across a trust boundary is unsupported in v1
    // and sending one is `invalid_request` — not something to work around by
    // dropping it and re-sending, which would turn the delegation you asked
    // for into an impersonation you did not.

    // Omitting `scopes` asks for everything the trust configuration and the
    // user's own permissions allow. Naming scopes gets you told about any you
    // cannot have, which is usually what you want at a gateway.
    scopes: ['read:orders'],
    audience: 'https://orders.internal',
  });

  // Read what you actually got. The granted scope is the intersection of four
  // gates — your request, the provider's scope map, this client's
  // registration, and the RBAC engine at mint time — so it may be narrower
  // than you asked for even on success (§15.2 rule 7).
  console.log(
    `exchanged for ${exchanged.expiresIn}s, granted scope: ${exchanged.scope ?? '(server default)'}`,
  );
  // §15.2 rule 6: surfaced so a client that asked for one type and received
  // another can tell.
  console.log(`issued token type: ${exchanged.issuedTokenType}`);

  // Hand it onward in ONE outbound call, exactly as in the same-domain case.
  // It is not this gateway's session (rule 5) and there is no refresh token
  // (rule 4) — re-run the exchange.
  //
  // The issued token carries an `ext_exchange` claim naming the partner
  // issuer, which a resource server MAY read to tell a cross-domain token from
  // a locally-issued one. Forward the token as-is: never strip the claim, and
  // never treat its presence or absence as an authorization input of your own
  // — the `scope` claim and the server's checks remain the authority (§15.7).
  //
  // Do not feed this token back into another exchange either. Exchanges do not
  // compose: both paths refuse a subject token carrying `ext_exchange`,
  // because otherwise trust composes silently — A trusts B, B trusts C,
  // therefore A trusts C, which nobody configured.
  const authorizationHeader = `Bearer ${exchanged.accessToken.expose()}`;
  void authorizationHeader;
} catch (err) {
  // Turn a refusal into the one thing that matters: whose problem it is.
  if (!(err instanceof OAuthProtocolError)) {
    // Not a protocol refusal — a transport or configuration failure.
    throw err;
  }

  switch (err.error) {
    case 'invalid_grant':
      // The single distinguishable external failure. Everything else on
      // `invalid_grant` — bad signature, expired, too old, audience not
      // accepted, wrong token kind, subject not linked — answers with a
      // generic description on purpose: which of a dozen checks refused a
      // token is a map of the server's validation order, drawn one request at
      // a time.
      if (err.errorDescription?.includes(ISSUER_NOT_CONFIGURED)) {
        console.error(
          'FIX THE AXIAM TRUST CONFIG: an operator must enable token exchange for ' +
            'this federation provider and list your audience in accepted_audiences. ' +
            'Your token is not the problem.',
        );
      } else {
        console.error(
          'FIX YOUR TOKEN: the subject token was refused. Check that it is current, ' +
            'addressed to the audience AXIAM accepts, and that its subject is linked ' +
            'to an AXIAM user. The precise reason is in the AXIAM audit log.',
        );
      }
      break;

    case 'invalid_request':
      // Sending an actor token, naming a refresh or ID token type, or
      // presenting a token that is itself the product of an exchange. None of
      // these is retryable as a different type or a rewritten request.
      console.error(`The request is not one AXIAM will accept, as written: ${err.errorDescription}`);
      break;

    case 'invalid_scope':
      // Do NOT re-send with fewer scopes. The server refused rather than
      // silently narrowing precisely so you would find out here. Either the
      // provider's scope_map does not map onto the scope you named, or the
      // resolved user does not hold it in AXIAM's own RBAC.
      console.error(`A requested scope is not available to this user: ${err.errorDescription}`);
      break;

    case 'invalid_target':
      console.error(
        `The audience/resource is not registered to this client: ${err.errorDescription}`,
      );
      break;

    case 'unauthorized_client':
      console.error(
        'This client is not registered for the token-exchange grant — a ' +
          'registration fact an operator must fix.',
      );
      break;

    default:
      throw err;
  }
  process.exitCode = 1;
}
