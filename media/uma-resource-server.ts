// UMA 2.0 (CONTRACT.md §20) — the **resource-server** half of the pair.
//
// The situation: this service holds invoices that belong to *users*, not to
// itself. When someone asks for one, the useful answer is not just "no" — it is
// "not with what you're carrying, and here is where to go and get better". That
// actionable refusal is what UMA adds over plain RBAC.
//
// What this shows, in order:
//
//   1. Mint a PAT — a client-credentials token carrying `uma_protection`.
//      §20.2 rule 1 requires a *client* token: a minted ticket is bound to the
//      `client_id` that minted it, so a user token cannot stand in.
//   2. Register the resource this service guards. The returned `id` *is* the
//      AXIAM resource id — there is no parallel resource store to keep in sync.
//   3. Guard a route with `requireAccess(..., { umaChallenge })`, so a denial
//      carries `WWW-Authenticate: UMA` with a fresh ticket.
//
// Its counterpart is `examples/uma-client.ts`, which consumes that header.
//
// Run: `npx tsx examples/uma-resource-server.ts` — serves on 127.0.0.1:8081,
// with `GET /invoices/:id` as the guarded route.

import express from 'express';
import { AxiamClient } from 'axiam-sdk/rest';
import { createNodeSession, createOidcClient, UMA_PROTECTION_SCOPE } from 'axiam-sdk/node';
import {
  axiamMiddleware,
  fromParam,
  requireAccess,
  type AuthzVerifiableSession,
  type UmaChallenger,
} from 'axiam-sdk/middleware';

const baseUrl = process.env.AXIAM_BASE_URL ?? 'https://localhost:8443';
const tenantSlug = process.env.AXIAM_TENANT_SLUG ?? 'default';
const tenantId = process.env.AXIAM_TENANT_ID ?? '00000000-0000-0000-0000-000000000000';
const clientId = process.env.AXIAM_OIDC_CLIENT_ID ?? 'invoices-resource-server';
const clientSecret = process.env.AXIAM_OIDC_CLIENT_SECRET ?? 'resource-server-secret';

async function main(): Promise<void> {
  // A resource server is a confidential client: it authenticates at the token
  // endpoint with a secret, and it is the subject its tickets are bound to.
  // One session for the whole app: it carries the cookie jar (§4), the TLS
  // configuration (§6) and the single-flight refresh guard (§9) the OIDC client
  // reuses rather than duplicating.
  const nodeSession = createNodeSession({ baseUrl, tenantId });
  const oidc = createOidcClient(nodeSession, { clientId, clientSecret });

  // ---- 1. The PAT ----
  //
  // §20.2 rule 1: a client-credentials token carrying `uma_protection`. Not a
  // user token, and not this client's ambient session — the SDK will not
  // substitute either, and the Protection API would refuse them anyway.
  let pat: string;
  try {
    const session = await oidc.loginClientCredentials({ scope: UMA_PROTECTION_SCOPE });
    pat = session.accessToken.expose();
  } catch (err) {
    // Nothing below works without it, and starting anyway would produce a
    // service that fails on its first denial instead of saying why.
    console.error('could not mint a PAT:', err);
    console.error(`this client needs the \`${UMA_PROTECTION_SCOPE}\` scope granted to it.`);
    return;
  }

  // ---- 2. Registration ----
  //
  // Registering the same name twice creates two resources, so a real service
  // registers once at provisioning time and stores the id, or reconciles by
  // listing. Inline here because it is the step that shows the id is the AXIAM
  // resource id.
  const registered = await oidc.umaRegisterResource(pat, {
    name: 'invoice-7',
    type: 'invoice',
    // The declared scopes are the allow-list the permission endpoint validates
    // a ticket request against. A resource registered with none can never
    // appear in a ticket.
    resourceScopes: ['invoices:read', 'invoices:approve'],
  });
  console.log(`registered invoice-7 as ${registered.id}`);
  console.log(`try:  curl -i http://127.0.0.1:8081/invoices/${registered.id}`);

  // ---- 3. The guard ----
  //
  // `asUri` names where the caller should redeem the ticket. Read it from the
  // discovery document rather than assembling it by hand — a deployment is free
  // to move its endpoints, which is why §12.3 rule 6 forbids hardcoding them.
  const configuration = await oidc.oidcDiscover();
  const challenger: UmaChallenger = {
    realm: 'invoices',
    asUri: configuration.issuer,
    pat,
    // The minter is taken as a function so the middleware core does not depend
    // on the Node-only OIDC entry point — it is shared with the browser build,
    // which has no Protection API client.
    mint: (token, permissions) => oidc.umaRequestTicket(token, [...permissions]),
  };

  const session: AuthzVerifiableSession = {
    ...createNodeSession({ baseUrl, tenantSlug }),
    authzClient: new AxiamClient({ baseUrl, tenantSlug }),
  };

  const app = express();
  // The §10 middleware runs first and injects the verified identity; the §11
  // guard consumes it and never re-extracts the token (§11.2.1).
  app.use(axiamMiddleware(session));
  app.get(
    '/invoices/:id',
    // The load-bearing option is `umaChallenge`. Without it this is an ordinary
    // §11 check and a denial is a bare 403. With it, the denial carries a ticket
    // and the caller can act on it.
    requireAccess(session, 'invoices:read', fromParam('id'), { umaChallenge: challenger }),
    (_req, res) => {
      // Reached only when the engine allowed it — including honouring any deny
      // rule, which UMA does not bypass: the ticket asks for the same action
      // this check just evaluated, so the same grants and denies apply.
      res.json({ id: registered.id, total: '42.00', currency: 'EUR' });
    },
  );

  app.listen(8081, '127.0.0.1', () => {
    console.log('resource server listening on http://127.0.0.1:8081');
  });
}

void main();
