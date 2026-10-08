// CIBA — client-initiated backchannel authentication (CONTRACT.md §33).
//
// A back-office system that already knows whom it wants to authenticate asks
// AXIAM to authenticate that user on another device, then collects the tokens.
// Poll mode here; see the README for ping mode and the signed request form.
//
// Run: npx tsx examples/ciba.ts

import { Sensitive } from '../src/core/index.js';
import { createNodeSession, createOidcClient, isAccessDenied, isExpiredToken } from '../src/node/index.js';

const baseUrl = process.env.AXIAM_BASE_URL ?? 'https://localhost:8443';
const tenantId = process.env.AXIAM_TENANT_ID ?? '11111111-2222-3333-4444-555555555555';
const clientId = process.env.AXIAM_OIDC_CLIENT_ID ?? 'teller-app';

const session = createNodeSession({ baseUrl, tenantId });
// A CIBA client is never public: it authenticates with its secret (or a §6.1
// client certificate on the session).
const oidc = createOidcClient(session, {
  clientId,
  clientSecret: new Sensitive(process.env.AXIAM_OIDC_CLIENT_SECRET ?? ''),
});

const initiated = await oidc.cibaInitiate({
  scope: 'openid profile',
  loginHint: process.argv[2] ?? 'ada',
  // Show the same short code to the person in front of you; the approval page
  // shows it to the user, so they can tell your request from an attacker's.
  bindingMessage: 'W4SCT',
});
// A success proves nothing about the user (§33.3 rule 4): an unknown, locked
// and real user are answered alike. Only `expired_token` says nobody answered.
console.log(`Asked; waiting up to ${initiated.expiresIn} s…`);

try {
  const tokens = await oidc.cibaAwait(initiated);
  console.log(`Approved by ${tokens.idClaims?.sub ?? 'unknown subject'}.`);
} catch (err) {
  if (isAccessDenied(err)) console.log('The user refused.');
  else if (isExpiredToken(err)) console.log('Nobody answered in time.');
  else throw err;
}
