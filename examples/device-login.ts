// Device Authorization Grant (CONTRACT.md §14) — signing in a device that
// cannot show a browser.
//
// The shape this example is really demonstrating: the SDK hands you the user
// code and verification URI *before* it starts polling, and what you do with
// them is yours. Here that is `console.log`; on a real device it is a screen,
// a QR code, or an e-ink panel. The SDK never prints them for you (§14.3
// rule 2).
//
// Run: npx tsx examples/device-login.ts

import { createNodeSession, createOidcClient } from '../src/node/index.js';

const baseUrl = process.env.AXIAM_BASE_URL ?? 'https://localhost:8443';
const tenantId = process.env.AXIAM_TENANT_ID ?? '11111111-2222-3333-4444-555555555555';
const clientId = process.env.AXIAM_OIDC_CLIENT_ID ?? 'my-device';

const session = createNodeSession({ baseUrl, tenantId });

// No client secret: a device that cannot show a browser cannot keep one
// either, and §14.1 makes `deviceAuthorize` unauthenticated for that reason.
const oidc = createOidcClient(session, { clientId });

const tokens = await oidc.deviceLogin({
  scope: 'openid profile',
  onUserCode: (authorization) => {
    // Called BEFORE the first poll. Display, then the SDK waits.
    console.log(`\n  To sign in, visit: ${authorization.verificationUri}`);
    console.log(`  and enter code:    ${authorization.userCode}`);
    if (authorization.verificationUriComplete) {
      // Prefer this when the device can render a QR code — the user then
      // types nothing at all. Never build it yourself when it is absent: the
      // format is the server's to choose (§14.3).
      console.log(`  or go straight to: ${authorization.verificationUriComplete}`);
    }
    console.log('\nWaiting for approval…');
  },
});

// §14.3 rule 4 (contract 1.7): this SDK returns the tokens; adopting them is
// the application's decision, matching its loginClientCredentials posture.
console.log(`Signed in. Access token expires in ${tokens.expiresIn}s.`);
if (tokens.idClaims) {
  console.log(`Subject: ${tokens.idClaims.sub}`);
}

// The two failure modes worth telling apart in real code — a human said no,
// versus nobody answered:
//
//   catch (err) {
//     if (err instanceof OAuthProtocolError && err.error === 'access_denied') { /* refused */ }
//     if (err instanceof OAuthProtocolError && err.error === 'expired_token') { /* timed out */ }
//   }
//
// Collapsing them loses the only information the device can act on (§14.2
// rule 3): whether re-prompting could possibly help.
