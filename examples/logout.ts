// RP-initiated and back-channel logout (CONTRACT.md §12.7).
//
// Two halves that close each other's hole. Without the first, a user who logs
// out of your app stays logged in at AXIAM and is silently signed back in on
// the next "Login with AXIAM". Without the second, a user who logs out *of
// AXIAM* stays logged in at your app indefinitely, because nothing tells you —
// which is what leaves live sessions behind when an admin revokes a
// compromised account.
//
// Run: npx tsx examples/logout.ts

import { createNodeSession, createOidcClient } from '../src/node/index.js';
import { Sensitive } from '../src/core/index.js';

const baseUrl = process.env.AXIAM_BASE_URL ?? 'https://localhost:8443';
const tenantId = process.env.AXIAM_TENANT_ID ?? '11111111-2222-3333-4444-555555555555';
const clientId = process.env.AXIAM_OIDC_CLIENT_ID ?? 'my-app';

const session = createNodeSession({ baseUrl, tenantId });
const oidc = createOidcClient(session, { clientId });

// ---------------------------------------------------------------------------
// Half 1: the user clicked "log out" in YOUR app.
// ---------------------------------------------------------------------------

// The ID token you stored at login. It is what identifies *which* session to
// end — a signed statement rather than a parameter anyone could send. AXIAM
// does not check its expiry (a logging-out user's ID token has usually expired
// already), but it does check the signature.
const storedIdToken = process.env.AXIAM_ID_TOKEN ?? 'the-id-token-from-login';

const url = await oidc.logoutUrl({
  idToken: new Sensitive(storedIdToken),
  postLogoutRedirectUri: 'https://app.example.com/goodbye',
  // `state` is yours to generate and yours to check when it comes back. The
  // SDK passes it through and never invents one.
  state: 'csrf-value-you-stored-in-the-session',
});

// Redirect the browser here. Note what the SDK did NOT do: it did not clear
// this client's own session. Whether your local session ends is your decision
// — a backend holding a service-account session must not lose it because a
// *user* logged out.
console.log(`Redirect the user agent to:\n  ${url}`);

// The redirect URI is honoured only if it exactly matches your client's
// registered `post_logout_redirect_uris` — a separate list from
// `redirect_uris`. The SDK does not pre-check it against a local copy (§12.7.2
// rule 3): that copy would drift and would reject a URI an operator had just
// registered. If it does not match, AXIAM still logs the user out.

// ---------------------------------------------------------------------------
// Half 2: AXIAM tells YOU a session ended.
// ---------------------------------------------------------------------------
//
// Mount this at the `backchannel_logout_uri` you registered. AXIAM POSTs
// `logout_token=<jwt>`, form-encoded.

const inboundLogoutToken = process.env.AXIAM_LOGOUT_TOKEN;
if (inboundLogoutToken) {
  try {
    const verified = await oidc.verifyLogoutToken(inboundLogoutToken);

    // Dedup on `jti` in YOUR store. Delivery is at-least-once, so a valid
    // token legitimately arrives twice — that is a retry, not an attack. The
    // SDK deliberately does not dedup: it has no durable store, and an
    // in-memory guard would silently drop a real second logout after a
    // restart.
    console.log(`logout token ${verified.jti} verified`);

    if (verified.sid) {
      // End THAT session only. Falling back to "every session for this user"
      // is over-reach AXIAM itself refuses to make — the user's other devices
      // are still signed in on purpose.
      console.log(`end session ${verified.sid} only`);
    } else {
      console.log(`no sid: this token names only sub ${verified.sub ?? '(none)'}`);
    }
  } catch (err) {
    // Answer 400 and log. Do not end anything: an unverifiable token is not a
    // logout instruction, and treating it as one would make your endpoint a
    // denial-of-service primitive for anyone who can reach it.
    console.error(`rejected logout token: ${String(err)}`);
  }
}
