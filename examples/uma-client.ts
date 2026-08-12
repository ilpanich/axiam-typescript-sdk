// UMA 2.0 (CONTRACT.md §20) — the **client** half of the pair.
//
// Run `examples/uma-resource-server.ts` first; this program talks to it.
//
// The flow, which is the whole reason UMA exists:
//
//   1. Ask for the invoice with the user's ordinary token. The resource server
//      refuses — but its 403 carries `WWW-Authenticate: UMA` naming a ticket
//      and an authorization server.
//   2. Parse the challenge. Note what happens next, and what does not: parsing
//      performs no exchange (§20.3). The `as_uri` in that header is a host the
//      *server we just failed against* chose; auto-redeeming would send the
//      user's token wherever a 403 pointed.
//   3. Decide to trust it, then exchange the ticket for an RPT.
//   4. Retry with the RPT.
//
// Step 3 is a decision, not a formality — this example makes it explicitly, by
// comparing the nominated `as_uri` against the issuer this client already
// trusts, and refusing when they differ.
//
// Run: `npx tsx examples/uma-client.ts`

import { createNodeSession, createOidcClient, umaParseChallenge } from 'axiam-sdk/node';

const baseUrl = process.env.AXIAM_BASE_URL ?? 'https://localhost:8443';
const tenantId = process.env.AXIAM_TENANT_ID ?? '00000000-0000-0000-0000-000000000000';
const clientId = process.env.AXIAM_OIDC_CLIENT_ID ?? 'invoices-client';
const clientSecret = process.env.AXIAM_OIDC_CLIENT_SECRET ?? 'client-secret';

// The resource server printed this id when it registered.
const invoiceId = process.env.AXIAM_INVOICE_ID ?? '00000000-0000-0000-0000-000000000000';
const resourceServer = process.env.AXIAM_RESOURCE_SERVER ?? 'http://127.0.0.1:8081';

// The requesting party's own token — what this program would normally send and,
// in step 3, the `claimToken` that names *who* is asking.
const userToken = process.env.AXIAM_USER_TOKEN ?? 'the-requesting-partys-access-token';

async function main(): Promise<void> {
  // The exchange is a token-endpoint grant, so this client is confidential.
  const oidc = createOidcClient(createNodeSession({ baseUrl, tenantId }), {
    clientId,
    clientSecret,
  });
  const url = `${resourceServer}/invoices/${invoiceId}`;

  // ---- 1. The refusal ----
  const refused = await fetch(url, { headers: { authorization: `Bearer ${userToken}` } });
  console.log(`first attempt: ${refused.status}`);

  const header = refused.headers.get('www-authenticate');
  if (!header) {
    // A resource server that refuses without a challenge is telling you it has
    // nothing to offer — there is no ticket to redeem, and retrying the same
    // request would be pointless.
    console.log('no WWW-Authenticate header: this refusal is not actionable.');
    return;
  }

  // ---- 2. Parse, and only parse ----
  const challenge = umaParseChallenge(header);
  if (!challenge?.ticket) {
    console.log('the challenge names no ticket; nothing to redeem.');
    return;
  }

  // Log the *parsed* fields, never the raw header. The header contains
  // `ticket="..."`, and §20.6 is explicit that the ticket's 60-second life does
  // not make it harmless: for those 60 seconds it is the credential that
  // converts into an RPT, so a header in a log line is a live credential in a
  // log line. `realm` and `asUri` are not secrets and are the two fields you
  // actually need to look at.
  console.log(`challenge: realm=${challenge.realm} as_uri=${challenge.asUri} ticket=[REDACTED]`);

  // ---- 3. The trust decision ----
  //
  // This is the step §20.3 exists to keep in the caller's hands. The SDK parsed
  // the header and stopped; deciding whether to send the user's token to the
  // host it names is this program's call, and it is a real one — a compromised
  // or merely misconfigured resource server could nominate anything here.
  const trusted = (await oidc.oidcDiscover()).issuer;
  const nominated = challenge.asUri;
  if (nominated && nominated.replace(/\/$/, '') !== trusted.replace(/\/$/, '')) {
    console.log(`refusing to redeem: as_uri ${nominated} is not our issuer ${trusted}.`);
    console.log('this is the auto-exchange §20.3 forbids, and why it forbids it.');
    return;
  }
  console.log('as_uri matches the issuer we already trust; redeeming.');

  // ---- 4. Exchange, then retry ----
  //
  // One request. A ticket is spent whether or not this succeeds (§20.2 rule 6),
  // so on failure the next step is a *new* ticket — which means going back to
  // step 1, not resending this one.
  let rpt;
  try {
    rpt = await oidc.umaExchangeTicket({ ticket: challenge.ticket, claimToken: userToken });
  } catch (err) {
    console.log('exchange failed:', err);
    console.log('the ticket is spent either way — request a new one by retrying the call.');
    return;
  }
  console.log(`got an RPT, valid for ${rpt.expiresIn}s`);

  const allowed = await fetch(url, {
    headers: { authorization: `Bearer ${rpt.accessToken.expose()}` },
  });
  console.log(`second attempt: ${allowed.status}`);
  if (allowed.ok) {
    console.log('body:', await allowed.text());
  }
}

void main();
