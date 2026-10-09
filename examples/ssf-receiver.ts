// The SSF receiver helper (CONTRACT.md §32.7) — polling a stream AXIAM
// transmits security events on, verifying every SET, acknowledging what was
// processed and refusing what failed on the next call.
//
// Run: npx tsx examples/ssf-receiver.ts <stream-id>

import { Sensitive } from '../src/core/index.js';
import {
  createNodeClient,
  createOidcClient,
  setErrFromReason,
  SSF_EVENT_TYPES,
  SsfReceiver,
  type SecurityEvent,
  type SetErr,
} from '../src/node/index.js';

const baseUrl = process.env.AXIAM_BASE_URL ?? 'https://localhost:8443';
const tenantId = process.env.AXIAM_TENANT_ID ?? '11111111-2222-3333-4444-555555555555';
const streamId = process.argv[2] ?? '22222222-2222-4222-8222-222222222222';

const client = createNodeClient({ baseUrl, tenantId });
const oidc = createOidcClient(client.session, {
  clientId: process.env.AXIAM_SSF_CLIENT_ID ?? 'ssf-receiver',
  clientSecret: new Sensitive(process.env.AXIAM_SSF_CLIENT_SECRET ?? ''),
});

const receiver = new SsfReceiver(client, {
  issuer: `${baseUrl}/t/${tenantId}`,
  audience: process.env.AXIAM_SSF_AUDIENCE ?? 'https://rp.example.com',
  jwksUri: `${baseUrl}/oauth2/jwks`,
  // A client-credentials token carrying ssf.manage, fetched per poll.
  accessTokenProvider: async () => (await oidc.loginClientCredentials({ scope: 'ssf.manage' })).accessToken,
});

function handle(event: SecurityEvent): void {
  if (event.eventType === SSF_EVENT_TYPES.SESSION_REVOKED) {
    console.log(`session revoked (${event.jti})`);
  } else {
    console.log(`${event.eventType} (${event.jti})`);
  }
}

let ack: string[] = [];
let setErrs: Record<string, SetErr> = {};
for (let round = 0; round < 10; round += 1) {
  // Nothing is acknowledged on your behalf: a verified SET has been recorded,
  // so one you neither ack nor refuse reads as `replayed` when re-offered.
  const { events, refused, moreAvailable } = await receiver.poll(streamId, {
    ack,
    setErrs,
    returnImmediately: true,
  });
  events.forEach(handle);
  // A `replayed` SET was accepted on an earlier poll: acknowledge it rather
  // than report it (CONTRACT.md §34.2 P2). `unjudged` SETs are neither acked
  // nor refused: the transmitter offers them again.
  ack = [...events.map((e) => e.jti), ...refused.filter((r) => r.reason === 'replayed').map((r) => r.jti)];
  setErrs = Object.fromEntries(
    refused.filter((r) => r.reason !== 'replayed').map((r) => [r.jti, setErrFromReason(r.reason)]),
  );
  if (!moreAvailable) await new Promise((resolve) => setTimeout(resolve, 1000));
}
