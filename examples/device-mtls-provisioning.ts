// Provision an IoT device and authenticate it with mTLS — CONTRACT §27 + §6.1.
//
// This is the flow that motivated the §27 management surface. Before it, an
// SDK could *authenticate* a device with a client certificate but could not
// **issue** one: minting the certificate, binding it to a service account, and
// anchoring the CA for mTLS all had to happen out of band, by hand, before any
// SDK client could be built.
//
// Five steps, and every one of them a §27 call:
//
//   1. Anchor the organization CA as an mTLS trust anchor, so the server will
//      accept certificates it signed at the TLS layer.
//   2. Create a service account — the device's identity.
//   3. Generate a device certificate. This is the only moment the private key
//      exists outside the device; it is returned once and never again.
//   4. Bind the certificate to the service account, so presenting it
//      authenticates as that identity rather than as an anonymous holder.
//   5. Build a second client that presents the certificate, and use it.
//
//   npx tsx examples/device-mtls-provisioning.ts
//
// No network I/O: every call is printed rather than made, so the example is
// readable and runnable without a server.

import { AxiamClient, Sensitive } from 'axiam-sdk/rest';
import type { SetMtlsTrustAnchor } from 'axiam-sdk/rest';

async function main(): Promise<void> {
  const admin = new AxiamClient({
    baseUrl: 'https://iam.example.com',
    tenantId: '00000000-0000-0000-0000-000000000000',
    orgId: '00000000-0000-0000-0000-000000000000',
  });
  // A real run authenticates first: §27.4 rule 1 refuses to make a wire call
  // without a session, so this would be `await admin.login(...)`.
  void admin;

  console.log('1. anchor the organization CA for mTLS');
  call(
    'PUT /api/v1/organizations/{org}/ca-certificates/{ca}/mtls-trust-anchor',
    'caCertificates.setMtlsTrustAnchor(caId, { enabled: true })',
  );
  // Note the shape: `SetMtlsTrustAnchor` has a *required* field, because this
  // route is a replacement rather than a patch (§27.4 rule 5). TypeScript will
  // not let you send a half-filled one.
  const anchor: SetMtlsTrustAnchor = { enabled: true };
  void anchor;

  console.log('\n2. create the device\'s service account');
  call('POST /api/v1/service-accounts', 'serviceAccounts.create({ ... })');
  // The response carries `client_secret`, returned **once** (§27.5). A device
  // authenticating by certificate does not need it — but if you discard it and
  // later decide you do, the only way back is `rotateSecret`.

  console.log('\n3. generate the device certificate');
  call(
    'POST /api/v1/certificates',
    'certificates.generate({ cert_type: "Device", ... })',
  );
  // `GeneratedCertificate.private_key_pem` is `Sensitive<string>` and is
  // returned by this call and by no other. `certificates.get(id)` afterwards
  // returns the *projection* — same certificate, no key field at all, and
  // nothing in the response to suggest something is missing. Write it to the
  // device now, or mint a new certificate later; there is no third option.
  const deviceKey = new Sensitive('-----BEGIN PRIVATE KEY-----…');
  console.log(`   private key: ${String(deviceKey)}  <- redacted by §7, even here`);
  console.log(`   JSON.stringify: ${JSON.stringify({ key: deviceKey })}`);

  console.log('\n4. bind the certificate to the service account');
  call(
    'POST /api/v1/service-accounts/{sa}/bind-certificate',
    'serviceAccounts.bindCertificate(saId, { certificate_id })',
  );
  // Without this, the certificate is valid TLS material that authenticates as
  // nobody: the handshake succeeds and the authorization check finds no
  // subject to check.

  console.log('\n5. the device builds its own client and authenticates');
  console.log(`
   On the device itself, with the key from step 3 and the cert alongside it —
   note the Node subpath, since presenting a client certificate needs a TLS
   agent the browser does not give you:

       import { createNodeClient } from 'axiam-sdk/node';

       const device = createNodeClient({
         baseUrl: 'https://iam.example.com',
         tenantId,
         clientCert: { certPem, keyPem },
       });
       const decision = await device.checkAccess({
         action: 'telemetry:publish',
         resourceId,
       });

   §6.1: the certificate is presented at the TLS layer on every request,
   including the gRPC channel, and the server maps it to the service account
   bound in step 4.`);

  console.log(`
Rotation, when the certificate nears expiry:
   - generate a new one (step 3) and bind it (step 4) BEFORE revoking the old
   - then certificates.revoke(oldId) — a device that revokes first is a device
     that has locked itself out and cannot call the API to fix it`);
}

function call(route: string, code: string): void {
  console.log(`   → ${route}`);
  console.log(`     ${code}`);
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
