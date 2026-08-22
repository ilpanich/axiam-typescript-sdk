/**
 * OPAQUE (RFC 9807) login and enrolment — CONTRACT.md §23.
 *
 * What is worth reading here is the error handling, not the happy path. Three
 * things about it are load-bearing:
 *
 *  1. `loginOpaque` returns the same `LoginResult` as `login`, MFA branch
 *     included, so an application switching a tenant to OPAQUE changes nothing
 *     else.
 *  2. A `NetworkError` means the tenant has OPAQUE disabled, or this
 *     installation lacks `@axiam/opaque-wasm`. That is the ONLY case where
 *     falling back to `login()` is correct.
 *  3. Anything else is a failed login. Retrying it over `login()` would hand
 *     the plaintext to a server that just failed to prove it holds the record,
 *     which is the one mistake this example exists to not make.
 *
 * Run: AXIAM_PASSWORD=… npx tsx examples/opaque-login.ts
 */

import { AxiamClient, NetworkError } from '../src/index.js';

const baseUrl = process.env.AXIAM_URL ?? 'https://axiam.example';
const tenantSlug = process.env.AXIAM_TENANT ?? 'default';
const orgSlug = process.env.AXIAM_ORG ?? 'acme';
const username = process.env.AXIAM_USER ?? 'alice';
const password = process.env.AXIAM_PASSWORD;

if (!password) {
  console.error('AXIAM_PASSWORD is required');
  process.exit(1);
}

const client = new AxiamClient({ baseUrl, tenantSlug, orgSlug });

try {
  // Reports rather than throws, so an application can choose the password path
  // up front instead of discovering the gap mid-exchange. `false` here means
  // the optional peer `@axiam/opaque-wasm` is not installed.
  if (!(await client.opaqueAvailable())) {
    console.warn('this installation cannot perform OPAQUE; install @axiam/opaque-wasm');
  }

  let result;
  try {
    result = await client.loginOpaque(username, password);
  } catch (err) {
    if (err instanceof NetworkError) {
      // The tenant does not offer OPAQUE, the peer is missing, or the server
      // named a KSF this SDK cannot perform. All configuration faults rather
      // than wrong passwords — the one case where the password path is right.
      console.warn(`OPAQUE unavailable (${err.message}); falling back to password login`);
      result = await client.login(username, password);
    } else {
      // An AuthError: wrong password, no such account, or a server that does
      // not hold the record — indistinguishable by design. Do NOT retry over
      // login().
      throw err;
    }
  }

  // Three outcomes since contract 1.28, and the switch is exhaustive on
  // purpose: the third one used to arrive as an AuthzError, which told the
  // caller they lacked permission to sign in when the server had in fact
  // handed back the means to finish (CONTRACT.md §25.2 rule 1).
  switch (result.status) {
    case 'mfa_required':
      console.log(`signed in; MFA required (methods: ${result.availableMethods.join(', ')})`);
      break;
    case 'mfa_setup_required':
      console.log('this tenant requires MFA and this account has none — see account-lifecycle.ts');
      break;
    case 'authenticated':
      console.log(`signed in over OPAQUE as ${result.user.username}; session ${result.sessionId}`);
      break;
  }

  // Enrolling a record for a new password. One argument, where the SRP verifier
  // this replaces took four: no identity (the server chooses the credential
  // identifier), no group and no KDF (the server names them in its
  // register/start response, which this call honours).
  const newPassword = process.env.AXIAM_NEW_PASSWORD;
  if (newPassword) {
    const enrollment = await client.opaqueEnrollment(newPassword);
    console.log(
      `built an enrolment (${enrollment.registration_record.length / 2}-byte record) — ` +
        'send it as the request body\'s `opaque` field',
    );
  }
} finally {
  await client.close();
}
