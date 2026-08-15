/**
 * Enforcing CONTRACT.md §10.1 rule 9 in a resource server — the full rule,
 * covering certificate-bound (RFC 8705) and DPoP-bound (RFC 9449) tokens.
 *
 * Run with:
 *
 * ```bash
 * npx tsx examples/sender-constrained-guard.ts
 * ```
 *
 * ## What rule 9 actually says
 *
 * A token carrying `cnf` is **not** a bearer token. Accepting one without
 * proving the caller holds the confirmed key converts it back into a bearer
 * token and discards the whole protection the operator turned on.
 *
 * Three cases are worth internalising, because they are the ones implemented
 * wrongly:
 *
 * 1. **An unbound token is still accepted** — no certificate, no proof. Rule 9
 *    is not "require evidence from everybody".
 * 2. **`cnf` naming both methods is a conjunction.** Two constraints means
 *    two; satisfying the more convenient one is not compliance.
 * 3. **A `cnf` this SDK cannot interpret is refused**, never read as
 *    unconstrained — including an *empty* one.
 */
import { createServer } from 'node:https';
import type { TLSSocket } from 'node:tls';
import {
  createVerifier,
  certificateThumbprintS256,
  verifyTokenBinding,
} from '../src/node/index.js';

const verifier = createVerifier(process.env.AXIAM_BASE_URL ?? 'https://axiam.example.com');

/**
 * The `jkt` of a DPoP proof you have **already verified** against this
 * request's method, URI, `iat` and `jti`.
 *
 * Returning a thumbprint here asserts the proof checked out. Lifting it off an
 * unverified proof would let a proof captured from any other endpoint
 * authorize this one — which is why this is a separate, deliberate step rather
 * than something the SDK reads out of a header for you.
 */
function verifiedDpopThumbprint(_req: unknown): string | undefined {
  return undefined;
}

const server = createServer({ requestCert: true, rejectUnauthorized: false }, async (req, res) => {
  const token = (req.headers.authorization ?? '').replace(/^Bearer /i, '');

  try {
    // Rules 1-8: signature, expiry, issuer, audience. NOT rule 9 — this call
    // has no transport to ask, which is exactly why the binding check is
    // separate rather than something you can forget to opt into.
    const claims = await verifier.verifyAccessToken(token, {
      expectedTenantId: process.env.AXIAM_TENANT_ID,
    });

    // The thumbprint must come from the connection, never a header the caller
    // can set: a forgeable input makes the mechanism decorative.
    const peer = (req.socket as TLSSocket).getPeerCertificate?.();
    const certificateThumbprint =
      peer?.raw !== undefined ? await certificateThumbprintS256(peer.raw) : undefined;

    // Rule 9. Returns immediately for an unbound token, so adopting this does
    // not break existing deployments.
    verifyTokenBinding(claims, {
      certificateThumbprint,
      dpopThumbprint: verifiedDpopThumbprint(req),
    });

    res.writeHead(200).end(`subject ${claims.sub} authorized\n`);
  } catch (err) {
    res.writeHead(401).end(`${(err as Error).message}\n`);
  }
});

server.listen(8443);
