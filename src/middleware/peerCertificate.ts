// CONTRACT.md §10.1 rule 9 (contract 1.15/1.16/1.51) — deriving the ONE piece
// of transport evidence `authenticateRequest` can gather on its own: the
// client certificate the TLS layer verified for THIS connection, when Node
// itself terminated TLS.
//
// This is deliberately the only automatic evidence source. §10.1 detail 2 is
// explicit that the comparison input "MUST come from the transport" and
// "MUST NOT" come from a caller-settable header — a raw `net.Socket`'s own
// `getPeerCertificate()` is exactly the transport, nothing forwarded. DPoP
// evidence is NOT derived here: proof verification (§21.7) is a materially
// larger obligation the middleware does not undertake automatically, and
// `verifyTokenBinding`'s own contract is to refuse a jkt-bound token when no
// verified proof is supplied — which is correct, not a gap this file needs
// to fill.

import type { PresentedProofs } from '../node/jwks.js';
import { certificateThumbprintS256 } from '../node/jwks.js';

/**
 * The minimal shape a Node `net.Socket`/`tls.TLSSocket` needs for this
 * module to read a peer certificate off it. `encrypted` is TLSSocket's own
 * "always true" marker (Node's documented way to tell a TLS socket from a
 * plain one); `getPeerCertificate` is TLSSocket's method.
 */
export interface PeerCertificateSocket {
  /** `tls.TLSSocket`'s own "this is a TLS socket" marker — always `true` there, absent on a plain `net.Socket`. */
  encrypted?: boolean;
  /** `tls.TLSSocket.getPeerCertificate`. Returns the DER-encoded peer certificate, when `detailed` is `true` and one was presented. */
  getPeerCertificate?: (detailed?: boolean) => PeerCertificateLike | undefined;
}

/** The one field this module reads off `tls.TLSSocket.getPeerCertificate()`'s return value. */
export interface PeerCertificateLike {
  /** The DER-encoded certificate bytes, when a certificate was presented. */
  raw?: Uint8Array;
}

/**
 * Derive {@link PresentedProofs} from a request's raw socket.
 *
 * Returns `{}` (no evidence) whenever there is nothing to read: `socket` is
 * absent or not TLS-shaped, `encrypted` is not `true` (a plain `net.Socket`
 * — no TLS at all, or TLS terminated by a proxy that forwards nothing to
 * this process), or `getPeerCertificate()` returned no certificate (the
 * common case: nothing requested one, or the handshake carried none). `{}`
 * is the same shape `verifyTokenBinding`'s default parameter already means
 * "no proofs" — an unbound token is accepted either way, and a bound one is
 * refused, exactly CONTRACT.md §10.1 rule 9 detail 3's "the SDK cannot see
 * any client certificate at all" case: fail closed, never silently accept.
 *
 * Does **not** check whether the certificate chains to any particular CA —
 * possession is what a completed TLS handshake already proves (the peer
 * demonstrated the matching private key to get this far), and comparing the
 * resulting thumbprint against the token's `cnf` is `verifyTokenBinding`'s
 * job, not this function's.
 */
export async function certificateProofFromSocket(
  rawSocket: unknown,
): Promise<PresentedProofs> {
  // `unknown` rather than `PeerCertificateSocket | null | undefined`: the
  // real callers (Express's `net.Socket`, Fastify's raw Node request socket)
  // are typed by @types/node with no `encrypted`/`getPeerCertificate`
  // members at all outside a `tls.TLSSocket` narrowing this module has no
  // reason to import — an all-optional interface with zero structural
  // overlap is exactly what TS's "weak type" check (TS2559) rejects at the
  // call site. The shape check below is the real guard either way.
  if (!rawSocket || typeof rawSocket !== 'object') {
    return {};
  }
  const socket = rawSocket as PeerCertificateSocket;
  if (socket.encrypted !== true || typeof socket.getPeerCertificate !== 'function') {
    return {};
  }
  let cert: PeerCertificateLike | undefined;
  try {
    cert = socket.getPeerCertificate(true);
  } catch {
    return {};
  }
  if (!cert?.raw || cert.raw.length === 0) {
    return {};
  }
  return { certificateThumbprint: await certificateThumbprintS256(cert.raw) };
}
