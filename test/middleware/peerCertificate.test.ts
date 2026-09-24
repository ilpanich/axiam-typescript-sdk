// certificateProofFromSocket (middleware/peerCertificate.ts, §10.1 rule 9,
// contract 1.51) — the transport evidence source axiamMiddleware/axiamPlugin
// wire into authenticateRequest automatically.

import { describe, expect, it } from 'vitest';
import { certificateProofFromSocket } from '../../src/middleware/peerCertificate.js';

function fakeTlsSocket(raw: Uint8Array | undefined): unknown {
  return {
    encrypted: true,
    getPeerCertificate: (_detailed?: boolean) => (raw ? { raw } : {}),
  };
}

describe('certificateProofFromSocket (§10.1 rule 9)', () => {
  it('returns {} for a null/undefined socket', async () => {
    expect(await certificateProofFromSocket(undefined)).toEqual({});
    expect(await certificateProofFromSocket(null)).toEqual({});
  });

  it('returns {} for a non-object value', async () => {
    expect(await certificateProofFromSocket('not-a-socket')).toEqual({});
    expect(await certificateProofFromSocket(42)).toEqual({});
  });

  it('returns {} for a plain (non-TLS) socket — encrypted is not true', async () => {
    expect(await certificateProofFromSocket({ encrypted: false })).toEqual({});
    expect(await certificateProofFromSocket({})).toEqual({});
  });

  it('returns {} when getPeerCertificate is missing entirely', async () => {
    expect(await certificateProofFromSocket({ encrypted: true })).toEqual({});
  });

  it('returns {} when a TLS socket presents no certificate (requestCert off, or none sent)', async () => {
    const socket = fakeTlsSocket(undefined);
    expect(await certificateProofFromSocket(socket)).toEqual({});
  });

  it('returns {} when getPeerCertificate throws', async () => {
    const socket = {
      encrypted: true,
      getPeerCertificate: () => {
        throw new Error('boom');
      },
    };
    expect(await certificateProofFromSocket(socket)).toEqual({});
  });

  it('derives certificateThumbprint from a TLS socket that DOES carry a peer certificate', async () => {
    const der = new Uint8Array([1, 2, 3, 4, 5]);
    const socket = fakeTlsSocket(der);
    const proofs = await certificateProofFromSocket(socket);
    expect(proofs.certificateThumbprint).toBeTypeOf('string');
    expect(proofs.certificateThumbprint!.length).toBeGreaterThan(0);
    expect(proofs.dpopThumbprint).toBeUndefined();
  });

  it('is deterministic — the same DER bytes always produce the same thumbprint', async () => {
    const der = new Uint8Array([9, 8, 7, 6, 5, 4, 3, 2, 1]);
    const first = await certificateProofFromSocket(fakeTlsSocket(der));
    const second = await certificateProofFromSocket(fakeTlsSocket(der));
    expect(first.certificateThumbprint).toBe(second.certificateThumbprint);
  });
});
