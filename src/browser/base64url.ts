// base64url ⇄ ArrayBuffer, for the WebAuthn JSON form (CONTRACT.md §24.6).
//
// Hand-rolled rather than pulled from `@simplewebauthn/browser`, which is what
// the AXIAM admin UI uses. The conversion is thirty lines and fully specified
// by RFC 4648 §5; a runtime dependency on every consumer's bundle to avoid
// writing them, in a package whose whole job is to add as little as possible
// to a browser bundle, is the wrong trade. The test file pins both directions
// against fixed vectors, including the padding cases that are the only part
// anyone gets wrong.
//
// Every buffer in a WebAuthn JSON message is base64url, **unpadded**. We
// accept padding on the way in, because a server or a library that emits it is
// not wrong, and never emit it on the way out.

/**
 * Decode an unpadded (or padded) base64url string to bytes.
 *
 * Typed `Uint8Array<ArrayBuffer>` rather than the bare `Uint8Array`, whose
 * default parameter is `ArrayBufferLike` and therefore admits
 * `SharedArrayBuffer` — which `BufferSource`, and so every WebAuthn DOM
 * option, does not. The buffer is freshly allocated here and is never shared.
 */
export function base64UrlToBytes(value: string): Uint8Array<ArrayBuffer> {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded.padEnd(Math.ceil(padded.length / 4) * 4, '='));
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/** Encode bytes as unpadded base64url. */
export function bytesToBase64Url(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  // Chunked: `String.fromCharCode(...bytes)` blows the argument limit on an
  // attestation object, which is routinely a few kilobytes.
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
