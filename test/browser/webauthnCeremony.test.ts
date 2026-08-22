// @vitest-environment jsdom
//
// §24.6b — the browser ceremony, and §24.6a's base64url transcription.
//
// jsdom has no WebAuthn implementation, so `navigator.credentials` is stubbed.
// That is the right level for these assertions anyway: what §24.8 asks about
// this layer is what the SDK *passes to* the platform API and what it does with
// the five error names it gets back — neither of which needs a real
// authenticator, and both of which a real one would make harder to pin.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  base64UrlToBytes,
  bytesToBase64Url,
  classifyWebauthnError,
  isConditionalMediationAvailable,
  isWebauthnSupported,
  webauthnErrorMessage,
  webauthnRegister,
  webauthnDiscoverableLogin,
  webauthnLogin,
} from '../../src/browser/index.js';
import type { AxiamClient } from '../../src/rest/index.js';
import { Sensitive } from '../../src/rest/index.js';
import {
  CREATION_CHALLENGE,
  DISCOVERABLE_CHALLENGE,
  MINIMAL_CREATION_CHALLENGE,
  REQUEST_CHALLENGE,
  STATE_TOKEN,
} from '../rest/webauthnFixtures.js';

// ---------------------------------------------------------------------------
// Platform stubs
// ---------------------------------------------------------------------------

/** What the last `create()`/`get()` call was handed. The subject of most tests. */
let lastCreate: CredentialCreationOptions | undefined;
let lastGet: CredentialRequestOptions | undefined;

function fakeCredential(kind: 'create' | 'get'): PublicKeyCredential {
  const bytes = (s: string) => base64UrlToBytes(s).buffer;
  const common = {
    id: 'bmV3LWNyZWRlbnRpYWwtaWQ',
    rawId: bytes('bmV3LWNyZWRlbnRpYWwtaWQ'),
    type: 'public-key',
    authenticatorAttachment: 'platform',
    getClientExtensionResults: () => ({ credProps: { rk: true } }),
  };
  const response =
    kind === 'create'
      ? {
          clientDataJSON: bytes('eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0'),
          attestationObject: bytes('o2NmbXRkbm9uZQ'),
          getTransports: () => ['internal'],
        }
      : {
          clientDataJSON: bytes('eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0'),
          authenticatorData: bytes('YXV0aGVudGljYXRvci1kYXRh'),
          signature: bytes('c2lnbmF0dXJl'),
          userHandle: bytes('dXNlci1oYW5kbGU'),
        };
  return { ...common, response } as unknown as PublicKeyCredential;
}

/** Install a WebAuthn-capable `navigator`/`PublicKeyCredential` on jsdom. */
function installAuthenticator(options?: {
  createThrows?: Error;
  getThrows?: Error;
  conditionalProbe?: (() => Promise<boolean>) | 'missing';
}) {
  const ctor = function PublicKeyCredential() {} as unknown as Record<string, unknown>;
  if (options?.conditionalProbe !== 'missing') {
    ctor.isConditionalMediationAvailable =
      options?.conditionalProbe ?? (() => Promise.resolve(true));
  }
  Object.defineProperty(globalThis, 'PublicKeyCredential', { value: ctor, configurable: true });
  Object.defineProperty(globalThis.navigator, 'credentials', {
    value: {
      create: vi.fn(async (o: CredentialCreationOptions) => {
        lastCreate = o;
        if (options?.createThrows) throw options.createThrows;
        return fakeCredential('create');
      }),
      get: vi.fn(async (o: CredentialRequestOptions) => {
        lastGet = o;
        if (options?.getThrows) throw options.getThrows;
        return fakeCredential('get');
      }),
    },
    configurable: true,
  });
}

function removeAuthenticator() {
  Object.defineProperty(globalThis, 'PublicKeyCredential', {
    value: undefined,
    configurable: true,
  });
  Object.defineProperty(globalThis.navigator, 'credentials', {
    value: undefined,
    configurable: true,
  });
}

/** A client stub: the ceremony helpers only touch these six methods. */
function stubClient(overrides: Partial<Record<string, unknown>> = {}): AxiamClient {
  return {
    webauthnRegisterStart: vi.fn(async () => ({
      challenge: CREATION_CHALLENGE,
      stateToken: new Sensitive(STATE_TOKEN),
    })),
    webauthnRegisterFinish: vi.fn(async () => ({
      id: 'x',
      credentialId: 'y',
      name: 'n',
      credentialType: 'passkey',
      createdAt: '2026-08-22T10:00:00Z',
    })),
    webauthnAuthenticateStart: vi.fn(async () => ({
      challenge: REQUEST_CHALLENGE,
      stateToken: new Sensitive(STATE_TOKEN),
    })),
    webauthnAuthenticateFinish: vi.fn(async () => ({
      accessToken: new Sensitive('a'),
      refreshToken: new Sensitive('r'),
      sessionId: 's',
      expiresIn: 900,
    })),
    webauthnDiscoverableStart: vi.fn(async () => ({
      challenge: DISCOVERABLE_CHALLENGE,
      stateToken: new Sensitive(STATE_TOKEN),
    })),
    webauthnDiscoverableFinish: vi.fn(async () => ({
      accessToken: new Sensitive('a'),
      refreshToken: new Sensitive('r'),
      sessionId: 's',
      expiresIn: 900,
    })),
    ...overrides,
  } as unknown as AxiamClient;
}

beforeEach(() => {
  lastCreate = undefined;
  lastGet = undefined;
  installAuthenticator();
});
afterEach(() => vi.restoreAllMocks());

// ---------------------------------------------------------------------------
// base64url (§24.6a's transcription, and the only maths in this module)
// ---------------------------------------------------------------------------

describe('base64url', () => {
  // The three residue classes mod 3 are the whole of the padding behaviour, and
  // padding is the only part of base64url anyone gets wrong.
  it.each([
    ['', ''],
    ['f', 'Zg'],
    ['fo', 'Zm8'],
    ['foo', 'Zm9v'],
    ['foob', 'Zm9vYg'],
    ['fooba', 'Zm9vYmE'],
    ['foobar', 'Zm9vYmFy'],
  ])('encodes %o as %o, unpadded', (plain, encoded) => {
    expect(bytesToBase64Url(new TextEncoder().encode(plain))).toBe(encoded);
  });

  it('round-trips every byte value', () => {
    const all = new Uint8Array(256).map((_, i) => i);
    expect([...base64UrlToBytes(bytesToBase64Url(all))]).toEqual([...all]);
  });

  it('uses the URL-safe alphabet, never + or /', () => {
    // 0xFB 0xFF encodes to "+/8" in standard base64.
    const encoded = bytesToBase64Url(new Uint8Array([0xfb, 0xff, 0xfe]));
    expect(encoded).not.toMatch(/[+/=]/);
    expect([...base64UrlToBytes(encoded)]).toEqual([0xfb, 0xff, 0xfe]);
  });

  it('accepts padded input, because a server that emits it is not wrong', () => {
    expect([...base64UrlToBytes('Zm8=')]).toEqual([...base64UrlToBytes('Zm8')]);
  });

  it('handles a buffer larger than the fromCharCode argument limit', () => {
    // An attestation object is routinely kilobytes; the naive spread breaks here.
    const big = new Uint8Array(100_000).map((_, i) => i % 251);
    expect([...base64UrlToBytes(bytesToBase64Url(big))]).toEqual([...big]);
  });
});

// ---------------------------------------------------------------------------
// §24.6b rule 6 — feature detection is a query
// ---------------------------------------------------------------------------

describe('feature detection', () => {
  it('reports support when the platform has it', () => {
    expect(isWebauthnSupported()).toBe(true);
  });

  it('answers false rather than throwing when it does not', () => {
    removeAuthenticator();
    expect(isWebauthnSupported()).toBe(false);
  });

  it('answers false when the conditional-mediation probe is missing entirely', async () => {
    installAuthenticator({ conditionalProbe: 'missing' });
    await expect(isConditionalMediationAvailable()).resolves.toBe(false);
  });

  it('answers false when the probe itself throws', async () => {
    installAuthenticator({
      conditionalProbe: () => Promise.reject(new Error('nope')),
    });
    await expect(isConditionalMediationAvailable()).resolves.toBe(false);
  });

  it('reports conditional mediation when the probe says yes', async () => {
    await expect(isConditionalMediationAvailable()).resolves.toBe(true);
  });

  it('refuses a ceremony on an unsupported runtime, without calling the server', async () => {
    removeAuthenticator();
    const client = stubClient();
    await expect(webauthnRegister(client, 'key')).rejects.toThrow(/no WebAuthn authenticator/);
    expect(client.webauthnRegisterStart).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// §24.6b rule 5 — error classification
// ---------------------------------------------------------------------------

describe('error classification', () => {
  it.each([
    ['NotAllowedError', 'cancelled'],
    ['InvalidStateError', 'already_registered'],
    ['AbortError', 'timeout'],
    ['NotSupportedError', 'unsupported'],
    ['SecurityError', 'unsupported'],
    ['SomethingElseError', 'unknown'],
  ])('maps %s to %s', (name, expected) => {
    expect(classifyWebauthnError(Object.assign(new Error('x'), { name }))).toBe(expected);
  });

  it('distinguishes already_registered from cancelled', () => {
    // The one classification whose remedy is "use a different device" rather
    // than "try again" — collapsing it into `unknown` loses that.
    const invalid = classifyWebauthnError({ name: 'InvalidStateError' });
    const notAllowed = classifyWebauthnError({ name: 'NotAllowedError' });
    expect(invalid).not.toBe(notAllowed);
    expect(webauthnErrorMessage(invalid)).toMatch(/different device/);
  });

  it('does not accuse the user of cancelling, since the same name covers a timeout', () => {
    expect(webauthnErrorMessage('cancelled')).toMatch(/cancelled or timed out/);
  });

  it('classifies a bare platform error name relayed as a string', () => {
    // An Android CreateCredentialException, or an ASAuthorizationError code,
    // reaching a server-side caller as a string (§24.6b rule 5's last line).
    expect(classifyWebauthnError('canceled')).toBe('cancelled');
  });

  it('never throws, whatever it is handed', () => {
    for (const value of [undefined, null, 0, '', [], {}]) {
      expect(classifyWebauthnError(value)).toBe('unknown');
    }
  });
});

// ---------------------------------------------------------------------------
// §24.0 / §24.6b rule 4 — what reaches the platform API
// ---------------------------------------------------------------------------

describe('options handed to the authenticator', () => {
  it('transcribes every server option without adding or dropping one', async () => {
    await webauthnRegister(stubClient(), 'Alice’s laptop');
    const pk = lastCreate!.publicKey!;
    const source = CREATION_CHALLENGE.publicKey;

    expect([...new Uint8Array(pk.challenge as ArrayBuffer)]).toEqual([
      ...base64UrlToBytes(source.challenge),
    ]);
    expect(pk.rp).toEqual(source.rp);
    expect(pk.user.name).toBe(source.user.name);
    expect(pk.user.displayName).toBe(source.user.displayName);
    expect(pk.pubKeyCredParams).toEqual(source.pubKeyCredParams);
    expect(pk.timeout).toBe(source.timeout);
    expect(pk.attestation).toBe(source.attestation);
    expect(pk.extensions).toEqual(source.extensions);
    expect(pk.excludeCredentials).toHaveLength(1);
    expect(pk.excludeCredentials![0]!.transports).toEqual(['usb', 'nfc']);
    expect(pk.authenticatorSelection).toMatchObject({
      residentKey: 'required',
      requireResidentKey: true,
      userVerification: 'required',
    });
  });

  it('adds authenticatorAttachment only when the caller asked for it', async () => {
    await webauthnRegister(stubClient(), 'key', 'cross-platform');
    expect(lastCreate!.publicKey!.authenticatorSelection!.authenticatorAttachment).toBe(
      'cross-platform',
    );
  });

  it('omits authenticatorAttachment when the caller did not', async () => {
    await webauthnRegister(stubClient(), 'key');
    expect(lastCreate!.publicKey!.authenticatorSelection).not.toHaveProperty(
      'authenticatorAttachment',
    );
  });

  it('synthesizes no authenticatorSelection or timeout the server omitted', async () => {
    const client = stubClient({
      webauthnRegisterStart: vi.fn(async () => ({
        challenge: MINIMAL_CREATION_CHALLENGE,
        stateToken: new Sensitive(STATE_TOKEN),
      })),
    });
    await webauthnRegister(client, 'key');

    expect(lastCreate!.publicKey).not.toHaveProperty('authenticatorSelection');
    expect(lastCreate!.publicKey).not.toHaveProperty('timeout');
    expect(lastCreate!.publicKey).not.toHaveProperty('excludeCredentials');
    expect(lastCreate!.publicKey).not.toHaveProperty('attestation');
  });

  it('passes an empty allowCredentials through for a discoverable ceremony', async () => {
    await webauthnDiscoverableLogin(stubClient());
    expect(lastGet!.publicKey!.allowCredentials).toEqual([]);
  });

  it('requests conditional mediation only when asked', async () => {
    await webauthnDiscoverableLogin(stubClient(), undefined, { conditional: true });
    expect(lastGet!.mediation).toBe('conditional');

    await webauthnDiscoverableLogin(stubClient());
    expect(lastGet).not.toHaveProperty('mediation');
  });
});

// ---------------------------------------------------------------------------
// The composed helpers
// ---------------------------------------------------------------------------

describe('composed helpers', () => {
  it('runs start → ceremony → finish and returns the credential', async () => {
    const client = stubClient();
    await webauthnRegister(client, 'Alice’s laptop');

    expect(client.webauthnRegisterStart).toHaveBeenCalledOnce();
    const [, name, response] = (client.webauthnRegisterFinish as ReturnType<typeof vi.fn>).mock
      .calls[0]!;
    expect(name).toBe('Alice’s laptop');
    // The JSON form, base64url-encoded back out of the ArrayBuffers.
    expect(response.response.clientDataJSON).toBe('eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0');
    expect(response.response.attestationObject).toBe('o2NmbXRkbm9uZQ');
    expect(response.response.transports).toEqual(['internal']);
    expect(response.type).toBe('public-key');
  });

  it('assembles an assertion with its userHandle', async () => {
    const client = stubClient();
    await webauthnLogin(client, 'challenge-token');

    const [, response] = (client.webauthnAuthenticateFinish as ReturnType<typeof vi.fn>).mock
      .calls[0]!;
    expect(response.response.signature).toBe('c2lnbmF0dXJl');
    expect(response.response.userHandle).toBe('dXNlci1oYW5kbGU');
  });

  it('lets a ceremony error reach the caller unchanged, for classification', async () => {
    installAuthenticator({
      createThrows: Object.assign(new Error('excluded'), { name: 'InvalidStateError' }),
    });
    const client = stubClient();
    await expect(webauthnRegister(client, 'key')).rejects.toMatchObject({
      name: 'InvalidStateError',
    });
    // And the ceremony failing must not have posted anything back.
    expect(client.webauthnRegisterFinish).not.toHaveBeenCalled();
  });

  it('does not finish a sign-in whose ceremony the user abandoned', async () => {
    installAuthenticator({
      getThrows: Object.assign(new Error('abandoned'), { name: 'NotAllowedError' }),
    });
    const client = stubClient();
    await expect(webauthnDiscoverableLogin(client)).rejects.toThrow();
    expect(client.webauthnDiscoverableFinish).not.toHaveBeenCalled();
  });
});
