// `idp_hint` — CONTRACT.md §12.1 (contract 1.65) on oidcBegin, §26.2 rule 8 on oidcPar.

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { ValidationError } from '../../src/management/errors.js';
import {
  CLIENT_ID,
  createClient,
  createServer,
  discoveryDocument,
  PAR_ENDPOINT,
  REDIRECT_URI,
} from './oidcTestKit.js';

const server = createServer();
beforeAll(() => server.listen({ onUnhandledFrame: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const EIGHT = [
  'client_id',
  'code_challenge',
  'code_challenge_method',
  'nonce',
  'redirect_uri',
  'response_type',
  'scope',
  'state',
];

const params = (url: string): [string, string][] => [...new URL(url).searchParams.entries()];

describe('oidcBegin idp_hint (§12.1)', () => {
  it('idp_hint_emitted_once', () => {
    const { oidc } = createClient();
    const configuration = discoveryDocument();
    for (const hint of ['corp-okta', '3f2b8c1e-0a4d-4f6e-9b1a-7c5d2e8f9a10', 'Google', 'a b&c=d/é+%']) {
      const request = oidc.oidcBegin({ configuration, redirectUri: REDIRECT_URI, idpHint: hint });
      const list = params(request.url);
      const hints = list.filter(([k]) => k === 'axiam_idp_hint');
      expect(hints).toEqual([['axiam_idp_hint', hint]]);
      expect(list.map(([k]) => k).sort()).toEqual([...EIGHT, 'axiam_idp_hint'].sort());
      expect(list.find(([k]) => k === 'client_id')![1]).toBe(CLIENT_ID);
      expect(list.find(([k]) => k === 'state')![1]).toBe(request.state);
    }
  });

  it('idp_hint_omitted_when_unset', () => {
    const { oidc } = createClient();
    const request = oidc.oidcBegin({ configuration: discoveryDocument(), redirectUri: REDIRECT_URI });
    expect(params(request.url).map(([k]) => k).sort()).toEqual(EIGHT);
    expect(request.url).not.toContain('idp_hint');
  });

  it('idp_hint_not_duplicated', () => {
    const { oidc } = createClient();
    const configuration = discoveryDocument();
    const set = oidc.oidcBegin({
      configuration,
      redirectUri: REDIRECT_URI,
      idpHint: 'corp-okta',
      extraParams: { axiam_idp_hint: 'other', prompt: 'login' },
    });
    expect(params(set.url).filter(([k]) => k === 'axiam_idp_hint')).toEqual([['axiam_idp_hint', 'corp-okta']]);
    expect(params(set.url).filter(([k]) => k === 'prompt')).toEqual([['prompt', 'login']]);

    // Unset: the caller's own extra passes through, still once.
    const passthrough = oidc.oidcBegin({
      configuration,
      redirectUri: REDIRECT_URI,
      extraParams: { axiam_idp_hint: 'other' },
    });
    expect(params(passthrough.url).filter(([k]) => k === 'axiam_idp_hint')).toEqual([['axiam_idp_hint', 'other']]);
  });

  it('idp_hint_bounds', () => {
    const { oidc } = createClient();
    const configuration = discoveryDocument();
    const begin = (idpHint: string) => oidc.oidcBegin({ configuration, redirectUri: REDIRECT_URI, idpHint });

    expect(() => begin('')).toThrow(ValidationError);
    expect(() => begin('a'.repeat(257))).toThrow(ValidationError);
    // Bytes, not characters: 129 two-byte characters is 258 bytes.
    expect(() => begin('é'.repeat(129))).toThrow(ValidationError);

    const max = 'a'.repeat(256);
    expect(params(begin(max).url).find(([k]) => k === 'axiam_idp_hint')![1]).toBe(max);
    // Not trimmed, not folded: whitespace-only is non-empty and goes through.
    expect(params(begin(' ').url).find(([k]) => k === 'axiam_idp_hint')![1]).toBe(' ');
  });
});

describe('oidcPar idp_hint (§26.2 rule 8)', () => {
  async function push(idpHint?: string) {
    let form = new URLSearchParams();
    server.use(
      http.post(PAR_ENDPOINT, async ({ request }) => {
        form = new URLSearchParams(await request.text());
        return HttpResponse.json({ request_uri: 'urn:ietf:params:oauth:request_uri:abc', expires_in: 90 }, { status: 201 });
      }),
    );
    const { oidc } = createClient({ clientSecret: 's' });
    const configuration = discoveryDocument();
    // The hint is also given to oidcBegin, to prove it cannot leak into the redirect.
    const request = oidc.oidcBegin({
      configuration,
      redirectUri: REDIRECT_URI,
      ...(idpHint !== undefined ? { idpHint } : {}),
    });
    const pushed = await oidc.oidcPar({
      request,
      redirectUri: REDIRECT_URI,
      configuration,
      ...(idpHint !== undefined ? { idpHint } : {}),
    });
    return { form, pushed };
  }

  it('par_idp_hint_in_pushed_body', async () => {
    const withHint = await push('corp-okta');
    expect([...withHint.form.entries()].filter(([k]) => k === 'axiam_idp_hint')).toEqual([
      ['axiam_idp_hint', 'corp-okta'],
    ]);
    expect(withHint.form.has('kc_idp_hint')).toBe(false);
    expect(params(withHint.pushed.authorizationUrl).map(([k]) => k).sort()).toEqual(['client_id', 'request_uri']);

    const without = await push();
    expect(without.form.has('axiam_idp_hint')).toBe(false);
    expect(params(without.pushed.authorizationUrl).map(([k]) => k).sort()).toEqual(['client_id', 'request_uri']);
  });

  it('refuses an empty or over-long hint before any request', async () => {
    const { oidc } = createClient();
    const configuration = discoveryDocument();
    const request = oidc.oidcBegin({ configuration, redirectUri: REDIRECT_URI });
    for (const idpHint of ['', 'a'.repeat(257)]) {
      await expect(oidc.oidcPar({ request, redirectUri: REDIRECT_URI, configuration, idpHint })).rejects.toBeInstanceOf(
        ValidationError,
      );
    }
  });
});
