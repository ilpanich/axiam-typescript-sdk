// The two endpoint-qualified §2 rows added by contract 1.4, plus the
// OAuthProtocolError sub-type itself (CONTRACT.md §2, §12.3 rule 3).

import { describe, expect, it } from 'vitest';
import {
  AuthError,
  AxiamError,
  isOAuth2EndpointUrl,
  isOAuth2ErrorBody,
  mapHttpStatusToError,
  NetworkError,
  OAuthProtocolError,
} from '../../src/core/index.js';

const OAUTH_BODY = { error: 'invalid_grant', error_description: 'code already redeemed' };

describe('OAuthProtocolError (§2 sub-type table)', () => {
  it('is an AuthError sub-type, so existing catch blocks keep working', () => {
    const error = new OAuthProtocolError('invalid_client', 'bad secret');
    expect(error).toBeInstanceOf(OAuthProtocolError);
    expect(error).toBeInstanceOf(AuthError);
    expect(error).toBeInstanceOf(AxiamError);
    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe('OAuthProtocolError');
  });

  it('sets message to exactly "<error>: <error_description>"', () => {
    const error = new OAuthProtocolError('unsupported_grant_type', 'implicit is not supported');
    expect(error.message).toBe('unsupported_grant_type: implicit is not supported');
    expect(error.error).toBe('unsupported_grant_type');
    expect(error.errorDescription).toBe('implicit is not supported');
  });
});

describe('isOAuth2EndpointUrl', () => {
  it.each([
    'https://iam.example.com/oauth2/token',
    'https://iam.example.com/oauth2/introspect?tenant_id=x',
    '/oauth2/revoke',
  ])('recognises %s', (url) => {
    expect(isOAuth2EndpointUrl(url)).toBe(true);
  });

  it.each([
    'https://iam.example.com/api/v1/auth/login',
    '/api/v1/authz/check',
    'https://iam.example.com/.well-known/openid-configuration',
    // A path segment merely containing the word must not qualify.
    'https://iam.example.com/api/oauth2',
    undefined,
  ])('does not recognise %s', (url) => {
    expect(isOAuth2EndpointUrl(url)).toBe(false);
  });
});

describe('isOAuth2ErrorBody', () => {
  it('requires both fields to be present and string-typed', () => {
    expect(isOAuth2ErrorBody(OAUTH_BODY)).toBe(true);
    expect(isOAuth2ErrorBody({ error: 'invalid_grant' })).toBe(false);
    expect(isOAuth2ErrorBody({ error_description: 'why' })).toBe(false);
    expect(isOAuth2ErrorBody({ error: 1, error_description: 'why' })).toBe(false);
    expect(isOAuth2ErrorBody(null)).toBe(false);
    expect(isOAuth2ErrorBody('invalid_grant')).toBe(false);
  });
});

describe('mapHttpStatusToError endpoint-qualified rows (§2)', () => {
  it('400 from /oauth2/* with an OAuth2ErrorResponse body -> OAuthProtocolError', () => {
    const error = mapHttpStatusToError(400, 'ignored message', {
      url: 'https://iam.example.com/oauth2/token?tenant_id=t',
      body: OAUTH_BODY,
    });
    expect(error).toBeInstanceOf(OAuthProtocolError);
    expect(error.message).toBe('invalid_grant: code already redeemed');
  });

  it('401 from /oauth2/* with an OAuth2ErrorResponse body -> OAuthProtocolError', () => {
    const error = mapHttpStatusToError(401, 'ignored message', {
      url: 'https://iam.example.com/oauth2/introspect',
      body: { error: 'invalid_client', error_description: 'client authentication failed' },
    });
    expect(error).toBeInstanceOf(OAuthProtocolError);
    expect(error.message).toBe('invalid_client: client authentication failed');
  });

  it('keeps the generic 400 -> NetworkError row for a non-/oauth2 endpoint', () => {
    const error = mapHttpStatusToError(400, 'malformed request', {
      url: '/api/v1/auth/login',
      body: OAUTH_BODY,
    });
    expect(error).toBeInstanceOf(NetworkError);
    expect(error).not.toBeInstanceOf(OAuthProtocolError);
  });

  it('keeps the generic 400 -> NetworkError row for an /oauth2 endpoint with a non-OAuth2 body', () => {
    const error = mapHttpStatusToError(400, 'malformed request', {
      url: '/oauth2/token',
      body: { message: 'something else' },
    });
    expect(error).toBeInstanceOf(NetworkError);
  });

  it('keeps the generic 401 -> AuthError row when no url is supplied', () => {
    const error = mapHttpStatusToError(401, 'unauthenticated', { body: OAUTH_BODY });
    expect(error).toBeInstanceOf(AuthError);
    expect(error).not.toBeInstanceOf(OAuthProtocolError);
    expect(error.message).toBe('unauthenticated');
  });

  it('does not apply the OAuth2 rows to any other status', () => {
    for (const status of [403, 409, 429, 500]) {
      const error = mapHttpStatusToError(status, 'other', { url: '/oauth2/token', body: OAUTH_BODY });
      expect(error).not.toBeInstanceOf(OAuthProtocolError);
    }
  });
});
