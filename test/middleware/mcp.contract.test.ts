// CONTRACT.md §28.9 required tests 1 and 2 — the two that need no framework:
// the document's shape and its validation negatives, and the challenge's
// quoting and its refusals.
//
// §28.9 asks for the same five assertions, on the same fixtures, in every
// SDK repository, so that a divergence shows up as a different expected value
// rather than as a different test. This file and its two framework siblings
// (`mcp.express.test.ts`, `mcp.fastify.test.ts`) are that suite for
// TypeScript, and they are written to be read by the ten ports:
//
// 1. document shape + validation negatives .......... here
// 2. challenge quoting + refusals ................... here
// 3. 401 with the challenge ......................... mcp.{express,fastify}.test.ts
// 4. 403 insufficient_scope ......................... mcp.{express,fastify}.test.ts
// 5. a token whose `aud` is not the resource ........ mcp.{express,fastify}.test.ts
// + the regression that matters more than all five .. mcp.{express,fastify}.test.ts

import { describe, expect, it } from 'vitest';
import {
  bearerChallenge,
  protectedResourceMetadata,
  serveProtectedResourceMetadata,
  type McpMetadataApp,
  type ProtectedResourceMetadataOptions,
} from '../../src/middleware/mcpCore.js';
import { ValidationError } from '../../src/management/errors.js';
import { FIXTURE, METADATA_PATH, METADATA_URL, VECTORS } from './mcpFixture.js';

/** An app double that records every route registration and serves none of them. */
function recordingApp(): { routes: string[]; app: McpMetadataApp } {
  const routes: string[] = [];
  const app = {
    get(path: string) {
      routes.push(path);
    },
  };
  return { routes, app: app as unknown as McpMetadataApp };
}

/**
 * Assert that building the document from `options` is refused, and that no
 * route was registered as a side effect. §28.9 test 1 asks for both halves:
 * validation is at construction time, before any route exists.
 */
function refusesDocument(options: ProtectedResourceMetadataOptions): ValidationError {
  const { routes, app } = recordingApp();
  let caught: unknown;
  try {
    serveProtectedResourceMetadata(app, protectedResourceMetadata(options));
  } catch (err) {
    caught = err;
  }
  expect(caught, 'the configuration must be refused').toBeInstanceOf(ValidationError);
  expect(routes, 'a refused document registers no route').toEqual([]);
  return caught as ValidationError;
}

// ---------------------------------------------------------------------------
// §28.9 test 1 — document shape, and the validation negatives
// ---------------------------------------------------------------------------

describe('§28.9 test 1 — the document and its validation', () => {
  it('produces the exact JSON of §28.2 from the fixture', () => {
    const metadata = protectedResourceMetadata(FIXTURE);

    // §28.2: member order in JSON is not semantically significant, so this
    // compares parsed values. The order is still fixed in the emitted bytes so
    // that an implementation has one obvious answer.
    expect(JSON.parse(JSON.stringify(metadata.document))).toEqual({
      resource: 'https://mcp.example.com/mcp',
      authorization_servers: ['https://axiam.example.com'],
      scopes_supported: ['mcp:read', 'mcp:tools'],
      bearer_methods_supported: ['header'],
      resource_documentation: 'https://mcp.example.com/docs',
    });
    expect(Object.keys(metadata.document)).toEqual([
      'resource',
      'authorization_servers',
      'scopes_supported',
      'bearer_methods_supported',
      'resource_documentation',
    ]);
    expect(metadata.metadataPath).toBe(METADATA_PATH);
    expect(metadata.metadataUrl).toBe(METADATA_URL);
  });

  it('derives every metadata_path in §28.3’s table', () => {
    // A trailing slash is carried through rather than trimmed: it is part of
    // the resource identifier the client will compare, and two resources that
    // differ only by it are two resources.
    const cases: ReadonlyArray<readonly [string, string]> = [
      ['https://mcp.example.com', '/.well-known/oauth-protected-resource'],
      ['https://mcp.example.com/', '/.well-known/oauth-protected-resource'],
      ['https://mcp.example.com/mcp', '/.well-known/oauth-protected-resource/mcp'],
      ['https://mcp.example.com/mcp/', '/.well-known/oauth-protected-resource/mcp/'],
      ['https://mcp.example.com/a/b', '/.well-known/oauth-protected-resource/a/b'],
    ];
    for (const [resource, metadataPath] of cases) {
      const metadata = protectedResourceMetadata({ ...FIXTURE, resource });
      expect(metadata.metadataPath, resource).toBe(metadataPath);
      expect(metadata.metadataUrl, resource).toBe(`https://mcp.example.com${metadataPath}`);
      // The document keeps the resource exactly as written — nothing is
      // normalised, and the trailing slash of the fourth row survives.
      expect(metadata.document.resource, resource).toBe(resource);
    }
  });

  it('refuses a resource that is relative, or carries a fragment or a query', () => {
    refusesDocument({ ...FIXTURE, resource: '/mcp' });
    refusesDocument({ ...FIXTURE, resource: 'mcp.example.com/mcp' });
    refusesDocument({ ...FIXTURE, resource: 'https://mcp.example.com/mcp#tools' });
    // §28.3 derives the document's own URL from this value and a query makes
    // that derivation ambiguous — so §28 forbids what RFC 8707 permits.
    refusesDocument({ ...FIXTURE, resource: 'https://mcp.example.com/mcp?tenant_id=acme' });
  });

  it('refuses http on a routable host and accepts it on 127.0.0.1', () => {
    refusesDocument({ ...FIXTURE, resource: 'http://mcp.example.com/mcp' });

    const loopback = protectedResourceMetadata({
      ...FIXTURE,
      resource: 'http://127.0.0.1:8080/mcp',
      authorizationServers: ['http://localhost:9000'],
    });
    expect(loopback.document.resource).toBe('http://127.0.0.1:8080/mcp');
    expect(loopback.metadataUrl).toBe(
      'http://127.0.0.1:8080/.well-known/oauth-protected-resource/mcp',
    );

    // The carve-out is the host, not a substring of it: an authority whose
    // userinfo merely reads `localhost` resolves to a routable host.
    refusesDocument({ ...FIXTURE, resource: 'http://localhost@evil.example.com/mcp' });

    // §28.2 rule 2 names three hosts; `[::1]` is the third, and the brackets
    // are part of the host rather than punctuation around it.
    const v6 = protectedResourceMetadata({
      ...FIXTURE,
      resource: 'http://[::1]:8080/mcp',
      authorizationServers: ['http://[::1]:9000'],
    });
    expect(v6.metadataUrl).toBe('http://[::1]:8080/.well-known/oauth-protected-resource/mcp');
    refusesDocument({ ...FIXTURE, resource: 'http://[2001:db8::1]:8080/mcp' });

    // An empty or non-string value is a refusal, not an empty document.
    refusesDocument({ ...FIXTURE, resource: '' });
    refusesDocument({ ...FIXTURE, authorizationServers: [42 as unknown as string] });
    refusesDocument({ ...FIXTURE, authorizationServers: 'https://axiam.example.com' as unknown as string[] });
  });

  it('refuses an empty authorization_servers, and an entry with a query, a fragment or a duplicate', () => {
    // A document that names no authorization server answers none of the
    // question the client asked.
    refusesDocument({ ...FIXTURE, authorizationServers: [] });
    // §28.2 rule 4: the tenant travels as `?tenant_id=` on the individual
    // endpoint URLs and never on the issuer. An entry with one is not an
    // issuer, and no token's `iss` would ever equal it.
    refusesDocument({ ...FIXTURE, authorizationServers: ['https://axiam.example.com?tenant_id=a'] });
    refusesDocument({ ...FIXTURE, authorizationServers: ['https://axiam.example.com#frag'] });
    refusesDocument({
      ...FIXTURE,
      authorizationServers: ['https://axiam.example.com', 'https://axiam.example.com'],
    });
  });

  it('refuses a duplicate scope and a scope token outside NQCHAR, and preserves the caller’s order', () => {
    refusesDocument({ ...FIXTURE, scopesSupported: ['mcp:read', 'mcp:read'] });
    refusesDocument({ ...FIXTURE, scopesSupported: ['mcp read'] });
    refusesDocument({ ...FIXTURE, scopesSupported: ['mcp:"read"'] });
    refusesDocument({ ...FIXTURE, scopesSupported: [''] });

    // The order is the caller's, never sorted: `scopes_supported` is what the
    // operator chose to publish, in the form they chose to publish it.
    const reordered = protectedResourceMetadata({
      ...FIXTURE,
      scopesSupported: ['mcp:tools', 'mcp:read'],
    });
    expect(reordered.document.scopes_supported).toEqual(['mcp:tools', 'mcp:read']);
  });

  it('refuses any bearer_methods_supported that is not exactly ["header"]', () => {
    // §10's guard reads a bearer credential from the `Authorization` header
    // alone, so `body` or `query` would describe behaviour no conformant SDK
    // has.
    refusesDocument({ ...FIXTURE, bearerMethodsSupported: ['query'] });
    refusesDocument({ ...FIXTURE, bearerMethodsSupported: ['header', 'body'] });
    refusesDocument({ ...FIXTURE, bearerMethodsSupported: [] });
    refusesDocument({ ...FIXTURE, bearerMethodsSupported: ['header', 'header'] });

    // Absent means the default, and the default is the only accepted value.
    const defaulted = protectedResourceMetadata({
      ...FIXTURE,
      bearerMethodsSupported: undefined,
    });
    expect(defaulted.document.bearer_methods_supported).toEqual(['header']);
  });

  it('omits scopes_supported when empty, and resource_documentation when absent — never null', () => {
    const bare = protectedResourceMetadata({
      resource: FIXTURE.resource,
      authorizationServers: FIXTURE.authorizationServers,
      scopesSupported: [],
    });

    const json = JSON.parse(JSON.stringify(bare.document)) as Record<string, unknown>;
    expect(json).toEqual({
      resource: 'https://mcp.example.com/mcp',
      authorization_servers: ['https://axiam.example.com'],
      bearer_methods_supported: ['header'],
    });
    // An empty `scopes_supported` would assert that this resource server
    // understands no scopes — a different and almost always false claim. And
    // an explicit `null` is not an omission.
    expect('scopes_supported' in json).toBe(false);
    expect('resource_documentation' in json).toBe(false);
    expect(JSON.stringify(bare.document)).not.toContain('null');
  });

  it('accepts a resource_documentation with a query and a fragment — it is a page, not an identifier', () => {
    const metadata = protectedResourceMetadata({
      ...FIXTURE,
      resourceDocumentation: 'https://mcp.example.com/docs?v=2#tools',
    });
    expect(metadata.document.resource_documentation).toBe(
      'https://mcp.example.com/docs?v=2#tools',
    );
    refusesDocument({ ...FIXTURE, resourceDocumentation: 'http://docs.example.com/mcp' });
  });

  it('registers exactly one route, at the derived path', () => {
    const { routes, app } = recordingApp();
    const metadata = protectedResourceMetadata(FIXTURE);

    const returned = serveProtectedResourceMetadata(app, metadata);

    // §28.3: the root form is NOT also registered for a resource that has a
    // path — a deployment fronting two resources would then have two helpers
    // competing for the same root path, and registration order would pick the
    // loser.
    expect(routes).toEqual([METADATA_PATH]);
    // §28.1: the same value comes back, so the guard's `resourceMetadataUrl`
    // is fed from the helper that derived it rather than retyped.
    expect(returned).toBe(metadata);
  });

  it('refuses a guard whose resourceMetadataUrl or expectedAudience does not match the document', () => {
    const metadata = protectedResourceMetadata(FIXTURE);

    // §28.5 rule 3, first equality: a challenge pointing at a document that is
    // not this resource server's.
    expect(() =>
      serveProtectedResourceMetadata(recordingApp().app, metadata, {
        expectedAudience: 'https://mcp.example.com/mcp',
        resourceMetadataUrl: `${METADATA_URL}/`,
      }),
    ).toThrow(ValidationError);

    // Second equality: the document announces one identifier and the guard
    // checks `aud` against another, so every token the flow produces is
    // refused.
    expect(() =>
      serveProtectedResourceMetadata(recordingApp().app, metadata, {
        expectedAudience: 'https://mcp.example.com/mcp/',
        resourceMetadataUrl: METADATA_URL,
      }),
    ).toThrow(ValidationError);

    // The two strings compared are DIFFERENT strings. An implementation that
    // compared the resource against the metadata URL would reject this, the
    // only correct configuration.
    const { routes, app } = recordingApp();
    serveProtectedResourceMetadata(app, metadata, {
      expectedAudience: 'https://mcp.example.com/mcp',
      resourceMetadataUrl: METADATA_URL,
    });
    expect(routes).toEqual([METADATA_PATH]);
  });
});

// ---------------------------------------------------------------------------
// §28.9 test 2 — challenge quoting
// ---------------------------------------------------------------------------

describe('§28.9 test 2 — the challenge and its quoting', () => {
  it('produces §28.4’s four vectors as exact strings', () => {
    expect(bearerChallenge({ resourceMetadataUrl: METADATA_URL })).toBe(VECTORS.noCredential);

    expect(bearerChallenge({ resourceMetadataUrl: METADATA_URL, error: 'invalid_token' })).toBe(
      VECTORS.invalidToken,
    );

    expect(
      bearerChallenge({
        resourceMetadataUrl: METADATA_URL,
        error: 'insufficient_scope',
        scope: 'mcp:tools',
      }),
    ).toBe(VECTORS.insufficientScope);

    // The parameter order is fixed — error, error_description, scope,
    // resource_metadata — and the separator is exactly one comma and one
    // space, so that these are exact strings rather than a set a test has to
    // re-parse.
    expect(
      bearerChallenge({
        resourceMetadataUrl: METADATA_URL,
        error: 'invalid_request',
        errorDescription: 'The access token is malformed',
        scope: 'mcp:read mcp:tools',
      }),
    ).toBe(VECTORS.allFour);
  });

  it('refuses an error code RFC 6750 §3.1 does not define', () => {
    // Not even a well-formed-looking OAuth error code: `invalid_grant` is a
    // token-endpoint error and has no meaning in a challenge.
    expect(() =>
      bearerChallenge({
        resourceMetadataUrl: METADATA_URL,
        error: 'invalid_grant' as never,
      }),
    ).toThrow(ValidationError);
  });

  it('refuses rather than escapes an error_description outside NQSCHAR', () => {
    // RFC 6750 §3 restricts each parameter to a character set that cannot
    // contain `"` or `\`, so a value needing an escape is a value that does not
    // belong in a challenge.
    for (const errorDescription of [
      'he said "no"',
      'a back\\slash',
      'two\nlines',
      'a control',
      'non-ASCII: café',
      '',
    ]) {
      let caught: unknown;
      try {
        bearerChallenge({
          resourceMetadataUrl: METADATA_URL,
          error: 'invalid_request',
          errorDescription,
        });
      } catch (err) {
        caught = err;
      }
      expect(caught, JSON.stringify(errorDescription)).toBeInstanceOf(ValidationError);
      // No escaping occurred: the refusal is an exception, never a challenge
      // carrying `\"`.
      expect(String((caught as Error).message)).not.toContain('\\"');
    }
  });

  it('refuses a scope with a leading, trailing or doubled space, or an empty one', () => {
    for (const scope of [' mcp:read', 'mcp:read ', 'mcp:read  mcp:tools', '', ' ', 'mcp:"read"']) {
      expect(() =>
        bearerChallenge({
          resourceMetadataUrl: METADATA_URL,
          error: 'insufficient_scope',
          scope,
        }),
        JSON.stringify(scope),
      ).toThrow(ValidationError);
    }
  });

  it('refuses a resource_metadata that is not an encoded absolute URL', () => {
    // A correctly encoded URL cannot contain a space, a quote or a backslash,
    // so one that does has not been encoded.
    for (const resourceMetadataUrl of [
      'https://mcp.example.com/.well-known/oauth protected resource',
      'https://mcp.example.com/"quoted"',
      'https://mcp.example.com/back\\slash',
      '/.well-known/oauth-protected-resource/mcp',
      'http://mcp.example.com/.well-known/oauth-protected-resource/mcp',
    ]) {
      expect(() => bearerChallenge({ resourceMetadataUrl }), resourceMetadataUrl).toThrow(
        ValidationError,
      );
    }

    // It MAY carry a query and a fragment, unlike the resource identifier.
    expect(bearerChallenge({ resourceMetadataUrl: `${METADATA_URL}?v=2#x` })).toBe(
      `Bearer resource_metadata="${METADATA_URL}?v=2#x"`,
    );
  });
});
