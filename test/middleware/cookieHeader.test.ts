// Pure cookie/credential/CSRF helpers (middleware/cookieHeader.ts, §3/§10).
// These back both the Express and Fastify adapters; testing them directly
// pins the RFC6265-lenient parsing, the cookie-then-Bearer extraction order,
// and the constant-time double-submit CSRF check.

import { describe, expect, it } from 'vitest';
import {
  ACCESS_COOKIE_NAME,
  CSRF_COOKIE_NAME,
  extractCredential,
  extractToken,
  isCsrfValid,
  isSafeMethod,
  parseCookieHeader,
} from '../../src/middleware/cookieHeader.js';

describe('parseCookieHeader', () => {
  it('returns an empty map for an undefined header', () => {
    expect(parseCookieHeader(undefined)).toEqual({});
  });

  it('parses multiple pairs, trimming whitespace', () => {
    expect(parseCookieHeader('a=1; b=2 ;  c=3')).toEqual({ a: '1', b: '2', c: '3' });
  });

  it('splits only on the first "=" so values may contain "="', () => {
    expect(parseCookieHeader('jwt=aaa.bbb==')).toEqual({ jwt: 'aaa.bbb==' });
  });

  it('skips empty segments and valueless/nameless pairs', () => {
    expect(parseCookieHeader(';; =orphan; noeq ; d=4')).toEqual({ d: '4' });
  });
});

describe('extractCredential / extractToken', () => {
  it('prefers the axiam_access cookie and reports source "cookie"', () => {
    const cred = extractCredential(`${ACCESS_COOKIE_NAME}=cookie-tok`, 'Bearer header-tok');
    expect(cred).toEqual({ token: 'cookie-tok', source: 'cookie' });
  });

  it('falls back to a case-insensitive Bearer header, source "header"', () => {
    expect(extractCredential(undefined, 'bearer header-tok')).toEqual({
      token: 'header-tok',
      source: 'header',
    });
  });

  it('returns undefined with neither cookie nor auth header', () => {
    expect(extractCredential(undefined, undefined)).toBeUndefined();
  });

  it('returns undefined for a header with no scheme separator', () => {
    expect(extractCredential(undefined, 'Bearertoken')).toBeUndefined();
  });

  it('returns undefined for a non-Bearer scheme or an empty credential', () => {
    expect(extractCredential(undefined, 'Basic abc')).toBeUndefined();
    expect(extractCredential(undefined, 'Bearer   ')).toBeUndefined();
  });

  it('extractToken discards the source', () => {
    expect(extractToken(`${ACCESS_COOKIE_NAME}=t`, undefined)).toBe('t');
    expect(extractToken(undefined, undefined)).toBeUndefined();
  });
});

describe('isSafeMethod', () => {
  it('treats GET/HEAD/OPTIONS (any case) and undefined as safe', () => {
    for (const m of ['GET', 'head', 'Options', undefined]) {
      expect(isSafeMethod(m)).toBe(true);
    }
  });

  it('treats state-changing methods as unsafe', () => {
    for (const m of ['POST', 'put', 'PATCH', 'delete']) {
      expect(isSafeMethod(m)).toBe(false);
    }
  });
});

describe('isCsrfValid (double-submit, constant time)', () => {
  it('accepts a header equal to the axiam_csrf cookie', () => {
    expect(isCsrfValid(`${CSRF_COOKIE_NAME}=tok123`, 'tok123')).toBe(true);
  });

  it('rejects a missing header', () => {
    expect(isCsrfValid(`${CSRF_COOKIE_NAME}=tok123`, undefined)).toBe(false);
  });

  it('rejects when the cookie is absent', () => {
    expect(isCsrfValid('other=x', 'tok123')).toBe(false);
  });

  it('rejects a length mismatch without throwing', () => {
    expect(isCsrfValid(`${CSRF_COOKIE_NAME}=short`, 'a-much-longer-value')).toBe(false);
  });

  it('rejects an equal-length but different value', () => {
    expect(isCsrfValid(`${CSRF_COOKIE_NAME}=aaaaa`, 'bbbbb')).toBe(false);
  });
});
