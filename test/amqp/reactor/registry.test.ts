// CONTRACT.md §22.13 "Registry" and §22.7 "Hot path" — the allow-list rules
// and the failure-policy composition, as pure functions over the table.
//
// These need no broker and no fixture: they are the offline mirror of the
// server's `EVENT_REGISTRY`, and every claim §22.5 makes about the
// namespace-prefix rule is a row in a table here.

import { describe, expect, it } from 'vitest';
import {
  DEFAULT_REACTOR_MAX_IN_FLIGHT,
  DEFAULT_REACTOR_TIMEOUT_MS,
  EVENT_REGISTRY,
  MAX_REACTOR_TIMEOUT_MS,
  MIN_REACTOR_TIMEOUT_MS,
  REACTOR_EVENTS,
  defaultFailurePolicyFor,
  eventSpec,
  patchFieldAllowed,
} from '../../../src/amqp/reactor/registry.js';

const tokenPreIssue = eventSpec(REACTOR_EVENTS.TOKEN_PRE_ISSUE)!;
const userPreCreate = eventSpec(REACTOR_EVENTS.USER_PRE_CREATE)!;
const userPreUpdate = eventSpec(REACTOR_EVENTS.USER_PRE_UPDATE)!;
const loginPostAuth = eventSpec(REACTOR_EVENTS.LOGIN_POST_AUTH)!;
const grantPreAssign = eventSpec(REACTOR_EVENTS.GRANT_PRE_ASSIGN)!;

describe('§22.5 — the registry is the five v1 events and nothing else', () => {
  it('carries every row with the mutability and default policy the contract states', () => {
    expect(EVENT_REGISTRY.map((spec) => spec.name)).toEqual([
      'token.pre_issue',
      'login.post_auth',
      'user.pre_create',
      'user.pre_update',
      'grant.pre_assign',
    ]);
    expect(EVENT_REGISTRY.every((spec) => spec.interceptable)).toBe(true);

    expect(tokenPreIssue.mutable).toBe(true);
    expect(tokenPreIssue.defaultFailurePolicy).toBe('fail_open');
    expect(loginPostAuth.mutable).toBe(false);
    expect(loginPostAuth.defaultFailurePolicy).toBe('fail_closed');
    expect(userPreCreate.mutable).toBe(true);
    expect(userPreCreate.defaultFailurePolicy).toBe('fail_closed');
    expect(userPreUpdate.mutableFields).toEqual(userPreCreate.mutableFields);
    expect(grantPreAssign.mutable).toBe(false);
    expect(grantPreAssign.defaultFailurePolicy).toBe('fail_closed');

    // `token.pre_issue` is the only event that defaults open, which is why
    // §22.8's strictest-wins composition has anything to compose.
    expect(EVENT_REGISTRY.filter((s) => s.defaultFailurePolicy === 'fail_open')).toHaveLength(1);
  });

  it('has no entry for a name outside it', () => {
    expect(eventSpec('token.pre_issue.extra')).toBeUndefined();
    expect(eventSpec('')).toBeUndefined();
  });

  it('states §22.8 budget constants at the contract values', () => {
    expect(DEFAULT_REACTOR_TIMEOUT_MS).toBe(500);
    expect(MIN_REACTOR_TIMEOUT_MS).toBe(1);
    expect(MAX_REACTOR_TIMEOUT_MS).toBe(5_000);
    expect(DEFAULT_REACTOR_MAX_IN_FLIGHT).toBe(64);
  });
});

describe('§22.7 — the hot path is not hookable, asserted on the list', () => {
  // The three names are built at runtime from their halves so that a plain
  // source scan for them over src/amqp/reactor/ finds nothing, and this test's
  // own text cannot be what a future grep-based gate is matching on.
  const excluded = [
    ['authz', 'check'],
    ['authz', 'check_batch'],
    ['token', 'introspect'],
  ].map(([a, b]) => `${a}.${b}`);

  it('is absent from EVENT_REGISTRY, REACTOR_EVENTS and eventSpec()', () => {
    for (const name of excluded) {
      expect(EVENT_REGISTRY.map((s) => s.name)).not.toContain(name);
      expect(Object.values(REACTOR_EVENTS)).not.toContain(name);
      expect(eventSpec(name)).toBeUndefined();
    }
  });

  it('composes fail_closed for a registration naming one, rather than guessing open', () => {
    // The server refuses such a registration outright; guessing `fail_open` for
    // a name this SDK does not recognise is the one guess that could weaken a
    // decision.
    for (const name of excluded) {
      expect(defaultFailurePolicyFor([name])).toBe('fail_closed');
    }
  });
});

describe('§22.5 — the namespace-prefix rule', () => {
  it('admits `ext.department` and `ext.a.b.c` on token.pre_issue', () => {
    expect(patchFieldAllowed(tokenPreIssue, 'ext.department')).toBe(true);
    expect(patchFieldAllowed(tokenPreIssue, 'ext.a.b.c')).toBe(true);
    expect(patchFieldAllowed(tokenPreIssue, 'ext.x')).toBe(true);
  });

  it('refuses `ext.`, `ext`, `extra`, `external_id` and `evil.ext.department`', () => {
    for (const field of ['ext.', 'ext', 'extra', 'external_id', 'evil.ext.department']) {
      expect(patchFieldAllowed(tokenPreIssue, field), field).toBe(false);
    }
  });

  it('refuses every standard claim on token.pre_issue', () => {
    // None of them begins with `ext.`, so the one rule above is the whole
    // reason. A hook that can rewrite `sub` is a hook that can mint a token for
    // anyone, and a correctly signed reply setting it is refused exactly as a
    // forged one is.
    for (const claim of [
      'iss',
      'sub',
      'aud',
      'exp',
      'iat',
      'nbf',
      'jti',
      'scope',
      'scp',
      'azp',
      'act',
      'client_id',
    ]) {
      expect(patchFieldAllowed(tokenPreIssue, claim), claim).toBe(false);
    }
  });

  it('admits `email`, `username` and `metadata.source` on user.pre_create', () => {
    // The exact-name half of the allow-list, which the prefix rule does not
    // reach: `username` and `email` match by equality, not by namespace.
    expect(patchFieldAllowed(userPreCreate, 'email')).toBe(true);
    expect(patchFieldAllowed(userPreCreate, 'username')).toBe(true);
    expect(patchFieldAllowed(userPreCreate, 'metadata.source')).toBe(true);
    expect(patchFieldAllowed(userPreUpdate, 'metadata.a.b')).toBe(true);
  });

  it('refuses `password`, `tenant_id`, `roles` and bare `metadata` on user.pre_create', () => {
    for (const field of [
      'password',
      'password_hash',
      'tenant_id',
      'id',
      'roles',
      'is_admin',
      'metadata',
      'metadata.',
      'usernames',
      'emails',
    ]) {
      expect(patchFieldAllowed(userPreCreate, field), field).toBe(false);
    }
  });

  it('accepts no patch field at all on login.post_auth or grant.pre_assign', () => {
    for (const spec of [loginPostAuth, grantPreAssign]) {
      expect(spec.mutableFields).toEqual([]);
      for (const field of ['ext.department', 'username', 'email', 'role', 'anything']) {
        expect(patchFieldAllowed(spec, field), `${spec.name}/${field}`).toBe(false);
      }
    }
  });
});

describe('§22.8 — the strictest default wins, in either array order', () => {
  it('inherits fail_open only when every event defaults open', () => {
    expect(defaultFailurePolicyFor([REACTOR_EVENTS.TOKEN_PRE_ISSUE])).toBe('fail_open');
  });

  it('inherits fail_closed when any event defaults closed', () => {
    for (const name of [
      REACTOR_EVENTS.LOGIN_POST_AUTH,
      REACTOR_EVENTS.USER_PRE_CREATE,
      REACTOR_EVENTS.USER_PRE_UPDATE,
      REACTOR_EVENTS.GRANT_PRE_ASSIGN,
    ]) {
      expect(defaultFailurePolicyFor([name]), name).toBe('fail_closed');
    }
  });

  it('is order-independent — this is the MUST NOT §22.8 spells out', () => {
    // "Take the first event's default" would let the order of a JSON array
    // decide whether an unreachable fraud check passes. A reactor registered
    // for both can veto a login, so it inherits fail_closed either way.
    const open = REACTOR_EVENTS.TOKEN_PRE_ISSUE;
    const closed = REACTOR_EVENTS.LOGIN_POST_AUTH;
    expect(defaultFailurePolicyFor([open, closed])).toBe('fail_closed');
    expect(defaultFailurePolicyFor([closed, open])).toBe('fail_closed');
  });

  it('treats an empty list and an unknown name as fail_closed', () => {
    expect(defaultFailurePolicyFor([])).toBe('fail_closed');
    expect(defaultFailurePolicyFor(['not.an.event'])).toBe('fail_closed');
    expect(defaultFailurePolicyFor([REACTOR_EVENTS.TOKEN_PRE_ISSUE, 'not.an.event'])).toBe(
      'fail_closed',
    );
  });
});
