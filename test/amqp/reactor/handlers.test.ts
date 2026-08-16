// CONTRACT.md §22.14 — declarative reactor handler binding.
//
// Six tests for six rules. None needs a broker: `reactorHandlers` is pure
// composition over the handler `reactorServe` already takes, so what is under
// test is the binding table and the one answer it gives for an event nobody
// bound.

import { describe, expect, it } from 'vitest';

import {
  REACTOR_EVENTS,
  allow,
  defaultFailurePolicyFor,
  deny,
  hookableEvents,
  mutate,
  reactorHandlers,
  type ReactorDecision,
  type ReactorEvent,
  type ReactorHandler,
} from '../../../src/amqp/reactor/index.js';

// Built at runtime from halves, as registry.test.ts already does: §22.13 bars
// these three names from the reactor source, and a literal here would be one
// more place for a scan to trip over.
const EXCLUDED_HOT_PATH = [
  ['authz', 'check'],
  ['authz', 'check_batch'],
  ['token', 'introspect'],
].map(([a, b]) => `${a}.${b}`);

/** A minimal verified event — only `event` is read by the binder. */
function evt(name: string): ReactorEvent {
  return {
    keyVersion: 2,
    tenantId: '11111111-1111-1111-1111-111111111111',
    event: name,
    correlationId: 'c-1',
    payload: {},
    timeoutMs: 500,
    nonce: 'n-1',
    issuedAt: '2026-08-16T00:00:00Z',
  } as unknown as ReactorEvent;
}

describe('§22.14 rule 1 — it composes, it does not replace', () => {
  it('dispatches each event to its own handler', async () => {
    const handler = reactorHandlers({
      [REACTOR_EVENTS.TOKEN_PRE_ISSUE]: () => mutate({ 'ext.department': 'engineering' }),
      [REACTOR_EVENTS.LOGIN_POST_AUTH]: async () => deny('embargoed region'),
    });

    expect((await handler(evt(REACTOR_EVENTS.TOKEN_PRE_ISSUE))).kind).toBe('mutate');
    expect((await handler(evt(REACTOR_EVENTS.LOGIN_POST_AUTH))).kind).toBe('deny');
  });

  it('produces a value assignable to reactorServe’s handler parameter', () => {
    // A compile-time assertion: if the composed value stopped being a
    // ReactorHandler, this file would not typecheck.
    const handler: ReactorHandler = reactorHandlers({
      [REACTOR_EVENTS.TOKEN_PRE_ISSUE]: () => allow(),
    });
    expect(typeof handler).toBe('function');
  });

  it('merges several groups, so handlers can be split across modules', async () => {
    const tokenHandlers = { [REACTOR_EVENTS.TOKEN_PRE_ISSUE]: () => allow() };
    const loginHandlers = { [REACTOR_EVENTS.LOGIN_POST_AUTH]: () => deny('nope') };

    const handler = reactorHandlers(tokenHandlers, loginHandlers);

    expect((await handler(evt(REACTOR_EVENTS.TOKEN_PRE_ISSUE))).kind).toBe('allow');
    expect((await handler(evt(REACTOR_EVENTS.LOGIN_POST_AUTH))).kind).toBe('deny');
  });
});

describe('§22.14 rule 2 — an unregistered name is refused at bind time', () => {
  it('rejects a misspelled event name', () => {
    expect(() =>
      // A JavaScript caller gets no type help, which is what the runtime check
      // is for; the cast reproduces that caller from TypeScript.
      reactorHandlers({ 'token.pre_isue': () => allow() } as never),
    ).toThrow(/not a hookable reactor event/);
  });

  it('rejects the three hot-path operations', () => {
    for (const name of EXCLUDED_HOT_PATH) {
      expect(() => reactorHandlers({ [name]: () => allow() } as never)).toThrow(
        /not a hookable reactor event/,
      );
    }
  });

  it('names the registry in the rejection, never the exclusions', () => {
    let message = '';
    try {
      reactorHandlers({ nope: () => allow() } as never);
    } catch (err) {
      message = (err as Error).message;
    }
    expect(message).toContain(REACTOR_EVENTS.TOKEN_PRE_ISSUE);
    for (const excluded of EXCLUDED_HOT_PATH) {
      expect(message).not.toContain(excluded);
    }
  });

  it('rejects a handler that is not a function', () => {
    expect(() =>
      reactorHandlers({ [REACTOR_EVENTS.TOKEN_PRE_ISSUE]: 'nope' } as never),
    ).toThrow(/is not a function/);
  });

  it('rejects an empty binding set', () => {
    expect(() => reactorHandlers({})).toThrow(/no bindings/);
    expect(() => reactorHandlers()).toThrow(/no bindings/);
  });
});

describe('§22.14 rule 3 — one handler per event', () => {
  it('rejects the same event bound by two groups', () => {
    const first = { [REACTOR_EVENTS.TOKEN_PRE_ISSUE]: () => allow() };
    const second = { [REACTOR_EVENTS.TOKEN_PRE_ISSUE]: () => deny('second') };

    expect(() => reactorHandlers(first, second)).toThrow(/already bound/);
  });
});

describe('§22.14 rule 4 — an unbound event abstains', () => {
  it('publishes nothing rather than allowing', async () => {
    const handler = reactorHandlers({ [REACTOR_EVENTS.TOKEN_PRE_ISSUE]: () => allow() });

    const decision = await handler(evt(REACTOR_EVENTS.GRANT_PRE_ASSIGN));

    expect(decision.kind).toBe('abstain');
    // Stated separately and deliberately: "not allow" is the whole claim. A
    // `default: return allow()` arm answers on behalf of code that never ran,
    // which defeats an operator's fail_closed setting (§22.10 rule 2).
    expect(decision.kind).not.toBe('allow');
    expect(decision.kind).not.toBe('deny');
  });
});

describe('§22.14 rule 5 — a handler’s own failure propagates', () => {
  it('does not catch a rejection', async () => {
    const handler = reactorHandlers({
      [REACTOR_EVENTS.LOGIN_POST_AUTH]: async () => {
        throw new Error('fraud service unreachable');
      },
    });

    await expect(handler(evt(REACTOR_EVENTS.LOGIN_POST_AUTH))).rejects.toThrow(
      'fraud service unreachable',
    );
  });

  it('does not catch a synchronous throw', async () => {
    const handler = reactorHandlers({
      [REACTOR_EVENTS.USER_PRE_CREATE]: (): ReactorDecision => {
        throw new Error('directory timed out');
      },
    });

    await expect(handler(evt(REACTOR_EVENTS.USER_PRE_CREATE))).rejects.toThrow(
      'directory timed out',
    );
  });
});

describe('§22.14 rule 6 and the SHOULD — no filtering, bound events visible', () => {
  it('sends a forbidden patch key unfiltered', async () => {
    const handler = reactorHandlers({
      [REACTOR_EVENTS.TOKEN_PRE_ISSUE]: () => mutate({ sub: 'attacker' }),
    });

    const decision = await handler(evt(REACTOR_EVENTS.TOKEN_PRE_ISSUE));

    expect(decision).toEqual({ kind: 'mutate', patch: { sub: 'attacker' } });
  });

  it('exposes the hookable events, which feed the failure policy', () => {
    expect(hookableEvents()).toEqual(
      [...Object.values(REACTOR_EVENTS)].sort((a, b) => a.localeCompare(b)),
    );

    // token.pre_issue defaults open, login.post_auth defaults closed; §22.8's
    // strictest-wins composition makes the pair fail_closed.
    const bound = Object.keys({
      [REACTOR_EVENTS.TOKEN_PRE_ISSUE]: () => allow(),
      [REACTOR_EVENTS.LOGIN_POST_AUTH]: () => allow(),
    });
    expect(defaultFailurePolicyFor(bound)).toBe('fail_closed');
  });
});
