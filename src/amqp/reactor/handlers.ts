// Declarative reactor handler binding — CONTRACT.md §22.14.
//
// `reactorServe` takes ONE function from an event to one answer, which is the
// right shape for the wire and the wrong shape for the code. A reactor
// registered for three events opens with a `switch (event.event)`, and that
// switch carries two defects.
//
// The first is cheap: a misspelled event name is a valid string literal, matches
// no case, and is discovered as an event that never fires. The second is not. It
// is the `default:` arm, which is almost always written `return allow()`. That
// answers on behalf of code that never ran — the defect §22.10 rule 2 forbids
// the RUNTIME from committing, relocated into user code where the rule does not
// reach it. An operator who set `fail_closed` on a registration has it defeated
// by a `default` arm in a file they never read.
//
// `reactorHandlers` is the declarative form. It is PURE SUGAR (§22.14 rule 1):
// it produces exactly the `ReactorHandler` `reactorServe` already takes, opens
// nothing, verifies nothing, signs nothing, and does not filter a patch. What it
// adds is the two answers the switch got wrong — an unregistered event name is
// refused when you BIND it, and an event with no handler ABSTAINS.

import { REACTOR_EVENTS, eventSpec, type ReactorEventName } from './registry.js';
import { abstain, type ReactorDecision, type ReactorHandler } from './runtime.js';
import type { ReactorEvent } from './protocol.js';

/**
 * One handler per hook event.
 *
 * The key type is {@link ReactorEventName}, so a misspelled event is a
 * **compile-time** error in TypeScript — and `reactorHandlers` re-checks at
 * runtime for JavaScript callers, who get no such help. Duplicate keys within a
 * single object literal are a compile-time error too (TS1117), which is §22.14
 * rule 3 enforced by the language; passing two groups that both bind the same
 * event is the case the runtime check exists for.
 */
export type ReactorHandlerMap = Partial<Record<ReactorEventName, ReactorHandler>>;

/**
 * The event names `reactorHandlers` accepts, sorted.
 *
 * Built from what IS hookable, deliberately: §22.13 requires the three hot-path
 * operations to be absent from every event constant this SDK exposes, so a list
 * naming them — even only to say they are refused — is the thing that would
 * break it (§22.14 rule 2).
 */
export function hookableEvents(): readonly string[] {
  return Object.values(REACTOR_EVENTS).slice().sort();
}

/**
 * Compose one handler per event into the single handler `reactorServe` takes
 * (CONTRACT.md §22.14).
 *
 * ```ts
 * await reactorServe(options, reactorHandlers({
 *   [REACTOR_EVENTS.TOKEN_PRE_ISSUE]: enrichToken,
 *   [REACTOR_EVENTS.LOGIN_POST_AUTH]: screenLogin,
 * }));
 * ```
 *
 * Several groups may be passed, so handlers can be split across modules and
 * merged here:
 *
 * ```ts
 * reactorHandlers(tokenHandlers, loginHandlers)
 * ```
 *
 * @param groups one or more event → handler maps.
 * @returns the `ReactorHandler` `reactorServe` accepts.
 * @throws TypeError if a key is outside the §22.5 registry — which is also how
 * §22.7's three hot-path operations are refused, since they are in no registry
 * row — if a value is not a function, if two groups bind the same event, or if
 * nothing is bound at all.
 */
export function reactorHandlers(...groups: readonly ReactorHandlerMap[]): ReactorHandler {
  const bound = new Map<string, ReactorHandler>();

  for (const group of groups) {
    for (const [event, handler] of Object.entries(group)) {
      if (eventSpec(event) === undefined) {
        throw new TypeError(
          `${event} is not a hookable reactor event; the registry is [${hookableEvents().join(', ')}]`,
        );
      }
      if (typeof handler !== 'function') {
        throw new TypeError(`the handler bound to ${event} is not a function`);
      }
      if (bound.has(event)) {
        throw new TypeError(`reactor event ${event} is already bound`);
      }
      bound.set(event, handler);
    }
  }

  if (bound.size === 0) {
    throw new TypeError('reactorHandlers received no bindings; bind at least one event');
  }

  return async (event: ReactorEvent): Promise<ReactorDecision> => {
    const handler = bound.get(event.event);
    if (handler === undefined) {
      // §22.14 rule 4. NOT allow(): publishing nothing lets the registration's
      // `failure_policy` resolve this exactly as it resolves a timeout (§22.8),
      // and this function does not know what the registration was for. The
      // operator's policy does.
      return abstain();
    }
    // Awaited without a try/catch on purpose (§22.14 rule 5): a handler's own
    // rejection must reach the runtime unchanged so it publishes nothing.
    // Catching it here would satisfy the letter of §22.10 rule 2 while
    // defeating it.
    return await handler(event);
  };
}

