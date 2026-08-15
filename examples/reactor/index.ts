/**
 * A runnable reactor — CONTRACT.md §22.
 *
 * Three hooks in one process:
 *
 * - `token.pre_issue` — enrich the token with `ext.` claims (mutable).
 * - `login.post_auth` — veto a sign-in from an embargoed region, or demand
 *   step-up MFA (veto-only).
 * - `grant.pre_assign` — four-eyes: refuse a self-granted admin role
 *   (veto-only).
 *
 * ```bash
 * export AXIAM_AMQP_URL='amqps://reactor:secret@broker.example.com:5671/%2f'
 * export AXIAM_TENANT_ID='11111111-1111-1111-1111-111111111111'
 * export AXIAM_REACTOR_ID='99999999-9999-9999-9999-999999999999'
 * export AXIAM_AMQP_SIGNING_KEY_HEX='…64 hex chars…'
 * npx tsx examples/reactor/index.ts
 * ```
 *
 * ## Before this runs, register the reactor (§22.9)
 *
 * ```bash
 * curl -X POST https://axiam.example.com/api/v1/reactors \
 *   -H "Authorization: Bearer $ADMIN_TOKEN" \
 *   -H 'Content-Type: application/json' \
 *   -d '{
 *         "name": "example-reactor",
 *         "events": ["token.pre_issue", "login.post_auth", "grant.pre_assign"],
 *         "mode": "intercept",
 *         "priority": 10,
 *         "timeout_ms": 500
 *       }'
 * ```
 *
 * The response carries the `id` this process needs as `AXIAM_REACTOR_ID`, and
 * the server declares the queue. **This process declares nothing** (§22.1).
 *
 * Note what the registration deliberately omits: `failure_policy`. Two of the
 * three events default to `fail_closed`, and §22.8 says the strictest default
 * wins — so this reactor being unreachable **denies** logins and grants, while
 * token enrichment keeps flowing. That is the right shape, and it is why naming
 * the policy explicitly is usually a mistake.
 *
 * ## What this example does not do
 *
 * It does not hook `authz.check`, `authz.check_batch` or `token.introspect`,
 * because §22.7 makes them un-hookable: a reactor round-trip is milliseconds and
 * the check path's budget is microseconds. External input on an authorization
 * decision belongs in a **deny grant**, which the engine evaluates at hot-path
 * cost.
 */

import { Sensitive } from 'axiam-sdk/amqp';
import {
  REACTOR_EVENTS,
  abstain,
  allow,
  chainedPatch,
  defaultFailurePolicyFor,
  deny,
  eventSpec,
  mutate,
  patchFieldAllowed,
  reactorQueueName,
  reactorServe,
  requireStepUp,
  type ReactorDecision,
  type ReactorEvent,
} from 'axiam-sdk/amqp';
import type { TelemetryEvent } from 'axiam-sdk';

function env(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must be set`);
  return value;
}

async function main(): Promise<void> {
  const tenantId = env('AXIAM_TENANT_ID');
  const reactorId = env('AXIAM_REACTOR_ID');

  // The tenant's HKDF-derived AMQP subkey (§8 v2), fetched from the management
  // API and wrapped in `Sensitive` so it cannot be printed, logged or serialized
  // by accident (§22.12). NEVER hard-code one.
  const signingKey = new Sensitive(Buffer.from(env('AXIAM_AMQP_SIGNING_KEY_HEX'), 'hex'));

  // The strictest default among the events we registered for (§22.8). Shown here
  // because it is worth knowing before you go live, not because the SDK needs
  // it: the server derives it from the registration.
  const policy = defaultFailurePolicyFor([
    REACTOR_EVENTS.TOKEN_PRE_ISSUE,
    REACTOR_EVENTS.LOGIN_POST_AUTH,
    REACTOR_EVENTS.GRANT_PRE_ASSIGN,
  ]);
  console.log(`failure policy when this reactor is unreachable: ${policy}`);
  console.log(`consuming ${reactorQueueName(tenantId, reactorId)} (declared by the server)`);

  // SIGINT drains the in-flight event and returns (§18) — it does not abandon a
  // dispatch the server is still waiting on.
  const controller = new AbortController();
  process.once('SIGINT', () => {
    console.log('shutting down; draining in-flight events');
    controller.abort();
  });

  await reactorServe(
    {
      amqpUrl: env('AXIAM_AMQP_URL'),
      tenantId,
      reactorId,
      signingKey,
      signal: controller.signal,
      logger: {
        warn(event, message, context) {
          console.warn(`[${event}] ${message}`, context ?? {});
        },
      },
      telemetryHook(event: TelemetryEvent) {
        if (event.type === 'requestEnd') {
          // `pathTemplate` is the registry event name — a bounded label set,
          // never a correlation id (§19).
          console.log(`reactor ${event.pathTemplate} finished in ${event.durationMs}ms: ${event.outcome}`);
        }
      },
    },
    decide,
  );
}

/** One function from an event to one of three answers (§22.10). */
function decide(event: ReactorEvent): ReactorDecision {
  // The payload is tenant business data: readable by design, but do not log it
  // at info level (§22.12).
  switch (event.event) {
    case REACTOR_EVENTS.TOKEN_PRE_ISSUE:
      return enrichToken(event);
    case REACTOR_EVENTS.LOGIN_POST_AUTH:
      return screenLogin(event);
    case REACTOR_EVENTS.GRANT_PRE_ASSIGN:
      return fourEyes(event);
    default:
      // An event we did not register for should never arrive. Abstaining
      // publishes nothing and lets the failure policy decide, which is the
      // honest answer to "I do not know what this is".
      return abstain();
  }
}

/**
 * `token.pre_issue` is the one mutable event here, and its allow-list is the
 * `ext.` namespace and nothing else — `sub`, `aud`, `exp` and every other
 * standard claim are unreachable, because none of them begins with `ext.`.
 */
function enrichToken(event: ReactorEvent): ReactorDecision {
  const sub = event.payload.sub;
  if (typeof sub !== 'string') return allow();

  const patch: Record<string, string> = {
    'ext.cost_center': `cc-${sub.length}`,
    'ext.department': 'engineering',
  };

  // A chained event carries what an earlier reactor already decided, so you can
  // decide against the state that will actually commit. It is read-only context
  // — do NOT copy it into your own patch; the server merges (§22.6).
  const prior = chainedPatch(event);
  if (prior && typeof prior === 'object' && 'ext.department' in prior) {
    // A higher-priority reactor will overwrite ours anyway, so do not contest
    // the key.
    delete patch['ext.department'];
  }

  // Optional self-check. The runtime will NOT prune a forbidden key for you
  // (§22.4 rule 1): one bad key rejects the whole patch server-side, and
  // silently dropping it would leave you believing a field was set.
  const spec = eventSpec(REACTOR_EVENTS.TOKEN_PRE_ISSUE);
  if (spec) {
    for (const key of Object.keys(patch)) {
      if (!patchFieldAllowed(spec, key)) {
        console.warn(`patch key ${key} is outside the allow-list and will reject the whole patch`);
      }
    }
  }

  return mutate(patch);
}

/**
 * `login.post_auth` fires on password sign-in, on SAML ACS and on the OIDC
 * callback — after the credentials verify and before any session or token is
 * issued (§22.5).
 */
function screenLogin(event: ReactorEvent): ReactorDecision {
  const ip = typeof event.payload.ip === 'string' ? event.payload.ip : '';

  if (ip.startsWith('198.51.100.')) {
    // A deny with no reason still denies; the reason is for the audit trail.
    return deny('embargoed region');
  }

  if (ip.startsWith('203.0.113.')) {
    // `require_mfa` rides on `allow` and is valid on this event only.
    //
    // Caveat worth knowing: the federated paths (SAML ACS, OIDC callback) have
    // no step-up branch, so a `require_mfa` answer there FAILS the sign-in
    // rather than being dropped. A reactor that needs step-up on a federated
    // login answers `deny` and drives enrolment out of band.
    return requireStepUp();
  }

  return allow();
}

/**
 * `grant.pre_assign` is veto-only: it can refuse a role assignment, and it
 * cannot rewrite one.
 */
function fourEyes(event: ReactorEvent): ReactorDecision {
  const actor = event.payload.actor_id;
  const subject = event.payload.subject_id;
  const role = event.payload.role;

  if (role === 'admin' && typeof actor === 'string' && actor === subject) {
    return deny('admin cannot be self-granted; needs a second approver');
  }
  return allow();
}

void main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
