// Telemetry hooks — CONTRACT.md §19.
//
// Wiring metrics to an AXIAM client **without this package depending on any
// metrics library**. The sink below aggregates in-process so the example runs
// with no extra dependencies; the block at the bottom shows the exact mapping
// onto OpenTelemetry, which is a drop-in replacement for the body.
//
// Run: npx tsx examples/telemetry-hook.ts

import { AxiamClient, type TelemetryEvent } from '../src/rest/index.js';

/** Accumulated call count and total latency for one (operation, outcome). */
interface Stat {
  count: number;
  totalMs: number;
}

const requests = new Map<string, Stat>();
const retries = new Map<string, number>();

function record(event: TelemetryEvent): void {
  switch (event.type) {
    // One pair per ATTEMPT, not per logical call (§19.2 rule 5), so counting
    // these gives the real number of wire calls — including the ones a retry
    // made on your behalf.
    case 'requestEnd': {
      const key = `${event.operation}/${event.outcome}`;
      const stat = requests.get(key) ?? { count: 0, totalMs: 0 };
      stat.count += 1;
      stat.totalMs += event.durationMs;
      requests.set(key, stat);
      break;
    }

    // §16.5 — the reason this event exists. A retried-then-succeeded operation
    // is otherwise invisible: the caller sees a slow success and no signal that
    // the server is failing. Alert on this rate, not on the error rate, or a
    // degrading server looks healthy right up until the retries stop being
    // enough.
    case 'retry':
      retries.set(event.operation, (retries.get(event.operation) ?? 0) + 1);
      break;

    // `requestStart` and `refresh` are available too; a metrics sink usually
    // only needs the ends.
    default:
      break;
  }
}

function report(): void {
  console.log('--- requests (per attempt) ---');
  for (const [key, { count, totalMs }] of requests) {
    console.log(`  ${key.padEnd(24)} count=${count} mean=${Math.round(totalMs / count)}ms`);
  }
  console.log('--- retries ---');
  if (retries.size === 0) console.log('  (none)');
  for (const [op, count] of retries) console.log(`  ${op.padEnd(24)} ${count}`);
}

async function main(): Promise<void> {
  const client = new AxiamClient({
    baseUrl: 'https://axiam.example.com',
    tenantSlug: 'acme',
    orgSlug: 'acme',
    telemetryHook: record,
  });

  // This will fail — the host does not resolve — which is the point: a failing
  // call still emits a `requestEnd` carrying the failure, and the §16 retries
  // are visible as `retry` events. Against a real server the same sink reports
  // the success path.
  try {
    const decision = await client.checkAccess({
      action: 'read',
      resourceId: '00000000-0000-0000-0000-000000000000',
    });
    console.log(`allowed=${decision.allowed} (${decision.reasonCode ?? 'no reason code'})`);
  } catch (err) {
    console.log(`check failed as expected in this example: ${(err as Error).message}`);
  }

  report();

  // §18: release the client's local resources. Does not log out.
  client.close();
}

void main();

// ---------------------------------------------------------------------------
// The same sink, against OpenTelemetry
// ---------------------------------------------------------------------------
//
// This package deliberately ships no `@opentelemetry/*` dependency — §19's
// whole point is that you choose your metrics stack. With the OTel API in YOUR
// package.json, `record` becomes:
//
// ```ts
// import { metrics } from '@opentelemetry/api';
//
// const meter = metrics.getMeter('axiam-sdk');
// const duration = meter.createHistogram('axiam.client.request.duration');
// const retryCounter = meter.createCounter('axiam.client.retries');
//
// function record(event: TelemetryEvent): void {
//   if (event.type === 'requestEnd') {
//     duration.record(event.durationMs / 1000, {
//       'axiam.operation': event.operation,
//       // The path TEMPLATE, never a substituted URL: a metric label carrying
//       // a UUID is a cardinality bomb.
//       'http.route': event.pathTemplate,
//       'http.response.status_code': event.status ?? 0,
//       'axiam.outcome': event.outcome,
//     });
//   } else if (event.type === 'retry') {
//     retryCounter.add(1, {
//       'axiam.operation': event.operation,
//       'axiam.attempt': event.attempt,
//     });
//   }
// }
// ```
//
// Two rules to keep in mind when writing any adapter:
//
//   * **Do not block.** Hooks run on the calling path (§19.2 rule 4). Every
//     mature metrics library already buffers; if yours does not, buffer on your
//     side rather than doing I/O here.
//   * **Do not enrich events from elsewhere.** `TelemetryEvent` is a closed
//     union precisely so this surface cannot leak a token into a metrics
//     backend (§19.2 rule 3). Adding, say, the current `Authorization` header
//     would defeat that on your side of the boundary.
//
// A hook that throws is caught and swallowed by the SDK (§19.2 rule 2) — an
// authorization check is never failed by telemetry — but that is a backstop,
// not a licence to let a sink throw.
