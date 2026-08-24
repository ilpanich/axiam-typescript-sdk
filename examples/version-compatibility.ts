// Runtime version preflight — is this Node inside the range the SDK supports?
//
// The SDK makes two separate claims. It is *built* against its floor (the
// oldest Node line still receiving security fixes) and *typechecked and
// tested* against the newest release line, so any runtime between the two is
// covered by a green CI leg. `engines.node` in the published package.json is
// the machine-readable half of that; npm only warns about it by default, and
// silently ignores it entirely in a Docker image built with
// `--omit=optional` or an `engine-strict=false` .npmrc.
//
// This turns "the base image is probably new enough" into something a process
// can assert at startup and fail loudly on, rather than discovering it as a
// `SyntaxError` or a missing built-in five imports deep. The range is read out
// of the SDK's own package.json rather than hardcoded, so it stays correct
// across SDK upgrades.
//
// Run: npx tsx examples/version-compatibility.ts

import { createRequire } from 'node:module';

// `engines` lives in package.json, not in the SDK's public API surface, so it
// is read rather than imported. The SDK exposes "./package.json" in its
// exports map precisely so a consumer can do this.
const require = createRequire(import.meta.url);

interface SdkManifest {
  name: string;
  version: string;
  engines?: { node?: string };
  devDependencies?: Record<string, string>;
}

// In this repo the example resolves the SDK from source; in a consuming
// application the specifier is 'axiam-sdk/package.json'.
const manifest = require('../package.json') as SdkManifest;

/** Parse the `>=X` floor out of an `engines.node` range. */
function floorMajor(engines: string | undefined): number {
  const match = /^>=\s*(\d+)/.exec((engines ?? '').trim());
  if (match === null) {
    throw new Error(
      `cannot read a floor out of engines.node = ${JSON.stringify(engines)}`,
    );
  }
  return Number(match[1]);
}

/**
 * The newest Node line the SDK is typechecked against, inferred from its
 * pinned @types/node. That pin is what `tsc` believed the runtime API surface
 * was, so it is the honest upper end of "proven to work".
 */
function newestTypedMajor(manifest: SdkManifest): number | undefined {
  const raw = manifest.devDependencies?.['@types/node'];
  const match = raw === undefined ? null : /(\d+)/.exec(raw);
  return match === null ? undefined : Number(match[1]);
}

const running = Number(process.versions.node.split('.')[0]);
const floor = floorMajor(manifest.engines?.node);
const newest = newestTypedMajor(manifest);

console.log(`running Node:      ${process.versions.node}`);
console.log(`${manifest.name} ${manifest.version} engines: ${manifest.engines?.node}`);
if (newest !== undefined) {
  console.log(`newest proven line: ${newest}`);
}

if (running < floor) {
  // npm would have warned about this; nothing would have stopped it.
  console.error(
    `UNSUPPORTED: Node ${running} is below the ${floor} floor. This SDK is ` +
      'not built against it, and its APIs may simply be absent.',
  );
  process.exit(1);
}

if (newest !== undefined && running > newest) {
  // Not an error, and deliberately not fatal. The published package is
  // transpiled to ES2022 and forward-compatible; this runtime is just newer
  // than the last one a green build has proven.
  console.warn(
    `UNTESTED: Node ${running} is newer than ${newest}, the newest line this ` +
      'SDK is built against. Expected to work, but not yet proven by CI.',
  );
} else {
  console.log(`SUPPORTED: Node ${running} is inside the tested range.`);
}
