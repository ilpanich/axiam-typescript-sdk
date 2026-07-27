// MemoryOidcStateStore: single-use consume + 10-minute TTL
// (CONTRACT.md §12.3 rule 1, §12.5).

import { describe, expect, it, vi } from 'vitest';
import { Sensitive } from '../../src/core/index.js';
import {
  MemoryOidcStateStore,
  OIDC_STATE_TTL_MS,
  type OidcStateEntry,
} from '../../src/node/oidcState.js';

function entry(state: string, overrides: Partial<OidcStateEntry> = {}): OidcStateEntry {
  return {
    state,
    nonce: `${state}-nonce`,
    codeVerifier: new Sensitive(`${state}-verifier`),
    redirectUri: 'https://app.example.com/auth/callback',
    ...overrides,
  };
}

describe('MemoryOidcStateStore (§12.3 rule 1)', () => {
  it('round-trips the whole tuple', async () => {
    const store = new MemoryOidcStateStore();
    await store.save(entry('s1', { returnTo: '/dashboard' }));

    const consumed = await store.consume('s1');

    expect(consumed?.state).toBe('s1');
    expect(consumed?.nonce).toBe('s1-nonce');
    expect(consumed?.codeVerifier.expose()).toBe('s1-verifier');
    expect(consumed?.redirectUri).toBe('https://app.example.com/auth/callback');
    expect(consumed?.returnTo).toBe('/dashboard');
  });

  it('is single-use: a second consume of the same state returns undefined', async () => {
    const store = new MemoryOidcStateStore();
    await store.save(entry('s1'));

    expect(await store.consume('s1')).toBeDefined();
    expect(await store.consume('s1')).toBeUndefined();
    expect(await store.consume('s1')).toBeUndefined();
  });

  it('returns undefined for a state it never held', async () => {
    const store = new MemoryOidcStateStore();
    expect(await store.consume('never-saved')).toBeUndefined();
  });

  it('keeps distinct states independent', async () => {
    const store = new MemoryOidcStateStore();
    await store.save(entry('a'));
    await store.save(entry('b'));

    expect((await store.consume('b'))?.nonce).toBe('b-nonce');
    expect((await store.consume('a'))?.nonce).toBe('a-nonce');
    expect(store.size).toBe(0);
  });

  it('expires an entry after the TTL and reports it as unknown', async () => {
    const store = new MemoryOidcStateStore();
    const realNow = Date.now();
    const clock = vi.spyOn(Date, 'now').mockReturnValue(realNow);

    // Both entries are saved at the same instant so their windows coincide.
    await store.save(entry('s1'));
    await store.save(entry('s2'));

    // One millisecond inside the 10-minute window: still there.
    clock.mockReturnValue(realNow + OIDC_STATE_TTL_MS - 1);
    expect(await store.consume('s1')).toBeDefined();

    // Past the window: gone, and indistinguishable from "never existed".
    clock.mockReturnValue(realNow + OIDC_STATE_TTL_MS + 1);
    expect(await store.consume('s2')).toBeUndefined();

    clock.mockRestore();
  });

  it('defaults to the contract-mandated 10-minute TTL', () => {
    expect(OIDC_STATE_TTL_MS).toBe(600_000);
  });

  it('honours a shorter TTL but clamps a longer one to 10 minutes', async () => {
    const realNow = Date.now();
    const clock = vi.spyOn(Date, 'now').mockReturnValue(realNow);

    const shortStore = new MemoryOidcStateStore(1_000);
    await shortStore.save(entry('short'));
    clock.mockReturnValue(realNow + 1_001);
    expect(await shortStore.consume('short')).toBeUndefined();

    // A caller asking for an hour still only gets ten minutes.
    const longStore = new MemoryOidcStateStore(3_600_000);
    clock.mockReturnValue(realNow);
    await longStore.save(entry('long'));
    clock.mockReturnValue(realNow + OIDC_STATE_TTL_MS + 1);
    expect(await longStore.consume('long')).toBeUndefined();

    clock.mockRestore();
  });

  it('sweeps expired entries rather than leaking them', async () => {
    const realNow = Date.now();
    const clock = vi.spyOn(Date, 'now').mockReturnValue(realNow);

    const store = new MemoryOidcStateStore();
    await store.save(entry('a'));
    await store.save(entry('b'));
    expect(store.size).toBe(2);

    clock.mockReturnValue(realNow + OIDC_STATE_TTL_MS + 1);
    // `size` sweeps first, so both expired entries are already gone.
    expect(store.size).toBe(0);

    // A save after the sweep does not resurrect anything.
    await store.save(entry('c'));
    expect(store.size).toBe(1);

    clock.mockRestore();
  });

  it('never serializes the code verifier (§12.5)', async () => {
    const store = new MemoryOidcStateStore();
    await store.save(entry('s1'));
    const consumed = await store.consume('s1');

    const serialized = JSON.stringify(consumed);
    expect(serialized).not.toContain('s1-verifier');
    expect(serialized).toContain('[SENSITIVE]');
    // state and nonce, by contrast, are not secrets (§12.3 rule 2).
    expect(serialized).toContain('s1-nonce');
  });
});
