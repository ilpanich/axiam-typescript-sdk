// withRetry (rest/retry.ts, CF-01): idempotent-only retry, transient
// NetworkError classification, Retry-After honoring, and attempt bounding.
// Backoff sleeps are driven with fake timers so no real wall-clock delay is
// incurred.

import { afterEach, describe, expect, it, vi } from 'vitest';
import { withRetry } from '../../src/rest/retry.js';
import { AuthError, NetworkError } from '../../src/core/index.js';

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('withRetry (CF-01)', () => {
  it('returns the result on first success without sleeping', async () => {
    const fn = vi.fn().mockResolvedValue('ok');
    await expect(withRetry(fn, { idempotent: true })).resolves.toBe('ok');
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('does not retry a non-idempotent call even on NetworkError', async () => {
    const fn = vi.fn().mockRejectedValue(new NetworkError('transient'));
    await expect(withRetry(fn, { idempotent: false })).rejects.toBeInstanceOf(NetworkError);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('does not retry a non-NetworkError failure', async () => {
    const fn = vi.fn().mockRejectedValue(new AuthError('nope'));
    await expect(withRetry(fn, { idempotent: true })).rejects.toBeInstanceOf(AuthError);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('retries a transient NetworkError and eventually succeeds (backoff via fake timers)', async () => {
    vi.useFakeTimers();
    const fn = vi
      .fn()
      .mockRejectedValueOnce(new NetworkError('down'))
      .mockResolvedValueOnce('recovered');

    const promise = withRetry(fn, { idempotent: true });
    await vi.runAllTimersAsync();

    await expect(promise).resolves.toBe('recovered');
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('honors a retryAfterMs hint on the thrown error in place of computed backoff', async () => {
    vi.useFakeTimers();
    const err = Object.assign(new NetworkError('rate limited'), { retryAfterMs: 1234 });
    const fn = vi.fn().mockRejectedValueOnce(err).mockResolvedValueOnce('ok');

    const promise = withRetry(fn, { idempotent: true });
    // Nothing resolves before the hinted delay elapses.
    await vi.advanceTimersByTimeAsync(1233);
    expect(fn).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    await expect(promise).resolves.toBe('ok');
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('throws the last error after exhausting maxAttempts', async () => {
    vi.useFakeTimers();
    const fn = vi.fn().mockRejectedValue(new NetworkError('always down'));

    const promise = withRetry(fn, { idempotent: true });
    const settled = promise.catch((e) => e);
    await vi.runAllTimersAsync();

    const err = await settled;
    expect(err).toBeInstanceOf(NetworkError);
    expect(fn).toHaveBeenCalledTimes(3);
  });
});

describe('withRetry admit (C164-48)', () => {
  it('a refused wait announces no retry event, sleeps nothing and sends nothing more', async () => {
    const emit = vi.fn();
    const sleepFn = vi.fn().mockResolvedValue(undefined);
    const fn = vi.fn().mockRejectedValue(new NetworkError('down'));
    const refusal = new AuthError('past the deadline');

    const err = await withRetry(fn, {
      idempotent: true,
      telemetry: { emit } as never,
      sleepFn,
      randomFn: () => 1,
      admit: () => {
        throw refusal;
      },
    }).catch((e: unknown) => e);

    expect(err).toBe(refusal);
    expect(fn).toHaveBeenCalledTimes(1);
    expect(emit).not.toHaveBeenCalled();
    expect(sleepFn).not.toHaveBeenCalled();
  });

  it('an admitted wait is announced once and served', async () => {
    const emit = vi.fn();
    const sleepFn = vi.fn().mockResolvedValue(undefined);
    const admit = vi.fn();
    const fn = vi.fn().mockRejectedValueOnce(new NetworkError('down')).mockResolvedValueOnce('ok');

    await expect(
      withRetry(fn, { idempotent: true, telemetry: { emit } as never, sleepFn, randomFn: () => 1, admit }),
    ).resolves.toBe('ok');

    expect(admit).toHaveBeenCalledWith(200);
    expect(emit).toHaveBeenCalledTimes(1);
    expect(sleepFn).toHaveBeenCalledWith(200);
  });
});
