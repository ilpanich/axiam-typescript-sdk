// CONTRACT.md §8, minimal profile (contract 1.60, §34.4 "§8 minimal profile"):
// the README of an AMQP SDK says that a broker confirm is not evidence that
// AXIAM saw a message, and that a minimal-profile server reads no AMQP queue.

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

describe('§8 minimal profile — the README says a broker confirm is not evidence AXIAM saw a message', () => {
  const readme = readFileSync(new URL('../../README.md', import.meta.url), 'utf8').replace(/\s+/g, ' ');

  it('states that a broker confirm is not evidence that AXIAM saw a message', () => {
    expect(readme).toContain('A broker confirm is not evidence that AXIAM saw a message');
  });

  it('states that a minimal-profile server reads no AMQP queue, and where to look instead', () => {
    expect(readme).toContain('AXIAM__AMQP__ENABLED=false');
    expect(readme).toContain('reads no AMQP queue');
    expect(readme).toContain('use REST or gRPC');
    expect(readme).toContain('`profile: minimal`');
  });
});
