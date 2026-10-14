import { describe, expect, it } from 'vitest';
import type { DriverRow } from './api';
import { plan } from './lifecycle';

const d = (name: string, state: string, startOption = 'Manual', guid: string | null = name): DriverRow =>
  ({ guid, name, dn: `cn=${name},cn=set,o=system`, state, startOption, cacheSize: '0', unprocessedSize: '0', traceLevel: null });

describe('start all / stop all', () => {
  const drivers = [d('a', 'Running'), d('b', 'Stopped'), d('c', 'Stopped', 'Disabled'), d('e', 'Starting'), d('f', 'Stopped', 'Auto', null)];

  it('starts the stopped drivers that can start', () => {
    const p = plan('start', drivers);
    expect(p.act.map((x) => x.name)).toEqual(['b']);
    expect(p.skip.map((x) => `${x.d.name}: ${x.why}`)).toEqual(['a: already running', 'c: disabled: it cannot start', 'e: already running', 'f: not readable']);
  });

  it('stops the running and starting drivers', () => {
    expect(plan('stop', drivers).act.map((x) => x.name)).toEqual(['a', 'e']);
  });
});
