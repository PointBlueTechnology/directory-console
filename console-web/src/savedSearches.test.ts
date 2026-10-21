import { describe, expect, it } from 'vitest';
import { type SavedSearch, loadSearches, removeSearch, saveSearch } from './savedSearches';

const memory = () => {
  const m = new Map<string, string>();
  return { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => { m.set(k, v); } };
};
const search = (name: string, base = ''): SavedSearch => ({ name, base, scope: 'subtree', objectClass: 'inetOrgPerson',
  conditions: [{ attribute: 'cn', op: 'prefix', value: 'a' }], join: 'and', advanced: false, ldapFilter: '', sort: 'cn', columns: 'mail', savedAt: '2026-10-21' });

describe('saved searches', () => {
  it('are kept per directory, by name, replacing one of the same name', () => {
    const store = memory();
    saveSearch('acme', search('Sales', 'ou=Sales,o=acme'), store);
    saveSearch('acme', search('All people'), store);
    saveSearch('test', search('Elsewhere'), store);
    expect(loadSearches('acme', store).map((s) => s.name)).toEqual(['All people', 'Sales']);
    saveSearch('acme', search('Sales', 'ou=Sales2,o=acme'), store);
    expect(loadSearches('acme', store).find((s) => s.name === 'Sales')!.base).toBe('ou=Sales2,o=acme');
    expect(removeSearch('acme', 'Sales', store).map((s) => s.name)).toEqual(['All people']);
    expect(loadSearches('test', store).map((s) => s.name)).toEqual(['Elsewhere']);
  });

  it('survive storage that is broken or holds something else', () => {
    expect(loadSearches('acme', { getItem: () => 'not json' })).toEqual([]);
    expect(loadSearches('acme', { getItem: () => { throw new Error('blocked'); } })).toEqual([]);
  });
});
