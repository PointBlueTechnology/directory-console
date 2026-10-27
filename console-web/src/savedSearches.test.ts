import { describe, expect, it } from 'vitest';
import { type SavedSearch, HISTORY_MAX, clearHistory, loadHistory, loadSearches, remember, removeSearch, saveSearch, upgrade } from './savedSearches';

const memory = () => {
  const m = new Map<string, string>();
  return { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => { m.set(k, v); } };
};
// as 0.3.22 and earlier saved them
const search = (name: string, base = ''): SavedSearch => ({ name, base, scope: 'subtree', objectClass: 'inetOrgPerson',
  conditions: [{ attribute: 'cn', op: 'prefix', value: 'a' }], join: 'and', advanced: false, ldapFilter: '', sort: 'cn', columns: 'mail', savedAt: '2026-10-21' }) as unknown as SavedSearch;

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

  it('from earlier versions open in the builder, or as text', () => {
    expect(upgrade(search('Old'))).toMatchObject({ mode: 'advanced', filterMode: 'build', tree: { kind: 'and', children: [
      { kind: 'cond', attribute: 'objectClass', op: 'eq', value: 'inetOrgPerson' },
      { kind: 'cond', attribute: 'cn', op: 'prefix', value: 'a' },
    ] } });
    const any = { ...search('Any'), join: 'or', conditions: [{ attribute: 'cn', op: 'eq', value: 'a' }, { attribute: 'sn', op: 'eq', value: 'b' }] } as unknown as SavedSearch;
    expect(upgrade(any).tree).toEqual({ kind: 'and', children: [
      { kind: 'cond', attribute: 'objectClass', op: 'eq', value: 'inetOrgPerson' },
      { kind: 'or', children: [{ kind: 'cond', attribute: 'cn', op: 'eq', value: 'a' }, { kind: 'cond', attribute: 'sn', op: 'eq', value: 'b' }] },
    ] });
    expect(upgrade({ ...search('Typed'), advanced: true, ldapFilter: '(cn=x)' } as SavedSearch)).toMatchObject({ mode: 'advanced', filterMode: 'write', ldapFilter: '(cn=x)' });
  });
});

describe('recent searches', () => {
  it('keep the newest first, once each, up to the most', () => {
    const store = memory();
    const basic = (find: string): SavedSearch => ({ name: find, mode: 'basic', base: '', scope: 'subtree', find, kind: 'people', ldapFilter: '', sort: 'cn', columns: '', savedAt: '' });
    remember('acme', basic('a'), store);
    remember('acme', basic('b'), store);
    remember('acme', basic('a'), store);
    expect(loadHistory('acme', store).map((s) => s.find)).toEqual(['a', 'b']);
    for (let i = 0; i < 30; i++) {
      remember('acme', basic(`n${i}`), store);
    }
    expect(loadHistory('acme', store)).toHaveLength(HISTORY_MAX);
    expect(loadHistory('acme', store)[0].find).toBe('n29');
    clearHistory('acme', store);
    expect(loadHistory('acme', store)).toEqual([]);
    expect(remember('acme', basic('x'), { getItem: () => null, setItem: () => { throw new Error('full'); } })).toHaveLength(1);
  });
});
