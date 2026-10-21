import { describe, expect, it } from 'vitest';
import { toFilter, toLdap } from './filters';

describe('toFilter', () => {
  it('joins complete rows and keeps values as text', () => {
    expect(toFilter([
      { attribute: 'cn', op: 'prefix', value: 'Smith (Admin' },
      { attribute: 'mail', op: 'contains', value: '*)(objectClass=*' },
      { attribute: 'loginDisabled', op: 'absent', value: '' },
    ], 'and')).toEqual({ and: [
      { prefix: { cn: 'Smith (Admin' } },
      { contains: { mail: '*)(objectClass=*' } },
      { not: { present: 'loginDisabled' } },
    ] });
  });

  it('leaves out incomplete rows and ands the class in', () => {
    expect(toFilter([{ attribute: '', op: 'eq', value: 'x' }, { attribute: 'sn', op: 'eq', value: '' }], 'or')).toBeUndefined();
    expect(toFilter([{ attribute: ' sn ', op: 'eq', value: 'Smith' }, { attribute: 'cn', op: 'present', value: '' }], 'or', 'inetOrgPerson'))
      .toEqual({ and: [{ eq: { objectClass: 'inetOrgPerson' } }, { or: [{ eq: { sn: 'Smith' } }, { present: 'cn' }] }] });
    expect(toFilter([], 'and', 'group')).toEqual({ eq: { objectClass: 'group' } });
  });

  it('refuses an attribute name that is filter syntax', () => {
    expect(() => toFilter([{ attribute: 'cn)(x', op: 'eq', value: 'y' }], 'and')).toThrow(/not an attribute name/);
  });
});

describe('toLdap', () => {
  it('writes each test as LDAP filter text', () => {
    const f = toFilter([
      { attribute: 'department', op: 'eq', value: 'Sales' },
      { attribute: 'cn', op: 'prefix', value: 'sm' },
      { attribute: 'mail', op: 'absent', value: '' },
      { attribute: 'title', op: 'contains', value: 'lead' },
    ], 'and')!;
    expect(toLdap(f)).toBe('(&(department=Sales)(cn=sm*)(!(mail=*))(title=*lead*))');
    expect(toLdap(toFilter([{ attribute: 'loginTime', op: 'gte', value: '2026' }, { attribute: 'sn', op: 'approx', value: 'smyth' }], 'or')!))
      .toBe('(|(loginTime>=2026)(sn~=smyth))');
  });

  it('escapes the characters that would change the filter', () => {
    expect(toLdap({ eq: { cn: 'a*b(c)\\d' } })).toBe('(cn=a\\2ab\\28c\\29\\5cd)');
    expect(toLdap({ suffix: { cn: '*)(objectClass=*' } })).toBe('(cn=*\\2a\\29\\28objectClass=\\2a)');
  });
});
