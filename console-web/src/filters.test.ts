import { describe, expect, it } from 'vitest';
import { toFilter } from './filters';

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
