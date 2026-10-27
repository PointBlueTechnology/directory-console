import { describe, expect, it } from 'vitest';
import { basicQuery } from './basicSearch';

describe('basicQuery', () => {
  it('matches the start of the name attributes, escaped by the server', () => {
    expect(basicQuery('smi', 'people')).toEqual({ filter: { and: [{ eq: { objectClass: 'inetOrgPerson' } },
      { or: ['cn', 'fullName', 'givenName', 'sn', 'mail', 'uid'].map((a) => ({ prefix: { [a]: 'smi' } })) }] } });
  });

  it('takes * alone, or nothing, as any name', () => {
    expect(basicQuery('*', 'people')).toEqual({ filter: { eq: { objectClass: 'inetOrgPerson' } } });
    expect(basicQuery(' ** ', 'everything')).toEqual({ filter: undefined });
    expect(basicQuery('', 'groups').filter).toEqual({ or: [{ eq: { objectClass: 'groupOfNames' } }, { eq: { objectClass: 'dynamicGroup' } }] });
  });

  it('takes * as a wildcard, escaping everything else', () => {
    expect(basicQuery('j*son', 'people').ldapFilter).toBe(
      '(&(objectClass=inetOrgPerson)(|(cn=j*son*)(fullName=j*son*)(givenName=j*son*)(sn=j*son*)(mail=j*son*)(uid=j*son*)))');
    expect(basicQuery('*admin', 'everything').ldapFilter).toBe('(|(cn=*admin*)(fullName=*admin*)(givenName=*admin*)(sn=*admin*)(mail=*admin*)(uid=*admin*))');
    expect(basicQuery('a(b)*', 'everything').ldapFilter).toContain('(cn=a\\28b\\29*)');
  });
});
