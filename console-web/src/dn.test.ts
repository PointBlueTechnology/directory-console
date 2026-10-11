import { describe, expect, it } from 'vitest';
import { rdns, within } from './dn';

describe('dn', () => {
  it('splits on unescaped commas and folds case and spaces', () => {
    expect(rdns('CN=Smith\\, John , OU=Sales,o=acme')).toEqual(['cn=smith\\, john', 'ou=sales', 'o=acme']);
    expect(rdns('cn=a+uid=b,o=x')).toEqual(['cn=a+uid=b', 'o=x']);
    expect(rdns('uid=b+cn=a,o=x')).toEqual(['cn=a+uid=b', 'o=x']);
  });

  it('decides containment', () => {
    expect(within('cn=alice,ou=Sales,o=acme', 'ou=sales,O=Acme')).toBe(true);
    expect(within('ou=Sales,o=acme', 'ou=Sales,o=acme')).toBe(true);
    expect(within('cn=bob,ou=Engineering,o=acme', 'ou=Sales,o=acme')).toBe(false);
    expect(within('o=acme', 'ou=Sales,o=acme')).toBe(false);
    expect(within('cn=x,ou=Sales\\,East,o=acme', 'ou=Sales,o=acme')).toBe(false);
  });
});
