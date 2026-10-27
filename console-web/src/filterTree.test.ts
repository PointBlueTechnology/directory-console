import { describe, expect, it } from 'vitest';
import { attributeAt, checkFilter, classAt, fromText, toStructured, toText } from './filterTree';

describe('checkFilter', () => {
  it('accepts every RFC 4515 form', () => {
    for (const f of ['(cn=smith)', '(cn=*)', '(cn=a*b*c)', '(!(cn=x))', '(&(objectClass=inetOrgPerson)(|(sn=a*)(mail=*@x.com)))',
      '(cn:caseExactMatch:=Smith)', '(cn=a\\28b\\29)', '(loginTime>=20260101000000Z)', ' (cn=x) ']) {
      expect(checkFilter(f), f).toBeNull();
    }
  });

  it('says what is wrong and where', () => {
    expect(checkFilter('')?.message).toMatch(/empty/);
    expect(checkFilter('cn=x')?.message).toMatch(/starts with/);
    expect(checkFilter('(cn=x')).toEqual({ message: 'the filter ends early: ")" expected', at: 5 });
    expect(checkFilter('(cn=x)(sn=y)')?.message).toMatch(/one filter only/);
    expect(checkFilter('(&)')?.message).toMatch(/at least one/);
    expect(checkFilter('(cn=a(b)')?.message).toMatch(/\\28/);
    expect(checkFilter('(cn=a\\zz)')?.message).toMatch(/two hex digits/);
    expect(checkFilter('(cn x=1)')?.message).toMatch(/not an attribute name/);
    expect(checkFilter('(age>=*)')?.message).toMatch(/not allowed/);
  });
});

describe('fromText and toText', () => {
  it('round-trips what the builder can show', () => {
    const t = '(&(objectClass=inetOrgPerson)(|(cn=smith*)(mail=*@acme.com)(title=*lead*))(!(loginDisabled=TRUE))(!(mail=*)))';
    const n = fromText(t);
    expect(n).toEqual({ kind: 'and', children: [
      { kind: 'cond', attribute: 'objectClass', op: 'eq', value: 'inetOrgPerson' },
      { kind: 'or', children: [
        { kind: 'cond', attribute: 'cn', op: 'prefix', value: 'smith' },
        { kind: 'cond', attribute: 'mail', op: 'suffix', value: '@acme.com' },
        { kind: 'cond', attribute: 'title', op: 'contains', value: 'lead' },
      ] },
      { kind: 'not', child: { kind: 'cond', attribute: 'loginDisabled', op: 'eq', value: 'TRUE' } },
      { kind: 'cond', attribute: 'mail', op: 'absent', value: '' },
    ] });
    expect(toText(n)).toBe(t);
  });

  it('decodes escapes for editing and escapes them again', () => {
    const n = fromText('(cn=Smith \\28Admin\\29)');
    expect(n).toEqual({ kind: 'cond', attribute: 'cn', op: 'eq', value: 'Smith (Admin)' });
    expect(toText(n)).toBe('(cn=Smith \\28Admin\\29)');
  });

  it('refuses forms it cannot show', () => {
    expect(() => fromText('(cn=a*b*c)')).toThrow(/keep it as text/);
    expect(() => fromText('(cn=a*c)')).toThrow(/keep it as text/);
    expect(() => fromText('(cn:dn:=x)')).toThrow(/keep it as text/);
  });

  it('leaves out incomplete items and collapses groups of one', () => {
    expect(toStructured({ kind: 'and', children: [
      { kind: 'cond', attribute: '', op: 'eq', value: 'x' },
      { kind: 'or', children: [{ kind: 'cond', attribute: 'cn', op: 'prefix', value: '' }, { kind: 'cond', attribute: 'sn', op: 'eq', value: 'a' }] },
    ] })).toEqual({ eq: { sn: 'a' } });
    expect(toText({ kind: 'and', children: [] })).toBe('(objectClass=*)');
    expect(() => toStructured({ kind: 'cond', attribute: 'c n', op: 'eq', value: 'x' })).toThrow(/not an attribute name/);
  });
});

describe('attributeAt', () => {
  it('finds the attribute name being typed', () => {
    expect(attributeAt('(&(objectCl', 11)).toEqual({ token: 'objectCl', start: 3 });
    expect(attributeAt('(cn=smi', 7)).toBeNull();
    expect(attributeAt('(', 1)).toBeNull();
  });
});

describe('classAt', () => {
  it('finds the class name being typed as an objectClass value', () => {
    expect(classAt('(&(objectclass=inetOrg', 22)).toEqual({ token: 'inetOrg', start: 15 });
    expect(classAt('(objectClass=', 13)).toEqual({ token: '', start: 13 });
    expect(classAt('(cn=inet', 8)).toBeNull();
  });
});
