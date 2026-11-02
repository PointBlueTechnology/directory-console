import { describe, expect, it } from 'vitest';
import { fromText } from './filterTree';
import { toCriteria } from './rbeCriteria';

describe('toCriteria', () => {
  it('writes one condition as Designer does', () => {
    expect(toCriteria(fromText('(Title=Clerk)'))).toBe('<selection-criterion><group><group-op>and</group-op>'
      + '<row><attribute>Title</attribute><operation>AS.Op.isEqual</operation><value>Clerk</value><row-op>and</row-op></row></group></selection-criterion>');
  });

  it('keeps flat conditions in one group, and groups as groups', () => {
    expect(toCriteria(fromText('(&(title=a)(!(ou=b))(mail=*))'))).toBe('<selection-criterion><group><group-op>and</group-op>'
      + '<row><attribute>title</attribute><operation>AS.Op.isEqual</operation><value>a</value><row-op>and</row-op></row>'
      + '<row><attribute>ou</attribute><operation>AS.Op.isNotEqual</operation><value>b</value><row-op>and</row-op></row>'
      + '<row><attribute>mail</attribute><operation>AS.Op.isPresent</operation><value></value><row-op>and</row-op></row></group></selection-criterion>');
    const two = toCriteria(fromText('(|(&(title=a)(l=x))(&(title=b)(l=y)))'))!;
    expect(two.match(/<group>/g)).toHaveLength(2);
    expect(two).toContain('<group-op>or</group-op>');
    expect(two).toContain('<row-op>and</row-op>');
  });

  it('gives up on what those editors cannot show', () => {
    expect(toCriteria(fromText('(cn=a*)'))).toBeNull();
    expect(toCriteria(fromText('(&(title=a)(|(l=x)(&(l=y)(ou=z))))'))).toBeNull();
    expect(toCriteria(fromText('(!(&(title=a)(l=x)))'))).toBeNull();
  });

  it('escapes values', () => {
    expect(toCriteria(fromText('(o=R&D <x>)'))).toContain('<value>R&amp;D &lt;x&gt;</value>');
  });
});
