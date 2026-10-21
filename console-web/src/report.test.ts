import { describe, expect, it } from 'vitest';
import { columnList, reportCsv, reportJson } from './report';
import type { DirObject } from './api';

const row = (dn: string, attributes: DirObject['attributes']) => ({ dn, name: dn.split(',')[0].split('=')[1], objectClass: 'inetOrgPerson', guid: 'g', attributes }) as unknown as DirObject;

describe('search reports', () => {
  it('writes the chosen columns, several values to a cell, and keeps formulas as text', () => {
    const rows = [
      row('cn=ann,o=acme', { mail: ['ann@acme.test'], groupMembership: [{ dn: 'cn=a,o=acme', name: 'a' }, { dn: 'cn=b,o=acme', name: 'b' }] }),
      row('cn=bob,o=acme', { Title: ['=HYPERLINK("x")'] }),
    ];
    const csv = reportCsv(rows, ['mail', 'groupMembership', 'title']);
    expect(csv.split('\r\n')[0]).toBe('dn,name,objectClass,mail,groupMembership,title');
    expect(csv.split('\r\n')[1]).toBe('"cn=ann,o=acme",ann,inetOrgPerson,ann@acme.test,"cn=a,o=acme; cn=b,o=acme",');
    expect(csv).toContain(`"'=HYPERLINK(""x"")"`);
    expect(JSON.parse(reportJson(rows, ['mail']))[0].attributes.mail).toEqual(['ann@acme.test']);
  });

  it('reads a column list typed with commas or spaces, each once', () => {
    expect(columnList(' mail, title  Mail;telephoneNumber ')).toEqual(['mail', 'title', 'telephoneNumber']);
  });
});
