import type { Filter } from './api';
import { escape, toLdap } from './filters';
import type { BasicKind } from './savedSearches';

/** The attributes a basic search matches a name against (the start of any of them). */
export const NAME_ATTRIBUTES = ['cn', 'fullName', 'givenName', 'sn', 'mail', 'uid'];

/** The classes each kind of basic search finds (none: any class). */
export const KIND_CLASSES: Record<BasicKind, string[]> = {
  people: ['inetOrgPerson'],
  groups: ['groupOfNames', 'dynamicGroup'],
  containers: ['organizationalUnit', 'organization', 'locality', 'country', 'domain'],
  everything: [],
};

/**
 * The basic search as a request's filter: the kind's classes, and the name typed matched at the start of
 * the name attributes. A "*" in the name is a wildcard (and "*" alone matches any name); every other
 * character is matched as typed. Without a wildcard the server escapes the value; with one, the filter
 * is sent as text with each part escaped here.
 */
export function basicQuery(find: string, kind: BasicKind): { filter?: Filter; ldapFilter?: string } {
  const classes = KIND_CLASSES[kind] ?? [];
  const cls: Filter | undefined = classes.length === 0 ? undefined
    : classes.length === 1 ? { eq: { objectClass: classes[0] } } : { or: classes.map((c) => ({ eq: { objectClass: c } })) };
  const name = find.trim();
  const wild = name.includes('*');
  if (!name || (wild && /^\*+$/.test(name))) {
    return { filter: cls };
  }
  if (!wild) {
    const names: Filter = { or: NAME_ATTRIBUTES.map((a) => ({ prefix: { [a]: name } })) };
    return { filter: cls ? { and: [cls, names] } : names };
  }
  const pattern = name.split('*').map(escape).join('*').replace(/\*+/g, '*') + (name.endsWith('*') ? '' : '*');
  const names = `(|${NAME_ATTRIBUTES.map((a) => `(${a}=${pattern})`).join('')})`;
  return { ldapFilter: cls ? `(&${toLdap(cls)}${names})` : names };
}
