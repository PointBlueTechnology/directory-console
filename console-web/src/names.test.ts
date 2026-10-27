import { describe, expect, it } from 'vitest';
import { matches } from './names';

describe('matches', () => {
  const names = ['cn', 'mail', 'mailboxLocation', 'givenName', 'groupMembership', 'loginDisabled', 'otherMail'].map((name) => ({ name }));

  it('offers names starting with what is typed, then those containing it, ignoring case', () => {
    expect(matches(names, 'MAIL').map((o) => o.name)).toEqual(['mailboxLocation', 'otherMail']);
    expect(matches(names, 'g').map((o) => o.name)).toEqual(['givenName', 'groupMembership', 'loginDisabled']);
  });

  it('offers nothing for nothing typed', () => {
    expect(matches(names, ' ')).toEqual([]);
  });
});
