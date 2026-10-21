import { describe, expect, it } from 'vitest';
import { breaks, generatePassword } from './passwordgen';

describe('generated passwords', () => {
  it('keep the policy\'s rules', () => {
    const rules = { minLength: 12, maxLength: 20, minUpper: 2, minLower: 2, minNumeric: 2, minSpecial: 1, maxSpecial: 2, numericAllowed: true, specialAllowed: true,
      numericFirst: false, specialFirst: false,
      specialLast: false, maxRepeated: 1, maxConsecutive: 1, minUnique: 10, excludeList: ['acme'] };
    for (let i = 0; i < 200; i++) {
      const pw = generatePassword(rules, 14);
      expect(breaks(pw, rules), pw).toBeNull();
      expect(pw.length).toBe(14);
    }
  });

  it('leave out what the policy does not allow, or leaves unset (NMAS does not allow it then)', () => {
    expect(generatePassword({ minLength: 8 })).toMatch(/^[A-Za-z]+$/);
    const rules = { minLength: 8, numericAllowed: false, specialAllowed: false };
    for (let i = 0; i < 50; i++) {
      expect(generatePassword(rules)).toMatch(/^[A-Za-z]+$/);
    }
  });

  it('meet a minimum length above the one asked for, and stop at the maximum', () => {
    expect(generatePassword({ minLength: 24 }, 16)).toHaveLength(24);
    expect(generatePassword({ maxLength: 10 }, 16)).toHaveLength(10);
  });

  it('say so when the rules cannot be met', () => {
    expect(() => generatePassword({ maxLength: 4, minUpper: 3, minNumeric: 3 })).toThrow(/No password fits/);
  });

  it('notice broken rules', () => {
    expect(breaks('short', { minLength: 8 })).toBe('too short');
    expect(breaks('1abcdefgh', { numericAllowed: true, numericFirst: false })).toBe('digit first');
    expect(breaks('abcdefgh1', {})).toBe('digits not allowed');
    expect(breaks('a1bcdefgh', { numericAllowed: true })).toBeNull();
    expect(breaks('1abcdefgh', { numericAllowed: true })).toBe('digit first');
    expect(breaks('aabcdefg', { maxConsecutive: 1 })).toBe('a character repeats in a row');
    expect(breaks('helloAcmeX', { excludeList: ['acme'] })).toBe('contains an excluded word');
  });
});
