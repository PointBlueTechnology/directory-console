import type { PolicyRules } from './api';

const UPPER = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
const LOWER = 'abcdefghijkmnopqrstuvwxyz';
const DIGITS = '23456789';
// no quotes, backslash, spaces or characters shells and LDAP treat specially
const SPECIAL = '!#%*+-.=?@_';

type Kind = 'upper' | 'lower' | 'digit' | 'special';
const SETS: Record<Kind, string> = { upper: UPPER, lower: LOWER, digit: DIGITS, special: SPECIAL };

const num = (r: PolicyRules, k: string): number | undefined => (typeof r[k] === 'number' ? (r[k] as number) : typeof r[k] === 'string' && /^\d+$/.test(r[k] as string) ? Number(r[k]) : undefined);
const flag = (r: PolicyRules, k: string, dflt: boolean): boolean => (typeof r[k] === 'boolean' ? (r[k] as boolean) : dflt);

function randomInt(n: number, random: (n: number) => number): number {
  return random(n);
}

/** A cryptographically random integer from 0 to n - 1. */
export function cryptoRandom(n: number): number {
  const limit = Math.floor(0x100000000 / n) * n;
  const buf = new Uint32Array(1);
  do {
    crypto.getRandomValues(buf);
  } while (buf[0] >= limit);
  return buf[0] % n;
}

const kindOf = (c: string): Kind => (UPPER.includes(c) || /[A-Z]/.test(c) ? 'upper' : LOWER.includes(c) || /[a-z]/.test(c) ? 'lower' : /[0-9]/.test(c) ? 'digit' : 'special');

/** Why {@code pw} breaks the policy's character rules, or null when it keeps them (NMAS still has the last word). */
export function breaks(pw: string, r: PolicyRules): string | null {
  const count = (k: Kind) => [...pw].filter((c) => kindOf(c) === k).length;
  const min = (k: string) => num(r, k) ?? 0;
  const max = (k: string) => { const v = num(r, k); return v === undefined || v === 0 ? Infinity : v; };
  if (pw.length < min('minLength')) return 'too short';
  if (pw.length > max('maxLength')) return 'too long';
  const pairs: [Kind, string, string][] = [['upper', 'minUpper', 'maxUpper'], ['lower', 'minLower', 'maxLower'], ['digit', 'minNumeric', 'maxNumeric'], ['special', 'minSpecial', 'maxSpecial']];
  for (const [k, lo, hi] of pairs) {
    if (count(k) < min(lo) || count(k) > max(hi)) return `${k} characters out of range`;
  }
  if (!flag(r, 'numericAllowed', true) && count('digit')) return 'digits not allowed';
  if (!flag(r, 'specialAllowed', true) && count('special')) return 'special characters not allowed';
  const first = pw[0];
  const last = pw[pw.length - 1];
  if (!flag(r, 'numericFirst', true) && kindOf(first) === 'digit') return 'digit first';
  if (!flag(r, 'numericLast', true) && kindOf(last) === 'digit') return 'digit last';
  if (!flag(r, 'specialFirst', true) && kindOf(first) === 'special') return 'special first';
  if (!flag(r, 'specialLast', true) && kindOf(last) === 'special') return 'special last';
  const repeated = max('maxRepeated');
  const seen = new Map<string, number>();
  for (const c of pw) seen.set(c, (seen.get(c) ?? 0) + 1);
  if ([...seen.values()].some((n) => n > repeated)) return 'a character repeats too often';
  const consecutive = max('maxConsecutive');
  let run = 1;
  for (let i = 1; i < pw.length; i++) {
    run = pw[i] === pw[i - 1] ? run + 1 : 1;
    if (run > consecutive) return 'a character repeats in a row';
  }
  if (seen.size < min('minUnique')) return 'too few different characters';
  const lower = pw.toLowerCase();
  const words = Array.isArray(r.excludeList) ? r.excludeList : [];
  if (words.some((w) => w && lower.includes(String(w).toLowerCase()))) return 'contains an excluded word';
  return null;
}

/**
 * A random password the policy's character rules allow: {@code length} long (within its minimum and maximum), with at
 * least the minimum of each kind and no more than the maximum, each character used once where possible.
 */
export function generatePassword(r: PolicyRules, length = 16, random: (n: number) => number = cryptoRandom): string {
  const min = (k: string) => num(r, k) ?? 0;
  const maxOf = (k: string) => { const v = num(r, k); return v === undefined || v === 0 ? Infinity : v; };
  const allowed: Record<Kind, boolean> = { upper: true, lower: true, digit: flag(r, 'numericAllowed', true), special: flag(r, 'specialAllowed', true) };
  const mins: Record<Kind, number> = { upper: min('minUpper'), lower: min('minLower'), digit: allowed.digit ? min('minNumeric') : 0, special: allowed.special ? min('minSpecial') : 0 };
  const maxs: Record<Kind, number> = { upper: maxOf('maxUpper'), lower: maxOf('maxLower'), digit: allowed.digit ? maxOf('maxNumeric') : 0, special: allowed.special ? maxOf('maxSpecial') : 0 };
  const required = Object.values(mins).reduce((a, b) => a + b, 0);
  const target = Math.min(Math.max(length, min('minLength'), required), maxOf('maxLength'));
  for (let attempt = 0; attempt < 200; attempt++) {
    const counts: Record<Kind, number> = { ...mins };
    let total = required;
    const kinds = (Object.keys(SETS) as Kind[]).filter((k) => allowed[k]);
    while (total < target) {
      const open = kinds.filter((k) => counts[k] < maxs[k]);
      if (!open.length) break;
      counts[open[randomInt(open.length, random)]]++;
      total++;
    }
    const chars: string[] = [];
    for (const k of kinds) {
      const pool = [...SETS[k]];
      for (let i = 0; i < counts[k]; i++) {
        // each character once while the set lasts
        const at = randomInt(pool.length, random);
        chars.push(pool[at]);
        if (pool.length > 1) pool.splice(at, 1);
      }
    }
    for (let i = chars.length - 1; i > 0; i--) {
      const j = randomInt(i + 1, random);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    const pw = chars.join('');
    if (!breaks(pw, r)) {
      return pw;
    }
  }
  throw new Error('No password fits these rules: check the policy\'s minimums and maximums.');
}
