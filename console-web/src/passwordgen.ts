import type { PolicyRules } from './api';

const UPPER = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
const LOWER = 'abcdefghijkmnopqrstuvwxyz';
const DIGITS = '23456789';
// no quotes, backslash, spaces or characters shells and LDAP treat specially
const SPECIAL = '!#%*+-.=?@_';

type Kind = 'upper' | 'lower' | 'digit' | 'special';
const SETS: Record<Kind, string> = { upper: UPPER, lower: LOWER, digit: DIGITS, special: SPECIAL };

const num = (r: PolicyRules, k: string): number | undefined => (typeof r[k] === 'number' ? (r[k] as number) : typeof r[k] === 'string' && /^\d+$/.test(r[k] as string) ? Number(r[k]) : undefined);
// unset, NMAS treats digits and special characters as not allowed, but a digit or special character first or last as
// allowed (lab, eDirectory 9.2.8): callers give the position rules a default of true
const flag = (r: PolicyRules, k: string, dflt = false): boolean => (typeof r[k] === 'boolean' ? (r[k] as boolean) : dflt);

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
  if (!flag(r, 'numericAllowed') && count('digit')) return 'digits not allowed';
  if (!flag(r, 'specialAllowed') && count('special')) return 'special characters not allowed';
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
 * Rules NMAS can never satisfy: a minimum of digits or special characters the policy does not allow (unset means not
 * allowed, and a minimum does not change that: lab, eDirectory 9.2.8), or minimums adding up past the maximum length.
 */
export function contradictions(r: PolicyRules): string[] {
  const out: string[] = [];
  const min = (k: string) => num(r, k) ?? 0;
  if (min('minNumeric') > 0 && !flag(r, 'numericAllowed')) {
    out.push(`it requires at least ${min('minNumeric')} digit${min('minNumeric') === 1 ? '' : 's'} but does not allow digits`);
  }
  if (min('minSpecial') > 0 && !flag(r, 'specialAllowed')) {
    out.push(`it requires at least ${min('minSpecial')} special character${min('minSpecial') === 1 ? '' : 's'} but does not allow them`);
  }
  const max = num(r, 'maxLength');
  const sum = min('minUpper') + min('minLower') + min('minNumeric') + min('minSpecial');
  if (max && sum > max) {
    out.push(`its minimums add up to ${sum} characters, more than its maximum length of ${max}`);
  }
  return out;
}

/**
 * A random password the policy's character rules allow: {@code length} long (within its minimum and maximum), with at
 * least the minimum of each kind and no more than the maximum, each character used once where possible.
 */
export function generatePassword(r: PolicyRules, length = 16, random: (n: number) => number = cryptoRandom): string {
  const impossible = contradictions(r);
  if (impossible.length) {
    throw new Error(`No password can meet this policy: ${impossible.join('; ')}. Correct the policy's rules first.`);
  }
  const min = (k: string) => num(r, k) ?? 0;
  const maxOf = (k: string) => { const v = num(r, k); return v === undefined || v === 0 ? Infinity : v; };
  const allowed: Record<Kind, boolean> = { upper: true, lower: true, digit: flag(r, 'numericAllowed'), special: flag(r, 'specialAllowed') };
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

/**
 * A policy's password rules in a few words each, for a compact line under a password field: length, the minimums and
 * maximums of each kind, what is not allowed, where digits and special characters may not go, repeats and history.
 */
export function describeRules(r: PolicyRules): string[] {
  const n = (k: string) => num(r, k);
  const out: string[] = [];
  const lo = n('minLength');
  const hi = n('maxLength');
  if (lo || hi) {
    out.push(lo && hi ? `${lo}–${hi} characters` : lo ? `at least ${lo} characters` : `at most ${hi} characters`);
  }
  const plural = (c: number, one: string, many: string) => `${c} ${c === 1 ? one : many}`;
  const mins = [
    n('minUpper') && plural(n('minUpper')!, 'capital', 'capitals'),
    n('minLower') && plural(n('minLower')!, 'lower-case letter', 'lower-case letters'),
    n('minNumeric') && plural(n('minNumeric')!, 'digit', 'digits'),
    n('minSpecial') && plural(n('minSpecial')!, 'special character', 'special characters'),
  ].filter(Boolean) as string[];
  if (mins.length) {
    out.push(`at least ${mins.length > 1 ? `${mins.slice(0, -1).join(', ')} and ${mins[mins.length - 1]}` : mins[0]}`);
  }
  const maxs = [
    n('maxUpper') && plural(n('maxUpper')!, 'capital', 'capitals'),
    n('maxLower') && plural(n('maxLower')!, 'lower-case letter', 'lower-case letters'),
    n('maxNumeric') && plural(n('maxNumeric')!, 'digit', 'digits'),
    n('maxSpecial') && plural(n('maxSpecial')!, 'special character', 'special characters'),
  ].filter(Boolean) as string[];
  if (maxs.length) {
    out.push(`at most ${maxs.join(', ')}`);
  }
  const digits = flag(r, 'numericAllowed');
  const specials = flag(r, 'specialAllowed');
  if (!digits || !specials) {
    out.push(!digits && !specials ? 'no digits or special characters' : !digits ? 'no digits' : 'no special characters');
  }
  const ends: string[] = [];
  if (digits && (!flag(r, 'numericFirst', true) || !flag(r, 'numericLast', true))) {
    ends.push(!flag(r, 'numericFirst', true) && !flag(r, 'numericLast', true) ? 'a digit' : !flag(r, 'numericFirst', true) ? 'a digit first' : 'a digit last');
  }
  if (specials && (!flag(r, 'specialFirst', true) || !flag(r, 'specialLast', true))) {
    ends.push(!flag(r, 'specialFirst', true) && !flag(r, 'specialLast', true) ? 'a special character' : !flag(r, 'specialFirst', true) ? 'a special character first' : 'a special character last');
  }
  if (ends.length) {
    out.push(`not ${ends.join(' or ')} at either end`.replace(/ first at either end| last at either end/g, (m) => m.replace(' at either end', '')));
  }
  if (n('maxConsecutive')) out.push(`no character more than ${n('maxConsecutive')} in a row`);
  if (n('maxRepeated')) out.push(`no character more than ${n('maxRepeated')} times`);
  if (n('minUnique')) out.push(`at least ${n('minUnique')} different characters`);
  const excluded = Array.isArray(r.excludeList) ? r.excludeList.length : 0;
  if (excluded) out.push(`none of ${excluded} excluded word${excluded === 1 ? '' : 's'}`);
  if (n('historyLimit') && r.uniqueRequired !== false) out.push(`not one of the last ${n('historyLimit')}`);
  return out;
}
