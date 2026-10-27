import type { Filter } from './api';
import { type Op, toLdap, validAttribute } from './filters';

/** A filter as the builder shows it: groups (all of, any of), a NOT around one item, and conditions. */
export type FilterNode =
  | { kind: 'and' | 'or'; children: FilterNode[] }
  | { kind: 'not'; child: FilterNode }
  | { kind: 'cond'; attribute: string; op: Op; value: string };

export const newCondition = (attribute = ''): FilterNode => ({ kind: 'cond', attribute, op: 'eq', value: '' });
export const newGroup = (kind: 'and' | 'or' = 'and'): FilterNode => ({ kind, children: [newCondition()] });

/** A problem in filter text, and where (0-based) it was found. */
export class FilterSyntaxError extends Error {
  constructor(message: string, readonly at: number) {
    super(message);
  }
}

/** What RFC 4515 text parses to: every form, including those the builder cannot show. */
type Parsed =
  | { kind: 'and' | 'or'; children: Parsed[] }
  | { kind: 'not'; child: Parsed }
  | { kind: 'eq' | 'gte' | 'lte' | 'approx'; attribute: string; value: string }
  | { kind: 'present'; attribute: string }
  | { kind: 'substring'; attribute: string; initial: string; any: string[]; final: string }
  | { kind: 'extensible'; text: string };

/** Parse RFC 4515 filter text; throws FilterSyntaxError with the position of the first problem. */
function parse(text: string): Parsed {
  let i = 0;
  const s = text.trim();
  const offset = text.indexOf(s);
  const fail = (m: string): never => {
    throw new FilterSyntaxError(m, offset + i);
  };
  const expect = (ch: string) => {
    if (s[i] !== ch) {
      fail(i >= s.length ? `the filter ends early: "${ch}" expected` : `"${ch}" expected, found "${s[i]}"`);
    }
    i++;
  };
  const item = (): Parsed => {
    expect('(');
    let out: Parsed;
    if (s[i] === '&' || s[i] === '|') {
      const kind = s[i] === '&' ? 'and' : 'or';
      i++;
      const children: Parsed[] = [];
      while (s[i] === '(') {
        children.push(item());
      }
      if (children.length === 0) {
        fail(`${kind === 'and' ? '&' : '|'} needs at least one filter in parentheses`);
      }
      out = { kind, children };
    } else if (s[i] === '!') {
      i++;
      out = { kind: 'not', child: item() };
    } else {
      out = simple();
    }
    expect(')');
    return out;
  };
  const value = (): string => {
    // up to ")" with RFC 4515 escapes (\XX) decoded; "*" is left for the caller
    let v = '';
    while (i < s.length && s[i] !== ')') {
      if (s[i] === '(') {
        fail('a "(" in a value must be written \\28');
      }
      if (s[i] === '\\') {
        const hex = s.slice(i + 1, i + 3);
        if (!/^[0-9a-fA-F]{2}$/.test(hex)) {
          fail('"\\" in a value must be followed by two hex digits (\\2a for *, \\28 for (, \\29 for ), \\5c for \\)');
        }
        v += `\\${hex}`;
        i += 3;
      } else {
        v += s[i];
        i++;
      }
    }
    return v;
  };
  const simple = (): Parsed => {
    const start = i;
    while (i < s.length && !'=<>~():'.includes(s[i])) {
      i++;
    }
    const attribute = s.slice(start, i);
    if (s[i] === ':') {
      // extensible match ([attr][:dn][:rule]:=value): checked loosely, kept as text
      while (i < s.length && s[i] !== ')') {
        i++;
      }
      if (!/:=/.test(s.slice(start, i))) {
        fail('an extensible match needs ":=", as in (cn:caseExactMatch:=Smith)');
      }
      return { kind: 'extensible', text: `(${s.slice(start, i)})` };
    }
    if (!attribute) {
      fail('an attribute name is expected');
    }
    if (!validAttribute(attribute)) {
      i = start;
      fail(`"${attribute}" is not an attribute name`);
    }
    let kind: 'eq' | 'gte' | 'lte' | 'approx' = 'eq';
    if (s[i] === '>' || s[i] === '<' || s[i] === '~') {
      kind = s[i] === '>' ? 'gte' : s[i] === '<' ? 'lte' : 'approx';
      i++;
    }
    if (s[i] !== '=') {
      fail(`"=" expected after ${attribute}`);
    }
    i++;
    const v = value();
    if (kind === 'eq' && v === '*') {
      return { kind: 'present', attribute };
    }
    if (kind === 'eq' && v.includes('*')) {
      const parts = v.split('*');
      return { kind: 'substring', attribute, initial: parts[0], any: parts.slice(1, -1).filter((p) => p !== ''), final: parts[parts.length - 1] };
    }
    if (kind !== 'eq' && v.includes('*')) {
      fail(`"*" is not allowed with ${kind === 'gte' ? '>=' : kind === 'lte' ? '<=' : '~='}; write \\2a for a literal *`);
    }
    return { kind, attribute, value: v };
  };
  if (!s) {
    throw new FilterSyntaxError('the filter is empty', 0);
  }
  if (s[0] !== '(') {
    throw new FilterSyntaxError('a filter starts with "(", as in (cn=smith*)', offset);
  }
  const f = item();
  if (i < s.length) {
    fail('one filter only: wrap several in (&…) or (|…)');
  }
  return f;
}

/** Null when {@code text} is one well-formed filter, else what is wrong and where. */
export function checkFilter(text: string): { message: string; at: number } | null {
  try {
    parse(text);
    return null;
  } catch (e) {
    if (e instanceof FilterSyntaxError) {
      return { message: e.message, at: e.at };
    }
    throw e;
  }
}

/** A value as the builder shows it: escapes (\2a and so on) decoded. */
function decode(v: string): string {
  return v.replace(/\\([0-9a-fA-F]{2})/g, (_m, h: string) => String.fromCharCode(parseInt(h, 16)));
}

/**
 * Filter text as builder items. Throws FilterSyntaxError for text that is not a filter, and for forms the
 * builder cannot show (extensible matches, substrings with a middle part such as a*b*c): those stay text.
 */
export function fromText(text: string): FilterNode {
  const walk = (p: Parsed): FilterNode => {
    switch (p.kind) {
      case 'and':
      case 'or':
        return { kind: p.kind, children: p.children.map(walk) };
      case 'not':
        if (p.child.kind === 'present') {
          return { kind: 'cond', attribute: p.child.attribute, op: 'absent', value: '' };
        }
        return { kind: 'not', child: walk(p.child) };
      case 'present':
        return { kind: 'cond', attribute: p.attribute, op: 'present', value: '' };
      case 'substring': {
        const { initial, any, final } = p;
        if (any.length > 1 || (any.length === 1 && (initial || final))) {
          throw new FilterSyntaxError(`the builder has no test for ${p.attribute}=${initial}*${any.join('*')}*${final}; keep it as text`, 0);
        }
        if (any.length === 1) {
          return { kind: 'cond', attribute: p.attribute, op: 'contains', value: decode(any[0]) };
        }
        if (initial && final) {
          throw new FilterSyntaxError(`the builder has no test for ${p.attribute}=${initial}*${final}; keep it as text`, 0);
        }
        return initial
          ? { kind: 'cond', attribute: p.attribute, op: 'prefix', value: decode(initial) }
          : { kind: 'cond', attribute: p.attribute, op: 'suffix', value: decode(final) };
      }
      case 'extensible':
        throw new FilterSyntaxError(`the builder has no test for ${p.text}; keep it as text`, 0);
      default:
        return { kind: 'cond', attribute: p.attribute, op: p.kind, value: decode(p.value) };
    }
  };
  return walk(parse(text));
}

/** A condition with an attribute, and a value where its test needs one. */
function complete(n: Extract<FilterNode, { kind: 'cond' }>): boolean {
  return n.attribute.trim() !== '' && (n.op === 'present' || n.op === 'absent' || n.value !== '');
}

/**
 * The builder's items as the server's structured filter (values escaped there). Incomplete conditions
 * and empty groups are left out; a group of one is that one. Undefined when nothing is left. Throws on
 * an attribute name that is not one.
 */
export function toStructured(n: FilterNode): Filter | undefined {
  switch (n.kind) {
    case 'cond': {
      if (!complete(n)) {
        return undefined;
      }
      const a = n.attribute.trim();
      if (!validAttribute(a)) {
        throw new Error(`"${a}" is not an attribute name`);
      }
      if (n.op === 'present') {
        return { present: a };
      }
      if (n.op === 'absent') {
        return { not: { present: a } };
      }
      return { [n.op]: { [a]: n.value } } as Filter;
    }
    case 'not': {
      const c = toStructured(n.child);
      return c ? { not: c } : undefined;
    }
    default: {
      const kids = n.children.map(toStructured).filter((x): x is Filter => x !== undefined);
      if (kids.length === 0) {
        return undefined;
      }
      if (kids.length === 1) {
        return kids[0];
      }
      return n.kind === 'and' ? { and: kids } : { or: kids };
    }
  }
}

/** The builder's items as filter text; "(objectClass=*)" when nothing is complete. */
export function toText(n: FilterNode): string {
  const f = toStructured(n);
  return f ? toLdap(f) : '(objectClass=*)';
}

/** The attribute name being typed at {@code cursor} in filter text, and where it starts; null outside one. */
export function attributeAt(text: string, cursor: number): { token: string; start: number } | null {
  let start = cursor;
  while (start > 0 && /[A-Za-z0-9-]/.test(text[start - 1])) {
    start--;
  }
  if (start === 0 || !'(&|!'.includes(text[start - 1])) {
    return null;
  }
  const token = text.slice(start, cursor);
  return /^[A-Za-z][A-Za-z0-9-]*$/.test(token) ? { token, start } : null;
}
