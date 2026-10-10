import type { Filter } from './api';

/** One row of the search form. Values are text: the server makes them filter arguments, never filter syntax. */
export type Op = 'eq' | 'prefix' | 'suffix' | 'contains' | 'present' | 'absent' | 'gte' | 'lte' | 'approx';

export interface Condition {
  attribute: string;
  op: Op;
  value: string;
}

export const OPS: { op: Op; label: string; needsValue: boolean }[] = [
  { op: 'eq', label: 'is', needsValue: true },
  { op: 'prefix', label: 'starts with', needsValue: true },
  { op: 'contains', label: 'contains', needsValue: true },
  { op: 'suffix', label: 'ends with', needsValue: true },
  { op: 'present', label: 'has a value', needsValue: false },
  { op: 'absent', label: 'has no value', needsValue: false },
  { op: 'gte', label: 'is at least', needsValue: true },
  { op: 'lte', label: 'is at most', needsValue: true },
  { op: 'approx', label: 'sounds like', needsValue: true },
];

const ATTRIBUTE = /^([A-Za-z][A-Za-z0-9-]*|\d+(\.\d+)+)$/;

export function validAttribute(a: string): boolean {
  return ATTRIBUTE.test(a);
}

function one(c: Condition): Filter {
  switch (c.op) {
    case 'present':
      return { present: c.attribute };
    case 'absent':
      return { not: { present: c.attribute } };
    default:
      return { [c.op]: { [c.attribute]: c.value } } as Filter;
  }
}

/**
 * The structured filter for the form: complete rows joined by {@code join}, and the object class when
 * one is chosen (always required). Rows without an attribute, or without a value where one is needed,
 * are left out. Throws on an attribute name that is not one.
 */
export function toFilter(conditions: Condition[], join: 'and' | 'or', objectClass?: string): Filter | undefined {
  const complete = conditions.filter((c) => c.attribute.trim() && (!OPS.find((o) => o.op === c.op)?.needsValue || c.value !== ''));
  for (const c of complete) {
    if (!validAttribute(c.attribute.trim())) {
      throw new Error(`"${c.attribute}" is not an attribute name`);
    }
  }
  const parts = complete.map((c) => one({ ...c, attribute: c.attribute.trim() }));
  const rows: Filter | undefined = parts.length === 0 ? undefined : parts.length === 1 ? parts[0] : join === 'and' ? { and: parts } : { or: parts };
  if (!objectClass) {
    return rows;
  }
  const cls: Filter = { eq: { objectClass } };
  return rows ? { and: [cls, rows] } : cls;
}
