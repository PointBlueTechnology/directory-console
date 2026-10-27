import { type DirObject, type Row, type Value, isAcl, isBinary, isPath, isReference, isWithheld } from './api';

/** A value as text for a report: a reference as its DN, binary and withheld values as a note. */
export function valueText(v: Value): string {
  if (typeof v === 'string') {
    return v;
  }
  if (isWithheld(v)) {
    return '(not shown)';
  }
  if (isBinary(v)) {
    return '(binary)';
  }
  if (isPath(v)) {
    return v.raw;
  }
  if (isReference(v)) {
    return v.dn;
  }
  if (isAcl(v)) {
    return `${v.privileges.join(' ')} on ${v.attribute} for ${'special' in v.trustee ? v.trustee.special : v.trustee.dn}`;
  }
  return JSON.stringify(v);
}

const attrsOf = (r: Row | DirObject): Record<string, Value[]> => ('attributes' in r ? r.attributes : {});

/** The values of {@code name} in a row, matched without regard to case (eDirectory's names are case-insensitive). */
export function valuesOf(r: Row | DirObject, name: string): Value[] {
  const a = attrsOf(r);
  const key = Object.keys(a).find((k) => k.toLowerCase() === name.toLowerCase());
  return key ? a[key] : [];
}

/** Column names typed as a list: commas or spaces between them, each once. */
export function columnList(text: string): string[] {
  const seen = new Set<string>();
  return text.split(/[\s,;]+/).map((x) => x.trim()).filter((x) => x && !seen.has(x.toLowerCase()) && seen.add(x.toLowerCase()));
}
