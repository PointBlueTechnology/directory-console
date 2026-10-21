import { type DirObject, type Row, type Value, isAcl, isBinary, isReference, isWithheld } from './api';
import { toCsv } from './csv';

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
  if (isReference(v)) {
    return v.dn;
  }
  if (isAcl(v)) {
    return `${v.privileges.join(' ')} on ${v.attribute} for ${'special' in v.trustee ? v.trustee.special : v.trustee.dn}`;
  }
  return JSON.stringify(v);
}

/** A cell a spreadsheet would run as a formula is kept as text. */
function safe(s: string): string {
  return /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
}

const attrsOf = (r: Row | DirObject): Record<string, Value[]> => ('attributes' in r ? r.attributes : {});

/** The values of {@code name} in a row, matched without regard to case (eDirectory's names are case-insensitive). */
export function valuesOf(r: Row | DirObject, name: string): Value[] {
  const a = attrsOf(r);
  const key = Object.keys(a).find((k) => k.toLowerCase() === name.toLowerCase());
  return key ? a[key] : [];
}

/** CSV with the DN, name and class, then each column; several values in one cell, separated by "; ". */
export function reportCsv(rows: (Row | DirObject)[], columns: string[]): string {
  const head = ['dn', 'name', 'objectClass', ...columns];
  const body = rows.map((r) => [r.dn, r.name, r.objectClass, ...columns.map((c) => valuesOf(r, c).map(valueText).join('; '))].map(safe));
  return toCsv([head, ...body]);
}

/** JSON: one object per row, each column a list of its values as text. */
export function reportJson(rows: (Row | DirObject)[], columns: string[]): string {
  return JSON.stringify(rows.map((r) => ({
    dn: r.dn, name: r.name, objectClass: r.objectClass, guid: r.guid,
    attributes: Object.fromEntries(columns.map((c) => [c, valuesOf(r, c).map(valueText)])),
  })), null, 2);
}

/** Column names typed as a list: commas or spaces between them, each once. */
export function columnList(text: string): string[] {
  const seen = new Set<string>();
  return text.split(/[\s,;]+/).map((x) => x.trim()).filter((x) => x && !seen.has(x.toLowerCase()) && seen.add(x.toLowerCase()));
}
