import type { SchemaAttribute, SchemaClass } from './api';

/** A name to offer: an attribute or class, with a note (its eDirectory name, or what it is). */
export interface NameOption {
  name: string;
  note?: string;
}

const MAX = 12;

/** A schema's attributes as offers, each noted with its eDirectory name when that differs. */
export function attributeOptions(attributes: SchemaAttribute[]): NameOption[] {
  return attributes.map((a) => ({ name: a.name, note: a.ndsName && a.ndsName !== a.name ? a.ndsName : undefined }));
}

/** A schema's classes as offers, noted with their kind (and eDirectory name when that differs). */
export function classOptions(classes: SchemaClass[]): NameOption[] {
  return classes.map((c) => ({ name: c.name, note: [c.kind, c.ndsName && c.ndsName !== c.name ? c.ndsName : ''].filter(Boolean).join(' · ') }));
}

/** Names matching what is typed: those starting with it first, then those containing it. */
export function matches(options: NameOption[], typed: string): NameOption[] {
  const t = typed.trim().toLowerCase();
  if (!t) {
    return [];
  }
  const starts = options.filter((o) => o.name.toLowerCase().startsWith(t) && o.name.toLowerCase() !== t);
  const within = options.filter((o) => !o.name.toLowerCase().startsWith(t) && o.name.toLowerCase().includes(t));
  return [...starts, ...within].slice(0, MAX);
}

