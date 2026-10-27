import type { Condition } from './filters';
import type { FilterNode } from './filterTree';

/** The basic search's choices of what to find. */
export type BasicKind = 'people' | 'groups' | 'containers' | 'everything';

/** Everything the Search page holds, as a search is saved or kept in the recent list. */
export interface SavedSearch {
  name: string;
  mode: 'basic' | 'advanced';
  base: string;
  scope: 'subtree' | 'one' | 'base';
  /** Basic: the name typed, and what to find. */
  find?: string;
  kind?: BasicKind;
  /** Advanced: the filter built as items, or written as text. */
  filterMode?: 'build' | 'write';
  tree?: FilterNode;
  ldapFilter: string;
  sort: string;
  columns: string;
  savedAt: string;
  /** Before 0.3.23: one class and a flat list of conditions, or a typed filter. */
  objectClass?: string;
  conditions?: Condition[];
  join?: 'and' | 'or';
  advanced?: boolean;
}

/** A search saved by an earlier version, in today's shape: its class and conditions become builder items. */
export function upgrade(s: SavedSearch): SavedSearch {
  if (s.mode) {
    return s;
  }
  if (s.advanced) {
    return { ...s, mode: 'advanced', filterMode: 'write' };
  }
  const rows: FilterNode[] = (s.conditions ?? []).map((c) => ({ kind: 'cond', attribute: c.attribute, op: c.op, value: c.value }));
  const children: FilterNode[] = [];
  if (s.objectClass) {
    children.push({ kind: 'cond', attribute: 'objectClass', op: 'eq', value: s.objectClass });
  }
  if (rows.length) {
    children.push(s.join === 'or' && rows.length > 1 ? { kind: 'or', children: rows } : rows.length === 1 ? rows[0] : { kind: 'and', children: rows });
  }
  const flat = children.flatMap((c) => (c.kind === 'and' ? c.children : [c]));
  return { ...s, mode: 'advanced', filterMode: 'build', tree: { kind: 'and', children: flat } };
}

const key = (directory: string) => `dc-saved-searches:${directory}`;
const historyKey = (directory: string) => `dc-search-history:${directory}`;
export const HISTORY_MAX = 20;

function read(store: Pick<Storage, 'getItem'>, k: string): SavedSearch[] {
  try {
    const raw = store.getItem(k);
    const list = raw ? JSON.parse(raw) : [];
    return Array.isArray(list) ? list.filter((s) => s && typeof s.name === 'string').map(upgrade) : [];
  } catch {
    return [];
  }
}

/** This browser's saved searches for a directory, by name; none when storage is unavailable. */
export function loadSearches(directory: string, store: Pick<Storage, 'getItem'> = localStorage): SavedSearch[] {
  return read(store, key(directory)).sort((a, b) => a.name.localeCompare(b.name));
}

/** Save under its name, replacing one of the same name. Answers the list, or throws when the browser keeps nothing. */
export function saveSearch(directory: string, s: SavedSearch, store: Pick<Storage, 'getItem' | 'setItem'> = localStorage): SavedSearch[] {
  const list = loadSearches(directory, store).filter((x) => x.name !== s.name);
  list.push(s);
  store.setItem(key(directory), JSON.stringify(list));
  return loadSearches(directory, store);
}

export function removeSearch(directory: string, name: string, store: Pick<Storage, 'getItem' | 'setItem'> = localStorage): SavedSearch[] {
  store.setItem(key(directory), JSON.stringify(loadSearches(directory, store).filter((x) => x.name !== name)));
  return loadSearches(directory, store);
}

/** What a search asks for, without its name and time: two runs of the same search are one history entry. */
function sameQuery(a: SavedSearch, b: SavedSearch): boolean {
  const q = (s: SavedSearch) => JSON.stringify([s.mode, s.base, s.scope, s.find, s.kind, s.filterMode, s.tree, s.ldapFilter, s.sort, s.columns]);
  return q(a) === q(b);
}

/** The searches last run in this browser for a directory, newest first. */
export function loadHistory(directory: string, store: Pick<Storage, 'getItem'> = localStorage): SavedSearch[] {
  return read(store, historyKey(directory));
}

/** Put {@code s} first in the recent list (once), keeping {@link HISTORY_MAX}. Never throws. */
export function remember(directory: string, s: SavedSearch, store: Pick<Storage, 'getItem' | 'setItem'> = localStorage): SavedSearch[] {
  const list = [s, ...loadHistory(directory, store).filter((x) => !sameQuery(x, s))].slice(0, HISTORY_MAX);
  try {
    store.setItem(historyKey(directory), JSON.stringify(list));
  } catch {
    // not kept
  }
  return list;
}

export function clearHistory(directory: string, store: Pick<Storage, 'setItem'> = localStorage): void {
  try {
    store.setItem(historyKey(directory), '[]');
  } catch {
    // nothing kept anyway
  }
}
