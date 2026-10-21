import type { Condition } from './filters';

/** Everything the Search form holds, as a search is saved. */
export interface SavedSearch {
  name: string;
  base: string;
  scope: 'subtree' | 'one';
  objectClass: string;
  conditions: Condition[];
  join: 'and' | 'or';
  advanced: boolean;
  ldapFilter: string;
  sort: string;
  columns: string;
  savedAt: string;
}

const key = (directory: string) => `dc-saved-searches:${directory}`;

/** This browser's saved searches for a directory, by name; none when storage is unavailable. */
export function loadSearches(directory: string, store: Pick<Storage, 'getItem'> = localStorage): SavedSearch[] {
  try {
    const raw = store.getItem(key(directory));
    const list = raw ? JSON.parse(raw) : [];
    return Array.isArray(list) ? list.filter((s) => s && typeof s.name === 'string').sort((a, b) => a.name.localeCompare(b.name)) : [];
  } catch {
    return [];
  }
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
