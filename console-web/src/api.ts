// The console's API (DESIGN-directory-console.md section 8). Objects are addressed by GUID; a DN is
// only ever a value in JSON or a query parameter encoded by URLSearchParams, never part of a path.

export interface Problem {
  type: string;
  title: string;
  status: number;
  detail: string;
  [extra: string]: unknown;
}

export class ApiError extends Error {
  constructor(readonly status: number, readonly problem: Problem) {
    super(problem.detail || problem.title || `HTTP ${status}`);
  }

  get code(): string {
    return this.problem.title;
  }
}

export interface Me {
  name: string;
  dn: string;
  directory: string;
  roles: string[];
  via: string;
  csrf: string;
}

export interface Directory {
  id: string;
  name: string;
}

export interface Candidate {
  choice: string;
  context: string;
  label?: string;
}

export interface Rdn {
  type: string;
  value: string;
}

export interface Identity {
  guid: string;
  dn: string;
  rdns: Rdn[][];
  name: string;
  parentDn: string;
  /** The containers above, root first. */
  ancestors: Reference[];
  display: { dot: string; slash: string };
}

export type ChildrenHint = 'yes' | 'maybe' | 'no';

export interface Row extends Identity {
  objectClass: string;
  objectClasses: string[];
  container: boolean;
  children: ChildrenHint;
  childCount?: number;
}

export type Reference = { dn: string; name: string };
export type Binary = { base64: string };
export interface Acl {
  privileges: string[];
  otherBits?: number;
  scope: 'entry' | 'subtree';
  trustee: Reference | { special: string };
  attribute: string;
}
export type Value = string | Reference | Binary | Acl;

export interface DirObject extends Row {
  attributes: Record<string, Value[]>;
  operational: Record<string, unknown>;
}

export interface Page<T> {
  offset: number;
  count: number;
  total: number;
  exact: boolean;
  items: T[];
  parent?: { guid: string; dn: string };
}

export interface SchemaClass {
  name: string;
  names: string[];
  oid: string;
  kind: 'structural' | 'auxiliary' | 'abstract';
  superiors: string[];
  container: boolean;
  containment: string[];
  naming: string[];
  must: string[];
  may: string[];
  allMust?: string[];
  allMay?: string[];
}

export interface SchemaAttribute {
  name: string;
  names: string[];
  oid: string;
  syntax: string;
  singleValue: boolean;
  readOnly: boolean;
  operational: boolean;
  binary: boolean;
  ndsName?: string;
}

export interface Rights {
  entry: string[];
  allAttributes: string[];
}

export type Change = { op: 'add' | 'remove' | 'replace'; attribute: string; values?: unknown[] };

export type Filter =
  | { and: Filter[] }
  | { or: Filter[] }
  | { not: Filter }
  | { present: string }
  | { [op in 'eq' | 'prefix' | 'suffix' | 'contains' | 'gte' | 'lte' | 'approx']?: Record<string, string> };

export interface SearchRequest {
  base?: { guid: string } | { dn: string };
  scope?: 'base' | 'one' | 'subtree';
  filter?: Filter;
  ldapFilter?: string;
  attributes?: string[];
  sort?: { attribute: string; order?: 'asc' | 'desc' };
  page?: { offset?: number; count?: number; startAt?: string };
}

export interface Reply<T> {
  data: T;
  etag?: string;
}

let csrf: string | null = null;

/** Remember the session's CSRF token; every write sends it. */
export function setCsrf(token: string | null): void {
  csrf = token;
}

/** Called when the session is gone (expired, signed out elsewhere, directory connection lost). */
let onSignedOut: () => void = () => {};
export function whenSignedOut(f: () => void): void {
  onSignedOut = f;
}

export async function request<T>(method: string, path: string, body?: unknown, headers: Record<string, string> = {},
                                  fetchImpl: typeof fetch = fetch): Promise<Reply<T>> {
  const h: Record<string, string> = { Accept: 'application/json', ...headers };
  if (body !== undefined) {
    h['Content-Type'] = 'application/json';
  }
  if (method !== 'GET' && csrf) {
    h['X-CSRF-Token'] = csrf;
  }
  const r = await fetchImpl(path, {
    method,
    headers: h,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: 'same-origin',
  });
  const text = await r.text();
  const parsed: unknown = text ? JSON.parse(text) : undefined;
  if (!r.ok) {
    const problem: Problem = typeof parsed === 'object' && parsed !== null
      ? (parsed as Problem)
      : { type: 'about:blank', title: 'error', status: r.status, detail: `HTTP ${r.status}` };
    if (r.status === 401 && path !== '/api/v2/session') {
      onSignedOut();
    }
    throw new ApiError(r.status, problem);
  }
  return { data: parsed as T, etag: r.headers.get('ETag') ?? undefined };
}

const enc = encodeURIComponent;

/** One directory's objects, for the signed-in person. */
export function tree(id: string) {
  const base = `/api/v2/trees/${enc(id)}`;
  const obj = (guid: string) => `${base}/objects/${guidPath(guid)}`;
  return {
    roots: () => request<{ items: Row[] }>('GET', `${base}/roots`).then((r) => r.data.items),
    resolve: (dn: string) => request<DirObject>('GET', `${base}/objects?${new URLSearchParams({ dn })}`),
    read: (guid: string) => request<DirObject>('GET', obj(guid)),
    children: (guid: string, q: { offset?: number; count?: number; startAt?: string; kind?: 'all' | 'containers' | 'leaves' } = {}) => {
      const p = new URLSearchParams();
      Object.entries(q).forEach(([k, v]) => v !== undefined && v !== '' && p.set(k, String(v)));
      return request<Page<Row>>('GET', `${obj(guid)}/children?${p}`).then((r) => r.data);
    },
    rights: (guid: string) => request<Rights>('GET', `${obj(guid)}/rights`).then((r) => r.data),
    search: (s: SearchRequest) => request<Page<Row | DirObject>>('POST', `${base}/search`, s).then((r) => r.data),
    modify: (guid: string, etag: string, changes: Change[]) => request<DirObject>('PATCH', obj(guid), { changes }, { 'If-Match': etag }),
    create: (parent: string, objectClass: string | string[], name: Rdn, attributes: Record<string, unknown[]>) =>
      request<DirObject>('POST', `${obj(parent)}/children`, { objectClass, name, attributes }),
    rename: (guid: string, etag: string, name: string) => request<DirObject>('POST', `${obj(guid)}/rename`, { name }, { 'If-Match': etag }),
    move: (guid: string, etag: string, newParent: string) => request<DirObject>('POST', `${obj(guid)}/move`, { newParent }, { 'If-Match': etag }),
    remove: (guid: string, etag: string) => request<void>('DELETE', obj(guid), undefined, { 'If-Match': etag }),
    classes: () => request<SchemaClass[]>('GET', `${base}/schema/classes`).then((r) => r.data),
    schemaClass: (name: string) => request<SchemaClass>('GET', `${base}/schema/classes/${enc(name)}`).then((r) => r.data),
    attributes: () => request<SchemaAttribute[]>('GET', `${base}/schema/attributes`).then((r) => r.data),
  };
}

export type Tree = ReturnType<typeof tree>;

/** A GUID goes into a path only after this check: 32 lowercase hex digits, nothing else. */
export function guidPath(guid: string): string {
  if (!/^[0-9a-f]{32}$/.test(guid)) {
    throw new Error(`not a GUID: ${guid}`);
  }
  return guid;
}

export const session = {
  me: () => request<Me>('GET', '/api/v2/session').then((r) => r.data),
  directories: () => request<Directory[]>('GET', '/api/v2/directories').then((r) => r.data),
  signIn: (directory: string, name: string | undefined, password: string, choice?: string) =>
    request<Me>('POST', '/api/v2/session', { directory, name, password, choice }).then((r) => r.data),
  signOut: () => request<void>('DELETE', '/api/v2/session'),
};

export function isReference(v: Value): v is Reference {
  return typeof v === 'object' && 'dn' in v && !('privileges' in v);
}

export function isBinary(v: Value): v is Binary {
  return typeof v === 'object' && 'base64' in v;
}

export function isAcl(v: Value): v is Acl {
  return typeof v === 'object' && 'privileges' in v;
}
