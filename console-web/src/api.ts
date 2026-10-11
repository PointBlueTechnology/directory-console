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

export type RoleId = 'viewer' | 'editor' | 'operator' | 'admin';

/** A role mapping's grant: a role and/or task presets, limited to containers when scopes are given. */
export interface Grant {
  role: RoleId | null;
  scopes: string[];
  presets: string[];
}

export interface Me {
  name: string;
  dn: string;
  directory: string;
  roles: RoleId[];
  grants: Grant[];
  via: 'direct' | 'break-glass' | 'oidc';
  csrf: string;
}

export interface Directory {
  id: string;
  name: string;
  direct: boolean;
  /** The single sign-on button's label, when the directory has single sign-on. */
  sso?: string;
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
  /** What the console offers the caller on this object (eDirectory may still refuse). */
  allowed?: { edit: boolean; presets: string[] };
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
  trustee?: Reference;
  entry: string[];
  allAttributes: string[];
  attribute?: { name: string; rights: string[] };
}

export interface Account {
  disabled: boolean | null;
  lockedByIntruder: boolean | null;
  intruderAttempts: number | null;
  intruderResetTime: string | null;
  loginExpires: string | null;
  maxConnections: number | null;
  lastLogin: string | null;
  passwordRequired: boolean | null;
  passwordAllowChange: boolean | null;
  passwordMinimumLength: number | null;
  passwordExpirationDays: number | null;
  passwordExpires: string | null;
  passwordUnique: boolean | null;
  graceLimit: number | null;
  graceRemaining: number | null;
  /** 84 hex digits: 7 days x 48 half-hours, Sunday first, least significant bit first in each byte. */
  timeMap: string | null;
}

export interface MembershipResult {
  group: Reference;
  member: Reference;
  status: 'ok' | 'unchanged' | 'failed';
  detail?: string;
}

export interface Members {
  dynamic: boolean;
  nested: boolean;
  memberQueryURL: string | null;
  offset: number;
  total: number;
  items: Reference[];
}

export type Target = string | { dn: string };

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
  headers?: Headers;
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
  if (!r.ok && r.status !== 207) {
    const problem: Problem = typeof parsed === 'object' && parsed !== null
      ? (parsed as Problem)
      : { type: 'about:blank', title: 'error', status: r.status, detail: `HTTP ${r.status}` };
    if (r.status === 401 && !path.startsWith('/api/v2/session')) {
      onSignedOut();
    }
    throw new ApiError(r.status, problem);
  }
  return { data: parsed as T, etag: r.headers.get('ETag') ?? undefined, headers: r.headers };
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
    rights: (guid: string, trustee?: string, attribute?: string) => {
      const p = new URLSearchParams();
      if (trustee) {
        p.set('trustee', trustee);
      }
      if (attribute) {
        p.set('attribute', attribute);
      }
      return request<Rights>('GET', `${obj(guid)}/rights?${p}`).then((r) => r.data);
    },
    password: (guid: string, password: string, mustChange: boolean) => request<void>('POST', `${obj(guid)}/password`, { password, mustChange }),
    account: (guid: string) => request<Account>('GET', `${obj(guid)}/account`),
    updateAccount: (guid: string, etag: string, change: Partial<Account>) => request<Account>('PATCH', `${obj(guid)}/account`, change, { 'If-Match': etag }),
    unlock: (guid: string) => request<Account>('POST', `${obj(guid)}/unlock`, {}),
    memberships: (guid: string) => request<{ items: (Reference & { securityEquivalent: boolean })[]; total: number }>('GET', `${obj(guid)}/memberships`).then((r) => r.data),
    changeMemberships: (guid: string, add: Target[], remove: Target[]) =>
      request<{ results: MembershipResult[] }>('POST', `${obj(guid)}/memberships`, { add, remove }).then((r) => r.data.results),
    members: (guid: string, offset = 1, count = 100) => request<Members>('GET', `${obj(guid)}/members?offset=${offset}&count=${count}`).then((r) => r.data),
    changeMembers: (guid: string, add: Target[], remove: Target[]) =>
      request<{ results: MembershipResult[] }>('POST', `${obj(guid)}/members`, { add, remove }).then((r) => r.data.results),
    subtree: (guid: string) => request<{ count: number; capped: boolean }>('GET', `${obj(guid)}/subtree`).then((r) => r.data),
    removeSubtree: (guid: string, etag: string, count: number) =>
      request<{ deleted: number }>('DELETE', `${obj(guid)}?subtree=true`, undefined, { 'If-Match': etag, 'X-Confirm-Count': String(count) }).then((r) => r.data),
    search: (s: SearchRequest) => request<Page<Row | DirObject>>('POST', `${base}/search`, s).then((r) => r.data),
    modify: (guid: string, etag: string, changes: Change[]) => request<DirObject>('PATCH', obj(guid), { changes }, { 'If-Match': etag }),
    create: (parent: string, objectClass: string | string[], name: Rdn, attributes: Record<string, unknown[]>) =>
      request<DirObject>('POST', `${obj(parent)}/children`, { objectClass, name, attributes }),
    rename: (guid: string, etag: string, name: string, leaveAlias = false) =>
      request<DirObject>('POST', `${obj(guid)}/rename`, { name, leaveAlias }, { 'If-Match': etag }),
    move: (guid: string, etag: string, newParent: string, leaveAlias = false) =>
      request<DirObject>('POST', `${obj(guid)}/move`, { newParent, leaveAlias }, { 'If-Match': etag }),
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
  stepUp: (password: string) => request<void>('POST', '/api/v2/session/step-up', { password }),
  /** Single sign-on starts with a full-page navigation (the provider's page), not a request. */
  ssoUrl: (directory: string, next = '/') => `/api/v2/oidc/start?directory=${encodeURIComponent(directory)}&next=${encodeURIComponent(next)}`,
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

const USER_CLASSES = ['inetorgperson', 'organizationalperson', 'person', 'user'];
const GROUP_CLASSES = ['groupofnames', 'group', 'groupofuniquenames', 'dynamicgroup'];

export function isUser(o: Pick<Row, 'objectClasses'>): boolean {
  return o.objectClasses.some((c) => USER_CLASSES.includes(c.toLowerCase()));
}

export function isGroup(o: Pick<Row, 'objectClasses'>): boolean {
  return o.objectClasses.some((c) => GROUP_CLASSES.includes(c.toLowerCase()) || c.toLowerCase() === 'dynamicgroupaux');
}

// ---- Identity Manager (Phase 4) ----------------------------------------------------------------

export interface IdmStatus {
  available: boolean;
  problem?: string;
  engineVersion?: string | null;
}

export interface DriverRow {
  guid: string | null;
  name: string;
  dn: string;
  state: string;
  startOption: string;
  cacheSize: string;
  unprocessedSize: string;
  traceLevel: string | null;
}

export interface DriverSet extends Identity {
  drivers: DriverRow[];
}

export interface Job {
  name: string;
  dn: string;
  owner: string;
  driver: string | null;
  javaClass: string;
  disabled: boolean;
  servers: number;
  running: string;
  config: string;
  scheduled: string;
  nextRun: string;
}

export type PasswordKind = 'named' | 'remote-loader' | 'key' | 'keystore';

/** Identity Manager for one directory. {@code confirm}: the directory's name, typed for a production directory. */
export function idm(id: string) {
  const base = `/api/v2/trees/${encodeURIComponent(id)}/idm`;
  const h = (confirm?: string): Record<string, string> => (confirm ? { 'X-Confirm-Directory': confirm } : {});
  const get = <T>(p: string) => request<T>('GET', base + p).then((r) => r.data);
  return {
    status: () => get<IdmStatus>(''),
    driverSets: () => get<{ items: Row[] }>('/driversets').then((r) => r.items),
    driverSet: (guid: string) => get<DriverSet>(`/driversets/${guidPath(guid)}`),
    setPart: <T>(guid: string, part: 'activation' | 'servers' | 'jobs' | 'log-level' | 'passwords') => get<T>(`/driversets/${guidPath(guid)}/${part}`),
    driver: (guid: string) => get<Record<string, unknown> & Identity>(`/drivers/${guidPath(guid)}`),
    driverPart: <T>(guid: string, part: string) => get<T>(`/drivers/${guidPath(guid)}/${part}`),
    lifecycle: (guid: string, action: 'start' | 'stop' | 'restart', confirm?: string) =>
      request<{ before: string; after: string; seen: string; error?: string }>('POST', `${base}/drivers/${guidPath(guid)}/${action}`, {}, h(confirm)).then((r) => r.data),
    startOption: (guid: string, option: 'auto' | 'manual' | 'disabled', confirm?: string) =>
      request<{ before: string; after: string }>('PUT', `${base}/drivers/${guidPath(guid)}/start-option`, { option }, h(confirm)).then((r) => r.data),
    logLevel: (guid: string, level: number | null, events: number[] | null, confirm?: string) =>
      request<unknown>('PUT', `${base}/drivers/${guidPath(guid)}/log-level`, { level, events }, h(confirm)).then((r) => r.data),
    clearCache: (guid: string, confirm?: string) => request<unknown>('POST', `${base}/drivers/${guidPath(guid)}/cache/clear`, {}, h(confirm)).then((r) => r.data),
    resync: (guid: string, since: string | null, confirm?: string) =>
      request<unknown>('POST', `${base}/drivers/${guidPath(guid)}/resync`, since ? { since } : {}, h(confirm)).then((r) => r.data),
    job: (guid: string, action: 'start' | 'abort', confirm?: string) =>
      request<unknown>('POST', `${base}/jobs/${guidPath(guid)}/${action}`, {}, h(confirm)).then((r) => r.data),
    passwords: (kind: 'drivers' | 'driversets', guid: string) => get<{ named: string[] }>(`/${kind}/${guidPath(guid)}/passwords`),
    setPassword: (kind: 'drivers' | 'driversets', guid: string, body: { kind: PasswordKind; name?: string; displayName?: string; value: string }, confirm?: string) =>
      request<void>('POST', `${base}/${kind}/${guidPath(guid)}/passwords`, body, h(confirm)),
    removePassword: (kind: 'drivers' | 'driversets', guid: string, body: { kind: PasswordKind; name?: string }, confirm?: string) =>
      request<void>('DELETE', `${base}/${kind}/${guidPath(guid)}/passwords`, body, h(confirm)),
    objectAssociations: (guid: string) => get<Record<string, unknown>>(`/objects/${guidPath(guid)}/associations`),
  };
}

export type Idm = ReturnType<typeof idm>;

// ---- Task presets and settings (Phase 3) -------------------------------------------------------

export type PresetAction = 'password' | 'unlock' | 'enable' | 'disable' | 'attributes';

export interface PresetField {
  name: string;
  label: string;
  required: boolean;
  readOnly: boolean;
  pattern?: string;
  value?: string;
}

export interface Preset {
  id: string;
  name: string;
  description?: string;
  objectClass: string;
  actions: PresetAction[];
  attributes: PresetField[];
  /** Where the caller may run it; empty means anywhere. */
  scopes?: string[];
}

export interface PresetRun {
  password?: string;
  mustChange?: boolean;
  unlock?: boolean;
  enabled?: boolean;
  attributes?: Record<string, string | null>;
}

export function presets(id: string) {
  const base = `/api/v2/trees/${encodeURIComponent(id)}`;
  return {
    list: () => request<Preset[]>('GET', `${base}/presets`).then((r) => r.data),
    run: (guid: string, preset: string, body: PresetRun) =>
      request<{ changed: string[] }>('POST', `${base}/objects/${guidPath(guid)}/presets/${encodeURIComponent(preset)}`, body).then((r) => r.data),
  };
}

export interface RoleMappingJson {
  group: string;
  role?: RoleId;
  scopes: string[];
  presets: string[];
}

export interface OidcSettings {
  issuer: string;
  clientId: string;
  clientSecret?: string | false;
  clientSecretSet?: boolean;
  scopes?: string;
  groupsClaim?: string;
  label?: string;
  claim?: string;
  attribute?: string;
  searchBases?: string[];
  objectClasses?: string[];
  roles?: RoleMappingJson[];
  neverProxy?: string[];
}

export interface DirectorySettings {
  id: string;
  name: string;
  tier: string;
  directLogin: boolean;
  serviceAccount: string | null;
  breakGlass: string[];
  roles: RoleMappingJson[];
  presets: Preset[];
  oidc: OidcSettings | null;
  redirectUri: string;
}

/** A directory's sign-in and authorization settings (admins; changes need a recent sign-in). */
export function settings(id: string) {
  const base = `/api/v2/directories/${encodeURIComponent(id)}`;
  const put = (part: string, body: unknown, etag?: string) =>
    request<DirectorySettings>('PUT', `${base}/${part}`, body, etag ? { 'If-Match': etag } : {});
  return {
    get: () => request<DirectorySettings>('GET', `${base}/settings`),
    roles: (roles: RoleMappingJson[], etag?: string) => put('roles', roles, etag),
    presets: (all: Record<string, unknown>, etag?: string) => put('presets', all, etag),
    exportPresets: () => request<Record<string, unknown>>('GET', `${base}/presets`).then((r) => r.data),
    oidc: (o: OidcSettings | null, etag?: string) => put('oidc', o, etag),
    testMapping: (value: string) => request<{ matches: string[]; neverProxy: boolean }>('POST', `${base}/oidc/test`, { value }).then((r) => r.data),
  };
}

// ---- eDirectory administration (Phase 5) -------------------------------------------------------

export type ReplicaType = 'master' | 'read-write' | 'read-only' | 'subordinate-reference' | 'sparse-write' | 'sparse-read';

export interface EdirServer extends Identity {
  version: string | null;
  dsRevision: string | null;
  status: string | null;
  connected: boolean;
  addresses: string[];
  ldapServer: { dn: string; guid: string } | null;
}

export interface ReplicaState {
  type: ReplicaType | string;
  state: string;
  transition: string | null;
  busy: boolean;
  modified: string | null;
  error?: string;
}

export interface EdirIndex {
  name: string;
  rule: 'value' | 'presence' | 'substring' | string;
  type: 'user' | 'attribute-creation' | 'system' | 'operational' | string;
  state: string;
  attributes: string[];
  removable: boolean;
}

export interface EdirServerDetail extends EdirServer {
  replicas: (ReplicaState & { partition: { dn: string; name: string; id: string | null } })[];
  indexes: EdirIndex[];
}

export interface EdirPartition {
  dn: string;
  name: string;
  /** The root's GUID, or "root" for the tree root. */
  id: string | null;
  entries: number | null;
  busy: boolean;
  replicas: (ReplicaState & { server: { dn: string; name: string; guid: string } })[];
}

/** eDirectory administration for one directory. {@code confirm}: the directory's name, typed for a production directory. */
export function edir(id: string) {
  const base = `/api/v2/trees/${encodeURIComponent(id)}/edir`;
  const h = (confirm?: string): Record<string, string> => (confirm ? { 'X-Confirm-Directory': confirm } : {});
  const part = (p: string) => (p === 'root' ? 'root' : guidPath(p));
  return {
    servers: () => request<EdirServer[]>('GET', `${base}/servers`).then((r) => r.data),
    server: (guid: string) => request<EdirServerDetail>('GET', `${base}/servers/${guidPath(guid)}`).then((r) => r.data),
    partitions: () => request<EdirPartition[]>('GET', `${base}/partitions`).then((r) => r.data),
    split: (container: string, confirm?: string) => request<unknown>('POST', `${base}/partitions`, { container }, h(confirm)),
    merge: (p: string, confirm?: string) => request<unknown>('POST', `${base}/partitions/${part(p)}/merge`, {}, h(confirm)),
    addReplica: (p: string, server: string, type: string, confirm?: string) =>
      request<unknown>('POST', `${base}/partitions/${part(p)}/replicas`, { server, type }, h(confirm)),
    changeReplica: (p: string, server: string, type: string, confirm?: string) =>
      request<unknown>('PUT', `${base}/partitions/${part(p)}/replicas/${guidPath(server)}`, { type }, h(confirm)),
    removeReplica: (p: string, server: string, confirm?: string) =>
      request<unknown>('DELETE', `${base}/partitions/${part(p)}/replicas/${guidPath(server)}`, undefined, h(confirm)),
    addIndex: (server: string, body: { name: string; attributes: string[]; rule: string }, confirm?: string) =>
      request<EdirServerDetail>('POST', `${base}/servers/${guidPath(server)}/indexes`, body, h(confirm)).then((r) => r.data),
    removeIndex: (server: string, name: string, confirm?: string) =>
      request<EdirServerDetail>('DELETE', `${base}/servers/${guidPath(server)}/indexes/${encodeURIComponent(name)}`, undefined, h(confirm)).then((r) => r.data),
    background: (server: string, process: 'limber' | 'janitor' | 'skulker', confirm?: string) =>
      request<void>('POST', `${base}/servers/${guidPath(server)}/background`, { process }, h(confirm)),
    ldapRefresh: (confirm?: string) => request<void>('POST', `${base}/ldap-refresh`, {}, h(confirm)),
    addAttribute: (body: { name: string; oid?: string; syntax: string; singleValue: boolean; upperBound?: number; description?: string }, confirm?: string) =>
      request<unknown>('POST', `${base}/schema/attributes`, body, h(confirm)),
    addClass: (body: { name: string; oid?: string; kind: string; superior: string[]; must: string[]; may: string[]; container?: boolean; naming?: string[]; containment?: string[] }, confirm?: string) =>
      request<unknown>('POST', `${base}/schema/classes`, body, h(confirm)),
    addOptional: (cls: string, attributes: string[], confirm?: string) =>
      request<unknown>('POST', `${base}/schema/classes/${encodeURIComponent(cls)}/may`, { attributes }, h(confirm)),
    removeAttribute: (name: string, confirm?: string) => request<unknown>('DELETE', `${base}/schema/attributes/${encodeURIComponent(name)}`, undefined, h(confirm)),
    removeClass: (name: string, confirm?: string) => request<unknown>('DELETE', `${base}/schema/classes/${encodeURIComponent(name)}`, undefined, h(confirm)),
  };
}

export type Edir = ReturnType<typeof edir>;
