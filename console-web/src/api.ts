// The console's API. Objects are addressed by GUID; a DN is
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
  via: 'direct' | 'break-glass' | 'oidc' | 'user-directory';
  csrf: string;
  /** How long the session may sit idle, and when it ends however active it is (the tree's limits). */
  session?: { idleSeconds: number; expiresAt: string };
}

/** A PKCS#12 export: its password, and PBES2 (AES) or the older PBES1 for software that cannot read PBES2. */
export interface KeyExport {
  password: string;
  scheme: 'pbes2' | 'pbes1';
}

/** The exported file, base64-encoded, and a name for it. */
export interface ExportedKey {
  fileName: string;
  pkcs12: string;
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
/** A secret attribute (a private key, a login secret): the console says it is set, never what it is. */
export type Withheld = { withheld: number };
export type Value = string | Reference | Binary | Acl | Withheld;

export function isWithheld(v: Value): v is Withheld {
  return typeof v === 'object' && 'withheld' in v;
}

export interface DirObject extends Row {
  attributes: Record<string, Value[]>;
  operational: Record<string, unknown>;
  /** The server that answered. */
  servedBy?: { dn: string };
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
  /** The class's eDirectory (NDAP) name when it differs from the LDAP name. */
  ndsName?: string;
  /** False for eDirectory's base schema (X-NDS_NONREMOVABLE). */
  removable?: boolean;
  /** eDirectory's X-NDS_* flags that are set. */
  ndsFlags?: string[];
}

export interface SchemaAttribute {
  /** Never synchronized: each server keeps its own value. */
  perReplica?: boolean;
  name: string;
  names: string[];
  oid: string;
  syntax: string;
  singleValue: boolean;
  readOnly: boolean;
  operational: boolean;
  binary: boolean;
  ndsName?: string;
  /** False for eDirectory's base schema (X-NDS_NONREMOVABLE). */
  removable?: boolean;
  /** eDirectory's X-NDS_* flags that are set. */
  ndsFlags?: string[];
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
  /** Where the last failed login counted towards lockout came from. */
  intruderAddress?: string | null;
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
  if (token === null) {
    limits = null;
  }
}

/** When the console last answered a request: each answer restarts the session's idle timer. */
let lastAnswer = Date.now();
export function lastServerContact(): number {
  return lastAnswer;
}

/** The session's limits as the console last sent them (headers on every signed-in answer); null before any. */
let limits: { idleSeconds: number; expiresAt: string } | null = null;
export function sessionLimits(): { idleSeconds: number; expiresAt: string } | null {
  return limits;
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
  if (r.status !== 401 && r.status !== 503) {
    lastAnswer = Date.now();
  }
  const idle = r.headers.get('X-Session-Idle-Seconds');
  const expires = r.headers.get('X-Session-Expires');
  if (idle && expires) {
    limits = { idleSeconds: Number(idle), expiresAt: expires };
  }
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
    read: (guid: string, server?: string) => request<DirObject>('GET', server ? `${obj(guid)}?server=${encodeURIComponent(server)}` : obj(guid)),
    /** The servers holding a replica of this object. */
    servers: (guid: string) => request<ServerChoice[]>('GET', `${obj(guid)}/servers`).then((r) => r.data),
    /** This object as each replica has it. */
    compare: (guid: string) => request<ObjectComparison>('GET', `${obj(guid)}?server=all`).then((r) => r.data),
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

/** Setup (bootstrap mode): every call carries the one-time setup token from the console's log. */
export const setup = {
  /** Checks the token: the console certificate's fingerprint and what is set up so far. */
  state: (token: string) => request<{ consoleCertificate: { sha256: string; names: string[] } }>('GET', '/api/v2/setup', undefined, { 'X-Setup-Token': token }).then((r) => r.data),
  /** The whole of setup in one step: the tree, its certificate and a tree administrator; then sign in as usual. */
  firstSignIn: (token: string, body: { host: string; port: number; dn: string; password: string; accept?: { probeId: string; confirm: string; index?: number } }) =>
    request<{ configured: boolean; directory: string }>('POST', '/api/v2/setup/first-sign-in', body, { 'X-Setup-Token': token }).then((r) => r.data),
};

export const session = {
  me: () => request<Me>('GET', '/api/v2/session').then((r) => r.data),
  directories: () => request<Directory[]>('GET', '/api/v2/directories').then((r) => r.data),
  /** Whether people may sign in to directories they enter themselves. */
  signInOptions: () => request<{ otherDirectories: boolean }>('GET', '/api/v2/sign-in/options').then((r) => r.data),
  /** Sign in to a directory by address; {@code accept} carries a certificate the person confirmed on the previous try. */
  signInOther: (host: string, port: number, name: string, password: string, accept?: { probeId: string; confirm: string; index?: number }) =>
    request<Me>('POST', '/api/v2/session/other', { host, port, name, password, accept }).then((r) => r.data),
  signIn: (directory: string, name: string | undefined, password: string, choice?: string) =>
    request<Me>('POST', '/api/v2/session', { directory, name, password, choice }).then((r) => r.data),
  signOut: () => request<void>('DELETE', '/api/v2/session'),
  stepUp: (password: string) => request<void>('POST', '/api/v2/session/step-up', { password }),
  /** Sign in to another server of the tree, as the same person, for its replica (direct sign-in). */
  signInServer: (server: string, password: string) =>
    request<{ server: { guid: string; name: string }; idm: boolean }>('POST', '/api/v2/session/servers', { server, password }).then((r) => r.data),
  /** Single sign-on starts with a full-page navigation (the provider's page), not a request. */
  ssoUrl: (directory: string, next = '/') => `/api/v2/oidc/start?directory=${encodeURIComponent(directory)}&next=${encodeURIComponent(next)}`,
};

export function isReference(v: Value): v is Reference {
  return typeof v === 'object' && 'dn' in v && !('privileges' in v) && !('withheld' in v);
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

// ---- Identity Manager ----------------------------------------------------------------

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

/** One entry of a configuration-values document: a header or a value, at a depth (subordinates are deeper); inactive under an unchosen option. */
export interface ConfigItem {
  kind: 'header' | 'value';
  depth: number;
  name?: string;
  label?: string | null;
  type?: string;
  value?: string | null;
  description?: string | null;
  inactive: boolean;
}

export interface DriverProperties {
  general: { javaModule: string | null; nativeModule: string | null; package: string | null; cacheLimit: string | null; securityEquals: string[] };
  authentication: { id: string | null; server: string | null; remoteLoader?: Record<string, string>; passwordSet: boolean };
  parameters: { section: string; items: ConfigItem[] }[];
  gcvs: { source: string; items: ConfigItem[] }[];
  engineControlValues: ConfigItem[];
  filter: { name: string; publisher: string; subscriber: string; attributes: { name: string; publisher: string; subscriber: string }[] }[];
  policies: { dn: string; name: string; set: string; setNumber: number; order: number }[];
}

/** Version discovery for one server: the engine now, and what the statistics job last collected there. */
export interface Versions {
  server: { dn: string; name: string };
  engineVersion: string | null;
  statisticsJobFound: boolean;
  collected: {
    when: string | null; whenText: string | null; product: string | null; version: string | null; edition: string | null; patch: string | null;
    host: string | null; hostIp: string | null; os: string | null; hostType: string | null; job: { dn: string; name: string };
    drivers: { name: string | null; version: string | null; driverId: string | null; usage?: { active: number | null; inactive: number | null; system: number | null; total: number | null } }[];
  } | null;
  packages: { driver: string; package: string | null; packageVersion: string | null }[];
}

export interface CacheSummary { size?: number | null; unprocessedSize?: number | null; oldest?: string | null; newest?: string | null; counts?: Record<string, number> }
export interface CacheEvent { position: number; type: string; className: string | null; srcDn: string | null; eventId: string | null; cachedTime: string | null; attributes: string[]; xml: string | null }
export interface CacheEvents { events: CacheEvent[]; next: number | null }

export interface ChannelStats { lastReset: string | null; groups: Record<string, Record<string, number>> }
export interface DriverSetStatistics {
  server: { dn: string; name: string };
  jvm: { heapUsed: string; heapCommitted: string; heapTotal: string; threadsCurrent: string; threadsDaemon: string; threadsPeak: string } | null;
  drivers: { guid: string | null; name: string; state?: string; error?: string; cache?: CacheSummary | null; subscriber?: ChannelStats; publisher?: ChannelStats }[];
}

export interface DriverSetProperties {
  javaEnvironment: { name: string; value: string }[];
  servers: string[];
  logLimit: string | null;
  passwordPolicy: string | null;
  package: string | null;
  gcvs: { source: string; items: ConfigItem[] }[];
  policies: { dn: string; name: string; set: string; setNumber: number; order: number }[];
}

export interface MigrateResult {
  ok: boolean;
  dryRun?: boolean;
  count?: number;
  objects?: string[];
  results?: { dn: string; ok: boolean; status: string }[];
  sent?: number;
  succeeded?: number;
  failed?: number;
  error?: string;
}

export type MappingColumnType = 'case' | 'nocase' | 'numeric' | 'interval-closed' | 'interval-open' | 'interval-rightopen' | 'interval-leftopen';
export interface MappingColumn { name: string; type: MappingColumnType | string }
export interface MappingTableRef extends Omit<Identity, 'guid'> {
  guid: string | null;
  owner: { dn: string; name: string; kind: 'driver set' | 'driver' | 'library' | 'subscriber' | 'publisher' | 'container' };
  /** The package it came from, when it did. */
  package: string | null;
}
export interface MappingTable extends MappingTableRef {
  version: string;
  columns: MappingColumn[];
  rows: string[][];
}

export interface JobParameter {
  name: string;
  label: string;
  description: string | null;
  type: 'boolean' | 'string' | 'integer' | 'enum' | 'list' | 'dn' | 'dn-ref' | 'password-ref' | string;
  value: string | string[];
  choices?: { value: string; label: string }[];
  depth: number;
  /** Shown under this parameter, and used only while it has activeValue. */
  parent?: string;
  activeValue?: string;
}

export interface JobType {
  type: string;
  displayName: string;
  description: string | null;
  schedule: string | null;
  scopeRequired: boolean;
  parameters: JobParameter[];
}

export type JobScopeKind = 'entry' | 'subordinates' | 'subtree' | 'members';

export interface NewJob {
  type: string;
  name: string;
  disabled: boolean;
  schedule: string | null;
  servers: string[];
  scope: { dn: string; scope: JobScopeKind }[];
  parameters: Record<string, string | string[]>;
}

export interface JobDefinition extends Identity {
  owner: { dn: string; name: string; kind: 'driver' | 'driver set' };
  /** A hash of the job's XmlData: a change carries it back. */
  version: string;
  displayName?: string;
  description?: string;
  javaClass?: string;
  disabled?: boolean;
  /** Cron: minute hour day-of-month month day-of-week; null when it has none. */
  schedule?: string | null;
  scopeRequired?: boolean;
  parameters?: { name: string; label: string; type: string; value?: string }[];
  servers: { dn: string; name: string }[];
  scope: { raw: string; dn?: string; scope?: string | null }[];
}

export type PasswordKind = 'named' | 'remote-loader' | 'key' | 'keystore';

/** Trace settings. A driver has level, file, name, encoding and sizeLimitKb, and its driver set's beside them; a driver set has level, xslLevel, javaDebugPort, file, encoding and sizeLimitKb. */
export interface TraceSettings {
  level?: number | null;
  xslLevel?: number | null;
  javaDebugPort?: number | null;
  file?: string | null;
  name?: string | null;
  encoding?: string | null;
  /** KB; 0 is unlimited. */
  sizeLimitKb?: number | null;
  driverSet?: TraceSettings | null;
}

export type AssociationState = 'disabled' | 'processed' | 'pending' | 'manual' | 'migrate';

export interface IdmDriverRef { guid: string | null; dn: string; name: string; driverSet: { dn: string; name: string } }

export interface ObjectAssociations {
  object: Identity & { guid: string; objectClasses: string[] };
  /** One per driver; {@code driver} null when no driver has that DN any more. */
  associations: { raw: string; driver?: IdmDriverRef | null; driverDn?: string; state?: AssociationState | string; value?: string }[];
  drivers: IdmDriverRef[];
  /** Each driver's last password synchronization for this object, as the engine records it (DirXML-PasswordSyncStatus). */
  passwordSync: { raw: string; driverGuid?: string; driver?: IdmDriverRef | null; when?: string; code?: number; status?: string; message?: string }[];
}

/** Identity Manager for one directory, on {@code server}'s engine (its GUID) or the connected server's. {@code confirm}: the directory's name, typed for a production directory. */
export function idm(id: string, server?: string) {
  const base = `/api/v2/trees/${encodeURIComponent(id)}/idm`;
  const h = (confirm?: string): Record<string, string> => (confirm ? { 'X-Confirm-Directory': confirm } : {});
  // every driver operation runs on one server's engine and replica (state, start and stop, start option, jobs,
  // cache, passwords): send the chosen server along; none is the connected server
  const at = (p: string, on = server) => (on ? `${p}${p.includes('?') ? '&' : '?'}server=${encodeURIComponent(on)}` : p);
  const get = <T>(p: string) => request<T>('GET', at(base + p)).then((r) => r.data);
  return {
    status: () => get<IdmStatus>(''),
    driverSets: () => get<{ items: Row[] }>('/driversets').then((r) => r.items),
    driverSet: (guid: string) => get<DriverSet>(`/driversets/${guidPath(guid)}`),
    setPart: <T>(guid: string, part: 'activation' | 'servers' | 'jobs' | 'log-level' | 'passwords' | 'versions' | 'statistics') => get<T>(`/driversets/${guidPath(guid)}/${part}`),
    driver: (guid: string) => get<Record<string, unknown> & Identity>(`/drivers/${guidPath(guid)}`),
    driverPart: <T>(guid: string, part: string) => get<T>(`/drivers/${guidPath(guid)}/${part}`),
    lifecycle: (guid: string, action: 'start' | 'stop' | 'restart', confirm?: string) =>
      request<{ before: string; after: string; seen: string; error?: string }>('POST', at(`${base}/drivers/${guidPath(guid)}/${action}`), {}, h(confirm)).then((r) => r.data),
    startOption: (guid: string, option: 'auto' | 'manual' | 'disabled', confirm?: string) =>
      request<{ before: string; after: string }>('PUT', at(`${base}/drivers/${guidPath(guid)}/start-option`), { option }, h(confirm)).then((r) => r.data),
    logLevel: (guid: string, level: number | null, events: number[] | null, confirm?: string) =>
      request<unknown>('PUT', at(`${base}/drivers/${guidPath(guid)}/log-level`), { level, events }, h(confirm)).then((r) => r.data),
    /** The cache in summary (size, oldest and newest, counts by type): from the driver statistics, for a running driver too. */
    cacheSummary: (guid: string) => get<CacheSummary>(`/drivers/${guidPath(guid)}/cache/summary`),
    /** Cached events from {@code position}, each with its position (a stopped driver only). */
    cacheEvents: (guid: string, position = 0, count = 25) => get<CacheEvents>(`/drivers/${guidPath(guid)}/cache/events?position=${position}&count=${count}`),
    /** Delete chosen events; each must still be the one read at its position, or it is skipped. */
    deleteCacheEvents: (guid: string, events: { position: number; eventId: string }[], confirm?: string) =>
      request<{ results: { position: number; eventId: string; status: 'deleted' | 'skipped' | 'failed'; detail?: string }[]; deleted: number }>(
        'POST', at(`${base}/drivers/${guidPath(guid)}/cache/delete`), { events }, h(confirm)).then((r) => r.data),
    clearCache: (guid: string, confirm?: string) => request<unknown>('POST', at(`${base}/drivers/${guidPath(guid)}/cache/clear`), {}, h(confirm)).then((r) => r.data),
    resync: (guid: string, since: string | null, confirm?: string) =>
      request<unknown>('POST', at(`${base}/drivers/${guidPath(guid)}/resync`), since ? { since } : {}, h(confirm)).then((r) => r.data),
    /** Vault objects to the application: with dryRun, the objects that would go; otherwise each one's outcome. */
    migrateToApp: (guid: string, body: { base: string; class: string; filter?: string; max?: number; dryRun?: boolean }, confirm?: string) =>
      request<MigrateResult>('POST', at(`${base}/drivers/${guidPath(guid)}/migrate/to-app`), body, h(confirm)).then((r) => r.data),
    /** The application's objects into the vault: the engine queries the application; the results show in the driver's trace. */
    migrateFromApp: (guid: string, body: { class: string; search?: { attribute: string; value: string }[] }, confirm?: string) =>
      request<unknown>('POST', at(`${base}/drivers/${guidPath(guid)}/migrate/from-app`), body, h(confirm)).then((r) => r.data),
    job: (guid: string, action: 'start' | 'abort', confirm?: string) =>
      request<unknown>('POST', at(`${base}/jobs/${guidPath(guid)}/${action}`), {}, h(confirm)).then((r) => r.data),
    /** A driver set's properties, read-only: Java environment, servers, log limit, GCVs and linked objects. */
    driverSetProperties: (guid: string) => request<DriverSetProperties>('GET', `${base}/driversets/${guidPath(guid)}/properties`).then((r) => r.data),
    /** A driver's properties, read-only: shim, authentication, parameters, GCVs, ECVs, filter and policies. */
    driverProperties: (guid: string) => request<DriverProperties>('GET', `${base}/drivers/${guidPath(guid)}/properties`).then((r) => r.data),
    /** The mapping tables under a driver set, driver or library (or the whole tree). */
    mappingTables: (under?: string) =>
      request<{ items: MappingTableRef[] }>('GET', `${base}/mapping-tables${under ? `?under=${encodeURIComponent(under)}` : ''}`).then((r) => r.data.items),
    mappingTable: (guid: string) => request<MappingTable>('GET', `${base}/mapping-tables/${guidPath(guid)}`).then((r) => r.data),
    /** Save a table whole, as read at {@code version}; refused (409) when it changed meanwhile. */
    saveMappingTable: (guid: string, body: { version: string; columns: MappingColumn[]; rows: string[][] }, confirm?: string) =>
      request<MappingTable>('PUT', `${base}/mapping-tables/${guidPath(guid)}`, body, h(confirm)).then((r) => r.data),
    createMappingTable: (body: { parent: string; name: string; columns: MappingColumn[]; rows: string[][] }, confirm?: string) =>
      request<MappingTable>('POST', `${base}/mapping-tables`, body, h(confirm)).then((r) => r.data),
    /** Delete a table; {@code name} is its name, typed. */
    deleteMappingTable: (guid: string, name: string, confirm?: string) =>
      request<void>('DELETE', `${base}/mapping-tables/${guidPath(guid)}`, { name }, h(confirm)),
    /** A job's definition, servers and scope (read over LDAP). */
    /** The job types the chosen server's engine offers for a driver or driver set. */
    jobTypes: (kind: 'drivers' | 'driversets', guid: string) => get<{ server: { dn: string; name: string }; types: JobType[] }>(`/${kind}/${guidPath(guid)}/job-types`),
    /** A new job of one of those types under the driver or driver set. */
    createJob: (kind: 'drivers' | 'driversets', guid: string, body: NewJob, confirm?: string) =>
      request<JobDefinition & { guid: string | null; notified: boolean }>('POST', at(`${base}/${kind}/${guidPath(guid)}/jobs`), body, h(confirm)).then((r) => r.data),
    jobDefinition: (guid: string) => request<JobDefinition>('GET', `${base}/jobs/${guidPath(guid)}/definition`).then((r) => r.data),
    /** Change a job, as read at {@code version}; refused (409) when it changed meanwhile. A null schedule removes it. */
    changeJob: (guid: string, body: { version: string; disabled?: boolean; schedule?: string | null; servers?: string[] }, confirm?: string) =>
      request<JobDefinition>('PATCH', `${base}/jobs/${guidPath(guid)}/definition`, body, h(confirm)).then((r) => r.data),
    /** Delete a job; {@code name} is its name, typed. */
    deleteJob: (guid: string, name: string, confirm?: string) => request<void>('DELETE', `${base}/jobs/${guidPath(guid)}`, { name }, h(confirm)),
    passwords: (kind: 'drivers' | 'driversets', guid: string) => get<{ named: string[] }>(`/${kind}/${guidPath(guid)}/passwords`),
    setPassword: (kind: 'drivers' | 'driversets', guid: string, body: { kind: PasswordKind; name?: string; displayName?: string; value: string }, confirm?: string) =>
      request<void>('POST', at(`${base}/${kind}/${guidPath(guid)}/passwords`), body, h(confirm)),
    removePassword: (kind: 'drivers' | 'driversets', guid: string, body: { kind: PasswordKind; name?: string }, confirm?: string) =>
      request<void>('DELETE', at(`${base}/${kind}/${guidPath(guid)}/passwords`), body, h(confirm)),
    /** Trace settings: a driver's (null: the driver set's applies) with the driver set's beside them, or a driver set's. */
    trace: (kind: 'drivers' | 'driversets', guid: string) => request<TraceSettings>('GET', `${base}/${kind}/${guidPath(guid)}/trace`).then((r) => r.data),
    /** Each named setting: a value, or null to remove it (a driver then uses the driver set's). */
    setTrace: (kind: 'drivers' | 'driversets', guid: string, body: Partial<Record<keyof TraceSettings, string | number | null>>, confirm?: string) =>
      request<TraceSettings>('PUT', `${base}/${kind}/${guidPath(guid)}/trace`, body, h(confirm)).then((r) => r.data),
    /** The object inspector: an object's associations, read over LDAP (no engine needed), and the tree's drivers. */
    associations: (guid: string) => request<ObjectAssociations>('GET', `${base}/objects/${guidPath(guid)}/associations`).then((r) => r.data),
    addAssociation: (guid: string, body: { driver: string; state: AssociationState; value: string }, confirm?: string) =>
      request<ObjectAssociations>('POST', `${base}/objects/${guidPath(guid)}/associations`, body, h(confirm)).then((r) => r.data),
    /** Change one association, named by its value as read ({@code raw}); refused (409) when that value has changed meanwhile. */
    changeAssociation: (guid: string, body: { raw: string; state?: AssociationState; value?: string }, confirm?: string) =>
      request<ObjectAssociations>('PATCH', `${base}/objects/${guidPath(guid)}/associations`, body, h(confirm)).then((r) => r.data),
    removeAssociation: (guid: string, raw: string, confirm?: string) =>
      request<ObjectAssociations>('DELETE', `${base}/objects/${guidPath(guid)}/associations`, { raw }, h(confirm)).then((r) => r.data),
    /** The servers that run this driver's driver set. */
    driverServers: (guid: string) => request<ServerChoice[]>('GET', `${base}/drivers/${guidPath(guid)}/servers`).then((r) => r.data),
    /** The servers that run a driver set, to choose which one the operations run on. */
    driverSetServers: (guid: string) => request<ServerChoice[]>('GET', `${base}/driversets/${guidPath(guid)}/server-choices`).then((r) => r.data),
    /** The driver's state and start option on each of those servers. */
    compareDriver: (guid: string) => request<Comparison<{ state?: string; startOption?: string; cacheSize?: string; unprocessedSize?: string }>>(
      'GET', at(`${base}/drivers/${guidPath(guid)}`, 'all')).then((r) => r.data),
    comparePasswords: (kind: 'drivers' | 'driversets', guid: string) => request<Comparison<{ named?: string[] }>>(
      'GET', at(`${base}/${kind}/${guidPath(guid)}/passwords`, 'all')).then((r) => r.data),
  };
}

export type Idm = ReturnType<typeof idm>;

/** A server an operation can run on: {@code connected} is the session's own; {@code signedIn} needs no further sign-in. */
export interface ServerChoice {
  guid: string;
  dn: string;
  name: string;
  type?: string;
  connected: boolean;
  signedIn: boolean;
}

/** One value per server (server=all): {@code status} is "ok", or why that server could not answer. */
export interface Comparison<T> {
  dn: string;
  servers: (T & { server: { guid: string; dn: string; name: string; type?: string }; status: string; detail?: string })[];
}

export interface ObjectComparison extends Comparison<{ revision?: unknown }> {
  /** Per-replica attributes, and any attribute whose values differ between servers; values by server GUID. */
  attributes: { name: string; perReplica: boolean; differs: boolean; values: Record<string, Value[]> }[];
}

// ---- Task presets and settings -------------------------------------------------------

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
  login: { searchBases: string[]; duplicates: 'choose' | 'error' };
  session: { idleMinutes: number; maxHours: number };
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
    tier: (tier: 'production' | 'lab', etag?: string) => put('tier', { tier }, etag),
    login: (login: { searchBases: string[]; duplicates: 'choose' | 'error' }, etag?: string) => put('login', login, etag),
    /** Checked by signing in as it; null removes it. */
    serviceAccount: (account: { dn: string; password: string } | null, etag?: string) => put('service-account', account, etag),
    /** Idle timeout and longest session for this tree; applies at once, to open sessions too. */
    sessionLimits: (limits: { idleMinutes: number; maxHours: number }, etag?: string) => put('session', limits, etag),
  };
}

// ---- eDirectory administration -------------------------------------------------------

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

/** Flags a new attribute may have (eDirectory's X-NDS_ schema flags). */
export type AttributeFlag = 'publicRead' | 'serverRead' | 'writeManaged' | 'perReplica' | 'notSyncImmediate';

export interface EdirIndex {
  name: string;
  rule: 'value' | 'presence' | 'substring' | string;
  type: 'user' | 'attribute-creation' | 'system' | 'operational' | string;
  state: 'online' | 'offline' | 'new' | 'pending' | string;
  attributes: string[];
  removable: boolean;
  /** User and auto-added indexes can be taken offline; system and operational ones cannot. */
  switchable: boolean;
}

export interface LdapServerSummary {
  guid: string;
  dn: string;
  name: string;
  host: Reference & { guid: string | null } | null;
  group: Reference & { guid: string | null } | null;
  interfaces: string[];
  tlsRequired: boolean;
  certificate: string | null;
}

export interface CefSettings {
  noReplicatedEvents: boolean;
  logLargeValues: boolean;
  logAttributeValues: boolean;
  logEncryptedAttributeValues: boolean;
  events: string[];
  objectClasses: string[];
  attributeFilter: { classes: string[]; attributes: string[] };
  exclude: { classes: string[]; attributes: string[] };
  /** Stored values the console does not understand; kept on save. */
  unknown?: string[];
}

export interface AuditConfig {
  server: Reference & { guid: string };
  /** eDirectory new enough for CEF. */
  supported: boolean;
  /** False: nothing stored, eDirectory's defaults apply. */
  configured: boolean;
  settings: CefSettings;
  /** Every event by category: security, object, attribute, ldap. */
  events: Record<string, string[]>;
  raw: string[];
}

export interface SnmpTrap { number: number; name: string; active: boolean; failure: boolean; interval: number }

export interface SnmpGroup {
  guid: string;
  dn: string;
  name: string;
  servers: (Reference & { guid: string | null })[];
  trapInterval: number | null;
  trapsDisabled: boolean;
  traps: SnmpTrap[];
}

export interface EncryptionOverview {
  policies: { guid: string; dn: string; name: string; attributes: { scheme: string; attribute: string }[]; requiresSecureChannel: boolean; servers: (Reference & { guid: string })[] }[];
  servers: (Reference & { guid: string; policy: string | null })[];
  replication: { partition: Reference & { id?: string | null }; values: { raw: string; on: boolean; wholePartition: boolean }[] }[];
}

export interface ReplicaFilter {
  server: Reference & { guid: string };
  classes: { class: string; attributes: string[] }[];
  sparseReplicas: (Reference & { type: string })[];
}

/** A mapping between an eDirectory name and its LDAP names; obsolete and description are Identity Console's own fields. */
export interface LdapMapping {
  eDirectory: string;
  ldap: string[];
  obsolete?: boolean;
  description?: string;
}

export interface TlsConfig {
  protocol: string;
  ciphers: string;
  ciphersuites: string;
}

export type LdapSettings = Record<string, boolean | number | string | string[] | LdapMapping[] | TlsConfig | null>;

export interface LdapObject {
  guid: string;
  dn: string;
  name: string;
  host?: Reference & { guid: string | null } | null;
  group?: Reference & { guid: string | null } | null;
  certificate?: string | null;
  servers?: (Reference & { guid: string | null })[];
  settings: LdapSettings;
  /** After a change: what applies it. */
  needs?: 'refresh' | 'reload';
}

export interface LdapConfigs {
  servers: LdapServerSummary[];
  groups: { guid: string; dn: string; name: string; servers: (Reference & { guid: string | null })[] }[];
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
    /** Take an index offline (for a bulk load, say) or bring it back; limber applies it. */
    indexState: (server: string, name: string, state: 'online' | 'offline', confirm?: string) =>
      request<EdirServerDetail>('PUT', `${base}/servers/${guidPath(server)}/indexes/${encodeURIComponent(name)}/state`, { state }, h(confirm)).then((r) => r.data),
    /** Put a user-defined index on other servers too; each answers copied, already-there or failed. */
    copyIndex: (server: string, name: string, servers: string[], confirm?: string) =>
      request<{ results: { server: string; name?: string; status: 'copied' | 'already-there' | 'not-a-server' | 'failed'; detail?: string }[] }>('POST',
        `${base}/servers/${guidPath(server)}/indexes/${encodeURIComponent(name)}/copy`, { servers }, h(confirm)).then((r) => r.data),
    background: (server: string, process: 'limber' | 'janitor' | 'skulker', confirm?: string) =>
      request<void>('POST', `${base}/servers/${guidPath(server)}/background`, { process }, h(confirm)),
    /** Every LDAP Server object (with its host server and group) and every LDAP Group (with its servers). */
    ldap: () => request<LdapConfigs>('GET', `${base}/ldap`).then((r) => r.data),
    /** The LDAP server re-reads its configuration, on its own host: a direct sign-in may first be asked to sign in there. */
    refreshLdapServer: (guid: string) => request<void>('POST', `${base}/ldap/servers/${guidPath(guid)}/refresh`, {}),
    /** Reload the LDAP module on the LDAP server's host: needed for TLS, cipher, port and certificate changes. It drops every LDAP connection to that server. */
    reloadLdapServer: (guid: string) => request<void>('POST', `${base}/ldap/servers/${guidPath(guid)}/reload`, {}),
    ldapServer: (guid: string) => request<LdapObject>('GET', `${base}/ldap/servers/${guidPath(guid)}`).then((r) => r.data),
    ldapGroup: (guid: string) => request<LdapObject>('GET', `${base}/ldap/groups/${guidPath(guid)}`).then((r) => r.data),
    /** Change only the settings named (null removes one). The answer says whether a refresh or a reload applies them. */
    changeLdapServer: (guid: string, settings: LdapSettings, confirm?: string) =>
      request<LdapObject>('PATCH', `${base}/ldap/servers/${guidPath(guid)}`, { settings }, h(confirm)).then((r) => r.data),
    changeLdapGroup: (guid: string, settings: LdapSettings, confirm?: string) =>
      request<LdapObject>('PATCH', `${base}/ldap/groups/${guidPath(guid)}`, { settings }, h(confirm)).then((r) => r.data),
    /** A server's CEF audit settings (eDirectory's defaults when it has none). */
    audit: (server: string) => request<AuditConfig>('GET', `${base}/servers/${guidPath(server)}/audit`).then((r) => r.data),
    changeAudit: (server: string, settings: CefSettings, confirm?: string) =>
      request<AuditConfig>('PUT', `${base}/servers/${guidPath(server)}/audit`, settings, h(confirm)).then((r) => r.data),
    /** Remove the server's CEF configuration, so eDirectory's defaults apply. */
    resetAudit: (server: string, confirm?: string) =>
      request<AuditConfig>('DELETE', `${base}/servers/${guidPath(server)}/audit`, undefined, h(confirm)).then((r) => r.data),
    snmp: () => request<{ groups: SnmpGroup[] }>('GET', `${base}/snmp`).then((r) => r.data.groups),
    changeSnmp: (group: string, body: { trapInterval?: number; trapsDisabled?: boolean; traps?: Record<number, Partial<Pick<SnmpTrap, 'active' | 'failure' | 'interval'>>> }, confirm?: string) =>
      request<SnmpGroup>('PATCH', `${base}/snmp/${guidPath(group)}`, body, h(confirm)).then((r) => r.data),
    encryption: () => request<EncryptionOverview>('GET', `${base}/encryption`).then((r) => r.data),
    createEncryptionPolicy: (body: { parent: string; name: string; attributes: { attribute: string; scheme?: string }[]; requiresSecureChannel: boolean }, confirm?: string) =>
      request<EncryptionOverview>('POST', `${base}/encryption/policies`, body, h(confirm)).then((r) => r.data),
    /** Attributes already in the policy keep their scheme unless another is named. */
    changeEncryptionPolicy: (guid: string, body: { attributes?: { attribute: string; scheme?: string }[]; requiresSecureChannel?: boolean }, confirm?: string) =>
      request<EncryptionOverview>('PATCH', `${base}/encryption/policies/${guidPath(guid)}`, body, h(confirm)).then((r) => r.data),
    deleteEncryptionPolicy: (guid: string, confirm?: string) =>
      request<EncryptionOverview>('DELETE', `${base}/encryption/policies/${guidPath(guid)}`, undefined, h(confirm)).then((r) => r.data),
    /** A server's policy (null: none), then limber there; applied is false when the policy has not reached that server yet. */
    assignEncryptionPolicy: (server: string, policy: string | null, confirm?: string) =>
      request<EncryptionOverview & { applied?: boolean }>('PUT', `${base}/servers/${guidPath(server)}/encryption-policy`, { policy }, h(confirm)).then((r) => r.data),
    /** Every filtered replica on the server resynchronises. An empty list clears the filter. */
    setReplicaFilter: (server: string, classes: { class: string; attributes: string[] }[], confirm?: string) =>
      request<ReplicaFilter>('PUT', `${base}/servers/${guidPath(server)}/replica-filter`, { classes }, h(confirm)).then((r) => r.data),
    replicaFilter: (server: string) => request<ReplicaFilter>('GET', `${base}/servers/${guidPath(server)}/replica-filter`).then((r) => r.data),
    ldapRefresh: (confirm?: string) => request<void>('POST', `${base}/ldap-refresh`, {}, h(confirm)),
    addAttribute: (body: { name: string; oid?: string; syntax: string; singleValue: boolean; upperBound?: number; description?: string; flags?: AttributeFlag[] }, confirm?: string) =>
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

// ---- Security services --------------------------------------------------------------

export interface Certificate {
  subject: string;
  issuer: string;
  serial: string;
  notBefore: string;
  notAfter: string;
  signatureAlgorithm: string;
  key: string;
  subjectAltNames: string[];
  keyUsage: string[];
  extendedKeyUsage: string[];
  ca: boolean;
  sha256: string;
  der: string;
  error?: string;
}

export interface Ref { guid?: string | null; dn: string; name: string }

export type DefaultCertificateKind = 'dns' | 'ec' | 'ip';

export interface DefaultCertificates {
  server: Ref;
  /** The console reaches the directory through this server. */
  connected: boolean;
  tree: string | null;
  /** The tree CA has an EC key, so SSL EC CertificateDNS applies. */
  ecAvailable: boolean;
  /** The server's IP addresses (from its network addresses) and the DNS names a replacement would carry. */
  ips: string[];
  dnsNames: string[];
  certificates: {
    kind: DefaultCertificateKind;
    name: string;
    applicable: boolean;
    guid: string | null;
    certificate: Certificate | null;
    /** Empty when nothing is wrong; "missing" when there is none. */
    problems: string[];
    /** LDAP servers on this server that use it. */
    usedBy: string[];
    /** Newer copies ("<name> <date>"), newest first. */
    successors: { guid: string | null; name: string; certificate: Certificate | null; usedBy: string[] }[];
  }[];
  /** This server's LDAP servers and the certificate each names. */
  ldapServers: (Ref & { certificate: string | null })[];
}

export interface DefaultCertificatesRequest {
  replace: 'invalid' | 'all';
  kinds: DefaultCertificateKind[];
  dnsNames?: string[];
  ips?: string[];
  validityYears?: number;
}

export interface DefaultCertificateResult {
  kind: DefaultCertificateKind;
  name: string;
  action: 'kept' | 'created';
  /** The standard name this one succeeds, when it was made beside it. */
  replaces?: string;
  guid?: string | null;
  status: 'ok' | 'failed';
  detail?: string;
  certificate?: Certificate | null;
}

export type ServerCertificate = Ref & { server: { dn: string; name: string } | null; usedBy?: string[]; certificate: Certificate | null; chain?: Certificate[] };

/** The Organizational CA's settings (ndspkiSecurityRightsLevel bits, and nDSPKISuiteBMode). */
export interface CaConfiguration {
  requireReadRights: boolean;
  requireWriteRights: boolean;
  /** The PKI Health Check (ndsd start, DSRepair) creates missing default certificates and renews expired ones, in place. */
  serverSelfProvisioning: boolean;
  /** Only with server self-provisioning: default certificates are made again when the CA changes. */
  forceHealthCheck: boolean;
  userEmergencyCrl: boolean;
  userSelfProvisioning: boolean;
  suiteB: boolean;
}

export interface Pki {
  ca: (Ref & { host?: string; defaultRsaKeySize?: string; defaultLifeYears?: string; certificates: Certificate[]; configuration?: CaConfiguration }) | null;
  serverCertificates: (Ref & { server: { dn: string; name: string } | null; usedBy: string[]; certificate: Certificate | null; chain: Certificate[] })[];
  trustedRoots: (Ref & { container: string; certificate: Certificate | null })[];
  /** The containers trusted roots live in, with how many each holds. */
  trustedRootContainers?: (Ref & { roots: number })[];
  crls: (Ref & { type: 'rsa' | 'ec'; issued?: string; nextIssue?: string; number?: string; status?: string; host?: string;
    distributionPoints: string[]; thisUpdate?: string; nextUpdate?: string | null; revoked?: number; der?: string; crlError?: string })[];
}

export type PolicyRules = Record<string, number | boolean | string | string[] | null>;
export type PolicyOptions = Record<'universalPassword' | 'advancedRules' | 'userRetrieve' | 'adminRetrieve' | 'syncDistribution' | 'removeNds' | 'syncNds' | 'syncSimple', boolean>;

export interface PasswordPolicySummary extends Ref {
  description?: string;
  universalPassword: boolean;
  minLength?: string;
  maxLength?: string;
  assignments: number;
}

export interface PasswordPolicy extends Ref {
  description?: string;
  rules: PolicyRules;
  options: PolicyOptions;
  challengeSet: Ref | null;
  forgotten: { enabled: boolean; action: string | null; authentication: string[]; loginConfig: boolean };
  assignments: Ref[];
}

export interface Question { kind: 'admin' | 'user'; text?: string | null; min?: number | null; max?: number | null }

export interface ChallengeSet extends Ref {
  description?: string;
  required: Question[];
  random: Question[];
  randomCount: number;
  minResponse?: number | null;
  maxResponse?: number | null;
}

export interface LoginPolicy {
  defaultSequence: string | null;
  passwordPolicy: Ref | null;
  /** {@code any}: any one of the methods will do; else every method, in turn. */
  sequences: { name: string; grade: string | null; methods: string[]; any: boolean }[];
  /** The sequences people may use; null when the policy does not restrict them. */
  authorized?: string[] | null;
  methods: (Ref & { description?: string; vendor?: string; postLogin: boolean })[];
}

export interface EbaCertificate {
  subject: string;
  issuer: string;
  serial: string;
  notBefore: string | null;
  notAfter: string | null;
  signatureAlgorithm: string;
}

/** The tree's EBA (enhanced background authentication): its CA, each server's NCP certificate, requests awaiting approval. */
export interface EbaState {
  available: boolean;
  problem?: string;
  caAddress?: string;
  ca?: EbaCertificate & { renewable: boolean };
  ncpCertificates?: (EbaCertificate & { address: string; server: { dn: string; name: string; guid: string } | null })[];
  pendingRequests?: unknown[];
}

export interface SequenceRequest {
  name?: string;
  methods: string[];
  any: boolean;
}

/** Security services for one directory. {@code confirm}: the directory's name, typed for a production directory. */
export function security(id: string) {
  const base = `/api/v2/trees/${encodeURIComponent(id)}/security`;
  const h = (confirm?: string, more: Record<string, string> = {}): Record<string, string> => ({ ...(confirm ? { 'X-Confirm-Directory': confirm } : {}), ...more });
  const get = <T>(p: string) => request<T>('GET', base + p).then((r) => r.data);
  return {
    pki: () => get<Pki>('/pki'),
    policies: () => get<PasswordPolicySummary[]>('/password-policies'),
    policy: (guid: string) => get<PasswordPolicy>(`/password-policies/${guidPath(guid)}`),
    createPolicy: (body: { name: string; description?: string; rules?: PolicyRules; options?: Partial<PolicyOptions>; challengeSet?: string | null }, confirm?: string) =>
      request<PasswordPolicy>('POST', `${base}/password-policies`, body, h(confirm)).then((r) => r.data),
    updatePolicy: (guid: string, body: { description?: string | null; rules?: PolicyRules; options?: Partial<PolicyOptions>; challengeSet?: string | null }, confirm?: string) =>
      request<PasswordPolicy>('PATCH', `${base}/password-policies/${guidPath(guid)}`, body, h(confirm)).then((r) => r.data),
    deletePolicy: (guid: string, count: number, confirm?: string) =>
      request<void>('DELETE', `${base}/password-policies/${guidPath(guid)}`, undefined, h(confirm, count ? { 'X-Confirm-Count': String(count) } : {})),
    assign: (guid: string, target: string, confirm?: string) =>
      request<PasswordPolicy>('POST', `${base}/password-policies/${guidPath(guid)}/assignments`, { target }, h(confirm)).then((r) => r.data),
    unassign: (guid: string, target: string, confirm?: string) =>
      request<PasswordPolicy>('DELETE', `${base}/password-policies/${guidPath(guid)}/assignments/${guidPath(target)}`, undefined, h(confirm)).then((r) => r.data),
    policyFor: (guid: string) => get<{ own: Ref | null; containers: { container: string; policy: Ref }[]; loginPolicy: Ref | null }>(`/objects/${guidPath(guid)}/password-policy`),
    challengeSets: () => get<(Ref & { description?: string; required: number; random: number; randomCount: number })[]>('/challenge-sets'),
    challengeSet: (guid: string) => get<ChallengeSet>(`/challenge-sets/${guidPath(guid)}`),
    createChallengeSet: (body: Partial<ChallengeSet> & { name: string }, confirm?: string) =>
      request<ChallengeSet>('POST', `${base}/challenge-sets`, body, h(confirm)).then((r) => r.data),
    updateChallengeSet: (guid: string, body: Partial<ChallengeSet>, confirm?: string) =>
      request<ChallengeSet>('PATCH', `${base}/challenge-sets/${guidPath(guid)}`, body, h(confirm)).then((r) => r.data),
    deleteChallengeSet: (guid: string, confirm?: string) => request<void>('DELETE', `${base}/challenge-sets/${guidPath(guid)}`, undefined, h(confirm)),
    loginPolicy: () => get<LoginPolicy>('/login-policy'),
    eba: () => get<EbaState>('/eba'),
    createSequence: (body: SequenceRequest, confirm?: string) =>
      request<LoginPolicy>('POST', `${base}/login-policy/sequences`, body, h(confirm)).then((r) => r.data),
    /** {@code count}: how many objects name the sequence, confirmed when the console asked. */
    updateSequence: (name: string, body: SequenceRequest, confirm?: string, count?: number) =>
      request<LoginPolicy>('PATCH', `${base}/login-policy/sequences/${encodeURIComponent(name)}`, body, h(confirm, count ? { 'X-Confirm-Count': String(count) } : {})).then((r) => r.data),
    deleteSequence: (name: string, confirm?: string, count?: number) =>
      request<LoginPolicy>('DELETE', `${base}/login-policy/sequences/${encodeURIComponent(name)}`, undefined, h(confirm, count ? { 'X-Confirm-Count': String(count) } : {})).then((r) => r.data),
    /** A server certificate (key material object) on a server, from the tree CA. */
    createServerCertificate: (serverGuid: string, body: CertificateRequest, confirm?: string) =>
      request<ServerCertificate>('POST', `${base}/pki/servers/${guidPath(serverGuid)}/certificates`, body, h(confirm)).then((r) => r.data),
    /** A server's default certificates (SSL CertificateDNS, SSL EC CertificateDNS, SSL CertificateIP) and what is wrong with each. */
    defaultCertificates: (serverGuid: string) => get<DefaultCertificates>(`/pki/servers/${guidPath(serverGuid)}/default-certificates`),
    /** New default certificates for one server: a missing one under its standard name, others as "<name> <date>"; nothing is deleted. */
    repairDefaultCertificates: (serverGuid: string, body: DefaultCertificatesRequest, confirm?: string) =>
      request<{ results: DefaultCertificateResult[] }>('POST', `${base}/pki/servers/${guidPath(serverGuid)}/default-certificates`, body, h(confirm)).then((r) => r.data.results),
    /** Change the named CA settings; the others keep their values. */
    caConfiguration: (body: Partial<CaConfiguration>, confirm?: string) =>
      request<CaConfiguration>('PUT', `${base}/pki/ca/configuration`, body, h(confirm)).then((r) => r.data),
    /** The certificate an LDAP server offers: one of its own server's certificates. It takes effect when the LDAP server is refreshed. */
    createTrustedRootContainer: (parent: string, name: string, confirm?: string) =>
      request<Pki>('POST', `${base}/pki/trusted-root-containers`, { parent, name }, h(confirm)).then((r) => r.data),
    deleteTrustedRootContainer: (guid: string, confirm?: string) =>
      request<Pki>('DELETE', `${base}/pki/trusted-root-containers/${guidPath(guid)}`, undefined, h(confirm)).then((r) => r.data),
    /** A certificate (PEM or base64 DER) as a trusted root in the container; the name defaults to its CN or OU. */
    addTrustedRoot: (container: string, certificate: string, name?: string, confirm?: string) =>
      request<Pki>('POST', `${base}/pki/trusted-root-containers/${guidPath(container)}/roots`, { certificate, name }, h(confirm)).then((r) => r.data),
    deleteTrustedRoot: (guid: string, confirm?: string) =>
      request<Pki>('DELETE', `${base}/pki/trusted-roots/${guidPath(guid)}`, undefined, h(confirm)).then((r) => r.data),
    useForLdap: (ldapServerGuid: string, certificateGuid: string, confirm?: string) =>
      request<{ ldapServer: string; certificate: string; previous: string }>('PUT', `${base}/pki/ldap-servers/${guidPath(ldapServerGuid)}/certificate`,
        { certificate: certificateGuid }, h(confirm)).then((r) => r.data),
    /** Refused while an LDAP server or SAS service uses it. */
    deleteServerCertificate: (guid: string, confirm?: string) =>
      request<void>('DELETE', `${base}/pki/server-certificates/${guidPath(guid)}`, undefined, h(confirm)),
    /** Revoke: an RFC 5280 reason and an optional comment; it is listed from the CRL's next issue. */
    revokeServerCertificate: (guid: string, body: Revocation, confirm?: string) =>
      request<RevocationResult>('POST', `${base}/pki/server-certificates/${guidPath(guid)}/revoke`, body, h(confirm)).then((r) => r.data),
    revokeUserCertificate: (guid: string, name: string, body: Revocation, confirm?: string) =>
      request<RevocationResult>('POST', `${base}/objects/${guidPath(guid)}/certificates/${encodeURIComponent(name)}/revoke`, body, h(confirm)).then((r) => r.data),
    /** The certificate with its private key and chain, as a PKCS#12 file under the password. Needs a recent sign-in. */
    exportServerCertificate: (guid: string, body: KeyExport) =>
      request<ExportedKey>('POST', `${base}/pki/server-certificates/${guidPath(guid)}/export`, body).then((r) => r.data),
    /** As exportServerCertificate, for one of the signed-in person's own certificates (nobody else can export it). */
    exportUserCertificate: (guid: string, name: string, body: KeyExport) =>
      request<ExportedKey>('POST', `${base}/objects/${guidPath(guid)}/certificates/${encodeURIComponent(name)}/export`, body).then((r) => r.data),
    userCertificates: (guid: string) => get<{ items: UserCertificate[] }>(`/objects/${guidPath(guid)}/certificates`).then((r) => r.items),
    createUserCertificate: (guid: string, body: CertificateRequest, confirm?: string) =>
      request<{ items: UserCertificate[] }>('POST', `${base}/objects/${guidPath(guid)}/certificates`, body, h(confirm)).then((r) => r.data.items),
  };
}

export interface Revocation {
  reason: number;
  comment?: string;
}

export interface RevocationResult {
  revoked: boolean;
  crlConfiguration: string;
  /** When the CRL is next issued, and so lists the certificate. */
  listedFrom: string | null;
}

/** A new certificate: names are dns:host, ip:address, email:address or uri:… */
export interface CertificateRequest {
  name: string;
  algorithm: 'rsa' | 'ec256' | 'ec384';
  rsaBits?: number;
  signature: 'sha256' | 'sha384' | 'sha512';
  validityYears: number;
  subject?: string;
  names?: string[];
  exportable?: boolean;
  email?: string;
}

export interface UserCertificate {
  name: string;
  subject: string;
  issuer: string;
  serial: string;
  notBefore: string;
  notAfter: string;
  keySize?: number;
  /** Base64 DER. */
  certificate?: string;
}

export type SecurityApi = ReturnType<typeof security>;

/** A certificate (base64 DER) as PEM text, for download. */
export function pem(der: string, label = 'CERTIFICATE'): string {
  return `-----BEGIN ${label}-----\n${der.match(/.{1,64}/g)?.join('\n') ?? ''}\n-----END ${label}-----\n`;
}

export interface ProbedCertificate {
  index: number;
  subject: string;
  issuer: string;
  sha256: string;
  notBefore: string;
  notAfter: string;
  names: string[];
  selfSigned: boolean;
}

export interface Probe {
  probeId: string;
  host: string;
  port: number;
  /** "trusted", or why not: "hostname", "untrusted", "expired", … */
  status: string;
  message: string;
  hostnameMatches: boolean;
  chain: ProbedCertificate[];
  recommended: number;
  confirm: string;
}

export interface TrustedCertificate {
  /** The fingerprint as lower-case hex, no separators. */
  id: string;
  /** Where it is kept: the fingerprint, with a suffix for a person's own certificate. */
  key?: string;
  sha256: string;
  /** "ca": chains that validate to it are trusted; "pinned-server": exactly this certificate is. */
  kind: 'ca' | 'pinned-server';
  /** "global", "directory:<id>" or "user:<subject>". */
  scope: string;
  subject: string;
  issuer: string;
  names: string[];
  selfSigned: boolean;
  notBefore: string;
  notAfter: string;
  addedBy: string;
  addedAt: string;
  /** "probe", "upload" or "bootstrap". */
  how: string;
}

export interface HostExceptionInfo {
  host: string;
  port: number;
  /** "global", or "user:<subject>" for one person's own. */
  scope?: string;
  leafId: string;
  sha256: string;
  addedBy: string;
  addedAt: string;
}

/** A pinned address that presented another certificate on a real connection. */
export interface TrustAlert {
  host: string;
  port: number;
  directory?: string;
  /** The fingerprints (lower-case hex) pinned there. */
  pinned: string[];
  presentedId: string;
  presentedSha256: string;
  presentedSubject: string;
  firstSeen: string;
  lastSeen: string;
  count: number;
}

export interface TrustState {
  certificates: TrustedCertificate[];
  hostExceptions: HostExceptionInfo[];
  alerts: TrustAlert[];
}

/** The console's trust store (administrators; changes need a recent sign-in). */
export const trust = {
  list: () => request<TrustState>('GET', '/api/v2/trust/certificates').then((r) => ({ ...r.data, alerts: r.data.alerts ?? [] })),
  dismissAlert: (host: string, port: number) => request<void>('DELETE', '/api/v2/trust/alerts', { host, port }).then(() => undefined),
  /** Probe host:port; with a directory, judged as that directory's connections are (its trusted CAs too). */
  probe: (host: string, port: number, directory?: string) =>
    request<Probe>('POST', '/api/v2/trust/probe', { host, port, directory }).then((r) => r.data),
  /** Probe a configured directory at its own address. */
  probeDirectory: (directory: string) => request<Probe>('POST', '/api/v2/trust/probe', { directory }).then((r) => r.data),
  /** Trust one certificate of a probed chain for this directory's connections. */
  add: (probeId: string, index: number, confirm: string, directory: string, kind?: 'ca' | 'pinned-server') =>
    request<unknown>('POST', '/api/v2/trust/certificates', { probeId, index, confirm, scope: `directory:${directory}`, kind }).then(() => undefined),
  /** Trust an uploaded PEM certificate (the last one in the file: the root of a chain). */
  upload: (pem: string, scope: string, kind?: 'ca' | 'pinned-server') =>
    request<TrustedCertificate>('POST', '/api/v2/trust/certificates', { pem, scope, kind }).then((r) => r.data),
  remove: (key: string) => request<void>('DELETE', `/api/v2/trust/certificates/${key}`).then(() => undefined),
  /** Accept this server's certificate at exactly this host and port, though it names others (NAT, a tunnel). */
  hostException: (probeId: string, confirm: string) =>
    request<unknown>('POST', '/api/v2/trust/host-exceptions', { probeId, confirm }).then(() => undefined),
  removeHostException: (host: string, port: number) =>
    request<void>('DELETE', '/api/v2/trust/host-exceptions', { host, port }).then(() => undefined),
};

/** Days from now until {@code iso}, a part day counting as one; negative once it has passed. */
export function daysUntil(iso: string, now = Date.now()): number {
  const d = (new Date(iso).getTime() - now) / 86_400_000;
  return d < 0 ? Math.floor(d) : Math.ceil(d);
}

/** Console-wide settings (administrators; a change needs a recent sign-in). */
/** Console-wide settings (not per directory). */
export interface ConsoleSettings {
  otherDirectories: boolean;
  /** Reverse proxies whose X-Forwarded-For is believed: addresses or CIDR ranges. */
  trustedProxies: string[];
}

export interface ConsoleTree {
  id: string;
  name: string;
  host: string;
  port: number;
  tier: 'production' | 'lab';
  /** The tree the person is signed in to. */
  current: boolean;
}

/** A certificate the person confirmed on the previous try (the last 8 hex digits of its fingerprint). */
export type Accept = { probeId: string; confirm: string; index?: number };

/** The trees the console knows, for console admins; changes need a recent sign-in. */
export const trees = {
  list: () => request<ConsoleTree[]>('GET', '/api/v2/console/trees').then((r) => r.data),
  /** Proven as at first sign-in: the new tree's own administrator, who becomes its break-glass account. */
  add: (body: { name?: string; tier: 'production' | 'lab'; host: string; port: number; dn: string; password: string; accept?: Accept }) =>
    request<ConsoleTree>('POST', '/api/v2/console/trees', body).then((r) => r.data),
  change: (id: string, body: { name?: string; tier?: 'production' | 'lab' }) =>
    request<ConsoleTree>('PATCH', `/api/v2/console/trees/${encodeURIComponent(id)}`, body).then((r) => r.data),
  remove: (id: string, name: string) => request<void>('DELETE', `/api/v2/console/trees/${encodeURIComponent(id)}`, { name }),
};

/** The console's version, and for admins the last check for a newer release. */
export interface UpdateState {
  enabled: boolean;
  current: string;
  latest?: string;
  newer?: boolean | null;
  url?: string;
  published?: string;
  checkedAt?: string;
  /** Why the last check failed; the console works as before. */
  error?: string;
}

/** Where the upgrade steps are documented. */
export const UPGRADING_URL = 'https://github.com/PointBlueTechnology/directory-console/blob/main/docs/UPGRADING.md';

export const updates = {
  version: () => request<{ version: string; update?: UpdateState }>('GET', '/api/v2/console/version').then((r) => r.data),
  setEnabled: (enabled: boolean) => request<UpdateState>('PUT', '/api/v2/console/updates', { enabled }).then((r) => r.data),
  checkNow: () => request<UpdateState>('POST', '/api/v2/console/updates/check', {}).then((r) => r.data),
};

export interface ExpiryFinding { kind: 'console' | 'trusted' | 'ca' | 'server' | 'trusted-root'; name: string; where: string; notAfter: string; days: number; level: 'expired' | '7days' | 'warn' }

export interface ExpirySettings {
  enabled: boolean;
  warnDays: number;
  email: null | { host: string; port: number; security: 'starttls' | 'tls' | 'none'; user?: string; password?: { set: true } | string | null; from: string; to: string[] };
  webhooks: { url: string; id?: string; secret?: { set: true } | string | null; clearSecret?: boolean }[];
}

export interface ExpiryState {
  settings: ExpirySettings;
  checkedAt?: string;
  findings?: ExpiryFinding[];
  /** Directories or stores that could not be read. */
  errors?: string[];
  sent?: { destination: string; ok: boolean; error?: string }[];
}

/** Certificate expiry monitoring: the console's own certificate, its trust store, and each directory's PKI (with a service account). */
export const expiry = {
  get: () => request<ExpiryState>('GET', '/api/v2/console/expiry').then((r) => r.data),
  save: (s: ExpirySettings) => request<ExpiryState>('PUT', '/api/v2/console/expiry', s).then((r) => r.data),
  checkNow: () => request<ExpiryState>('POST', '/api/v2/console/expiry/check', {}).then((r) => r.data),
  test: () => request<{ results: { destination: string; ok: boolean; error?: string }[] }>('POST', '/api/v2/console/expiry/test', {}).then((r) => r.data),
};

export interface SyslogState {
  enabled: boolean;
  host?: string | null;
  port: number;
  transport: 'tls' | 'tcp' | 'udp';
  facility: string;
  sent?: number;
  dropped?: number;
  waiting?: number;
  lastSent?: string | null;
  lastError?: string | null;
}

/** Every audit-log entry sent on to a syslog server: RFC 5424 carrying CEF, over TLS, TCP or UDP. */
export const syslog = {
  get: () => request<SyslogState>('GET', '/api/v2/console/syslog').then((r) => r.data),
  save: (s: Pick<SyslogState, 'enabled' | 'host' | 'port' | 'transport' | 'facility'>) => request<SyslogState>('PUT', '/api/v2/console/syslog', s).then((r) => r.data),
  test: () => request<{ ok: boolean; error?: string }>('POST', '/api/v2/console/syslog/test', {}).then((r) => r.data),
};

export const consoleSettings = {
  get: () => request<ConsoleSettings>('GET', '/api/v2/console/settings').then((r) => r.data),
  /** Either setting, or both; what is left out stays as it is. */
  put: (v: Partial<ConsoleSettings>) => request<ConsoleSettings>('PUT', '/api/v2/console/settings', v).then((r) => r.data),
};
