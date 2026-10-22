/**
 * One-sentence explanations of the console's terms, for tooltips and the ? beside a field. Kept in one
 * place so a term is explained the same way wherever it appears.
 */
export const GLOSSARY = {
  // objects and browsing
  actions: 'What you may do to this object: edit, set a password, enable or disable, rename, move, delete, auxiliary classes and your task presets.',
  childCount: 'How many objects this container holds, as eDirectory reports it.',
  estimate: 'eDirectory\'s estimate: it counts large sets approximately.',
  makePartition: 'Splits this container into its own partition. It changes replication for the whole directory and completes in the background.',
  aliasObject: 'An alias is an object that points to another, so references to the old name or place keep working.',
  aclInheritedBelow: 'Also applies to objects below this one.',
  aclThisObject: 'Applies to this object only.',
  // account
  accountRestrictions: 'The account\'s own NDS password restrictions. A Universal Password policy may apply its own rules as well.',
  graceLogins: 'Sign-ins allowed with an expired password before it must be changed.',
  // groups
  securityEquivalence: 'The member gets the group\'s rights. eDirectory records it on the member as well as the group.',
  securityEquivalenceMissing: 'The group lists this member, but the member does not carry the group\'s security equivalence. Adding the membership again repairs it.',
  // associations
  association: 'The value that names this object\'s account in the connected system.',
  'association.processed': 'Associated: the driver keeps the two in step.',
  'association.pending': 'Waiting for the driver to process it.',
  'association.manual': 'Set by hand; the driver treats the object as associated.',
  'association.migrate': 'Marked for migration.',
  'association.disabled': 'The driver ignores this object.',
  'association.undefined': 'A state outside the five the engine defines.',
  // rights
  irf: 'The Inherited Rights Filter blocks rights from flowing down to this object and below.',
  appliesTo: 'The whole entry, all attributes, or one attribute.',
  rightsAllowedToFlow: 'Which rights the filter lets through to this object and below.',
  inheritedBelow: 'Whether the right also applies to objects below this one.',
  '[Public]': 'Anyone, signed in or not.',
  '[Root]': 'Everyone who is signed in.',
  '[Self]': 'The object itself.',
  '[Creator]': 'Whoever creates an object below this one.',
  'right.browse': 'See the object.',
  'right.add': 'Create objects below it.',
  'right.delete': 'Delete it.',
  'right.rename': 'Rename it.',
  'right.supervisor': 'All rights, including to its attributes.',
  'right.compare': 'Test whether an attribute has a given value, without reading it.',
  'right.read': 'Read attribute values.',
  'right.write': 'Add, change and remove attribute values.',
  'right.self': 'Add or remove yourself as a value, such as joining a group.',
  // replicas
  perReplica: 'Kept separately on each server, so it is meant to differ.',
  differs: 'This server\'s value differs: replication may not have finished yet.',
  'replica.master': 'The one replica that can create and merge partitions.',
  'replica.read-write': 'Answers reads and writes.',
  'replica.read-only': 'Answers reads; writes go to another replica.',
  'replica.subordinate-reference': 'A pointer where a child partition starts, not a full copy. eDirectory manages it.',
  'replica.sparse-write': 'A writable copy holding only filtered classes and attributes.',
  'replica.sparse-read': 'A read-only copy holding only filtered classes and attributes.',
  merge: 'Joins this partition back into its parent. It affects replication for every object in it.',
  limber: 'Checks the server\'s name and addresses, builds new indexes, and applies index and encrypted attribute changes.',
  janitor: 'Housekeeping, such as purging deleted objects.',
  skulker: 'Checks and drives replica synchronization.',
  // eDirectory: indexes
  'index.user': 'Made by an administrator.',
  'index.attribute-creation': 'Made by eDirectory when the attribute was created.',
  'index.system': 'eDirectory\'s own; it cannot be removed or taken offline.',
  'index.operational': 'eDirectory\'s own; it cannot be removed or taken offline.',
  'index.new': 'Waiting for limber to build it.',
  'index.pending': 'Limber is building it; searches on it are slow until it is online.',
  'index.offline': 'Not maintained: searches on it are slow until it is brought back online.',
  // auditing, SNMP, encryption, replica filter
  cefauditds: 'eDirectory\'s CEF audit module. It must be loaded on the server for any event to be sent.',
  noReplicatedEvents: 'Each change is then reported only by the server where it was made, not by every server it replicates to.',
  failureTraps: 'Also send the trap when the event fails.',
  trapInterval: 'The shortest time between two of these traps, in seconds. 0 uses the group\'s default interval.',
  secureChannelOnly: 'Encrypted values can be read only over LDAPS or StartTLS; over plain LDAP the read fails.',
  replicaFilter: 'What this server\'s filtered (sparse) replicas hold: only these classes, and of each only these attributes.',
  // LDAP server
  cipherSuiteLevel: 'A further limit on ciphers, as Identity Console sets it. eDirectory does not document it: leave it at None unless you know you need it.',
  clientCertificates: 'Whether the server asks TLS clients for a certificate. Required refuses clients without one.',
  mutualAuthentication: 'Clients must present a certificate the server trusts. Needs a reload.',
  filteredReplicaUsage: 'LDAP searches may be answered from this server\'s filtered (sparse) replicas, which hold only some attributes.',
  persistentSearch: 'A search that stays open and returns entries as they change.',
  lburp: 'LDAP Bulk Update/Replication Protocol, used by ICE to bulk-load entries. More threads load faster on a busy server.',
  // Identity Manager
  idmServer: 'Driver state, start options, jobs, caches and passwords belong to one server: this says which, and chooses another when several run the driver set.',
  startOption: 'Automatic starts with the engine; Manual waits to be started; Disabled never starts, deletes the driver\'s cache and keeps no events.',
  'start.auto': 'Starts with the engine.',
  'start.manual': 'Waits to be started.',
  'start.disabled': 'Never starts. Disabling deletes its cache, and no events are queued while it is disabled.',
  cache: 'Events waiting to be sent to the connected system.',
  unprocessed: 'Cached events the driver has not processed yet.',
  traceLevel: '0 to 10: how much the driver writes to its trace. 5 shows password synchronization.',
  resync: 'Sends the driver\'s objects again, optionally only those changed since a date. On a large driver this loads the connected system.',
  remoteLoaderPassword: 'The password the engine and the Remote Loader use to trust each other.',
  mutualAuthKey: 'Passwords for the key and keystore used when the engine and the Remote Loader authenticate each other with certificates.',
  subscriber: 'The subscriber channel carries changes from the vault to the connected system.',
  publisher: 'The publisher channel brings changes from the connected system into the vault.',
  'filter.sync': 'The channel sends changes and keeps the two sides in step.',
  'filter.notify': 'Changes are reported to the policies but not written.',
  'filter.reset': 'A change is undone, back to the authoritative side\'s value.',
  'filter.ignore': 'The channel does not handle the attribute.',
  gcv: 'Global configuration values: named settings the driver\'s policies read.',
  ecv: 'Engine control values: settings for how the engine runs this driver.',
  driverParameters: 'Settings the driver\'s shim reads, as Designer configured them.',
  deleteEvents: 'Deleted events are never sent to the connected system.',
  clearCache: 'Discards every event waiting for this driver. The connected system will not receive them.',
  cannotStartDisabled: 'A disabled driver cannot start: choose Automatic or Manual first.',
  // security
  eba: 'Enhanced Background Authentication: certificates that secure server-to-server (NCP) connections.',
  ncpCertificates: 'The certificates servers use for EBA connections to each other.',
  defaultCertificates: 'Each server\'s SSL CertificateDNS, EC and SSL CertificateIP certificates, which LDAP and other services use.',
  universalPassword: 'One password for every way of signing in, kept in step with the older NDS password as the policy says.',
  grade: 'How strong the sequence is, as NMAS ranks it.',
  notAuthorized: 'Not in the list of sequences that may be used.',
  'up.syncNds': 'Changing the Universal Password changes the NDS password too.',
  'up.syncSimple': 'Keeps the simple password (used by some LDAP binds) the same.',
  'up.syncDistribution': 'Keeps the distribution password, which Identity Manager can read, the same.',
  'up.removeNds': 'Removes the NDS password once a Universal Password is set.',
  'up.retrieval': 'Lets authorized agents, such as Identity Manager, read the password.',
  // console trust and settings
  trustedAsCa: 'Any server certificate this authority issued is accepted.',
  trustedAsPinned: 'Exactly this certificate, at this address. If the server presents another, connections are refused and admins are alerted.',
  pinned: 'A certificate trusted for exactly one server. A changed one may be a renewal, or someone else answering: connections stay refused until it is reviewed.',
  breakGlass: 'An account that can always sign in as an admin, even when no role mapping applies, and with a password even when password sign-in is limited to single sign-on: the directory administrator who set the console up.',
  passwordSignIn: 'Break-glass accounts, and any accounts listed in Settings > Single sign-on > Password sign-in. Everyone else signs in with single sign-on.',
  passwordAllowed: 'With password sign-in limited to single sign-on, these accounts may still sign in with their name and password, for example administrators who need a way in when the identity provider is down. Unlike break-glass accounts, they are not made admins.',
  publicClient: 'The provider has no client secret for the console: PKCE alone protects the sign-in.',
  claim: 'The part of the provider\'s identity token that says who the person is, such as their user name.',
  claimAttribute: 'The eDirectory attribute whose value must equal the claim.',
  neverActAs: 'Accounts that may not sign in through single sign-on, such as administrators and the service account.',
  warnDays: 'How many days before expiry the daily check first sends a notice.',
  syslogFacility: 'The syslog facility the console\'s messages carry, for routing on the syslog server.',
  directoryName: 'The directory\'s name as the console shows it in the sign-in list and in Settings, not its eDirectory tree name.',
} as const;

export type Term = keyof typeof GLOSSARY;

/** A term's explanation; also usable as a table header's info (e.g. Th info={tip('irf')}). */
export function explain(term: Term): string {
  return GLOSSARY[term];
}

export function tip(term: Term): { tooltip: string } {
  return { tooltip: GLOSSARY[term] };
}
