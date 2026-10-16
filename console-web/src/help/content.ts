import type { HelpTopic } from './topics';

/** The help topics, by id: a page ("idm"), a tab ("idm.jobs") or a sub-page ("idm.driver.cache"). */
export const CONTENT: Record<string, HelpTopic> = {
  // ---- Browse and objects ----------------------------------------------------------------------
  browse: {
    title: 'Browsing the directory',
    summary: 'The panel on the left holds the containers; the list on the right shows what is in the open one. Click a row for its details.',
    sections: [
      {
        title: 'Finding your way',
        list: [
          'A container\'s name opens it; clicking anywhere else on a row shows the object\'s details beside the list.',
          'The number after a container\'s name is how many objects it holds, as eDirectory reports it.',
          'Everything, Containers and Other objects filter the list. Other objects are the leaves: users, groups and the like.',
          '"Go to a name" jumps to the first name at or after what you type, in alphabetical order.',
          'In a large container the total reads "about N": it is eDirectory\'s estimate while you page through it.',
        ],
      },
      {
        title: 'Creating objects',
        list: [
          'New offers a user, a group, or any other class this container can hold.',
          'A class that cannot be created here is greyed out: each class says which containers may hold it.',
          'The form asks for the naming attribute and any attribute the class requires.',
        ],
      },
      {
        title: 'Your rights',
        paragraphs: ['You see and change only what your eDirectory rights allow, however the console\'s roles are set.'],
      },
    ],
    related: ['object', 'search'],
  },
  object: {
    title: 'An object\'s details',
    summary: 'Everything about one object: its attributes, and tabs for what applies to its kind (account, groups, rights, Identity Manager associations, replicas).',
    sections: [
      {
        title: 'Actions',
        list: [
          'The ⋮ menu holds what you may do to this object: edit, rename, move, delete, add or remove auxiliary classes, and task presets granted to you.',
          'Rename and move can leave an alias at the old name or place, so references to it keep working.',
          'Deleting a container with objects in it asks you to type its name.',
        ],
      },
      {
        title: 'Make this a partition',
        caution: true,
        paragraphs: ['Splitting a container into its own partition changes replication for the whole directory. It completes in the background; follow it on the eDirectory page.'],
      },
    ],
    related: ['object.attributes', 'object.rights', 'edir'],
  },
  'object.attributes': {
    title: 'Attributes',
    summary: 'The object\'s attributes and their values, as eDirectory holds them.',
    sections: [
      {
        title: 'Reading values',
        list: [
          'A value naming another object is a link: it opens that object.',
          'Binary values show their size; ACL values show a summary (change rights on the Rights tab).',
          '"Set, never shown" marks values the console never displays, such as password hashes.',
        ],
      },
      {
        title: 'Auxiliary classes',
        paragraphs: [
          'An auxiliary class adds optional attributes to an object, alongside its own class. Adding one also adds the classes it builds on and asks for any attribute it requires; removing one removes the attributes only it allowed.',
        ],
      },
    ],
  },
  'object.account': {
    title: 'Account',
    summary: 'Sign-in status and the restrictions eDirectory applies to this account.',
    sections: [
      {
        title: 'Status',
        list: [
          'Disabled: the account cannot sign in until it is enabled.',
          'Expired: past its expiry date.',
          'Locked by intruder detection: too many wrong passwords. Unlock clears it; it also clears on its own after the container\'s reset interval.',
        ],
      },
      {
        title: 'Password restrictions',
        paragraphs: [
          'These are the account\'s own NDS password restrictions. A Universal Password policy (Security > Password policies) may apply its own rules as well.',
          'Grace logins let someone sign in a few times with an expired password before they must change it.',
        ],
      },
      {
        title: 'Login times',
        paragraphs: ['The time grid can be shown in your time zone or in UTC. eDirectory keeps it in UTC, so after a daylight-saving change the allowed hours fall an hour differently in local time.'],
      },
    ],
    related: ['security.password-policies'],
  },
  'object.certificates': {
    title: 'User certificates',
    summary: 'Certificates issued to this user by the directory\'s Organizational CA.',
    sections: [
      { title: 'Revoking', caution: true, paragraphs: ['Revoking a certificate cannot be undone. The next CRL lists it.'] },
    ],
    related: ['security.certificates'],
  },
  'object.groups': {
    title: 'Groups',
    summary: 'The groups this object belongs to.',
    sections: [
      {
        title: 'How membership is kept',
        list: [
          'eDirectory records membership on both sides: the group lists the member, and the member lists the group.',
          'Security equivalence gives the member the group\'s rights. "Missing" means the group grants it but this object does not carry it; adding the membership again repairs it.',
        ],
      },
    ],
  },
  'object.members': {
    title: 'Members',
    summary: 'The group\'s members.',
    sections: [
      {
        title: 'Kinds of group',
        list: [
          'Static groups list their members.',
          'Dynamic groups find their members with a query (an LDAP URL), and may also list some by hand.',
          'A nested group is a member that is itself a group.',
        ],
      },
    ],
  },
  'object.associations': {
    title: 'Identity Manager associations',
    summary: 'Which Identity Manager drivers this object is linked to, and how.',
    sections: [
      {
        title: 'States',
        list: [
          'Processed: associated; the driver keeps the two in step.',
          'Pending: waiting for the driver to process it.',
          'Manual: set by hand; the driver treats the object as associated.',
          'Migrate: marked for migration.',
          'Disabled: the driver ignores this object.',
        ],
      },
      {
        title: 'Changing one',
        caution: true,
        paragraphs: ['The association value names the account in the connected system. Removing an association means the driver may create or match a different account the next time this object changes.'],
      },
    ],
    related: ['idm.driver.associations'],
  },
  'object.rights': {
    title: 'Rights',
    summary: 'Who has rights to this object (its trustees), what flows down to objects below, and anyone\'s effective rights here.',
    sections: [
      {
        title: 'Trustees and rights',
        list: [
          'Entry rights: browse, add (create below), delete, rename, and supervisor (all rights).',
          'Attribute rights: compare, read, write, self (add or remove oneself as a value), and supervisor.',
          '[Public] is anyone, signed in or not; [Root] is everyone signed in; [Self] is the object itself; [Creator] is whoever creates an object below.',
          '"Inherited below" means the right also applies to objects under this one.',
        ],
      },
      {
        title: 'Inherited Rights Filter',
        caution: true,
        paragraphs: ['A filter blocks rights from flowing down to this object. Blocking Supervisor can leave no one able to manage it: make sure someone has explicit rights here first.'],
      },
      { title: 'Effective rights', paragraphs: ['What a person can actually do here, after everything that applies to them: their own grants, groups, security equivalences and inheritance.'] },
    ],
  },
  'object.replicas': {
    title: 'Replicas',
    summary: 'This object as each server that holds a replica of its partition sees it.',
    sections: [
      {
        title: 'Comparing',
        list: [
          'Sign in to another server to read its copy: each server answers for its own replica.',
          '"Kept per server" attributes are meant to differ between servers.',
          '"Differs" on any other attribute usually means replication has not finished yet.',
        ],
      },
    ],
    related: ['edir'],
  },
  'object.identity': {
    title: 'Identity',
    summary: 'How this object is named and found: its DN in LDAP form, dot form (cn.ou.o) and slash form, its GUID, and which server answered.',
    sections: [],
  },

  // ---- Search and schema -----------------------------------------------------------------------
  search: {
    title: 'Searching',
    summary: 'Find objects by class and attribute values, anywhere under a starting point.',
    sections: [
      {
        title: 'Building a search',
        list: [
          'Start at a container, and choose its own level or everything below it.',
          '"All" matches objects meeting every condition; "any" those meeting at least one.',
          '"Sounds like" matches names that sound alike; "is at least" and "is at most" compare in order.',
          'Or type an LDAP filter. Escape parentheses and asterisks in values as \\28, \\29 and \\2a.',
        ],
      },
      { title: 'Results', paragraphs: ['Large results are sorted and paged by eDirectory, and their total is an estimate.'] },
    ],
  },
  schema: {
    title: 'Schema',
    summary: 'The classes and attributes this directory knows, and what eDirectory says about each.',
    sections: [
      {
        title: 'Classes',
        list: [
          'Structural classes are what objects are created as; auxiliary classes add attributes to them; abstract classes are only built on.',
          'Container classes can hold other objects. "Can be created in" lists where a class\'s objects may live; "Named by" its naming attributes.',
          'Required (must) attributes have to be set when an object is created; optional (may) attributes can be.',
        ],
      },
      { title: 'Attribute flags', paragraphs: ['Flags such as per replica, public read and never synchronized are eDirectory\'s own settings for how an attribute is stored, read and replicated.'] },
      {
        title: 'Changing the schema',
        caution: true,
        paragraphs: ['A schema change reaches every server in the directory. Only optional attributes can be added to an existing class, and base schema cannot be deleted.'],
      },
    ],
  },

  // ---- eDirectory ------------------------------------------------------------------------------
  edir: {
    title: 'Partitions and replicas',
    summary: 'How the directory is divided into partitions, and which servers hold a copy (a replica) of each.',
    sections: [
      {
        title: 'Replica types',
        list: [
          'Master: the one replica that can create and merge partitions.',
          'Read/write: answers reads and writes.',
          'Read-only: answers reads; writes go elsewhere.',
          'Subordinate reference: a pointer kept where a child partition starts, not a full copy. eDirectory manages these itself.',
          'Sparse write and sparse read: hold only filtered classes and attributes.',
        ],
      },
      {
        title: 'Changes take time',
        paragraphs: ['Adding, removing and changing replicas, and splitting or merging partitions, complete in the background. The page refreshes while they run.'],
      },
      {
        title: 'Cautions',
        caution: true,
        list: [
          'These changes affect every server in the directory. They need an editor role over the whole directory.',
          'Merging a partition into its parent, or moving the master, changes replication for every object in it.',
        ],
      },
    ],
    related: ['edir.servers'],
  },
  'edir.servers': {
    title: 'Servers',
    summary: 'The directory\'s servers: version, status, and the server the console is connected through.',
    sections: [],
    related: ['edir.server'],
  },
  'edir.server': {
    title: 'A server',
    summary: 'One server: its replicas, indexes and background processes.',
    sections: [
      {
        title: 'Background processes',
        list: [
          'Limber: checks the server\'s name and addresses, and builds new indexes.',
          'Janitor: housekeeping, such as purging deleted objects.',
          'Skulker: checks and drives replica synchronization.',
          'Refresh the LDAP server: makes LDAP re-read its configuration.',
        ],
      },
      {
        title: 'Indexes',
        paragraphs: ['Indexes make searches on an attribute fast: value (equals), presence (has a value) and substring (contains). Limber builds a new one; removing one slows searches on that attribute on this server.'],
      },
    ],
  },

  // ---- Security --------------------------------------------------------------------------------
  security: {
    title: 'Security',
    summary: 'The directory\'s certificates, password policies, challenge sets, login methods and Enhanced Background Authentication.',
    sections: [],
    related: ['security.certificates', 'security.password-policies'],
  },
  'security.certificates': {
    title: 'Directory certificates',
    summary: 'The directory\'s Organizational CA, the certificates it has issued to servers, trusted roots and CRLs.',
    sections: [
      {
        title: 'Default certificates',
        paragraphs: [
          'Each server has default certificates (SSL CertificateDNS, an EC one and SSL CertificateIP) that LDAP and other services use. Renewing makes a new certificate beside the old one; you then move the LDAP server to it and refresh it, as a separate step.',
        ],
      },
      { title: 'CA configuration', paragraphs: ['Server self-provisioning lets eDirectory\'s own PKI Health Check renew default certificates in place when ndsd starts.'] },
      { title: 'Revoking', caution: true, paragraphs: ['Revoking a certificate cannot be undone.'] },
    ],
    related: ['certificates'],
  },
  'security.password-policies': {
    title: 'Password policies',
    summary: 'Universal Password policies: password rules, and where they apply.',
    sections: [
      {
        title: 'Universal Password',
        paragraphs: [
          'Universal Password is one password for every way of signing in. The policy says whether it is kept in step with the older NDS password, the simple password and the distribution password Identity Manager uses.',
        ],
      },
      { title: 'Assignment', paragraphs: ['A policy assigned to a container applies to everything below it, unless something lower has its own.'] },
      { title: 'Deleting', caution: true, paragraphs: ['Deleting a policy removes it from everything it was assigned to.'] },
    ],
    related: ['security.challenge-sets', 'object.account'],
  },
  'security.password-policy': {
    title: 'A password policy',
    summary: 'This policy\'s Universal Password options and rules, and what it is assigned to.',
    sections: [],
    related: ['security.password-policies'],
  },
  'security.challenge-sets': {
    title: 'Challenge sets',
    summary: 'The questions people answer to recover a forgotten password.',
    sections: [
      { title: 'Questions', list: ['Required questions are always asked.', 'Random questions are asked a set number at a time, from the list.', 'User-defined questions are written by each person.'] },
    ],
    related: ['security.password-policies'],
  },
  'security.challenge-set': { title: 'A challenge set', summary: 'This set\'s questions and answer lengths.', sections: [], related: ['security.challenge-sets'] },
  'security.login-methods': {
    title: 'Login methods',
    summary: 'NMAS login methods and the sequences that combine them.',
    sections: [
      {
        title: 'Sequences',
        list: [
          'A sequence names methods that must all succeed, or that are alternatives.',
          'Its grade says how strong it is.',
          'The default sequence is used when a client names none; only authorized sequences may be used.',
        ],
      },
    ],
  },
  'security.eba': {
    title: 'Enhanced Background Authentication',
    summary: 'EBA secures server-to-server connections (NCP) with certificates from the directory\'s EBA CA.',
    sections: [],
  },

  // ---- Identity Manager ------------------------------------------------------------------------
  idm: {
    title: 'Identity Manager',
    summary: 'The driver set\'s drivers, jobs and settings, on one server\'s engine.',
    sections: [
      {
        title: 'Each server runs its own copy',
        paragraphs: [
          'Driver state, start options, jobs, caches and named passwords belong to one server. The server picker chooses which; it starts on the server the console is connected through.',
        ],
      },
      {
        title: 'Drivers',
        list: [
          'Start options: Automatic starts with the engine; Manual waits to be started; Disabled never starts.',
          'A stopped driver queues events in its cache and sends them when started again.',
          'A disabled driver keeps no events: changes made meanwhile are not sent.',
        ],
      },
    ],
    related: ['idm.jobs', 'idm.driver'],
  },
  'idm.drivers': { title: 'Drivers', summary: 'The driver set\'s drivers on the chosen server: state, start option, cache and trace level.', sections: [], related: ['idm', 'idm.driver'] },
  'idm.jobs': {
    title: 'Jobs',
    summary: 'Scheduled and on-demand tasks the engine runs, such as triggering a driver or checking driver health.',
    sections: [
      {
        title: 'Working with jobs',
        list: [
          'New job offers the types this server\'s engine has.',
          'The schedule is five cron fields (minute hour day month weekday), in each server\'s local time. No schedule means it runs only when started.',
          'A scope makes the job run once per object found there; without one it runs once.',
          'Some job types need a named password on the job; set it before the job runs.',
        ],
      },
    ],
    related: ['idm'],
  },
  'idm.servers': { title: 'Servers and activation', summary: 'Which servers run this driver set, and Identity Manager\'s activation (licence) state on each.', sections: [] },
  'idm.properties': {
    title: 'Driver set properties',
    summary: 'The driver set\'s settings, as configured. They are changed in Designer, not here.',
    sections: [{ title: 'Global configuration values', paragraphs: ['GCVs are named settings policies read, set on the driver set and on each driver.'] }],
  },
  'idm.statistics': {
    title: 'Statistics',
    summary: 'The engine\'s Java memory and each driver\'s cache and event counts on this server.',
    sections: [
      {
        title: 'Channels',
        paragraphs: ['The subscriber channel carries changes from the vault to the connected system; the publisher channel brings changes back. Counts are grouped by stage of each channel.'],
      },
    ],
  },
  'idm.versions': { title: 'Versions', summary: 'The engine\'s version, and each driver\'s shim version as the statistics job last collected it.', sections: [] },
  'idm.trace': {
    title: 'Trace',
    summary: 'How much the engine and drivers write to their trace for troubleshooting.',
    sections: [
      {
        title: 'Levels',
        list: [
          '0 to 10. Level 1 shows errors but not their causes; 5 shows password synchronization.',
          'A driver without its own level uses the driver set\'s.',
          'Higher levels slow the engine: set them back when you are done.',
        ],
      },
    ],
  },
  'idm.mapping-tables': {
    title: 'Mapping tables',
    summary: 'Lookup tables that policies use to translate values, such as department codes into names.',
    sections: [
      {
        title: 'Editing',
        list: [
          'Each column has a type that decides how values compare.',
          'Tables can be exported and imported as CSV.',
          'A table installed by a package may be overwritten when the package is upgraded.',
        ],
      },
      { title: 'When changes apply', caution: true, paragraphs: ['Drivers read a table when they start: restart the drivers that use it.'] },
    ],
  },
  'idm.log': { title: 'Log level', summary: 'Which events the engine records in its log, for the driver set or a single driver.', sections: [] },
  'idm.passwords': {
    title: 'Named passwords',
    summary: 'Passwords stored for drivers and the driver set, such as the Remote Loader\'s.',
    sections: [{ title: 'Write-only', paragraphs: ['Passwords can be set or removed here, but never read back.'] }],
  },
  'idm.driver': {
    title: 'A driver',
    summary: 'One driver on the chosen server: its state and start option, and tabs for its jobs, associations, cache and settings.',
    sections: [
      {
        title: 'Resynchronising',
        caution: true,
        paragraphs: ['Resynchronising asks the driver to send its objects again, optionally only those changed since a date. On a large driver this loads the connected system.'],
      },
    ],
    related: ['idm', 'idm.driver.cache'],
  },
  'idm.driver.overview': { title: 'Driver overview', summary: 'State, start option and cache, with start, stop and restart.', sections: [], related: ['idm.driver'] },
  'idm.driver.associations': {
    title: 'Association inspector',
    summary: 'Every object associated with this driver, counted by state, with bulk changes.',
    sections: [
      { title: 'Counts', paragraphs: ['A count marked with ~ is an estimate.'] },
      { title: 'Bulk changes', caution: true, paragraphs: ['Removing associations means the driver may create or match accounts again the next time those objects change.'] },
    ],
    related: ['object.associations'],
  },
  'idm.driver.cache': {
    title: 'Cache inspector',
    summary: 'The events waiting in this driver\'s cache on this server.',
    sections: [
      { title: 'Reading events', paragraphs: ['The summary is always shown; the events themselves can be read only while the driver is stopped.'] },
      { title: 'Deleting', caution: true, paragraphs: ['Deleted events, and a cleared cache, are never sent to the connected system.'] },
    ],
  },
  'idm.driver.health': { title: 'Driver health', summary: 'The driver\'s recent health states and how its health is judged.', sections: [] },
  'idm.driver.properties': {
    title: 'Driver properties',
    summary: 'The driver\'s configuration: shim, authentication, parameters, GCVs, engine control values and filter. Read-only: they are changed in Designer.',
    sections: [{ title: 'Filter', list: ['Sync: the channel sends changes and keeps the two sides in step.', 'Notify: changes are reported to the policies but not written.', 'Reset: a change is undone, back to the authoritative side\'s value.', 'Ignore: the channel does not handle the attribute.'] }],
  },
  'idm.driver.password-sync': { title: 'Password synchronization', summary: 'How this driver handles passwords between the vault and the connected system.', sections: [] },

  // ---- Console certificates and settings -------------------------------------------------------
  certificates: {
    title: 'How the console trusts directories',
    summary: 'The certificates the console accepts from your directories\' servers. This is the console\'s own trust store; it does not change eDirectory.',
    sections: [
      {
        title: 'Kinds of trust',
        list: [
          'Certificate authority: any server certificate it issued is accepted.',
          'This server only (pinned): exactly this certificate, at this address. If the server presents another, admins are alerted.',
          'Host exception: a certificate accepted at an address it does not name (NAT, a tunnel, a load balancer).',
        ],
      },
      { title: 'Changes', paragraphs: ['Adding or removing trust needs a sign-in within the last 10 minutes.'] },
    ],
  },
  settings: { title: 'Settings', summary: 'How people sign in and what they may do. Most settings belong to the directory you are signed in to; some apply to the whole console.', sections: [] },
  'settings.directory': {
    title: 'Directory settings',
    summary: 'This directory\'s tier, session limits, service account and how people are found at sign-in.',
    sections: [
      {
        title: 'Tier',
        list: [
          'Production: every change asks for the directory\'s name to be typed first.',
          'Lab: changes go ahead without that step. Use it for dev and test directories.',
        ],
      },
      { title: 'Sessions', paragraphs: ['Idle sign-out and the longest session apply to everyone on this directory, at once. People are warned before either ends.'] },
      {
        title: 'Service account',
        paragraphs: ['The account the console uses to find people by a short name at sign-in, and for single sign-on. It needs to read the people it finds. Without one, people sign in with their full name (DN).'],
      },
    ],
  },
  'settings.roles': {
    title: 'Role mappings',
    summary: 'Which eDirectory groups get which console role.',
    sections: [
      {
        title: 'Roles',
        list: [
          'Viewer: read objects, schema and Identity Manager status.',
          'Editor: change directory objects.',
          'Operator: Identity Manager operations.',
          'Admin: console settings.',
        ],
      },
      { title: 'Where', paragraphs: ['A mapping can be limited to containers. eDirectory\'s own rights still apply on top.'] },
      { title: 'Break-glass accounts', paragraphs: ['The directory administrators who set the console up. They can always sign in as admins, even when no mapping applies.'] },
    ],
  },
  'settings.presets': {
    title: 'Task presets',
    summary: 'Narrow, named tasks (such as "reset a password") that people can run without a broader role.',
    sections: [{ title: 'Fields', list: ['Required: must be filled in.', 'Read-only: shown, not changed.', 'Pattern: the value must match.', 'Fixed value: always set to this.'] }],
  },
  'settings.sso': {
    title: 'Single sign-on',
    summary: 'Sign-in through an OpenID Connect provider such as Entra ID, Okta or Keycloak.',
    sections: [
      {
        title: 'How it works',
        list: [
          'The provider says who the person is; a claim, such as their user name, is matched to an eDirectory attribute.',
          'The console then acts as that person, with their own eDirectory rights, through the service account.',
          '"Never act as" lists accounts that must not sign in this way.',
          'A public client uses PKCE and has no secret.',
        ],
      },
    ],
    related: ['settings.directory'],
  },
  'settings.trees': {
    title: 'Directories',
    summary: 'The directories people choose from at sign-in. This applies to the whole console.',
    sections: [
      { title: 'Adding a directory', paragraphs: ['Sign in to the new directory as its own administrator; that account becomes its break-glass account.'] },
      { title: 'Removing a directory', caution: true, paragraphs: ['Everyone signed in to it is signed out, and its settings go with it. The directory itself is not touched.'] },
    ],
  },
  'settings.other': { title: 'Other directories', summary: 'Whether people may sign in to an eDirectory server by typing its address, with their own rights only. This applies to the whole console.', sections: [] },
  'settings.updates': {
    title: 'Updates',
    summary: 'This console\'s version, and the daily check for a newer release.',
    sections: [{ title: 'The check', paragraphs: ['The console asks GitHub for the latest release once a day and sends nothing about this installation. Turn it off if the console has no internet access.'] }],
  },
  'settings.proxy': {
    title: 'Reverse proxy',
    summary: 'The proxies in front of the console whose X-Forwarded-For header is believed, so audit entries and sign-in limits see each person\'s own address.',
    sections: [],
  },
};
