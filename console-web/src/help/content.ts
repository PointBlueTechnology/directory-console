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
          'To view or edit a container itself, use the details button at the end of its row, or Details beside the open container\'s name.',
          'Export as LDIF… in an object\'s actions saves it, a container\'s children, or a container and everything below it (as LDIF, CSV or JSON).',
          'The label at the top of the page names the directory you are signed in to; hover over it for its address. It is red for a production directory.',
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
          'The ⋮ menu holds what you may do to this object: edit an attribute, set a user\'s password, enable or disable a user, rename, move, delete, add or remove auxiliary classes, make a container a partition, and task presets granted to you.',
          'Rename and move can leave an alias at the old name or place, so references to it keep working.',
          'Move: type the new container\'s DN, or use Browse to pick it from the directory\'s containers.',
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
          'A value that names an object and adds to it (eDirectory\'s Path syntax, such as a role assignment in nrfAssignedRoles) shows the object as a link, then the rest; a role assignment reads as since when, by whom and why. Editing uses the value exactly as stored.',
          'Binary values show their size; ACL values show a summary (change rights on the Rights tab).',
          '"Set, never shown" marks values the console never displays, such as password hashes.',
          'Each value stays on one line, cut off with an ellipsis; point at it (or tab to it) to see it in full. Wrap long values shows them all wrapped; this browser remembers the choice.',
          'An attribute with many values shows the first ten; Show all lists the rest.',
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
        title: 'Setting a password',
        list: [
          'Under the field: the policy that governs this user (its own, else the nearest container\'s, else the Login Policy\'s) and its rules in short.',
          'A password you type is checked by NMAS first; if the policy refuses it, the reason is shown and nothing is set.',
          'Generate makes a random password from the rules of the policy that governs this user, and has NMAS check it before offering it.',
          'Copy it from the box under the field before you set it: it is not shown again.',
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
      {
        title: 'Working with certificates',
        list: [
          'New certificate issues one for this user from the Organizational CA.',
          'Download gives the certificate and its chain. Export with key gives a password-protected .pfx (PKCS#12) file with the private key; it needs a recent sign-in and is recorded in the audit log. eDirectory refuses a key not made exportable.',
        ],
      },
      { title: 'Revoking', caution: true, paragraphs: ['Revoking cannot be undone, except with the reason "Certificate on hold". The CA lists the certificate on its CRL from the CRL\'s next issue.'] },
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
    summary: 'Find objects by name (Basic), or by any filter (Advanced), anywhere under a starting point; export what you find.',
    sections: [
      {
        title: 'Basic',
        list: [
          'Type the start of a name: it is matched against cn, fullName, givenName, sn, mail and uid. Leave it empty to list everything of the kind chosen.',
          'People, Groups and Containers choose what to find; Everything finds any kind of object.',
          'Search under a container to look only below it; use Browse to pick it.',
        ],
      },
      {
        title: 'Advanced',
        list: [
          'Depth: everything below the starting point, only what is directly inside it, or only that object.',
          '"Build it" makes the filter from items: conditions (attribute, test, value) in groups that need all or any of what they hold. Groups go inside groups to any depth; put a condition or a group inside NOT to match what does not match it.',
          '"Write LDAP filter text" takes an RFC 4515 filter. It is checked as you type, and attribute names are offered as you write them. In values, write \\28 for (, \\29 for ), \\2a for * and \\5c for \\.',
          'Switching between the two carries the filter across. A filter the builder has no test for (a*b*c, or an extensible match) stays as text.',
          '"Sounds like" matches names that sound alike; "is at least" and "is at most" compare in order.',
          'Attribute names, and class names in an objectClass condition, are offered as you type them: arrow down to choose one, Enter to take it.',
          'Sort by names an attribute; eDirectory sorts large results itself.',
          'Columns names the attributes each result shows, in order (Choose… picks them from the schema). * is every attribute, + the operational ones.',
        ],
      },
      { title: 'Results', paragraphs: ['Large results are sorted and paged by eDirectory, and their total is an estimate.'] },
      {
        title: 'Export',
        list: [
          'Export… saves every match, not only this page: as LDIF, CSV or JSON, all of them or at most a number you choose.',
          'The console writes the file as it reads the directory, with your own rights, so a large export takes as long as reading it. Each export is in the audit log, with how many objects it held.',
          'LDIF has every attribute you can read (or the columns chosen), base64 for binary values and anything not plain ASCII, lines folded at 76 characters unless you choose otherwise.',
          'CSV has the DN, name and class, then the columns; choose the separators, the quote, line endings, whether cells a spreadsheet would run as formulas are kept as text, and a UTF-8 mark for Excel.',
          'Passwords, private keys and other secrets are never written: LDIF notes that they were left out.',
          'Your choices are remembered in this browser for the next export.',
        ],
      },
      {
        title: 'Saved and recent searches',
        list: [
          'Save this search keeps the whole form under a name. Saving under a name already used replaces it.',
          'Choose a saved search, or one from Recent, to fill in the form and run it. Recent holds the last 20 searches run.',
          'Both are kept in this browser, for this directory only: another browser or computer does not have them. Searches saved by versions before 0.3.23 open in the Advanced builder.',
        ],
      },
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
        paragraphs: ['A schema change reaches every server in the directory. New attributes and classes can be made, and optional attributes added to an existing class. An attribute or class in use, and base schema, cannot be deleted.'],
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
        paragraphs: ['Adding, removing and changing replicas, and splitting or merging partitions, complete in the background. The page follows them while they run, and marks the partition "in progress".'],
      },
      {
        title: 'Changing replicas',
        list: [
          'Add a replica puts a read/write or read-only copy of the partition on another server.',
          'Change the type can also make a replica the master; the current master becomes read/write.',
          'Remove deletes the server\'s copy; it keeps a subordinate reference where eDirectory needs one.',
        ],
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
    sections: [{ title: 'Status', paragraphs: ['Up or down as eDirectory reports it; "connected" marks the server the console works through.'] }],
    related: ['edir.server'],
  },
  'edir.server': {
    title: 'A server',
    summary: 'One server: its replicas, indexes and background processes.',
    sections: [
      {
        title: 'Background processes',
        list: [
          'Limber: checks the server\'s name and addresses, builds new indexes, and applies index and encrypted attribute changes.',
          'Janitor: housekeeping, such as purging deleted objects.',
          'Skulker: checks and drives replica synchronization.',
          'Refresh the LDAP server (only on the server the console is connected through): its LDAP server re-reads its configuration. Refresh other servers\' LDAP servers on eDirectory > LDAP.',
        ],
      },
      {
        title: 'Indexes',
        paragraphs: ['Indexes make searches on an attribute fast: value (equals), presence (has a value) and substring (contains). Limber builds a new one; removing one slows searches on that attribute on this server.'],
      },
      {
        title: 'Taking an index offline',
        paragraphs: ['eDirectory stops maintaining an offline index, which speeds up a bulk load; searches on it are slower until it is brought back online and limber rebuilds it. eDirectory\'s own (system and operational) indexes always stay online.'],
      },
      {
        title: 'Index kinds and states',
        list: [
          'User-defined indexes can be removed, taken offline and copied to other servers; a copy is built there by limber, and a server with an index of that name keeps its own.',
          'System and operational indexes are eDirectory\'s own. "With its attribute" ones were made when the attribute was created.',
          'New and pending indexes are waiting for limber, or being built.',
        ],
      },
      {
        title: 'Replica filter',
        caution: true,
        paragraphs: ['The filter says which classes and attributes this server\'s filtered (sparse) replicas hold, by LDAP name. Changing it resynchronises every filtered replica on the server. A filtered read/write replica can create an object only if the filter holds all of its mandatory attributes.'],
      },
    ],
    related: ['edir', 'edir.encryption'],
  },
  'edir.audit': {
    title: 'Auditing',
    summary: 'Which events each server sends as CEF (Common Event Format), and what they include.',
    sections: [
      {
        title: 'What is set here, and what on the server',
        list: [
          'Here: the events, whether replicated events are skipped, whether values are logged, and filters by class and attribute. Stored on the server\'s object.',
          'On the server: where events go (syslog over UDP, TCP or TLS, or a file), caching, and loading the cefauditds module. These are in auditlogconfig.properties.',
          'eDirectory applies a change here within three minutes, or at once when cefauditds is reloaded.',
          'Use eDirectory\'s defaults removes what is stored here; the server then audits its default events.',
        ],
      },
      {
        title: 'Losing events',
        caution: true,
        list: [
          'Without caching, events are lost while the syslog server cannot be reached. Caching does not work over UDP.',
          'Read, search and LDAP search events are numerous on a busy server.',
        ],
      },
    ],
    related: ['settings.syslog'],
  },
  'edir.snmp': {
    title: 'SNMP',
    summary: 'The eDirectory traps each server\'s SNMP subagent sends, and how often.',
    sections: [
      {
        title: 'Traps',
        paragraphs: ['Send no traps turns a group\'s traps off. A trap is sent when its event happens, at most once per interval (0 uses the group\'s default). Failure traps report the event failing. Where traps go, and community strings, are set in the server\'s SNMP agent; the subagent may need restarting to pick up a change made here.'],
      },
    ],
  },
  'edir.encryption': {
    title: 'Encryption',
    summary: 'Encrypted attribute policies and which server uses which, encrypted replication (shown only), and where FIPS mode is set.',
    sections: [
      {
        title: 'Encrypted attributes',
        paragraphs: ['A policy names attributes a server keeps encrypted in its database; each server uses at most one. Giving a server a policy runs limber there, which applies it. A new policy must first reach that server: the console waits up to about 30 seconds, and if it has not arrived by then says so, and you run limber on that server later (eDirectory > Servers, the server). Changing an existing policy applies on each of its servers when limber next runs there. A policy can be deleted only when no server uses it. Encrypting cannot be undone securely: values written before stay on disk in clear text, and so do pieces of old values when a scheme changes. With secure channel only, clear-text LDAP reads of the values fail (-6089). Do not encrypt indexed attributes or eDirectory\'s own. DES and Triple DES are older schemes: prefer AES-256.'],
      },
      {
        title: 'Encrypted replication',
        paragraphs: ['Deprecated from eDirectory 9.2.7; Enhanced Background Authentication secures traffic between servers instead.'],
      },
      { title: 'Auditing encrypted attributes', caution: true, paragraphs: ['With "Log values of encrypted attributes" on (eDirectory > Auditing), their values are written to the audit log in clear text.'] },
    ],
  },
  'edir.ldap': {
    title: 'LDAP',
    summary: 'Each eDirectory server has an LDAP Server object (ports, TLS, limits) in an LDAP Group (name mappings, referrals, TLS for simple binds).',
    sections: [
      {
        title: 'Refresh or reload',
        list: [
          'Refresh: the LDAP server re-reads its LDAP Server and LDAP Group objects. Connections stay open. eDirectory also does this by itself every 30 minutes.',
          'Reload: the LDAP module restarts, which applies TLS, cipher, bind-restriction, mutual authentication, port and certificate changes. Every LDAP connection to that server drops for a moment; reloading the server the console uses signs everyone out of the console.',
          'Both run on the LDAP server\'s own eDirectory server; with a password sign-in you may be asked to sign in to that server once.',
          'This tab refreshes. Reload is on each LDAP server\'s own page; an LDAP group\'s page refreshes all of its servers.',
        ],
      },
    ],
    related: ['edir.ldap-server', 'edir.ldap-group'],
  },
  'edir.ldap-server': {
    title: 'An LDAP server',
    summary: 'One server\'s LDAP settings: where it listens, its certificate and TLS, bind restrictions, limits, searches and trace.',
    sections: [
      {
        title: 'After saving',
        paragraphs: ['Most settings apply at the next refresh. TLS, ciphers, bind restrictions, ports and the certificate need a reload, which drops the server\'s LDAP connections for a moment. The notice after saving says which, with a button.'],
      },
      {
        title: 'Bind restrictions and ciphers',
        list: [
          'Bind restrictions refuse anonymous binds, password binds, or binds with a name and no password.',
          'The cipher level is the weakest cipher a client may use; High is the default. Protocols and ciphers listed under TLS override it.',
          'TLS protocols and ciphers, and referrals, set here override the LDAP group\'s.',
        ],
      },
      {
        title: 'Limits, searches and compatibility',
        list: [
          'Limits: 0 means no limit. The search entry limit does not apply to administrators of the LDAP Server object.',
          'Persistent searches and event monitoring let clients follow changes; they can load a busy server, so cap them.',
          'Compatibility settings are for clients that expect non-standard behaviour: change them only for such a client.',
          'Trace chooses what the LDAP server writes to ndstrace.',
        ],
      },
      {
        title: 'Changing ports or TLS',
        caution: true,
        paragraphs: ['Clients that rely on the old port or on clear-text binds stop working after the reload. The console itself connects with LDAPS; keep its port open on the server it uses.'],
      },
    ],
    related: ['edir.ldap', 'edir.ldap-group'],
  },
  'edir.ldap-group': {
    title: 'An LDAP group',
    summary: 'Settings shared by its LDAP servers: TLS for password binds, the proxy user for anonymous clients, referrals, TLS protocols, and how LDAP names map to eDirectory names.',
    sections: [
      {
        title: 'Name mappings',
        paragraphs: ['Each mapping gives an eDirectory class or attribute its LDAP names. The first is the name the server returns; the others are accepted in requests. Removing a mapping that clients use breaks them.'],
      },
      {
        title: 'Applying changes',
        paragraphs: ['A change applies when each server in the group is refreshed (TLS settings need a reload). Use Refresh its servers, or wait up to 30 minutes.'],
      },
    ],
    related: ['edir.ldap', 'edir.ldap-server'],
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
        title: 'Importing a certificate',
        list: [
          'Import… takes a PKCS#12 (.pfx or .p12) file with a key and its chain, and makes it a new certificate on a server.',
          'eDirectory reads only files protected the way it exports them (3DES for the key, RC2-40 for the certificates), so use an export from eDirectory: Export with key here with PBES1, Identity Console or iManager. Other files are refused before eDirectory is asked.',
        ],
      },
      {
        title: 'Trusted roots',
        list: [
          'Trusted root containers hold certificates that services set up to use them (NMAS, SSL clients configured with the container) accept, with whatever those roots sign.',
          'New container makes one in the Security container, an Organization or an OU; it can be deleted once empty.',
          'Add a root takes a PEM or DER certificate; its name defaults to the certificate\'s CN, or OU. Removing a root stops those services accepting what it signed.',
          'These are the directory\'s trusted roots. The certificates the console itself trusts are under Settings > Trusted certificates.',
        ],
      },

      {
        title: 'Default certificates',
        paragraphs: [
          'Each server has default certificates (SSL CertificateDNS, an EC one and, if you choose, SSL CertificateIP) that LDAP and other services use. Renewing makes a new certificate beside the old one. At the end, the dialog offers to move each LDAP server to its new certificate, and then to reload the moved LDAP servers, each on its own server, so they use it. A reload drops every LDAP connection to that server for a moment; reloading the server the console uses signs everyone out of the console. Delete the old certificates once nothing uses them.',
        ],
      },
      {
        title: 'Server certificates',
        list: [
          'New server certificate: issued by the Organizational CA; eDirectory makes and keeps the key pair. Allow export when you make it if you will need the key elsewhere.',
          'Download gives the certificate and its chain. Export with key gives a password-protected .pfx (PKCS#12) file with the private key; it needs a recent sign-in and is recorded in the audit log. eDirectory refuses a key not made exportable.',
          'PBES2 with AES-256 is the protection to use; PBES1 with 3DES is for older software, such as Java 8 or Windows Server 2016.',
          'A certificate an LDAP server uses cannot be deleted.',
        ],
      },
      { title: 'Expiry', paragraphs: ['Certificates that have expired, or expire within 30 days, are listed at the top.'] },
      { title: 'CA configuration', paragraphs: ['Each switch changes the Organizational CA at once. Server self-provisioning lets eDirectory\'s own PKI Health Check create or renew a server\'s SSL CertificateDNS in place when ndsd starts or DSRepair runs there. Suite B mode needs a CA with only an EC P-256 or P-384 certificate.'] },
      { title: 'Revoking', caution: true, paragraphs: ['Revoking cannot be undone, except with the reason "Certificate on hold". The CA lists the certificate on its CRL from the CRL\'s next issue.'] },
    ],
    related: ['settings.trust'],
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
    sections: [
      {
        title: 'Test a password',
        list: [
          'Choose a user and type a password, or Generate one from this policy\'s rules. Test asks NMAS whether the policy that governs that user accepts it.',
          'Nothing is set and nobody signs in, so a test never counts as a failed login. The audit log records that a test was made, never the password.',
          'NMAS uses the policy governing the user: their own, else the nearest container\'s, else the Login Policy\'s. If that is another policy, the result says so.',
          'When a policy does not say whether digits or special characters are allowed, NMAS does not allow them: tick those rules if passwords may have them.',
        ],
      },
    ],
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
    sections: [{ title: 'Shown only', paragraphs: ['The EBA CA, each server\'s NCP certificate and requests awaiting approval are shown here; EBA is set up and renewed on the servers.'] }],
    related: ['edir.encryption'],
  },

  // ---- Identity Manager ------------------------------------------------------------------------
  idm: {
    title: 'Identity Manager',
    summary: 'The driver set\'s drivers, jobs and settings, on one server\'s engine.',
    sections: [
      {
        title: 'Each server runs its own copy',
        paragraphs: [
          'Driver state, start options, jobs, caches and named passwords belong to one server. Server, beside the driver set\'s name, says which: a choice when several servers run the driver set, else the one that does. It starts on the server the console is connected through.',
        ],
      },
      {
        title: 'Drivers',
        list: [
          'Start options: Automatic starts with the engine; Manual waits to be started; Disabled never starts.',
          'A stopped driver queues events in its cache and sends them when started again.',
          'Disabling a driver deletes its cache: queued events are discarded, and changes made while it is disabled are never sent. It cannot start until its start option is Automatic or Manual again.',
        ],
      },
    ],
    related: ['idm.jobs', 'idm.driver'],
  },
  'idm.drivers': {
    title: 'Drivers',
    summary: 'The driver set\'s drivers on the chosen server: state, start option, cache and trace level.',
    sections: [
      { title: 'Start all and stop all', paragraphs: ['They act on every driver on the chosen server that needs it, one at a time, and show each result. A disabled driver is not started.'] },
    ],
    related: ['idm', 'idm.driver'],
  },
  'idm.jobs': {
    title: 'Jobs',
    summary: 'Scheduled and on-demand tasks the engine runs, such as triggering a driver or checking driver health.',
    sections: [
      {
        title: 'Working with jobs',
        list: [
          'New job offers the types this server\'s engine has.',
          'The schedule is five cron fields (minute hour day month weekday), in each server\'s local time. No schedule means it runs only when started.',
          'Objects: the job runs once per object found under each container or entry you give; with none it runs once.',
          'Runs on: the servers whose engine runs the job. Each server needs it chosen; it runs in that server\'s local time.',
          'Select a job to change it: enabled, schedule, servers, objects and its parameters. Only the values you change are rewritten; the rest of the job\'s definition is kept as it was.',
          'A job that is not enabled keeps its settings but never runs. Deleting a job asks for its name.',
        ],
      },
      {
        title: 'Named passwords',
        list: [
          'Some job types (Driver Health, Password Expiration Notification) log in somewhere with a password. The job keeps it as a named password, which the parameter names.',
          'Each server that runs the job keeps its own copy, so the console sets it on every server in Runs on and shows where it is set. Add a server later, and set the password again.',
          'Passwords are never shown or read back; set one again to change it.',
        ],
      },
    ],
    related: ['idm'],
  },
  'idm.servers': { title: 'Servers and activation', summary: 'Which servers run this driver set, and Identity Manager\'s activation (licence) state on each.', sections: [] },
  'idm.properties': {
    title: 'Driver set properties',
    summary: 'The driver set\'s settings, as configured. They are changed in Designer, not here.',
    sections: [
      { title: 'Global configuration values', paragraphs: ['GCVs are named settings policies read, set on the driver set and on each driver.'] },
      { title: 'Java environment', paragraphs: ['Java environment changes take effect when the Identity Vault restarts.'] },
    ],
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
          'Only the trace level is changed here. The trace file, its size limit and the other settings are shown; they are changed in Designer.',
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
          'Deleting a table asks for its name; policies that name it then fail to find it.',
        ],
      },
      { title: 'When changes apply', caution: true, paragraphs: ['Drivers read a table when they start: restart the drivers that use it.'] },
    ],
  },
  'idm.log': {
    title: 'Log level',
    summary: 'Which events the engine records in its log. The driver set\'s level is shown here; each driver\'s is changed on its own Log level tab.',
    sections: [{ title: 'Levels', list: ['Off, errors, or errors and warnings.', '"Only record when it last logged" keeps no events, only the time.', 'A driver can use the driver set\'s level.'] }],
  },
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
  'idm.driver.overview': {
    title: 'Driver overview',
    summary: 'State, start option and cache on the chosen server, with start, stop and restart, resynchronising and migrating.',
    sections: [
      { title: 'Start option', paragraphs: ['Automatic starts with the engine; Manual waits to be started. Disabled deletes the cache and keeps no events: stop the driver instead to keep queueing them.'] },
      { title: 'On each server', paragraphs: ['With more than one server, a table shows the driver\'s state and start option on each.'] },
      {
        title: 'Migrate',
        list: [
          'Vault objects to the application: each object found is sent as if just added, so the driver matches or creates it. Find the objects shows what would be sent first.',
          'Choose the container with Browse, then a class and conditions as on the Search page, or write an LDAP filter instead.',
          'Application objects into the vault: the engine asks the application for its objects and brings each in through the publisher channel\'s matching, creation and placement policies.',
        ],
      },
      { title: 'Resynchronising', caution: true, paragraphs: ['Resynchronising asks the driver to send its objects again, optionally only those changed since a date. On a large driver this loads the connected system.'] },
    ],
    related: ['idm.driver'],
  },
  'idm.driver.associations': {
    title: 'Association inspector',
    summary: 'Every object associated with this driver, counted by state, with bulk changes.',
    sections: [
      { title: 'Counts', paragraphs: ['A count marked with ~ is an estimate.'] },
      { title: 'Setting the state', paragraphs: ['Set to changes the state of the chosen objects; the five states are explained on an object\'s Associations tab.'] },
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
  'idm.driver.trace': {
    title: 'Driver trace',
    summary: 'How much this driver writes to its trace, and where.',
    sections: [{ title: 'Levels', list: ['0 to 10; 5 shows password synchronization.', '"Use the driver set\'s" removes the driver\'s own level.', 'Higher levels slow the engine: set them back when you are done.'] }],
    related: ['idm.trace'],
  },
  'idm.driver.log': { title: 'Log level', summary: 'Which events the engine records in its log for this driver, or the driver set\'s level.', sections: [], related: ['idm.log'] },
  'idm.driver.passwords': {
    title: 'Driver passwords',
    summary: 'Named passwords for this driver\'s policies, and the passwords it uses with the Remote Loader.',
    sections: [
      { title: 'Write-only', paragraphs: ['Passwords can be set or cleared here, but never read back. Removing a named password leaves policies that read it with nothing.'] },
      { title: 'Remote Loader', list: ['Remote Loader password: what the engine and the Remote Loader use to trust each other.', 'Key and keystore passwords: for mutual authentication with certificates.'] },
    ],
    related: ['idm.passwords'],
  },
  'idm.driver.password-sync': { title: 'Password synchronization', summary: 'How this driver handles passwords between the vault and the connected system.', sections: [] },

  // ---- Console certificates and settings -------------------------------------------------------
  'settings.trust': {
    title: 'Trusted certificates',
    summary: 'The certificates the console accepts from your directories\' servers, and from the services it calls. This is the console\'s own trust store; it does not change eDirectory.',
    sections: [
      {
        title: 'Kinds of trust',
        list: [
          'Certificate authority: any server certificate it issued is accepted.',
          'This server only (pinned): exactly this certificate, at this address. If the server presents another, connections to it are refused until you review and trust the new one (Changed certificates).',
          'Host exception: a certificate accepted at an address it does not name (NAT, a tunnel, a load balancer).',
        ],
      },
      {
        title: 'On this page',
        list: [
          'Directories: what each configured directory\'s server presents now. Review trusts it; Check again asks again.',
          'Probe a server reads a server\'s certificate to trust it; Upload a certificate trusts a PEM file. Either can be for one directory or for all.',
          'Changed certificates: a pinned server presented a different one. Connections stay refused until you trust the new one; dismiss an alert only once you know why it changed.',
          'Certificates people accepted for directories they entered themselves are listed too, and can be removed.',
        ],
      },
      {
        title: 'What else uses it',
        paragraphs: ['Single sign-on providers, ACME certificate authorities and syslog servers over TLS are accepted with a certificate from a public CA (Java\'s own list) or from a certificate authority trusted here. Add an internal CA here for those; a CA trusted for one directory also covers that directory\'s single sign-on provider. It applies from the next connection, without a restart.'],
      },
      { title: 'Expiry', paragraphs: ['A banner on every page warns admins of trusted certificates that have expired or expire within the warning window set in Settings > Certificate expiry (30 days unless changed).'] },
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
      { title: 'Sessions', paragraphs: ['Idle sign-out and the longest session apply to everyone on this directory, at once. People are warned two minutes before an idle sign-out, and told when the longest session will end.'] },
      {
        title: 'Service account',
        paragraphs: [
          'The account the console uses to find people by a short name at sign-in, and for single sign-on. It needs to read the people it finds. Without one, people sign in with their full name (DN).',
          'Check its rights reads the account\'s own effective rights on a few people under each container: Browse, Compare and Read for sign-in; Supervisor for single sign-on (and Identity Manager under it). It also flags more than it needs: Supervisor over the whole tree, or over a break-glass account. A sample stands for each container, so a pass is a good sign, not a proof for every account.',
        ],
      },
      {
        title: 'Finding people at sign-in',
        list: [
          'Search bases are where a short name is looked for; none searches the whole directory. This needs the service account.',
          'When a name matches several people, they choose their account, or are asked for their full name.',
          'With password sign-in limited to single sign-on (Settings > Single sign-on), a short name is looked for only among the accounts still allowed a password.',
        ],
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
      { title: 'Break-glass accounts', paragraphs: ['The directory administrators who set the console up. They can always sign in as admins, even when no mapping applies, and always with a password, even when password sign-in is limited to single sign-on.'] },
    ],
  },
  'settings.presets': {
    title: 'Task presets',
    summary: 'Narrow, named tasks (such as "reset a password") that people can run without a broader role.',
    sections: [
      { title: 'Fields', list: ['Required: must be filled in.', 'Read-only: shown, not changed.', 'Pattern: the value must match.', 'Fixed value: always set to this.'] },
      { title: 'Moving presets', paragraphs: ['Export saves every preset as a JSON file; Import adds or replaces presets from one, by id. A preset granted to anyone cannot be removed.'] },
    ],
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
          'The provider\'s certificate must be from a public CA, or from a CA the console trusts (Settings > Trusted certificates, for every directory or this one).',
          'Provider groups map groups in the provider\'s groups claim to console roles and task presets, as role mappings do for eDirectory groups.',
          'Under these containers limits who can sign in this way. The service account needs Supervisor over those people, and nobody else.',
          'Try the mapping shows which account a claim value finds. No match, several matches, or a never-act-as account means the sign-in is refused.',
          'Check its rights (at the top) shows whether the service account can act as people under these containers, which single sign-on and Identity Manager under it need.',
        ],
      },
      {
        title: 'Password sign-in',
        list: [
          'By default people may sign in with single sign-on or with their name and password.',
          'Single sign-on only: the sign-in page offers single sign-on first, and only the break-glass accounts and the accounts listed here may sign in with a password. Listed accounts keep the roles their groups give them.',
          'Keep a way in for when the provider is down: the break-glass accounts always have one.',
          'While password sign-in is limited, single sign-on and the service account cannot be removed. Allow passwords again first.',
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
  'settings.certificate': {
    title: 'Console certificate',
    summary: 'The certificate the console presents for HTTPS: one you upload, or one got and renewed from an ACME certificate authority.',
    sections: [
      {
        title: 'Uploading a certificate',
        list: [
          'A PKCS#12 file (.pfx, .p12) with its password, or PEM: the certificate with its intermediate CAs (in any order) and the private key (PKCS#8, RSA or EC, encrypted or not).',
          'The console checks that the key and certificate belong together, that the certificate is valid now, and that it names the address browsers use. It installs it at once, without a restart, and records it in the audit log.',
          'Only when a reverse proxy connects to the console by another name, tick the box that lets the certificate name something else.',
          'An uploaded certificate is not renewed: the expiry check warns before it runs out. While ACME is on, it would replace an upload, so upload is offered only with ACME off.',
        ],
      },
      {
        title: 'How DNS-01 works here',
        list: [
          'For each name the CA gives a token; the console adds it as a TXT record at _acme-challenge.<name> with a dynamic update (RFC 2136) signed with your TSIG key.',
          'It waits until the zone\'s server answers the record, tells the CA to look, and removes the record whatever happens.',
          'It then sends a request for a new key (P-256) and installs the certificate at once, without a restart.',
          'Once a day it renews when 30 days or fewer remain, or when the names change.',
        ],
      },
      {
        title: 'Setting it up',
        list: [
          'Create a TSIG key on the DNS server, allowed to change only TXT records under _acme-challenge in the zone (in BIND: update-policy { grant key. zonesub TXT; }).',
          'Enter the zone\'s primary server, the zone, the key\'s name, algorithm and secret, and use Test DNS: it adds a record, reads it back and removes it.',
          'Try Let\'s Encrypt staging first; its certificates are not trusted by browsers, but its limits are generous.',
          'An internal ACME CA (step-ca, for example) works too, once the console trusts its root (Settings > Trusted certificates, for every directory).',
        ],
      },
      {
        title: 'When something fails',
        paragraphs: ['The current certificate stays in use. The page shows the error and the steps that were done; the attempt is also in the audit log.'],
      },
    ],
    related: ['settings.expiry', 'settings.trust'],
  },
  'settings.expiry': {
    title: 'Certificate expiry',
    summary: 'A daily check of every certificate the console can see, with notices by e-mail and webhook.',
    sections: [
      {
        title: 'What is checked',
        list: [
          'The console\'s own TLS certificate and the certificates it trusts.',
          'For each directory with a service account: its Organizational CA, server certificates and trusted roots.',
          'A directory without a service account is skipped, and said so.',
        ],
      },
      {
        title: 'The warning window',
        paragraphs: ['Warn this many days ahead (1 to 365) sets when these notices go out, and when the banner at the top of every page starts warning. The alerts on Security > Certificates and the default-certificate check always warn 30 days ahead.'],
      },
      {
        title: 'When notices go out',
        paragraphs: ['Once when a certificate enters the warning window, again when it is within a week, and once when it has expired. Each is also written to the audit log. Send a test checks the e-mail and webhooks now.'],
      },
      { title: 'Webhooks', paragraphs: ['Up to five. Each notice is POSTed as JSON; with a secret, X-Console-Signature carries sha256= and the HMAC-SHA256 of the body.'] },
    ],
    related: ['settings.trust', 'security.certificates'],
  },
  'settings.syslog': {
    title: 'Syslog',
    summary: 'Every audit-log entry sent on to a syslog server as it is written, in CEF, so a SIEM can collect the console\'s events beside eDirectory\'s.',
    sections: [
      {
        title: 'The format',
        list: [
          'RFC 5424 syslog messages; the text is CEF: CEF:0|Point Blue|Directory Console|version|event|name|severity|...',
          'suser is who acted, src the person\'s address, cs1 how they signed in, act the event, outcome ok, refused or failed, cs2 the target, cs3 the details (secrets are never included; cs3 is cut at 3000 characters), rt the time, cn1 the entry\'s number in the audit log.',
          'Severity 3 when it went through, 5 when refused, 7 when it failed.',
        ],
      },
      {
        title: 'Transports',
        list: [
          'TLS (RFC 5425, port 6514): the server\'s certificate must be from a public CA or a CA the console trusts, and name the host.',
          'TCP (octet counting) or UDP (port 514) are not encrypted; UDP can lose messages without telling.',
        ],
      },
      { title: 'Facility', paragraphs: ['The syslog facility the messages carry; authpriv by default. Send a test sends one message now.'] },
      {
        title: 'When the server cannot be reached',
        paragraphs: ['Entries wait in a queue of 2000 and are retried; beyond that they are dropped and counted here. The console\'s own audit log always keeps every entry.'],
      },
    ],
    related: ['settings.expiry'],
  },
  'settings.backup': {
    title: 'History and backup',
    summary: 'Earlier versions of the console\'s settings, and a passphrase-protected backup of everything in its data volume that a restore needs.',
    sections: [
      {
        title: 'Configuration history',
        list: [
          'Every change to the console\'s settings is saved as a new version, with who made it and why. Select the change to see which settings it touched (secrets show only as a secret).',
          'Restore makes an earlier version current again, as a new version; nothing is lost from the history. Secrets come back with it.',
          'The trust store and the console\'s own certificate are not part of a version: they are files beside it.',
        ],
      },
      {
        title: 'Backups',
        list: [
          'A backup holds the configuration and its history, the trust store, the console\'s TLS key and certificate, the configuration key, and (if you choose) the audit log.',
          'It is encrypted with AES-256-GCM under your passphrase (at least 12 characters). The passphrase is not kept: without it the backup cannot be restored.',
          'Keep the file and its passphrase apart: together they unlock every secret the console holds.',
        ],
      },
      {
        title: 'Restoring',
        list: [
          'The file is checked when you choose it, then waits until the console next starts; restart the container to apply it. Until then you can cancel it.',
          'At the start the configuration, its history, the trust store, the TLS identity and the configuration key are replaced, and everyone signs in again. The restore is written to the audit log.',
          'The audit log in a backup is restored only onto a console whose audit log is empty (a new volume), so the record of what happened since is never rewritten.',
        ],
        caution: true,
      },
    ],
    related: ['audit'],
  },
  audit: {
    title: 'Audit log',
    summary: 'Everything done through the console, by whom, and whether it went through: sign-ins, changes to the directory, Identity Manager operations and the console\'s own settings.',
    sections: [
      {
        title: 'Reading it',
        list: [
          'Newest first. Filter by event (a prefix such as object. or idm. works), by who acted, by outcome, by date, or by any text in the entry.',
          'Expand an entry for its details. Attribute names are recorded, never values; secrets never appear.',
          'Older entries loads the next page.',
        ],
      },
      {
        title: 'Exports',
        paragraphs: ['CSV for a spreadsheet, or JSON Lines exactly as stored. Exports follow the filters. In CSV, a cell starting with =, +, - or @ is prefixed with a quote so a spreadsheet does not run it.'],
      },
      {
        title: 'Check the chain',
        paragraphs: ['Each entry carries a hash of the one before it, so an edited or removed entry breaks the chain. The check reads every entry and says where a break is, if there is one.'],
      },
    ],
    related: ['settings.syslog', 'settings.backup'],
  },
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
