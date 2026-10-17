# Status

Where Directory Console stands as of version 0.3.8 (October 2026): what works, what has limits, and what is not built yet.
It is a beta release. It has been tested against lab trees running eDirectory 9.2 and 9.3, and Identity Manager 4.8.

## Works

| Area | What |
|---|---|
| Setup | First sign-in from the setup link sets the console up. More directories (dev, test, production) are added, renamed and removed under Settings > Directories. |
| Sign-in | Direct sign-in with a full name (DN), or a short name once a service account is set. Single sign-on with OpenID Connect. Break-glass accounts. Sign-in to a directory a person types in, when an admin allows it. "Remember my name" keeps the name and directory in the browser, never the password. Each directory sets its own idle timeout and longest session, and people are warned before either ends. |
| Access | Role mappings from eDirectory groups to viewer, editor, operator and admin, optionally limited to containers. Task presets. Sensitive changes ask for a recent sign-in; production directories ask for the directory's name. |
| Directory objects | Browse and search (sorted and paged in large containers), view and edit, create (users and groups with eDirectory's standard classes, or any class), rename, move, delete, auxiliary classes with their mandatory attributes, effective rights, account tasks, group membership. |
| Schema | Browse classes and attributes, with their flags and where each attribute is used. Add classes and attributes (with flags such as public read and per replica), and add optional attributes to a class. |
| eDirectory | Partitions and replicas, servers, indexes (taking them offline and back, copying them to other servers), LDAP servers and groups (eDirectory > LDAP: ports, TLS, bind restrictions, limits, referrals, trace, class and attribute mappings) with refresh and reload, CEF auditing settings (eDirectory > Auditing, per server), SNMP traps (eDirectory > SNMP), encrypted attribute policies (eDirectory > Encryption) and, on a server's page, its encryption policy and replica filter, encrypted replication (read-only, deprecated), password policies, challenge sets, login methods, enhanced background authentication. |
| Certificates | The organizational CA and its configuration, server and user certificates, repairing the default server certificates, CRLs, export with the private key (PKCS#12), import of a server certificate from a PKCS#12 file in eDirectory's own form, trusted root containers and roots (made and removed). |
| Identity Manager | **Drivers and driver sets:** state, start and stop (also all at once), start options, trace and log levels, named and Remote Loader passwords, properties (read-only), statistics, versions. **Jobs:** run, abort, create, edit, delete. **Inspection:** the cache inspector, the association inspector, the object inspector, per-user password synchronization status. **Data:** migrate and synchronize, mapping tables. |
| Console | Its own TLS certificate, from an ACME CA with DNS-01 through RFC 2136 updates and renewed automatically (Settings > Console certificate), a daily certificate expiry check (its own, its trust store's, and the PKI of each directory with a service account) with e-mail and signed webhook notices (Settings > Certificate expiry), audit entries forwarded to syslog as CEF over RFC 5424, by TLS, TCP or UDP (Settings > Syslog), a trust store with fingerprint confirmation, versioned configuration with encrypted secrets, a hash-chained audit log, trusted reverse proxies. Shows its version, and tells administrators when a newer release is out (a daily check that can be turned off). |
| Interface | Help for each page and tab (the ? in the header), with hover hints and field help from one glossary. Disabled buttons say why. Consequential actions ask first: resynchronise, migrate, abort a job, remove a named password, remove the service account, unassign a password policy. |
| Container | Published for amd64 and arm64. Distroless, non-root, read-only root file system. No OpenText code, and nothing to mount for Identity Manager. |

## Limits

- **Identity Manager and other sign-in types:** Identity Manager needs a direct sign-in. People who sign in with single sign-on, or to a directory they typed in, can do everything else.
- **Identity Manager is per server:** it works on the engine of the server you signed in to. Driver state, jobs, caches and passwords apply to that server; the console lets you choose another server of the tree.
- **Driver properties are read-only, by design:** they are changed in Designer. The trace level is the exception.
- **Jobs:** a job's own named passwords (used by Driver Health and Password Expiration Notification) cannot be set yet. After a job is created, only its enabled state, schedule and servers can be changed, not its parameters or scope.
- **Login policy:** the default login sequence and the list of authorized sequences are shown but cannot be changed yet.
- **Certificates:** user certificates cannot be deleted. Only a user can export their own certificate's private key (eDirectory keeps it under their key). Validation results are not shown.
- **Work on another server:** replica changes, LDAP refresh and reload, and applying an encrypted attribute policy go over a connection to that server. The console must reach that server's LDAPS port. With a direct sign-in, it asks you to sign in to that server once.
- **Syslog forwarding is best effort:** while the syslog server cannot be reached, up to 2000 entries wait. After that they are dropped and counted under Settings > Syslog. The console's own audit log keeps every entry.
- **Audit log and configuration history:** there is no screen for them. Check the audit chain with `admin verify-audit` or `GET /api/v2/audit/verify`, and forward entries as they are written under **Settings > Syslog**. The entries (`audit/audit-YYYY-MM.jsonl`) and earlier configurations (`config/history/`) are files in the data volume.

## Not built yet

- **Certificates and trust:** ACME with HTTP-01 or TLS-ALPN-01 (DNS-01 only, so far), importing a user certificate, and importing a CA.
- **Configuration:** backup and restore, and reading the audit log and the configuration's history, from inside the console. A volume backup works today; see [UPGRADING.md](UPGRADING.md).
- **eDirectory:**
  - changing encrypted replication (deprecated from 9.2.7; shown only);
  - CEF destinations and caching, SNMP trap destinations and FIPS mode: these are set in files on each server, not in the directory;
  - extra password policy options.
- **Identity Manager:** work orders, e-mail templates and RBE policies.

## Known issues

- **Docker's network overlaps 172.17.x:** Docker uses `172.17.0.0/16` for its own network. A tree whose address is in that range cannot be reached from the container until Docker's networks are moved; the [quickstart](QUICKSTART.md#troubleshooting) shows how.
