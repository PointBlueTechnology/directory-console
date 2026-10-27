# Status

Where Directory Console stands as of version 0.3.24 (October 2026): what works, what has limits, and what is not built yet.
It is a beta release. It has been tested against lab trees running eDirectory 9.2 and 9.3, and Identity Manager 4.8.

## Works

| Area | What |
|---|---|
| Setup | First sign-in from the setup link sets the console up. More directories (dev, test, production) are added, renamed and removed under Settings > Directories. |
| Sign-in | Direct sign-in with a full name (DN), or a short name once a service account is set. Single sign-on with OpenID Connect (with a check of the service account's rights), optionally the only way in: password sign-in is then for break-glass and listed accounts only. Break-glass accounts. Sign-in to a directory a person types in, when an admin allows it. "Remember my name" keeps the name and directory in the browser, never the password. Each directory sets its own idle timeout and longest session, and people are warned before either ends. |
| Access | Role mappings from eDirectory groups to viewer, editor, operator and admin, optionally limited to containers. Task presets. Sensitive changes ask for a recent sign-in; production directories ask for the directory's name. |
| Directory objects | Browse and search (basic by name and kind; advanced with a nested AND/OR/NOT filter builder or RFC 4515 text checked as typed, three depths, chosen and ordered columns; sorted and paged in large containers; saved and recent searches in the browser), export of a search or of an object, its children or its subtree as LDIF (RFC 2849), CSV or JSON, streamed by the server with no size cap and audited, view and edit (long values on one line until pointed at; role assignments and other Path values as links), create (users and groups with eDirectory's standard classes, or any class), rename, move, delete, auxiliary classes with their mandatory attributes, effective rights, account tasks, group membership. |
| Schema | Browse classes and attributes, with their flags and where each attribute is used. Add classes and attributes (with flags such as public read and per replica), and add optional attributes to a class. |
| eDirectory | Partitions and replicas, servers, indexes (taking them offline and back, copying them to other servers), LDAP servers and groups (eDirectory > LDAP: ports, TLS, bind restrictions, limits, referrals, trace, class and attribute mappings) with refresh and reload, CEF auditing settings (eDirectory > Auditing, per server), SNMP traps (eDirectory > SNMP), encrypted attribute policies (eDirectory > Encryption) and, on a server's page, its encryption policy and replica filter, encrypted replication (read-only, deprecated), password policies (with testing a password against one, and generating one from it), challenge sets, login methods, enhanced background authentication. |
| Certificates | The organizational CA and its configuration, server and user certificates, repairing the default server certificates, CRLs, export with the private key (PKCS#12), import of a server certificate from a PKCS#12 file in eDirectory's own form, trusted root containers and roots (made and removed). |
| Identity Manager | **Drivers and driver sets:** state, start and stop (also all at once), start options, trace and log levels, named and Remote Loader passwords, properties (read-only), statistics, versions. **Jobs:** run, abort, create, edit (enabled, schedule, servers, objects and parameters), delete, and their named passwords, set on each server that runs the job. **Inspection:** the cache inspector, the association inspector, the object inspector, per-user password synchronization status. **Data:** migrate and synchronize, mapping tables. |
| Console | One Java 21 server, published as a container image: with Docker or on Kubernetes, or (discouraged) as a plain Java program ([DEPLOYING.md](DEPLOYING.md)). Its own TLS certificate, uploaded (PKCS#12 or PEM) or from an ACME CA with DNS-01 through RFC 2136 updates and renewed automatically (Settings > Console certificate), a daily certificate expiry check (its own, its trust store's, and the PKI of each directory with a service account) with e-mail and signed webhook notices (Settings > Certificate expiry), audit entries forwarded to syslog as CEF over RFC 5424, by TLS, TCP or UDP (Settings > Syslog), a trust store with fingerprint confirmation (Settings > Trusted certificates), also used beside Java's public roots for single sign-on providers, ACME CAs and syslog over TLS, versioned configuration with encrypted secrets and its history with restore of any earlier version (Settings > History and backup), passphrase-encrypted backups downloaded from the console and restored at the next start, a hash-chained audit log with filters, CSV and JSON Lines export and a chain check (Audit log), trusted reverse proxies. Shows its version, and tells administrators when a newer release is out (a daily check that can be turned off). |
| Interface | Help for each page and tab (the ? in the header), with hover hints and field help from one glossary. Disabled buttons say why. Consequential actions ask first: resynchronise, migrate, abort a job, remove a named password, remove the service account, unassign a password policy. |
| Container | Published for amd64 and arm64. Distroless, non-root, read-only root file system. No OpenText code, and nothing to mount for Identity Manager. |

## Limits

- **Identity Manager and directories typed in:** Identity Manager is not available on a directory a person types in at sign-in; they can do everything else there. With single sign-on it works as with a direct sign-in: the console's service account opens the engine connection and every request acts as the person, so the engine decides with their rights.
- **Identity Manager is per server:** it works on the engine of the server you signed in to. Driver state, jobs, caches and passwords apply to that server. Server, on the driver set's and driver's pages, names it, and offers the other servers that run the driver set.
- **Driver properties are read-only, by design:** they are changed in Designer. The trace level is the exception.
- **Job named passwords are per server:** each server that runs a job keeps its own copy. The console sets one on every server in the job's Runs on list; a server added later needs it set again (the job shows where it is set).
- **Login policy:** the default login sequence and the list of authorized sequences are shown but cannot be changed yet.
- **Certificates:** user certificates cannot be deleted. Only a user can export their own certificate's private key (eDirectory keeps it under their key). Validation results are not shown.
- **Work on another server:** replica changes, LDAP refresh and reload, and applying an encrypted attribute policy go over a connection to that server. The console must reach that server's LDAPS port. With a direct sign-in, it asks you to sign in to that server once.
- **A restore applies at the next start:** Settings > History and backup checks the file and stages it; restart the console (the container, or the service without one) to apply it. A backup's audit log is restored only onto an empty one.
- **Search:** saved and recent searches are kept in the browser that ran them, for one directory; they are not shared. Results cannot be edited in the table (use the object's details). Exports are in the directory's order, not sorted. LDIF import is not built.
- **Password policies:** eDirectory treats unset "digits allowed" and "special characters allowed" as not allowed, even when the policy requires a minimum of them; such a policy accepts no password, and the console says so.
- **Syslog forwarding is best effort:** while the syslog server cannot be reached, up to 2000 entries wait. After that they are dropped and counted under Settings > Syslog. The console's own audit log keeps every entry.

## Not built yet

- **Certificates and trust:** ACME with HTTP-01 or TLS-ALPN-01 (DNS-01 only, so far), importing a user certificate, and importing a CA.
- **eDirectory:**
  - changing encrypted replication (deprecated from 9.2.7; shown only);
  - CEF destinations and caching, SNMP trap destinations and FIPS mode: these are set in files on each server, not in the directory;
  - extra password policy options.
- **Identity Manager:** work orders, e-mail templates and RBE policies; viewing a driver's policies and its trace output (Designer and DirXMLDevWeb do these today).
- **Search:** saved searches shared between people.

## Known issues

- **Docker's network overlaps 172.17.x:** Docker uses `172.17.0.0/16` for its own network. A tree whose address is in that range cannot be reached from the container until Docker's networks are moved; the [quickstart](QUICKSTART.md#troubleshooting) shows how.
