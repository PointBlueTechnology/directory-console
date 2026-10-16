# Status

Where Directory Console stands as of version 0.3.6 (October 2026): what works, what has limits, and what is not built yet.
It is a beta release. It has been tested against lab trees running eDirectory 9.2 and 9.3, and Identity Manager 4.8.

## Works

| Area | What |
|---|---|
| Setup | First sign-in from the setup link sets the console up. More directories (dev, test, production) are added, renamed and removed under Settings > Directories. |
| Sign-in | Direct sign-in with a full name (DN), or a short name once a service account is set. Single sign-on with OpenID Connect. Break-glass accounts. Sign-in to a directory a person types in, when an admin allows it. "Remember my name" keeps the name and tree in the browser, never the password. Each tree sets its own idle timeout and longest session, and people are warned before either ends. |
| Access | Role mappings from eDirectory groups to viewer, editor, operator and admin, optionally limited to containers. Task presets. Sensitive changes ask for a recent sign-in; production trees ask for the tree's name. |
| Directory objects | Browse and search (sorted and paged in large containers), view and edit, create (users and groups with eDirectory's standard classes, or any class), rename, move, delete, auxiliary classes with their mandatory attributes, effective rights, account tasks, group membership. |
| Schema | Browse classes and attributes, with their flags and where each attribute is used. Add classes and attributes, and add optional attributes to a class. |
| eDirectory | Partitions and replicas, servers, indexes, password policies, challenge sets, login methods, enhanced background authentication. |
| Certificates | The organizational CA and its configuration, server and user certificates, repairing the default server certificates, CRLs. |
| Identity Manager | **Drivers and driver sets:** state, start and stop (also all at once), start options, trace and log levels, named and Remote Loader passwords, properties (read-only), statistics, versions. **Jobs:** run, abort, create, edit, delete. **Inspection:** the cache inspector, the association inspector, the object inspector, per-user password synchronization status. **Data:** migrate and synchronize, mapping tables. |
| Console | Its own TLS certificate, a trust store with fingerprint confirmation, versioned configuration with encrypted secrets, a hash-chained audit log, trusted reverse proxies. Shows its version, and tells administrators when a newer release is out (a daily check that can be turned off). |
| Container | Published for amd64 and arm64. Distroless, non-root, read-only root file system. No OpenText code, and nothing to mount for Identity Manager. |

## Limits

- **Identity Manager and other sign-in types:** Identity Manager needs a direct sign-in. People who sign in with single sign-on, or to a directory they typed in, can do everything else.
- **Identity Manager is per server:** it works on the engine of the server you signed in to. Driver state, jobs, caches and passwords apply to that server; the console lets you choose another server of the tree.
- **Driver properties are read-only, by design:** they are changed in Designer. The trace level is the exception.
- **Jobs:** a job's own named passwords (used by Driver Health and Password Expiration Notification) cannot be set yet. After a job is created, only its enabled state, schedule and servers can be changed, not its parameters or scope.
- **Login policy:** the default login sequence and the list of authorized sequences are shown but cannot be changed yet.
- **Certificates:** user certificates cannot be deleted. Validation results are not shown.
- **API only for now:** reading and exporting the audit log, and the configuration's history.

## Not built yet

- **Certificates and trust:** ACME certificates for the console, expiry monitoring and notifications (e-mail and webhooks), creating and deleting trusted roots, PKCS#12 export with the private key, and importing a CA.
- **Configuration:** backup and restore from inside the console. A volume backup works today; see [UPGRADING.md](UPGRADING.md).
- **eDirectory:**
  - LDAP Server and LDAP Group forms, including class and attribute mappings;
  - encrypted attributes and replication;
  - replica filters;
  - CEF auditing and SNMP;
  - FIPS 140-3 mode;
  - extra password policy options.
- **Identity Manager:** work orders, e-mail templates and RBE policies.

## Known issues

- **Docker's network overlaps 172.17.x:** Docker uses `172.17.0.0/16` for its own network. A tree whose address is in that range cannot be reached from the container until Docker's networks are moved; the [quickstart](QUICKSTART.md#troubleshooting) shows how.
- **Occasional CI stall:** about once a week, one test in CI waits about 40 seconds for an answer that never comes, and passes on a rerun. It has not been reproduced locally.
