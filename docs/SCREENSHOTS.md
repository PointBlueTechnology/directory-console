# Screenshots

A tour of the main functions. These screenshots come from the built-in demo (`DemoServer`, an in-memory sample tree
with a stand-in Identity Manager engine), so the names and numbers are made up. The pages look the same against a
real tree.

- [Signing in](#signing-in)
- [Directory objects](#directory-objects): browse, attributes, set a password, search
- [Schema](#schema)
- [eDirectory](#edirectory): partitions and replicas, a server, an LDAP server
- [Security](#security): certificates, password policies
- [Identity Manager](#identity-manager): driver set, driver, jobs
- [Audit log](#audit-log)
- [Settings](#settings): single sign-on, trusted certificates, history and backup, the console's certificate

## Signing in

Sign in with an eDirectory name and password, or through single sign-on when it is set up. With several
directories configured, you choose one here.

![The sign-in page](images/sign-in.png)

## Directory objects

**Browse.** The tree on the left and the container's contents in the middle, sorted and paged even in large
containers. Choosing an object opens a summary beside the list.

![Browsing the tree, with a user open beside the list](images/browse.png)

**Attributes.** Every attribute and its values, each editable in place. Distinguished names link to their objects.
Passwords are never shown. The tabs cover the account, certificates, groups, Identity Manager associations,
effective rights and replicas.

![A user's attributes](images/object-attributes.png)

**Set a password.** The dialog names the password policy that governs the user and shows its rules compactly.
Generate makes a password from those rules, and NMAS checks it against the policy before anything is set.

![Setting a password with a generated one](images/set-password.png)

**Search.** Search under any container (with a browser for choosing it), on conditions or an LDAP filter. Choose
the columns, save the search for later, and export the results as CSV or JSON.

![Search results with chosen columns](images/search.png)

## Schema

Classes and attributes, with their OIDs, inheritance, containment and flags. Add classes and attributes, or add
optional attributes to an existing class.

![The inetOrgPerson class in the schema browser](images/schema.png)

## eDirectory

**Partitions and replicas.** Every partition with its replicas and their types. Add replicas, change their type,
merge partitions and set replica filters.

![Partitions and replicas](images/edir-partitions.png)

**A server.** Its replicas, and its indexes: add one, take it offline and back, or copy it to other servers. Run
limber, janitor and skulker, or refresh the LDAP server.

![A server with its replicas and indexes](images/edir-server.png)

**An LDAP server.** Ports, certificate, TLS and client-certificate requirements, bind restrictions and cipher level,
with refresh and reload. LDAP groups, auditing, SNMP and encrypted attribute policies have their own tabs.

![An LDAP server's settings](images/edir-ldap-server.png)

## Security

**Certificates.** The organizational CA and its configuration, server and user certificates, repair of the default
server certificates, CRLs, and export with the private key.

![The organizational CA](images/security-certificates.png)

**Password policies.** Edit a policy's rules and assignments. Test a password against the policy that governs a
chosen user, without setting it. Rules that contradict each other (so no password could pass) are flagged.

![A password policy's assignments and password test](images/password-policy.png)

## Identity Manager

**Driver set.** Its drivers with their state and start options; start, stop and restart one or all. The tabs cover
jobs, servers and activation, properties, statistics, versions, trace, mapping tables, log level and named
passwords.

![A driver set and its drivers](images/idm-driver-set.png)

**Driver.** State and start options, resynchronize and migrate, and the cache, association and health inspectors,
trace, passwords and password synchronization.

![A driver's overview](images/idm-driver.png)

**Jobs.** Run and abort jobs, and create, edit and delete them: schedule (shown in words), servers, objects in scope
and the job's own parameters, including passwords.

![Editing a job's schedule, servers and objects](images/idm-jobs.png)

## Audit log

What was done through the console: sign-ins, changes, refusals and exports. Filter it, export it, and check its
hash chain.

![The audit log](images/audit-log.png)

## Settings

**Single sign-on.** An OpenID Connect provider for signing in, with the redirect URI to register at the provider.

![Single sign-on settings](images/settings-sso.png)

**Trusted certificates.** The certificates the console trusts for each directory, single sign-on and ACME, with
probing, upload and host exceptions.

![Trusted certificates](images/settings-trusted-certificates.png)

**History and backup.** Every change to the console's settings is kept and can be restored. A backup is a single
file encrypted with your passphrase.

![Configuration history and backup](images/settings-history-backup.png)

**The console's certificate.** Upload one, or get one from an ACME CA and renew it automatically.

![The console's own certificate](images/settings-console-certificate.png)

## Refreshing these screenshots

Start `DemoServer` (port 8443) and the web UI's development server (`npm run dev` in `console-web`, port 5173), then
run:

```bash
node docs/images/capture.mjs docs/images
```

Add a name (for example `search`) to retake one screenshot. The script uses Chrome headless; set `CHROME` to its path
if it is not in the macOS default location. Use it against the demo only.
