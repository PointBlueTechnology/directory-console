# API notes

The web UI uses the console's HTTPS API, under `/api/v2`. Each handler in
`console-server/src/main/java/com/pointblue/console/server/http/` lists its own routes at the top of its source.
This page covers the conventions they share, and the directory-object routes as an example.

## Conventions

- **Sessions:**
  - Sign in with `POST /api/v2/session`. The console sets a `__Host-` session cookie.
  - Writes need the session's `X-CSRF-Token` header, and must come from the console's own origin.
- **Rights:** every call runs on the person's own directory connection, so eDirectory applies their rights. The
  console's roles narrow what they may do:
  - any role reads;
  - `editor` writes objects;
  - `operator` runs Identity Manager;
  - `admin` changes the console's settings.
- **Sensitive changes:** these need a sign-in within the last 10 minutes; otherwise the answer asks for one:
  - changes to the console's own settings: trust, directories, roles, single sign-on, sign-in to other
    directories, reverse proxies, certificate expiry, syslog, updates, the console's ACME certificate (settings and getting one now), and uploading the console's certificate;
  - restoring an earlier configuration, downloading a backup and staging a restore;
  - exporting a certificate with its private key.
- **Production directories:** changes need the `X-Confirm-Directory` header with the directory's name. Exports
  with a private key need a recent sign-in instead.
- **Paths:** `{tree}` in `/api/v2/trees/{tree}/…` is the directory's id. The paths still say `trees`; the UI now
  says directory.
- **Errors:** problem details (RFC 9457) with a stable `title` code, such as `confirm-directory` or
  `version-conflict`.
- **Objects:** objects are addressed by GUID; DNs appear only in JSON.
- **Concurrent edits:** writes to an object need `If-Match` with the ETag of the last read (`*` overrides).
- **Audit:** writes are audited with attribute names, never values.

## Setup

Until it is set up, the console answers only health checks and the setup API. Setup calls need the one-time token
from the log in an `X-Setup-Token` header:

```
POST /api/v2/setup/first-sign-in     {host, port?, dn, password, accept?: {probeId, confirm}}
```

The web UI's first sign-in uses that call. For automation, the step-by-step calls are:

```
GET  /api/v2/setup                   what is done so far
PUT  /api/v2/setup/directory         {id, name, host, port, tier}
POST /api/v2/setup/probe             the directory's certificate chain
POST /api/v2/setup/trust             {probeId, index, confirm} or {pem}
POST /api/v2/setup/authority         {dn, password}: a tree administrator
PUT  /api/v2/setup/service-account   {dn, password} (optional)
PUT  /api/v2/setup/login             {duplicates, searchBases}
POST /api/v2/setup/finish
```

## Directory objects

```
GET    /api/v2/trees/{tree}/roots
GET    /api/v2/trees/{tree}/objects?dn=…                 resolve a DN (any spelling)
GET    /api/v2/trees/{tree}/objects/{guid}               read, with an ETag
GET    /api/v2/trees/{tree}/objects/{guid}/children      ?offset=&count=&startAt=&kind=containers|leaves|all
GET    /api/v2/trees/{tree}/objects/{guid}/rights        the signed-in person's effective rights
POST   /api/v2/trees/{tree}/search                       structured filter, or one ldapFilter expression
PATCH  /api/v2/trees/{tree}/objects/{guid}               {"changes": [{"op", "attribute", "values"}]}
POST   /api/v2/trees/{tree}/objects/{guid}/children      create: {"objectClass", "name": {"type", "value"}, "attributes"}
POST   /api/v2/trees/{tree}/objects/{guid}/rename        {"name"}
POST   /api/v2/trees/{tree}/objects/{guid}/move          {"newParent": guid}
DELETE /api/v2/trees/{tree}/objects/{guid}
GET    /api/v2/trees/{tree}/schema/classes[/{name}], /schema/attributes[/{name}]
```

Lists are sorted windows with a total:
- small results are sorted by the console;
- large ones use eDirectory's server-side sort and virtual list view.

They are split by naming attribute, because eDirectory's sort leaves out entries that lack the sort
attribute.

## eDirectory, new in 0.3.7

```
PUT    /api/v2/trees/{tree}/edir/servers/{id}/indexes/{name}/state   {"state": "online|offline"}: user and auto-added indexes
POST   /api/v2/trees/{tree}/edir/servers/{id}/indexes/{name}/copy    {"servers": [guid]}: a user-defined index, built by limber there
GET    /api/v2/trees/{tree}/edir/ldap                                LDAP servers and groups
GET    /api/v2/trees/{tree}/edir/ldap/servers/{id} | ldap/groups/{id}
PATCH  /api/v2/trees/{tree}/edir/ldap/servers/{id} | ldap/groups/{id}   {"settings": {attribute: value|null}}
POST   /api/v2/trees/{tree}/edir/ldap/servers/{id}/refresh | reload  on the LDAP server's own host
GET    /api/v2/trees/{tree}/edir/servers/{id}/audit                  the server's CEF audit settings
PUT    /api/v2/trees/{tree}/edir/servers/{id}/audit                  the whole configuration, as GET gives it
DELETE /api/v2/trees/{tree}/edir/servers/{id}/audit                  back to eDirectory's defaults
GET    /api/v2/trees/{tree}/edir/snmp
PATCH  /api/v2/trees/{tree}/edir/snmp/{id}                           {"trapInterval"?, "trapsDisabled"?, "traps"?: {number: {active?, failure?, interval?}}}
GET    /api/v2/trees/{tree}/edir/encryption                          encrypted attribute policies and replication (read-only)
POST   /api/v2/trees/{tree}/edir/encryption/policies                 {"parent", "name", "attributes": [{attribute, scheme?}], "requiresSecureChannel"?}
PATCH  /api/v2/trees/{tree}/edir/encryption/policies/{id}            {"attributes"?, "requiresSecureChannel"?}
DELETE /api/v2/trees/{tree}/edir/encryption/policies/{id}            only a policy no server uses
PUT    /api/v2/trees/{tree}/edir/servers/{id}/encryption-policy      {"policy": guid|null}, then limber on that server
GET    /api/v2/trees/{tree}/edir/servers/{id}/replica-filter
PUT    /api/v2/trees/{tree}/edir/servers/{id}/replica-filter         {"classes": [{class, attributes}]}; [] clears it
POST   /api/v2/trees/{tree}/security/pki/server-certificates/{guid}/export           {password, scheme}: PKCS#12
POST   /api/v2/trees/{tree}/security/objects/{guid}/certificates/{name}/export       the same, for a user's own certificate
POST   /api/v2/trees/{tree}/security/pki/servers/{guid}/certificates/import          {"name", "pkcs12": base64, "password"}: only files in eDirectory's export form
POST   /api/v2/trees/{tree}/security/pki/trusted-root-containers                     {"parent", "name"}
DELETE /api/v2/trees/{tree}/security/pki/trusted-root-containers/{guid}              only an empty one
POST   /api/v2/trees/{tree}/security/pki/trusted-root-containers/{guid}/roots        {"certificate": PEM or base64 DER, "name"?}
DELETE /api/v2/trees/{tree}/security/pki/trusted-roots/{guid}
```

An export answers `{fileName, pkcs12}`, with the file base64-encoded. The password is at least 6 characters, and
the scheme is PBES2 unless `pbes1` is asked for.

## Identity Manager jobs, changed in 0.3.9

```
PATCH  /api/v2/trees/{tree}/idm/jobs/{guid}/definition   {"version", "disabled"?, "schedule"?, "servers"?, "parameters"? {name: value}, "scope"? [{dn, scope}]}
GET    /api/v2/trees/{tree}/idm/jobs/{guid}/passwords    ?server=: the job's named passwords on that server's engine
POST   /api/v2/trees/{tree}/idm/jobs/{guid}/passwords    ?server=  {"name", "displayName"?, "value"}
DELETE /api/v2/trees/{tree}/idm/jobs/{guid}/passwords    ?server=  {"name"}
```

A parameter's value is checked against the job's own definition (a list is an array; an enum one of its
choices); only each changed `<value>` is rewritten. `scope: []` removes the objects unless the job type needs
some. A password-ref parameter's value is the name of the job's named password, set with the passwords route.

## Passwords, new in 0.3.14

```
POST /api/v2/trees/{tree}/security/objects/{guid}/password-check   {"password"}: {passes, code, reason, policy}
GET  /api/v2/trees/{tree}/security/objects/{guid}/password-policy  {own, containers, loginPolicy, governing}
```

The check is NMAS's Password Policy Check (`2.16.840.1.113719.1.39.42.100.17`): nothing is set and nobody signs in.
`code` is NMAS's or eDirectory's (0 when it passes; -216 too short, -16000 too long, -16057 digits or special
characters the policy does not allow, and so on).

## Console settings

```
GET  /api/v2/console/version          {version}; admins also get {update}
PUT  /api/v2/console/updates          {"enabled"}
POST /api/v2/console/updates/check
GET  /api/v2/console/expiry           settings (secrets shown only as set), the last check's findings and errors
PUT  /api/v2/console/expiry           {enabled, warnDays (1-365, default 30), email?: {host, port?, security: starttls|tls|none, user?, password?, from, to: […]}, webhooks: [{url, secret?, clearSecret?}] (at most 5)}
POST /api/v2/console/expiry/check     check now
POST /api/v2/console/expiry/test      send a test notice to every recipient and webhook
GET  /api/v2/console/syslog           settings and counters: sent, dropped, waiting, last error
PUT  /api/v2/console/syslog           {enabled, host, port?, transport: tls|tcp|udp, facility (default authpriv)}
POST /api/v2/console/syslog/test
GET  /api/v2/console/acme             settings (the TSIG secret shown only as set), the current certificate, the last attempt
PUT  /api/v2/console/acme             {enabled, directoryUrl (https), email?, names: [...], dns: {host, port?, zone, keyName, algorithm: hmac-sha256|hmac-sha512, secret?}}
POST /api/v2/console/acme/dns-test    add a test TXT record, read it back from the server, remove it
POST /api/v2/console/acme/issue       get a certificate now and install it
POST /api/v2/console/certificate      upload: {pkcs12: base64, password} or {certificate: PEM, key: PEM, password?}, anyName?; refused (409) while ACME is on
GET  /api/v2/audit                    ?event (prefix)&actor&outcome&text&from&to&before (seq)&limit (≤500): {entries, more}, newest first
GET  /api/v2/audit/export             the same filters, every match, oldest first: ?format=csv|jsonl
GET  /api/v2/audit/verify             the hash chain checked end to end
GET  /api/v2/config/history           the configuration's versions, the current one first
GET  /api/v2/config/history/{v}       that version (secrets redacted) and what changed from the one before
POST /api/v2/config/history/{v}/restore   make it current again, as a new version
POST /api/v2/console/backup           {passphrase (12+), audit?}: the .dcbackup file
POST /api/v2/console/restore          {backup: base64, passphrase}: checked and staged for the next start
GET  /api/v2/console/restore          {pending}: what is staged, or null; DELETE cancels it
```

**Webhooks** receive a JSON `POST` with these fields: `event` (`certificates.expiring` or `test`), `subject`, `text`,
`certificates` (each with `kind`, `name`, `where`, `notAfter`, `days` and `level`), `console` and `sentAt`. When a
secret is set, the `X-Console-Signature` header is `sha256=` followed by the hex HMAC-SHA256 of the body with that
secret. A webhook URL is `https://`; `http://` is accepted only for this host.

## Other areas

| Prefix | Handler |
|---|---|
| `/api/v2/trees/{tree}/idm/…` | `Idm.java`, with `Jobs`, `JobTypes`, `Associations`, `Trace`, `MappingTables`, `DriverProperties` |
| `/api/v2/trees/{tree}/edir/…` | `Edir.java`: partitions, replicas, servers, indexes, schema changes, LDAP servers and groups, CEF auditing, SNMP, encryption policies, replica filters |
| `/api/v2/trees/{tree}/security/…` | `Security.java`: certificates, the CA, password and login policies, PKCS#12 export |
| `/api/v2/directories/{id}/…` | `Settings.java`: a directory's tier, session limits, service account, sign-in options, roles, presets, single sign-on |
| `/api/v2/console/trees` | `Trees.java`: the directories people choose from at sign-in, added, renamed and removed |
| `/api/v2/console/version`, `/updates` | `Updates.java` |
| `/api/v2/console/expiry` | `Expiry.java` |
| `/api/v2/console/syslog` | `Syslog.java` |
| `/api/v2/console/acme` | `AcmeService.java`: the console's own certificate by ACME (DNS-01) |
| `/api/v2/audit`, `/api/v2/config/history`, `/api/v2/console/backup`, `/restore` | `Records.java`: the audit log, configuration history, backup and restore |
| `/api/v2/console/settings`, `/api/v2/sign-in/options`, `/api/v2/session/other` | `OtherDirectory.java`: sign-in to other directories, trusted proxies |
| `/api/v2/session…`, `/api/v2/oidc/…`, `/api/v2/config`, `/api/v2/audit/verify`, `/api/v2/health/live` and `/ready` | `Server.java` |
| `/api/v2/trust/…` | `Server.java`: the console's trust store |
