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
- **Sensitive changes:** changes to the console's own settings (trust, trees, roles, single sign-on) need a sign-in within the last 10
  minutes; otherwise the answer asks for one.
- **Production directories:** changes need the `X-Confirm-Directory` header with the directory's name.
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

## Other areas

| Prefix | Handler |
|---|---|
| `/api/v2/trees/{tree}/idm/…` | `Idm.java`, with `Jobs`, `JobTypes`, `Associations`, `Trace`, `MappingTables`, `DriverProperties` |
| `/api/v2/trees/{tree}/edir/…` | `Edir.java`: partitions, replicas, servers, indexes, schema changes |
| `/api/v2/trees/{tree}/security/…` | `Security.java`: certificates, the CA, password and login policies |
| `/api/v2/directories/{id}/…` | `Settings.java`: a tree's tier, service account, sign-in options, roles, presets, single sign-on |
| `/api/v2/console/trees` | `Trees.java`: the trees people choose from at sign-in |
| `/api/v2/trust/…` | `Server.java`: the console's trust store |
