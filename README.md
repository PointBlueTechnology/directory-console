# Directory Console

An eDirectory and Identity Manager console built on the
[DirXMLDev](https://github.com/PointBlueTechnology/DirXMLDev) core. The design is
`../DESIGN-directory-console.md`; the Phase 1 spike results are `../SPIKES-phase1.md`.

Status: Phases 2, 2b, 3, 4 and 5a (directory objects, object tasks, single sign-on with scoped
roles and task presets, Identity Manager, eDirectory administration: partitions and replicas,
indexes, schema changes) on top of Phase 1's service skeleton (bootstrap mode, the
console's own TLS, the trust store with probe and import, sealed versioned configuration, the
hash-chained audit log, direct and contextless sign-in with roles, and the container). The web UI
covers sign-in, browsing, object details and editing, account and membership tasks, search, the
schema, Identity Manager (driver sets, drivers, jobs, associations, cache, log level, passwords), and
for admins a Settings page (role mappings with container scopes, task presets, single sign-on);
setup and the remaining administration (trust, configuration history, audit export) still use the API.

Single sign-on is OpenID Connect (code + PKCE) per directory. The console finds the person's
eDirectory object as the directory's service account and then acts as them with the RFC 4370
proxied-authorization control, so eDirectory applies their own rights; the service account needs
Supervisor over exactly those people (DESIGN section 7.3). Identity Manager operations still need a
direct sign-in.

Identity Manager needs the engine's jars (`dirxml_misc.jar`, `dirxml.jar`, `ldap.jar` from an IDM
install), which are not redistributable: mount them at `/engine` (see `compose.yaml`). Without them
the console runs and the Identity Manager page says why.

| Module | What |
|---|---|
| `console-auth` | OpenID Connect sign-in (authorization code + PKCE, ID-token verification against the provider's JWKS, groups claim) and merged TLS trust (the JDK's store plus operator-added certificates). No HTTP server assumed. Shared with DirXMLDevWeb. |
| `console-server` | The service: `java -jar console.jar` with its dependencies in `lib/`. |
| `console-web` | The web UI: React and PatternFly 6, built into `console.jar` and served by the console under its strict content security policy. |
| `console-theme` | `@pointblue/console-theme`: Point Blue's PatternFly design-token overrides, shared with DirXMLDevWeb. |

## Install

The image is published at `ghcr.io/pointbluetechnology/directory-console` for amd64 and arm64:
`latest` and `<version>` for each release, `main` for the newest commit. With `compose.yaml` from
this repository:

```
docker compose up -d
docker compose logs console   # the setup URL, the one-time token and the certificate fingerprint
```

or without compose:

```
docker run -d --name directory-console --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  -p 8443:8443 -e CONSOLE_PUBLIC_URL=https://console.example.com:8443 -v console-data:/data \
  ghcr.io/pointbluetechnology/directory-console:latest
docker logs directory-console
```

Identity Manager needs the engine's `dirxml_misc.jar` and `ldap.jar` (from an engine's
`lib/dirxml/classes`) mounted read-only at `/engine`; they are OpenText's and never in the image.

To build the image yourself: `container/build.sh` (tests, packages, `docker build` →
`directory-console:<version>`), then `CONSOLE_IMAGE=directory-console:<version> docker compose up -d`.

Check that your browser shows the printed fingerprint before using the token. Setup is the
`/api/v2/setup` API (directory, probe, trust, authority, service account, login, finish); after it,
sign in at `POST /api/v2/session`. The only settings outside the API are `CONSOLE_DATA` (`/data`),
`CONSOLE_PORT` (8443) and `CONSOLE_PUBLIC_URL`.

Host-side commands, from the host only:

```
docker compose exec console java -jar /app/console.jar admin reset-bootstrap   # back to setup on the next start
docker compose exec console java -jar /app/console.jar admin verify-audit
```

The image is distroless Java 21 as the nonroot user with a read-only root file system; it holds no
OpenText code (the build refuses an engine class).

## Directory objects

Signed in, a person works on objects by GUID; DNs appear only in JSON. Every call runs on the person's
own directory connection, so eDirectory applies their rights; any console role reads, `editor` writes.

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

Writes need `If-Match` with the ETag of the last read (`*` overrides), and are audited with attribute
names, never values. Lists are sorted windows with a total: small results are sorted by the console,
large ones use eDirectory's server-side sort and virtual list view, split by naming attribute because
eDirectory's sort leaves out entries without the sort attribute (`DESIGN-directory-console.md` §8.1).

DN handling (RFC 4514 / 4515, dot notation, GUIDs) is in `ldap/Names.java` for now; it moves onto
DirXMLDev's DN library (`com.pointblue.dirxml.dev.dn`) once that is released.

`LiveObjectsCheck` (test sources) drives the whole API against a lab vault; it writes only inside one
container it creates and removes.

## Web UI

```
cd console-web
npm ci --ignore-scripts
npm run dev       # http://localhost:5173, proxying /api to the console at https://localhost:8443 (CONSOLE_URL)
npm test          # unit tests
npm run build     # dist/, which Maven puts into console.jar
npm run preview   # the build at http://localhost:4173, under the console's production policy
```

The development server enforces the same content security policy as the console, plus a nonce for
Vite's hot reload, so a component that needs inline script or style fails during development.
For a console to point it at without a directory, run `DemoServer` from the test sources: the
in-memory fake directory with a sample tree, set up through the real setup API, on port 8443
(sign in as `cn=admin,o=system` / `admin-pw`, or `viewer` / `viewer-pw` for the read-only role).

The PatternFly MCP server (`.mcp.json`) gives coding agents PatternFly 6's rules and component docs.

## Build

JDK 21 and Maven. The modules build on a DirXMLDev release installed in the local
Maven repository (`mvn -o install -DskipTests` in the DirXMLDev checkout); the
version is `dirxmldev.version` in `pom.xml`.

```
mvn install
```

## License

[MIT](LICENSE).

## Releases

Each release attaches the module jars (`console-auth-<version>.jar`). DirXMLDevWeb's CI and
image build download them from here; because this repository is private, they authenticate
with a token stored as the `DIRECTORY_CONSOLE_TOKEN` secret in DirXMLDevWeb.
