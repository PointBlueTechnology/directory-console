# Directory Console

An eDirectory and Identity Manager console built on the
[DirXMLDev](https://github.com/PointBlueTechnology/DirXMLDev) core. The design is
`../DESIGN-directory-console.md`; the Phase 1 spike results are `../SPIKES-phase1.md`.

Status: Phase 1, the service skeleton: bootstrap mode, the console's own TLS, the trust store with
probe and import, sealed versioned configuration, the hash-chained audit log, direct and contextless
sign-in with roles, and the container. The API is usable; the web UI comes later.

| Module | What |
|---|---|
| `console-auth` | OpenID Connect sign-in (authorization code + PKCE, ID-token verification against the provider's JWKS, groups claim) and merged TLS trust (the JDK's store plus operator-added certificates). No HTTP server assumed. Shared with DirXMLDevWeb. |
| `console-server` | The service: `java -jar console.jar` with its dependencies in `lib/`. |

## Run it

```
container/build.sh            # tests, packages, docker build -> directory-console:<version>
docker compose up -d
docker compose logs console   # the setup URL, the one-time token and the certificate fingerprint
```

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

DN handling (RFC 4514 / 4515, dot notation, GUIDs) lives in the DirXMLDev core,
package `com.pointblue.dirxml.dev.dn`.

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
