# Directory Console

An eDirectory and Identity Manager console built on the
[DirXMLDev](https://github.com/PointBlueTechnology/DirXMLDev) core. The design is
`../DESIGN-directory-console.md`; the Phase 1 spike results are `../SPIKES-phase1.md`.

Status: Phase 0, shared libraries.

| Module | What |
|---|---|
| `console-auth` | OpenID Connect sign-in (authorization code + PKCE, ID-token verification against the provider's JWKS, groups claim) and merged TLS trust (the JDK's store plus operator-added certificates). No HTTP server assumed. Shared with DirXMLDevWeb. |

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
