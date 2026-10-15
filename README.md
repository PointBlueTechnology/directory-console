# Directory Console

A web console for NetIQ/OpenText **eDirectory** and **Identity Manager**. It runs as one container.

- **Directory objects:** browse, search, edit and manage objects.
- **eDirectory administration:** schema, partitions and replicas, indexes, password policies and certificates.
- **Identity Manager:** run and inspect drivers and jobs.

Every action runs with the signed-in person's own eDirectory rights, and every change is audited.

- **Install:** [docs/QUICKSTART.md](docs/QUICKSTART.md), including Docker Desktop on Windows.
- **What works today, and what does not yet:** [docs/STATUS.md](docs/STATUS.md).

## Install

You need Docker and an eDirectory tree whose LDAPS port the console can reach. Get
[`compose.yaml`](compose.yaml) (also attached to each [release](../../releases/latest)), then:

```bash
docker compose up -d
docker compose logs console
```

The log prints a setup link. Open it, check the certificate fingerprint it shows, and sign in to your tree
as an administrator. That tree becomes the console's tree, and that administrator its break-glass
account. You can add more trees (dev, test, production) later under **Settings > Trees**. The
[quickstart](docs/QUICKSTART.md) walks through every step.

The image is `ghcr.io/pointbluetechnology/directory-console`, for amd64 and arm64. Tags:
- `latest` and `<version>`: each release;
- `main`: the newest commit.

## Features

- **Directory objects:**
  - browse the tree and search, with sorted, paged results even in large containers;
  - view and edit attributes;
  - create users, groups and any object class;
  - rename, move and delete;
  - add auxiliary classes, including their mandatory attributes;
  - see effective rights;
  - account tasks: enable, unlock, reset a password;
  - group membership.
- **eDirectory administration:**
  - the schema: browse it, and add classes and attributes;
  - partitions and replicas;
  - servers and their indexes;
  - password policies, challenge sets, login methods and enhanced background authentication.
- **Certificates:**
  - the organizational CA and its configuration;
  - server and user certificates;
  - repair of the default server certificates;
  - CRLs.
- **Identity Manager:**
  - **driver sets and drivers:** state, start and stop (one at a time or all), start options, trace and log levels, named passwords, read-only properties, statistics and versions;
  - **jobs:** run, create, edit and delete;
  - **inspection:** the cache inspector, the association inspector, the object inspector, and per-user password synchronization status;
  - **data:** migrate and synchronize, and mapping tables.
- **Sign-in and access:**
  - direct sign-in, or single sign-on with OpenID Connect;
  - several trees, chosen at sign-in;
  - role mappings from eDirectory groups to four roles, optionally limited to containers: viewer, editor, operator (Identity Manager) and admin;
  - task presets for delegated work;
  - break-glass accounts.

## How it works

- **Your own rights:** the console signs in to eDirectory as the person using it, over LDAPS, so eDirectory
  applies their own rights. Single sign-on finds the person with a service account, then acts as them
  with the LDAP proxied-authorization control.
- **Identity Manager:** the console talks to the engine on the server you signed in to, with
  [DirXMLDev](https://github.com/PointBlueTechnology/DirXMLDev) over the open-source JLDAP library.
  Nothing needs to be installed or mounted, and the image contains no OpenText code.
- **Trust:** the console makes its own TLS certificate on first start, and prints its fingerprint so you
  can check it. Directory certificates are trusted only after you confirm their fingerprint, and the
  console keeps its own trust store.
- **Records:**
  - **Configuration:** versioned, and secrets in it are encrypted.
  - **Audit log:** hash-chained, so tampering shows.
  - **Writes:** each one is audited with attribute names, never values.
- **Hardened container:** distroless Java 21 as a non-root user, with a read-only root file system. Everything
  the console keeps is in the `/data` volume.

## Configuration

Almost everything is configured in the console itself. The container takes three environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `CONSOLE_PUBLIC_URL` | `https://localhost:8443` | How browsers reach the console; its host name goes into the console's certificate. |
| `CONSOLE_PORT` | `8443` | The HTTPS port inside the container. |
| `CONSOLE_DATA` | `/data` | Where the configuration, certificates and audit log are kept. |

Commands for the host, run in the folder with `compose.yaml`:

```bash
docker compose exec console java -jar /app/console.jar admin verify-audit      # check the audit chain
docker compose exec console java -jar /app/console.jar admin reset-bootstrap   # set up again on the next start
```

## Building from source

You need JDK 21, Maven, Node.js 24 and Docker. The server builds on two Point Blue libraries,
[DirXMLDev](https://github.com/PointBlueTechnology/DirXMLDev) and
[DirXMLSimulator](https://github.com/PointBlueTechnology/DirXMLSimulator). Install their releases into
your local Maven repository at the versions named in [`pom.xml`](pom.xml) (`dirxmldev.version`,
`simulator.version`), as [CI does](.github/workflows/test.yml). Then:

```bash
container/build.sh
```

`container/build.sh` does the following:
1. builds and tests the web UI;
2. builds and tests the Java modules;
3. checks that no OpenText class is included;
4. builds the image `directory-console:<version>`.

To run your build, use `CONSOLE_IMAGE=directory-console:<version> docker compose up -d`.

### Working on the web UI

```bash
cd console-web
npm ci --ignore-scripts
npm run dev       # http://localhost:5173, proxying /api to a console at https://localhost:8443 (CONSOLE_URL)
npm test
npm run build
```

The development server enforces the console's own content security policy, so a component that needs
inline script or style fails during development.

For a console to develop against without a real tree, run `DemoServer` from the server's test sources.
It is an in-memory directory with a sample tree and a stand-in Identity Manager engine, on port 8443.
Sign in as `cn=admin,o=system` / `admin-pw`, or `viewer` / `viewer-pw` for the read-only role.

### Layout

| Module | What |
|---|---|
| `console-server` | The service: the HTTPS API, sign-in, trust, configuration, audit, and the eDirectory and Identity Manager operations. |
| `console-web` | The web UI: React and PatternFly 6, built into the server's jar. |
| `console-auth` | OpenID Connect sign-in and merged TLS trust; also used by DirXMLDevWeb. |
| `console-theme` | Point Blue's PatternFly design tokens; also used by DirXMLDevWeb. |
| `container` | The image and its build script. |
| `docs` | The [quickstart](docs/QUICKSTART.md), [status](docs/STATUS.md) and [API notes](docs/API.md). |

## Releases

Each release publishes:
- the image, with its version tag and `latest`;
- the release itself, with `compose.yaml` and `console-auth-<version>.jar` attached.

## License

[MIT](LICENSE).
