# Security policy

Directory Console administers identity infrastructure, so we take reports seriously.

## Reporting a vulnerability

Please report it **privately**, not in a public issue: use **[Report a vulnerability](../../security/advisories/new)**
on this repository's Security tab (GitHub's private vulnerability reporting). If you cannot use GitHub,
contact Point Blue Technology through [pointbluetech.com](https://pointbluetech.com).

Include what you found, how to reproduce it, the version (`latest`, a version tag, or a commit), and what an
attacker could do with it. We will acknowledge the report, keep you informed while we work on a fix, and
credit you in the advisory unless you prefer otherwise.

## Supported versions

The project is in beta. Fixes go into the newest release; please check that you can reproduce the problem on
the current `latest` image before reporting.

## Scope

In scope: the console's server and web UI, its container image, and how it handles credentials, sessions,
certificates and the configuration in its data volume.

Out of scope: weaknesses in eDirectory or Identity Manager themselves (report those to OpenText), and findings
that need an attacker who already controls the host, the container or its `/data` volume.
