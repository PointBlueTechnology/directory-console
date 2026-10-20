# Upgrading Directory Console

Directory Console keeps everything it needs in its data volume: settings, certificates, trust and the
audit log. Upgrading replaces the container with a newer image and keeps the volume.

Administrators see a banner when a newer release is out, if the daily update check is on
(**Settings > Updates**). From version 0.3.4, your current version is at the foot of the navigation (in 0.3.3, in the user menu, top right).

## Before you upgrade

1. **Read the release notes** of every version between yours and the new one, on the
   [releases page](https://github.com/PointBlueTechnology/directory-console/releases). Directory Console is in
   beta, so a release may change things you rely on. The notes say when an upgrade needs an extra step.
2. **Back up the data volume** (below). Going back to an older version may need it.
3. **Pick a quiet time.** Restarting the console signs everyone out, and they sign in again afterwards.

### Back up the data volume

Compose names the volume after the folder holding `compose.yaml`, for example `directory-console_console-data`.
To find yours:

```bash
docker volume ls --filter name=console-data
```

Stop the console so nothing is written during the backup, copy the volume into a file in the current folder,
and start the console again. On **macOS or Linux**:

```bash
docker compose stop
docker run --rm -v directory-console_console-data:/data:ro -v "$PWD":/backup alpine tar czf /backup/console-data-backup.tgz -C /data .
docker compose start
```

On **Windows**, in PowerShell:

```powershell
docker compose stop
docker run --rm -v directory-console_console-data:/data:ro -v "${PWD}:/backup" alpine tar czf /backup/console-data-backup.tgz -C /data .
docker compose start
```

Use your own volume name if it differs. Keep the backup somewhere safe: it holds the console's private keys and
its encrypted configuration.

**From inside the console** (0.3.9 and later): an administrator can download a backup under **Settings > History
and backup**, encrypted with a passphrase of their choosing. It holds the configuration and its history, the trust
store, the console's TLS key and certificate, the configuration key and, optionally, the audit log. To restore one,
choose the file there and give its passphrase: it is checked, then applied when the console next starts
(`docker compose restart`). A backup's audit log is restored only onto a console whose audit log is empty, such as a
new volume. A volume backup, as above, is still the one to take before an upgrade.

## Upgrade with compose

In the folder with `compose.yaml`:

```bash
docker compose pull
docker compose up -d
docker compose logs --tail 20 console
```

`pull` fetches the newest image for the tag in `compose.yaml` (`latest` by default), and `up -d` replaces the
container. The log should show the console starting, with no setup link: a setup link means it found no
configuration. If that happens, see [Going back](#going-back).

Check the version at the foot of the navigation, or from the command line (change the port if you changed it):

```bash
curl -sk https://localhost:8443/api/v2/health/live
```

From version 0.3.3, the answer includes `"version"`. On Windows, use `curl.exe` instead of `curl`.

### If the release changed `compose.yaml`

The release notes say so. Download the new `compose.yaml` from the release, copy over any changes you made to
yours (port, `CONSOLE_PUBLIC_URL`, a pinned version), then run `docker compose up -d`.

## Upgrade a `docker run` install

Fetch the new image, remove the old container, and start a new one with the same options and the same volume:

```bash
docker pull ghcr.io/pointbluetechnology/directory-console:latest
docker stop directory-console
docker rm directory-console
docker run -d --name directory-console --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  -p 8443:8443 -e CONSOLE_PUBLIC_URL=https://console.example.com:8443 -v console-data:/data \
  ghcr.io/pointbluetechnology/directory-console:latest
```

Removing the container does not remove the `console-data` volume.

## Choosing when to upgrade: pin a version

`latest` moves to each new release when you pull. To upgrade only when you decide, name a version instead. In
`compose.yaml`, change the image line to, for example:

```yaml
    image: ghcr.io/pointbluetechnology/directory-console:0.3.10
```

or set it from the environment without editing the file: `CONSOLE_IMAGE=ghcr.io/pointbluetechnology/directory-console:0.3.10 docker compose up -d`.
To upgrade, change the version, then run `docker compose pull` and `docker compose up -d`.

## Going back

Set the image to the version you had (as in [pinning](#choosing-when-to-upgrade-pin-a-version)), then run
`docker compose up -d`. If the newer version changed the configuration in a way the older one cannot read,
restore your backup first. With the console stopped, on **macOS or Linux**:

```bash
docker compose stop
docker run --rm -v directory-console_console-data:/data -v "$PWD":/backup alpine sh -c "rm -rf /data/* && tar xzpf /backup/console-data-backup.tgz -C /data"
docker compose up -d
```

On Windows, use `"${PWD}:/backup"` as in the backup step. Restoring brings back the settings, certificates and audit
log exactly as they were at the backup; anything changed since is lost.

## Notes for particular versions

- **0.3.10:** nothing to change in `compose.yaml`, and the configuration format is the same, so going back to 0.3.9
  needs no restore. What is new for operators:
  - [DEPLOYING.md](DEPLOYING.md): running the console on a server or on Kubernetes, with or without single sign-on.
  - Kubernetes works: the health checks answer probes sent by IP address, and a data volume owned by root is
    accepted. Use this version or later there.
- **0.3.9:** nothing to change in `compose.yaml`, and the configuration format is the same, so going back to 0.3.8
  needs no restore (a restore staged but not yet applied is ignored by 0.3.8). What is new for operators:
  - **Audit log** page for administrators, with filters, CSV and JSON Lines export and a chain check.
  - **Settings > History and backup:** earlier configuration versions can be viewed and restored, and an encrypted
    backup downloaded and restored from inside the console (applied at the next start).
  - Identity Manager jobs: their named passwords can be set, and their parameters and objects changed after creation.
- **0.3.8:** nothing to change in `compose.yaml`, and the configuration format is the same, so going back to 0.3.7
  needs no restore. What is new for operators:
  - The console can get its own certificate from an ACME CA (**Settings > Console certificate**), proven with DNS-01
    through dynamic DNS updates signed with a TSIG key; off until set up. It then connects to the CA and to your DNS
    server (see the outbound connections below).
  - Trusted root containers and roots can be made and removed, and a server certificate imported from a PKCS#12 file
    that eDirectory exported.
- **0.3.7:** nothing to change in `compose.yaml`, and the configuration format is the same, so going back to 0.3.6
  needs no restore. What is new for operators:
  - The console says *directory* where it said *tree*: **Settings > Trees** is now **Settings > Directories**, and
    the setup page asks for the **Directory address**. API paths are unchanged.
  - A daily certificate expiry check is on by default (**Settings > Certificate expiry**). Until you add e-mail or
    webhooks, it only shows administrators a banner. It records what it has already reported in
    `expiry-notified.json` in the data volume.
  - Audit entries can be forwarded to syslog (**Settings > Syslog**); off by default.
  - Server certificates can be exported with their private key (PKCS#12); it needs a recent sign-in and is
    recorded in the audit log.
  - Fixed: a request could occasionally go unanswered for 30 to 40 seconds.
- **From 0.2.x or earlier to 0.3.0 or later:** Identity Manager no longer needs the engine's jars. Remove any
  `./engine:/engine:ro` line from `compose.yaml`; it is ignored if left.
- **0.3.0 or later:** setup is the first sign-in from the setup link. It only matters for a new install, or after
  `admin reset-bootstrap`.

## Outbound connections and air-gapped consoles

The console makes these outbound connections:

- **Each directory's servers,** over LDAPS: the server you sign in to, and other servers for work on them
  (replicas, LDAP refresh, encryption policies, Identity Manager).
- **GitHub** (`api.github.com`), once a day for the release check, unless it is turned off.
- **Your mail server** (SMTP: 587 with STARTTLS by default, 465 with TLS, or a relay without TLS on a port you
  choose) and **your webhooks** (HTTPS), only when certificate expiry notices are set up.
- **Your syslog server** (6514 over TLS, or 514 over TCP or UDP), only when forwarding is on.
- **Your ACME CA** (HTTPS) and **your DNS server** (TCP 53, dynamic updates), only when the console gets its own certificate by ACME.

If the console cannot reach the internet, turn off the update check in **Settings > Updates**, or leave it on:
a failed check only shows a notice, and nothing else is affected. If your network uses a proxy, give it to the
container as `HTTPS_PROXY`, for example in `compose.yaml` under `environment:`. `HTTPS_PROXY` is used for the
release check and webhooks. Mail and syslog connect directly. The mail server and webhooks need certificates from
a public CA. A syslog server's certificate may also come from a CA in the console's trust store.

To upgrade without internet access, copy the image across with `docker save` and `docker load`, then follow the
steps above.
