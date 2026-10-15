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

Check the version in the user menu, or from the command line (change the port if you changed it):

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
    image: ghcr.io/pointbluetechnology/directory-console:0.3.2
```

or set it from the environment without editing the file: `CONSOLE_IMAGE=ghcr.io/pointbluetechnology/directory-console:0.3.2 docker compose up -d`.
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

- **From 0.2.x or earlier to 0.3.0 or later:** Identity Manager no longer needs the engine's jars. Remove any
  `./engine:/engine:ro` line from `compose.yaml`; it is ignored if left.
- **0.3.0 or later:** setup is the first sign-in from the setup link. It only matters for a new install, or after
  `admin reset-bootstrap`.

## Air-gapped consoles

If the console cannot reach the internet, turn off the update check in **Settings > Updates**, or leave it on:
a failed check only shows a notice, and nothing else is affected. If your network uses a proxy, give it to the
container as `HTTPS_PROXY`, for example in `compose.yaml` under `environment:`. To upgrade without internet
access, copy the image across with `docker save` and `docker load`, then follow the steps above.
