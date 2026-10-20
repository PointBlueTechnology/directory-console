# Directory Console quickstart

Directory Console runs as one container. You need:

- **Docker:** Docker Desktop on Windows or macOS, or Docker Engine with the compose plugin on Linux.
- **Your eDirectory tree:** one of its servers' address, with LDAPS (normally port 636) reachable from this
  machine, and a tree administrator's full name (DN) and password.

Setup is one screen: you start the container, open the link it prints, and sign in to your tree. You can
add more directories, such as dev and test, afterwards.

1. [Get the compose file](#1-get-the-compose-file)
2. [Start the console](#2-start-the-console)
3. [Open the setup link and sign in](#3-open-the-setup-link-and-sign-in)
4. [After setup](#4-after-setup)

[Troubleshooting](#troubleshooting) is at the end. For a lasting deployment on a server or on Kubernetes, and for
single sign-on, see [DEPLOYING.md](DEPLOYING.md).

## 1. Get the compose file

The compose file tells Docker which image to run and how. Make a folder for it, for example
`C:\directory-console` on Windows or `~/directory-console` on macOS and Linux.

**If you can see the repository:** download `compose.yaml` from the
[latest release](https://github.com/PointBlueTechnology/directory-console/releases/latest) into that
folder. With the GitHub CLI:

```bash
gh release download --repo PointBlueTechnology/directory-console --pattern compose.yaml
```

**Otherwise, create it yourself.** The file's whole content is below; copy it exactly.

On **Windows**, open **PowerShell** and run this whole block, from `@'` to `'@`. It makes the folder
and writes the file:

```powershell
New-Item -ItemType Directory -Force C:\directory-console | Out-Null
Set-Location C:\directory-console
@'
services:
  console:
    image: ${CONSOLE_IMAGE:-ghcr.io/pointbluetechnology/directory-console:latest}
    restart: unless-stopped
    ports:
      - "8443:8443"
    environment:
      CONSOLE_PUBLIC_URL: https://localhost:8443
    volumes:
      - console-data:/data
    read_only: true
    tmpfs:
      - /tmp
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
volumes:
  console-data:
'@ | Set-Content -Encoding ascii compose.yaml
```

On **macOS or Linux**, the same in a terminal:

```bash
mkdir -p ~/directory-console && cd ~/directory-console
cat > compose.yaml <<'EOF'
services:
  console:
    image: ${CONSOLE_IMAGE:-ghcr.io/pointbluetechnology/directory-console:latest}
    restart: unless-stopped
    ports:
      - "8443:8443"
    environment:
      CONSOLE_PUBLIC_URL: https://localhost:8443
    volumes:
      - console-data:/data
    read_only: true
    tmpfs:
      - /tmp
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
volumes:
  console-data:
EOF
```

If people will use the console from other machines, change `CONSOLE_PUBLIC_URL` to the address they
will type, for example `https://console.example.com:8443`. The console puts that host name in its
certificate.

## 2. Start the console

**Windows:** start **Docker Desktop** and wait until it says the engine is running. It must be using
Linux containers (the default) and the WSL 2 backend (the default on Windows 10 and 11). Then, in
PowerShell, in the folder from step 1:

```powershell
docker compose up -d
```

**macOS or Linux:** in the folder from step 1:

```bash
docker compose up -d
```

The first time, Docker downloads the image. Then show the console's log:

```bash
docker compose logs console
```

In Docker Desktop you can also open **Containers**, then **directory-console**, then **console-1**, and
choose the **Logs** tab. You will see something like:

```
Directory Console is not configured yet. Within 60 minutes, open the setup URL and
sign in to your eDirectory tree as an administrator:

  Setup URL:   https://localhost:8443/setup#token=3f9c…
  Setup token: 3f9c…

Before entering anything, check that your browser shows this certificate fingerprint
(SHA-256) for the console:

  34:18:28:6C:…
```

## 3. Open the setup link and sign in

1. **Open the link.** Copy the **Setup URL** into your browser.
2. **Check the certificate.** The browser warns that the connection is not private, because the console
   made its own certificate. Before going on, check that you reached your console:
   - **Edge or Chrome:** click **Not secure** at the left of the address bar, then **Certificate details**.
     The **SHA-256 fingerprint** should match the fingerprint in the log.
   - **Firefox:** click **Advanced**, then **View Certificate**.
   - **Safari:** click **Show Details**, then **view the certificate**.
3. **Continue to the page.** If the fingerprints match, close the certificate window and continue:
   - **Edge:** **Advanced**, then **Continue to localhost (unsafe)**.
   - **Chrome:** **Advanced**, then **Proceed to localhost**.
4. **Fill in the setup page.** It shows **Set up Directory Console**:
   - **Directory address:** the host name or IP address of one of your eDirectory servers.
   - **LDAPS port:** normally 636.
   - **Administrator:** a tree administrator's full name (DN), such as `cn=admin,o=system`.
   - **Password:** that administrator's password.
5. **Sign in.** Choose **Sign in**.
6. **Trust the tree's certificate.** If the console does not yet trust it, it shows the certificate.
   Compare its fingerprint with your tree's certificate authority, for example in iManager or Identity
   Console under the Organizational CA. If it is right, type the last 8 characters of the fingerprint (colons and
   spaces do not matter) and choose **Trust and sign in**.

You are now signed in. That administrator is the console's break-glass account: it can always sign in,
even when nothing else is configured.

If the token has expired (after 60 minutes), the console prints a new link. Run
`docker compose logs console` again and use the newest one.

## 4. After setup

Open **Settings**, then **Directory**:

- **Service account:** without one, people sign in with their full name (DN) and single sign-on is
  unavailable. Give the console an account that can read the people who will sign in.
- **Search bases:** where a short name such as `jsmith` is looked for at sign-in.
- **Tier:** Production (the default) asks for the directory's name to be typed before a change. Lab does
  not.

Then, in **Settings**:

- **Role mappings:** decide who else may use the console. Map an eDirectory group to a role.
- **Single sign-on:** set it up if you want it; [DEPLOYING.md](DEPLOYING.md#6-sign-in-with-an-authorization-server-single-sign-on)
  covers the provider side.
- **Certificate expiry:** the console checks certificates daily and shows administrators a banner. To get notices,
  add e-mail recipients or a webhook.
- **Syslog:** to send the console's audit entries to your SIEM as CEF, set a syslog server.

**Several directories (dev, test, production):** in **Settings**, then **Directories**, choose **Add a directory**. Give it
a name people will recognize, such as Test, and choose Lab or Production. Then enter the directory's address and
sign in as that directory's own administrator, who becomes its break-glass account. From then on, the sign-in
page has a list of directories to choose from. Each directory has its own service account, role mappings and single
sign-on: sign in to a directory to set those under the other Settings tabs.

**Identity Manager** works with nothing else to install: the console talks to the engine on the
server you signed in to.

**Help:** the **?** in the header explains the page you are on.

**Everyday commands,** run in the folder with `compose.yaml`:

| What | Command |
|---|---|
| Update to the newest version | `docker compose pull` then `docker compose up -d`; see [UPGRADING.md](UPGRADING.md) first |
| Stop and start | `docker compose stop`, `docker compose start` |
| Check the audit log is intact | `docker compose exec console java -jar /app/console.jar admin verify-audit` |
| Set up again (the old configuration is kept aside) | `docker compose exec console java -jar /app/console.jar admin reset-bootstrap`, then `docker compose restart console` |
| Remove everything, including all settings | `docker compose down -v` |

The console keeps its settings, certificates, trust store and audit log in the `console-data` volume, which survives
updates. Back it up before upgrading: [UPGRADING.md](UPGRADING.md) shows how, and how to go back.

**New versions:** administrators see a banner when a newer release is out. The console checks once a day; turn
it off in **Settings > Updates** if this console has no internet access.

## Troubleshooting

**"The console could not reach … (Connect timed out)" at setup.** The console's container cannot reach
the tree's server.
- **Check the address and port from this machine,** for example in PowerShell:
  `Test-NetConnection 10.1.2.3 -Port 636`.
- **If the directory address starts with `172.17.`,** it falls inside the network Docker uses for containers,
  and Docker sends that traffic to its own bridge instead. Move Docker's networks out of the way: in
  Docker Desktop open **Settings**, then **Docker Engine**, add the two lines below inside the outer `{ }`,
  and choose **Apply & restart**. On Linux, put the same lines in `/etc/docker/daemon.json` and restart
  Docker. Pick ranges your network does not use.

  ```json
  "bip": "10.201.0.1/24",
  "default-address-pools": [{ "base": "10.202.0.0/16", "size": 24 }]
  ```

  Then, in the compose folder, run `docker compose down`, then `docker compose up -d`.
- **If the tree runs on this same computer,** use `host.docker.internal` as the **Directory address**.
- **If you reach the tree through a VPN,** connect the VPN before starting Docker Desktop.

**"Port is already allocated" when starting.** Something else uses 8443. In `compose.yaml`, change
`"8443:8443"` to, for example, `"9443:8443"`, and `CONSOLE_PUBLIC_URL` to `https://localhost:9443`. Then
run `docker compose up -d` again.

**The setup page asks for a token.** You opened the console's address without the token. Use the whole
Setup URL from the log, or paste the Setup token into the page.

**Windows Firewall asks about Docker.** Allow it on private networks if people will use the console from
other machines; otherwise it is not needed.

**"Signed in but does not have supervisor rights to the directory".** Setup needs a tree administrator: an
account with Supervisor rights at the top of the tree.
