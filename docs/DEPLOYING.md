# Deploying Directory Console

How to run the console as a lasting service in a container: on a server with Docker, or on Kubernetes, and
signing people in either with their eDirectory password or through an OpenID Connect provider (single sign-on).
[QUICKSTART.md](QUICKSTART.md) is the short version for trying it out on your own machine.

1. [Plan](#1-plan)
2. [Run it on a server with Docker](#2-run-it-on-a-server-with-docker)
3. [Run it on Kubernetes](#3-run-it-on-kubernetes)
4. [Set it up](#4-set-it-up)
5. [Sign-in without an authorization server](#5-sign-in-without-an-authorization-server)
6. [Sign-in with an authorization server (single sign-on)](#6-sign-in-with-an-authorization-server-single-sign-on)
7. [The console's certificate](#7-the-consoles-certificate)
8. [Behind a reverse proxy or load balancer](#8-behind-a-reverse-proxy-or-load-balancer)
9. [Check the deployment](#9-check-the-deployment)

## 1. Plan

- **One instance.** The console keeps its settings, sessions, trust store and audit log in one data volume and in
  memory, so run exactly one copy. It cannot be scaled out or run active-active; for availability, rely on the
  container restarting and back up the volume (see [UPGRADING.md](UPGRADING.md)).
- **Its address.** Choose the host name people will use, such as `https://console.example.com`. It becomes
  `CONSOLE_PUBLIC_URL`. It must be exactly what browsers see: the console checks it on every change, puts it in
  the single sign-on redirect URI, and puts its host in the certificate it makes.
- **HTTPS only.** The console serves HTTPS itself, on port 8443 inside the container. There is no plain HTTP
  port.
- **Network.** Inbound: HTTPS from people's browsers (or from your proxy). Outbound: LDAPS (normally 636) to
  every eDirectory server it works with, and the connections listed in
  [UPGRADING.md](UPGRADING.md#outbound-connections-and-air-gapped-consoles); with single sign-on, HTTPS to the
  provider (its certificate from a public CA, or from a CA you add to the console's trust store).
- **Accounts you need.** A tree administrator for setup (it becomes the break-glass account), and a service
  account for finding people by short name and for single sign-on (section 5).
- **Size.** Small: 1 CPU and 1 GB of memory are plenty; the volume needs well under 1 GB (the audit log grows
  slowly, one file a month).

## 2. Run it on a server with Docker

On a Linux server with Docker Engine and the compose plugin, make a folder (for example `/opt/directory-console`)
and download `compose.yaml` from the
[latest release](https://github.com/PointBlueTechnology/directory-console/releases/latest) into it. Change
two things in it: the port browsers use, and the public address.

```yaml
services:
  console:
    image: ${CONSOLE_IMAGE:-ghcr.io/pointbluetechnology/directory-console:latest}
    restart: unless-stopped
    ports:
      - "443:8443"
    environment:
      CONSOLE_PUBLIC_URL: https://console.example.com
    # the rest as released: the data volume, the read-only root, no capabilities
```

Leave the hardening lines as released (`read_only`, `tmpfs`, `cap_drop`, `no-new-privileges`). To choose when
you upgrade, pin a version instead of `latest` (see [UPGRADING.md](UPGRADING.md#choosing-when-to-upgrade-pin-a-version)).
If your network needs a proxy for outbound HTTPS, add `HTTPS_PROXY` under `environment:`.

Start it, and read the setup link from the log:

```bash
docker compose up -d
```

```bash
docker compose logs console
```

`restart: unless-stopped` brings the console back after a reboot as long as Docker starts at boot
(`systemctl enable docker` on most distributions). Then go to [Set it up](#4-set-it-up).

## 3. Run it on Kubernetes

Use version 0.3.10 or later on Kubernetes: 0.3.9 and earlier stop at start on a volume owned by root (as the
`local-path` provisioner makes them), and answer probes sent by IP address with 421.

[`container/kubernetes.yaml`](../container/kubernetes.yaml) has a namespace, a volume claim, a deployment of one
pod, a service, and an ingress for ingress-nginx to uncomment. It was tried on k3s 1.36 with the `local-path`
storage class and ingress-nginx. Edit `CONSOLE_PUBLIC_URL` (and the image tag, if you pin one), then:

```bash
kubectl apply -f kubernetes.yaml
```

```bash
kubectl -n directory-console logs deploy/directory-console
```

The log shows the setup link. What the manifest does, and why:

- **One replica, `Recreate` updates.** Never two pods at once: they would share, and fight over, one volume.
- **A `ReadWriteOnce` volume claim** for `/data`. Your cluster's default storage class provides it; set
  `storageClassName` to choose another. When the volume is owned by root and `fsGroup` does not apply to it, the log
  says so once: the console leaves `/data`'s own permissions as they are, and everything it writes inside is
  owner-only.
- **The same hardening as the container:** non-root user 65532 (`fsGroup` 65532 so the volume is writable), a
  read-only root file system with `/tmp` in memory, no capabilities, no privilege escalation, the runtime's
  default seccomp profile.
- **Probes on `/api/v2/health/live`,** over HTTPS. Not `/api/v2/health/ready` for readiness: that answers 503
  until setup is finished, which would keep the setup page itself out of reach.
- **A `ClusterIP` service on port 443.** Reach it through an ingress or a `LoadBalancer` service; see
  [section 8](#8-behind-a-reverse-proxy-or-load-balancer). To try it before that:
  `kubectl -n directory-console port-forward svc/directory-console 8443:443` and use `https://localhost:8443`
  (with `CONSOLE_PUBLIC_URL` set to that address while you try).

The `admin` commands run in the pod:

```bash
kubectl -n directory-console exec deploy/directory-console -- java -jar /app/console.jar admin verify-audit
```

To back up, copy the volume's contents with your usual tool (a volume snapshot, or Velero), or download a backup
from **Settings > History and backup**.

## 4. Set it up

Open the setup link from the log. It shows the console certificate's fingerprint, as the log does: check they
match. Enter one of your eDirectory servers and sign in as a tree administrator. That tree becomes the console's
first directory, and that administrator its break-glass account, who can always sign in with a password.

Then, in **Settings > Directory**, choose the **Tier**: Production (the default) asks for the directory's name to
be typed before every change; Lab does not.

## 5. Sign-in without an authorization server

People sign in with their eDirectory name and password, and act with their own eDirectory rights.

1. **Service account** (Settings > Directory). Without one, people must type their full name (DN), such as
   `cn=jsmith,ou=staff,o=acme`. With one, they type `jsmith`. Give it an account that can read the people who will
   sign in (browse and read `cn`), and nothing more.
2. **Search bases:** the containers where short names are looked for. None means the whole tree.
3. **When a name matches several people:** let them choose their account, or ask for the full name.
4. **Role mappings** (Settings > Role mappings): map eDirectory groups to the console's roles (viewer, editor,
   operator, admin), optionally limited to containers. Someone with no role cannot use the console, whatever their
   eDirectory rights.
5. **Sessions** (Settings > Directory): idle sign-out and the longest session.

## 6. Sign-in with an authorization server (single sign-on)

The provider (Entra ID, Okta, Keycloak, OpenText Access Manager or any OpenID Connect provider) says who the person
is. The console finds their eDirectory account through the service account, and then acts as them with eDirectory's
proxied authorization, so they still have only their own rights. Password sign-in stays available alongside it.

**At the provider,** register an application (a "web" or "confidential" client):

- **Redirect URI:** `https://console.example.com/api/v2/oidc/callback`, your `CONSOLE_PUBLIC_URL` followed by
  `/api/v2/oidc/callback`. **Settings > Single sign-on** shows the exact value to register.
- **Flow:** authorization code. Either keep a client secret, or make it a public client (PKCE, no secret).
- **Claims:** a claim that names the eDirectory account, such as `preferred_username` or `email`; and, to map
  provider groups to console roles, a groups claim in the ID token.
- Note the **issuer** URL (its `/.well-known/openid-configuration` must be reachable from the console), the
  **client id**, and the secret.

**The service account** finds people for single sign-on, and the console acts as them through it. In eDirectory,
give it the **Supervisor** right over the people who may sign in this way (for example on their container), and no
broader rights. Proxied authorization needs that right.

**In the console,** Settings > Single sign-on:

1. **Issuer, Client id, Client secret** (or **Public client**), **Scopes** (`openid profile email` unless your
   provider needs others), and a **Button label** for the sign-in page ("Sign in with …").
2. **Claim** and **Matches the attribute:** for example the claim `preferred_username` matches `cn`, or `email`
   matches `mail`. Exactly one account must match.
3. **Under these containers:** only people there can sign in this way. Keep it to the containers the service
   account has Supervisor over.
4. **Never act as:** accounts that must never be signed in through the provider, such as the tree administrator
   and other administrators. They sign in with a password.
5. **Groups claim** and **Provider groups:** map the provider's groups to console roles, as role mappings do for
   eDirectory groups. A dotted path such as `realm_access.roles` works for nested claims.
6. **Try the mapping:** enter a claim value and see which account it finds. Then sign in with the button.

**The provider's certificate** must come from a public CA, or from a CA the console trusts: add your internal CA
under **Certificates** in the console (for every directory, or for this one). It takes effect at the next sign-in,
without a restart. Each directory has its own provider settings: sign in to a directory to set up its single
sign-on.

## 7. The console's certificate

On first start the console makes a self-signed certificate for `CONSOLE_PUBLIC_URL`'s host and prints its
fingerprint. Browsers warn about it until you replace it, in **Settings > Console certificate**, in one of two ways:

- **Upload a certificate** from your own CA: a PKCS#12 file with its password, or PEM (the certificate with its
  intermediate CAs, and the private key, encrypted or not). It must name the host in `CONSOLE_PUBLIC_URL`. It is
  installed at once, without a restart; renew it by uploading again before it expires (the expiry check warns).
- **From an ACME CA** (Let's Encrypt, or an internal one such as step-ca), proven with DNS-01: the console adds a TXT
  record through an RFC 2136 dynamic update signed with a TSIG key, and renews by itself. While this is on, upload is
  not offered.

Behind a reverse proxy that holds the public certificate, the console's own certificate only needs to satisfy the
proxy (next section).

## 8. Behind a reverse proxy or load balancer

- **The proxy connects to the console over HTTPS** (port 8443, or 443 on the Kubernetes service). Either pass TLS
  through untouched (the console's certificate is what browsers see), or end TLS at the proxy and open a new HTTPS
  connection to the console; then have the proxy trust the console's certificate, or skip verifying it on that hop
  if your policy allows.
- **`CONSOLE_PUBLIC_URL` is the proxy's address,** the one browsers use. The console refuses changes from any other
  origin, and its session cookie needs HTTPS end to end.
- **Pass the `Host` header** through unchanged, and set `X-Forwarded-For`.
- **Settings > Reverse proxy:** list the proxy's addresses (IPs or CIDR ranges). Only then does the console believe
  its `X-Forwarded-For`, so audit entries and sign-in limits see each person's own address.
- **Kubernetes with ingress-nginx:** either `nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"` (TLS ends at the
  ingress) or `nginx.ingress.kubernetes.io/ssl-passthrough: "true"` (the controller must be started with
  `--enable-ssl-passthrough`). List the controller pods' addresses (or the pod network's range) as trusted proxies.

## 9. Check the deployment

- `https://console.example.com/api/v2/health/live` answers `{"version":…,"status":"live"}`, and
  `/api/v2/health/ready` answers `ready` once setup is finished.
- The certificate browsers see is the one you expect.
- A person with a role signs in with a short name; one without a role is refused.
- With single sign-on: the button signs someone in as their own account, and an account under **Never act as** is
  refused.
- The audit log (Audit log page, **Check the chain**) shows those sign-ins.
- A backup downloads from **Settings > History and backup**, and you have stored it and its passphrase apart.
