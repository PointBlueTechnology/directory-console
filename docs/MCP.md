# Agents over MCP (design)

**Status:** design note, decided 2026-10-30. Nothing here is built yet. The decisions are at the end.

This note proposes letting a person's AI agent do day-to-day administration through the console, over the Model
Context Protocol (MCP). Examples are looking up an account, finding out why a user did not synchronize, starting a
driver, running a job, resynchronizing an object, and later approving an Identity Applications task. The agent
acts as the person who made its key and can never do more than that person.

## Why the console, and not DirXMLDevWeb

DirXMLDevWeb already has an MCP server, but it is for development: driver configuration as code, versioned in git
and deployed with the environment's own credentials. Administration is different work, and it needs different
controls:

| | DirXMLDevWeb MCP | Administration (this note) |
|---|---|---|
| Acts as | The environment's configured bind account | The person, with their own eDirectory rights |
| Changes | Configuration in git: planned, deployed, promoted | Live data: accounts, groups, driver state, jobs, approvals |
| Undo | Revert the commit and deploy again | Often none: a resync or an approval cannot be taken back |
| Used by | Developers | Operators, the help desk, IDM administrators |

The console already has the controls administration needs:

- **The person's rights:** every call runs as the person, so eDirectory decides with their rights.
- **Roles:** console roles from group membership, optionally limited to containers.
- **Confirmation:** sensitive changes need a recent sign-in, and production changes need the directory's name.
- **Audit:** a hash-chained audit log, forwarded to syslog.

It also already covers most of the work, behind `/api/v2`.

Keeping the two MCP servers apart is deliberate. A developer's agent key cannot reach live data in production, and
an operator's agent cannot deploy configuration.

## Shape

- **Endpoint:** `/mcp` on the console server. It uses Streamable HTTP, is stateless, and answers in JSON, as
  DirXMLDevWeb's does.
- **One API:** every tool is a call into an existing `/api/v2` handler, made with the key's principal. The MCP layer
  holds no rules of its own: roles, container scopes, eDirectory rights, `If-Match`, the production rule and the
  audit entry are the API's.
- **Tools follow tasks, not LDAP:** for example "unlock this account" or "start this driver". There is no raw
  attribute modify. Tool output never holds a secret, a key or the CSRF value.

## Agent keys

An agent cannot complete a browser sign-in, and the console never keeps a password. A person therefore signs in and
makes a key for the agent.

### Making a key

1. The person signs in the usual way: directly, or with single sign-on.
2. Under *My agent keys*, they choose a label, the key's lifetime, and what it may do: a subset of their own roles.
   The default is read only.
3. They type their password again. This proves they are present now. If the directory has Identity Applications,
   the same password is used once to get their Identity Applications token (see below). It is not kept.
4. The console shows the key (`dc_` followed by 32 random bytes) once.

The console keeps only a SHA-256 of the key, with:

- its label and directory;
- the person's DN;
- the role ceiling;
- created, last used and expiry times.

### Using a key

- **Request:** the agent sends `Authorization: Bearer dc_…`. It sends no cookie, so the CSRF header and the origin
  check for writes do not apply. A bearer header is never sent by a browser on its own, which is what those checks
  guard against. The `Host` check still applies.
- **Acting as the person with LDAP alone:** each call runs on the directory service account's connection with the
  RFC 4370 proxied-authorization control for the person's DN. This is exactly how single sign-on works today
  (`Ldap.actAs`, and `Engines.openAs` for Identity Manager). It needs no OpenID provider and no OSP, and the key
  never stands for a password.
- **What that gives for free:**
  - **Disabled or expired accounts:** eDirectory refuses the control for them (-672), so a key stops working with
    the account. Checked on the lab (eDirectory 9.3.3) for `loginDisabled` and a past `loginExpirationTime`.
  - **Accounts never acted as:** the service account, the break-glass accounts and the `neverProxy` list. They
    cannot make keys.
  - **Other servers:** a key reaches another server's replica the way single sign-on does. There is no
    `server-sign-in-required` step.
  - **Identity Manager:** the engine connection is the service account's, acting as the person on every request.
- **What the console must check itself:** eDirectory **accepts** the control for an account locked by intruder
  detection. On the lab, an account with `lockedByIntruder: TRUE` could not bind with its own correct password
  (53), yet a proxied read as that account succeeded. Single sign-on has the same gap today. On every use, the
  console therefore reads the person's `lockedByIntruder` together with their grants, and refuses the key while the
  account is locked. An expired password with no grace logins left could not be produced on the lab: the account
  still bound. It stays to be checked.
- **What it needs:** the directory's service account, with Supervisor over the people who make keys.
  `ServiceAccountCheck` already checks this for single sign-on. Without a service account, keys are off for that
  directory.
- **Roles:** what a key may do is its role ceiling intersected with the person's current grants.
  - **Direct sign-in:** grants come from eDirectory group membership, so the console re-reads them on use, cached
    for five minutes. A role taken away reaches the person's keys within minutes.
  - **Single sign-on:** grants come from the provider's groups, which the console cannot read without a sign-in. It
    keeps the grants from the person's last sign-in. Their next sign-in with fewer roles narrows their keys at once.
    Such keys get a shorter longest life.

### Lifetime and control

- **Expiry:** keys expire after 30 days by default. Each directory sets the longest life, at most 90 days.
- **Idle:** a key unused for 14 days stops working.
- **Revoking:** the person can revoke a key at once. An administrator can list and revoke anyone's keys.
- **Directory switch:** *Agent keys* is set per directory, and is off by default.
- **Storage:** keys are kept in the data volume, outside the versioned configuration. Restoring an earlier
  configuration must not bring back a revoked key.
- **What a key cannot do:**
  - **The admin role:** a key never carries it, so console settings, trust, roles and sign-in methods stay out of
    an agent's reach.
  - **Recent sign-in:** a key never counts as one, so the changes that need one are refused.
- **Audit:** every entry made with a key names the person and the key (its label and the first characters of its
  id), with `via` set to `agent`.

## Production directories

On a directory marked production, writes from a key need a person's approval:

1. The tool records the change as pending: what, on which object, and with which key. It answers with the pending
   change's id and a link.
2. The person opens the link in the console, signed in, and approves it by typing the directory's name, as they do
   for their own changes today. They can also turn it down.
3. The agent can ask for the pending change's state.

Pending changes expire after an hour. Reads need no approval.

Two alternatives were considered:
- **`confirm` argument:** a `confirm` argument carrying the directory's name, as in DirXMLDevWeb. This is weaker: the
  agent can always pass it.
- **No writes:** none at all to production from keys.

## Passwords

No tool takes or returns a password.

- **Setting a person's password:** the console generates one from the person's password policy (this already exists)
  and records it as a pending change. An operator signed in to the console applies it and hands it over. The agent
  never sees it.
- **Named and Remote Loader passwords:** no tools.

## Tools, in phases

1. **Read** (viewer):
   - search and show an object, with secret attributes left out;
   - group membership;
   - password synchronization status;
   - driver set and driver state, and job state;
   - the association, cache and object inspectors;
   - driver statistics and versions.
2. **Operate** (operator and editor):
   - start and stop drivers;
   - run and abort jobs;
   - migrate and resynchronize an object;
   - account tasks: enable, disable and unlock;
   - add to a group and remove from it.
3. **Identity Applications** (below).

## Identity Applications

Identity Applications calls are only offered on a directory with an Identity Applications address set. That
needs OSP. A directory without it works as above, and the Identity Applications tools are simply not listed.

- **Client:** a vendor-free REST client in DirXMLDev core, built from what `bin/apps` and `docs/idapps-rest.md`
  already established. It is used by both the console and DirXMLDev.
- **The person's token:**
  1. When a key is made, the console makes one OSP password grant with the typed password, using the documented
     `rbpmrest` client and its secret, set for the directory.
  2. It keeps the refresh token, encrypted with the console's secret key, beside the key.
  3. It keeps access tokens in memory only, reused until they expire.
  4. It never signs in once per call. Every OSP password sign-in writes to the user's `oidpInstanceData`, and at
     about 32 KB every sign-in for that user fails (-649).
  5. When a refresh fails, the Identity Applications tools answer `authorize-again`. The person re-authorizes the
     key in the console by typing their password, and the key's LDAP tools keep working meanwhile.
- **People who sign in with single sign-on:** they may have no eDirectory password to type. In that case their keys
  get no Identity Applications tools, unless the provider is OSP itself.
- **Tools:**
  - **Reads:** my approval tasks; a request's status; a person's role and resource assignments; the request
    definitions a person can start.
  - **Writes:** approve or deny a task; request a role or a resource; start a request definition.
  - **Production:** writes follow the production rule above.
- **Checked on the lab** (Identity Applications 24.4, 2026-10-30):
  - **Lifetimes:** OSP sets them in `ism-configuration.properties`. `com.netiq.idm.osp.oauth.refreshTokenTTL` is
    2592000 s (30 days) for a client with a secret, such as `rbpmrest`. `…public.refreshTokenTTL` is 2700 s for public
    clients, and `accessTokenTTL` is 120 s, which matches the `expires_in` of 120 seen live. The console's
    re-authorization therefore comes at most every 30 days, matching the default key life.
  - **`oidpInstanceData`:** a password grant added 280 bytes to the person's value; two refreshes added nothing.
  - **The refresh token is not rotated:** a refresh returns only an access token, and the same refresh token
    works again.
  - **The refresh token alone is not enough:** a refresh with a wrong client secret is refused (401).
  - **Approvals are recorded as the person:** in a scratch PRD, one user requested and an approval step was
    addressed to a second user, who approved over REST with their own token. The request's history names the
    approver throughout: "User task assigned to / claimed by / approved by reviewer <approver>". Their comment
    carries `"user"` and `commentDn` = the approver's DN. The requester stays the requester, and the OAuth client
    (`rbpmrest`) appears nowhere. The reviewer's name in those entries is built from given name and surname, not
    `fullName`.
  - **A refresh token outlives OSP's session:** one taken at a sign-in still refreshed after 50 and 60 minutes,
    past `sessionTTL` (2700 s), and the new access token worked (`tasks/list` 200). An idle key's token therefore
    stays usable for the refresh token's 30 days, not just the 45-minute session.

## Not in scope

- Development work: policies, deploys and promotion stay in DirXMLDevWeb.
- Console settings, LDIF import, and agents acting for no one (for example CI).

## Decisions (taken 2026-10-30)

1. **Where keys live:** in the data volume, outside the versioned configuration. Backups leave them out, so a
   restore never brings back a revoked key; keys are cheap to make again.
2. **The role ceiling:** viewer, editor and operator, never admin. Default: read only.
3. **Roles under single sign-on:** keep the grants from the last sign-in, narrowed at the next one. These keys get a
   shorter longest life: 14 days.
4. **Production writes:** pending changes, approved in the console.
5. **Setting passwords:** generated, then applied by an operator in the console.
6. **The Identity Applications token:** one password grant when the key is made, then refresh tokens. The lab
   confirmed a 30-day lifetime that outlives OSP's session, and that refreshes do not touch `oidpInstanceData`.
7. **Lifetimes:** a 30-day default, at most 90 days, and 14 days idle.
8. **The per-directory switch:** off by default.
