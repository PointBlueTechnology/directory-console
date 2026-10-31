# Agents over MCP (design)

**Status:** decided 2026-10-30. All three phases are built: agent keys, `/mcp` and the read tools; the change
tools, with approval in the console; and Identity Applications. See [Using it](#using-it). The decisions are at the
end.

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
  - **Direct sign-in:** grants come from eDirectory group membership. The console reads them on every call, in the
    same read as the intruder lockout, so a role taken away reaches the person's keys at their next call.
  - **A role the key does not carry:** the grant still reads, with the same container scopes; admin becomes each
    of the key's roles. Task presets never reach a key: they are changes.
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

## Approving agents' changes

Each directory has a setting, *Changes an agent asks for wait for the person's approval*, on by default (changed
2026-10-30: it was going to apply to production directories only, always). While it is on, writes from a key need a
person's approval:

1. The tool records the change as pending: what, on which object, and with which key. It answers with the pending
   change's id and a link.
2. The person opens the link in the console, signed in, and approves it by typing the directory's name, as they do
   for their own changes today. They can also turn it down.
3. The agent can ask for the pending change's state.

Pending changes expire after an hour. Reads need no approval.

With the setting off, a key's writes go ahead within its roles, and are audited as the agent's. On a production
directory they still need what any change there needs.

Two alternatives were considered:
- **`confirm` argument:** a `confirm` argument carrying the directory's name, as in DirXMLDevWeb. This is weaker: the
  agent can always pass it.
- **No writes:** none at all to production from keys.

## Passwords

No tool takes or returns a password.

- **Setting a person's password (a future feature, not in phases 1 to 3):** the console would generate one from the
  person's password policy (this already exists) and record it as a pending change. An operator signed in to the
  console would apply it and hand it over. The agent would never see it. Until then, passwords are set in the console
  as today.
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
   - migrate an object into the application, migrate objects from it, and resynchronize a driver (the API resynchronizes
     a driver, all or since a time, rather than one object);
   - account tasks: enable, disable and unlock;
   - add to a group and remove from it.
3. **Identity Applications** (below).

## Identity Applications

Identity Applications calls are only offered on a directory with an Identity Applications address set. That
needs OSP. A directory without it works as above, and the Identity Applications tools are simply not listed.

- **Client:** a vendor-free REST client in DirXMLDev core (`com.pointblue.dirxml.dev.apps.IdApps`, from 0.60.0),
  built from what `bin/apps` and `docs/idapps-rest.md` already established. It is used by both the console and
  DirXMLDev.
- **The calls and their bodies** are documented, with what the server actually reads, in the PointBlueTechnology
  `idapps-rest` repository and DirXMLDev's `docs/idapps-rest.md`.
- **Which calls:** a person's assignments are `POST /assignments/list {"dn"}`; the request definitions come from the
  catalog (`GET /IDMProv/rest/catalog/prds`), which on the lab still listed PRDs deleted from the vault, so
  `request_definition` (the permission index) is the check before a request. Checked on idm254, 2026-10-30.
- **Changes need a key that may make changes:** approving tasks and making requests need the key to carry editor or
  operator; a read-only key sees tasks and requests only.
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
  - **Approval:** writes follow the approval setting above.
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

## Using it

Phase 1 has keys, the endpoint and the read tools, phase 2 the change tools, and phase 3 Identity Applications. All
three are in 0.4.0.

1. **An administrator turns keys on:** Settings > Directory > Agent keys. Keys need the directory's service account,
   with Supervisor over the people who make keys. The same section sets the longest life (1 to 90 days, 90 by
   default) and whether agents' changes wait for approval.
2. **A person makes a key:** under their name > Agent keys > New agent key: a label, a life, and what it may do
   (reading always; changing objects or running Identity Manager only with those roles). Direct sign-in types the
   password again; single sign-on needs a sign-in within the last 10 minutes. The key is shown once, with the
   command for Claude Code:

   ```bash
   claude mcp add --transport http directory-console https://console.example.com/mcp --header "Authorization: Bearer dc_…"
   ```

   Other clients take the same address and header.

   **The agent's machine must trust the console's certificate.** With the console's own self-signed certificate,
   Node-based clients such as Claude Code refuse it (`UNABLE_TO_VERIFY_LEAF_SIGNATURE`) until it is trusted. For
   example, save it with `openssl s_client -connect console.example.com:443 </dev/null | openssl x509 > console.pem`
   and start the client with `NODE_EXTRA_CA_CERTS=/path/to/console.pem`. A certificate from a public or internal CA
   the machine already trusts needs nothing. `claude mcp list` then shows the server as connected.
3. **The agent calls `whoami` first,** then the read tools:

   | Tool | What it reads |
   |---|---|
   | `whoami` | the person, the directory and its tier, the key's roles and expiry |
   | `search_objects`, `read_object`, `list_children`, `object_servers` | directory objects (secret attributes only as set) |
   | `account_status`, `group_memberships`, `group_members` | sign-in status and lockout, groups |
   | `object_associations` | the object inspector: associations and password synchronization |
   | `idm_status`, `list_driver_sets`, `driver_set`, `driver_status`, `driver_health` | Identity Manager's drivers and their state |
   | `list_jobs`, `job_definition` | jobs |
   | `driver_password_sync`, `driver_associations`, `driver_cache`, `driver_cache_events` | a driver's password synchronization, association and cache inspectors |
   | `driver_set_statistics`, `versions` | statistics and versions, per server |

   Objects, drivers, driver sets and jobs are named by GUID or DN. A `server` argument asks another server's
   replica or engine.
4. **Change tools,** listed only when the key has the role:

   | Tool | Role | What it changes |
   |---|---|---|
   | `enable_account`, `disable_account`, `unlock_account` | editor | a user's account |
   | `add_to_group`, `remove_from_group` | editor | group membership, both sides |
   | `start_driver`, `stop_driver` | operator | a driver, on one server's engine |
   | `run_job`, `abort_job` | operator | a job |
   | `resync_driver`, `migrate_object_to_app`, `migrate_from_app` | operator | synchronization through a driver |
   | `change_status` | any | a change the key asked for |

   The key's role must reach the object first (its container scopes), or the tool refuses at once.
5. **Approval** (on by default): a change tool answers `202` with a pending change: its id, a summary and a link
   (`/agent-keys?change=<id>`). The agent gives the person the link. In the console, under *Agent keys*, the person
   reviews it and approves it (typing the directory's name on a production directory) or declines it; an admin may also
   decline. Approving makes the call then, in-process, as the key: the key and the account are checked again, and
   eDirectory decides with the person's rights. The agent reads the outcome with `change_status`. A change not decided
   within an hour expires; one from a key revoked since cannot be approved. Pending changes are kept in memory, so a
   restart drops them.
6. **Without approval:** the change is made at once. On a production directory the tool then needs `confirm`, the
   directory's name, which the agent must get from the person; the engine's operations refuse without it.

7. **Identity Applications** (a directory with its address set, Settings > Directory > *Identity Applications for
   agents*: the address, the OSP client, normally `rbpmrest`, and its secret). A key made with a password also signs
   its person in to Identity Applications once; the key keeps the refresh token, sealed with the console's key, and
   shows *authorized*. Its tools:

   | Tool | What it does, as the person |
   |---|---|
   | `my_tasks`, `task` | their approval tasks |
   | `my_requests`, `request_detail` | their requests and each one's history |
   | `assignments` | a person's role and resource assignments |
   | `request_definitions`, `request_definition` | the catalog's PRDs; one PRD as the permission index has it |
   | `search_permissions`, `who_has` | find roles and resources; who holds one (only people under the applications' user search root) |
   | `others_tasks`, `request_tasks` | other people's tasks (help desk, administrators); a request's approval tasks |
   | `approve_tasks`, `deny_tasks` | act on tasks; with `form_data`, through the JSON approval form (a key that may make changes) |
   | `start_request`, `request_role`, `request_resource` | requests (a key that may make changes) |
   | `revoke_role`, `revoke_resource` | take a role or resource away from people; a resource's assignment ids are looked up first (a key that may make changes) |
   | `retract_request` | retract a running request; a role request it was approving stays as it was (a key that may make changes) |

   Changes follow the approval setting like any other. When the refresh token stops working (30 days on the lab, or
   revoked), the tools answer `authorize-again` and the key shows *authorize again*; its person types their password
   under Agent keys > Authorize. Keys made with single sign-on get no Identity Applications tools in this version.

Every change is audited twice over: `agent-change.request`, `.approve` or `.decline` name the tool and the summary,
and the change itself is audited as the person with `via` = `agent` and the key's label and id.

A key works only at `/mcp`: the API's other routes ignore it. Each tool call goes through the API in-process, as the
key's session. Revoking a key, turning keys off for the directory, or a locked, disabled or expired account stops it
at the next call.

## Future features

- **Setting a person's password** through an agent, as described under [Passwords](#passwords).

## Not in scope

- Development work: policies, deploys and promotion stay in DirXMLDevWeb.
- Console settings, LDIF import, and agents acting for no one (for example CI).

## Decisions (taken 2026-10-30)

1. **Where keys live:** in the data volume, outside the versioned configuration. Backups leave them out, so a
   restore never brings back a revoked key; keys are cheap to make again.
2. **The role ceiling:** viewer, editor and operator, never admin. Default: read only.
3. **Roles under single sign-on:** keep the grants from the last sign-in, narrowed at the next one. These keys get a
   shorter longest life: 14 days.
4. **Agents' writes:** pending changes, approved in the console. Changed the same day: approval is a per-directory
   setting, required by default, that an administrator can turn off.
5. **Setting passwords:** generated, then applied by an operator in the console. A future feature: not built in
   phases 1 to 3 (marked 2026-10-30).
6. **The Identity Applications token:** one password grant when the key is made, then refresh tokens. The lab
   confirmed a 30-day lifetime that outlives OSP's session, and that refreshes do not touch `oidpInstanceData`.
7. **Lifetimes:** a 30-day default, at most 90 days, and 14 days idle.
8. **The per-directory switch:** off by default.
