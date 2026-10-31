# Using AI agents with Directory Console

From version 0.4.0 an AI agent, such as Claude Code, can work in Directory Console for you. It can answer
questions about accounts, groups and Identity Manager, and, if you let it, make changes, which wait for your
approval. This page shows how to set an agent up, what to ask it, and what to expect.

How it works, and why it is safe, is in [MCP.md](MCP.md). In short:

- **It is you:** the agent acts as you, with your own eDirectory rights, and never with more than the roles you give
  its key.
- **Changes wait for you:** a change it asks for waits for your approval in the console (unless an administrator has
  turned that off for the directory).
- **You can stop it at once:** revoke the key, and the agent stops at its next call.

## Contents

1. [Setting up](#1-setting-up)
2. [First steps](#2-first-steps)
3. [Example prompts: looking things up](#3-example-prompts-looking-things-up)
4. [Example prompts: making changes](#4-example-prompts-making-changes)
5. [Example prompts: Identity Applications](#5-example-prompts-identity-applications)
6. [Good habits](#6-good-habits)
7. [When something goes wrong](#7-when-something-goes-wrong)

## 1. Setting up

### An administrator turns agent keys on

Once per directory: **Settings > Directory > Agent keys > Allow agent keys**.

- **Service account:** keys need the directory's service account, with Supervisor over the people who will make keys
  (the same as single sign-on).
- **Other settings in the same place:**
  - the longest life of a key;
  - whether changes an agent asks for wait for approval (on by default);
  - the Identity Applications address, if agents should also work with approvals and requests.
- **Behind a reverse proxy:** it must also forward `/mcp`
  ([DEPLOYING](DEPLOYING.md#8-behind-a-reverse-proxy-or-load-balancer)).

### You make a key

1. In the console, open your name (top right) > **Agent keys** > **New agent key**.
2. **Label:** name the agent or machine, for example "Claude Code on my laptop". The audit log names the key by it.
3. **What it may do:** reading is always allowed. Tick "Change directory objects" or "Run Identity Manager
   operations" only if you want the agent to ask for those changes. Start with a read-only key; you can make another
   later.
4. **Confirm:** type your password. With single sign-on, you need to have signed in within the last 10 minutes.
5. **Copy the key now:** it is shown once. The dialog also shows the command for Claude Code and the settings for other
   clients.

### You connect your agent

**Claude Code:** run the command the dialog shows. It looks like this:

```bash
claude mcp add --transport http directory-console https://console.example.com/mcp --header "Authorization: Bearer dc_…"
```

**Other MCP clients:** use the JSON the dialog shows, an `http` server with the same address and header.

**Trust the console's certificate.** The agent's machine must trust it.

- **A certificate from a CA the machine already trusts** needs nothing.
- **The console's own self-signed certificate** has to be trusted explicitly. Save a copy:

  ```bash
  openssl s_client -connect console.example.com:443 </dev/null | openssl x509 > console.pem
  ```

  Then start Claude Code (and other Node-based agents) with `NODE_EXTRA_CA_CERTS` pointing to that copy:

  ```bash
  NODE_EXTRA_CA_CERTS=$HOME/console.pem claude
  ```

**Check the connection.** `claude mcp list` should show `directory-console: … ✔ Connected`. It shows
`UNABLE_TO_VERIFY_LEAF_SIGNATURE` when the certificate is not trusted.

Keep the key like a password. Don't put it in a shared file, a repository or a chat.

## 2. First steps

Start every session by letting the agent find out who it is:

> Use the directory-console tools. Call whoami and tell me who you are acting as, which directory this is (and whether
> it is production), and what my key lets you do.

The agent should answer with:

- your name and DN;
- the directory and its tier;
- the key's roles and expiry;
- whether Identity Applications tools are available.

Some tips:

- **Name things as you would to a colleague:** a person's name, a DN or a GUID all work. The agent searches for what
  it needs.
- **Read-only first:** ask what it would do before asking it to do it.
- **Say which server, if it matters.** Identity Manager answers about the server you're signed in to, unless you name
  another.

## 3. Example prompts: looking things up

These only read, and need no approval.

**Why can't someone sign in?**

> Jo Smith says they can't sign in. Find their account, check whether it is disabled, locked by intruder detection,
> expired, or out of grace logins, and tell me what is wrong in plain words.

**Is this person set up correctly?**

> Show me cn=jsmith,ou=users,o=acme: their groups, their title and department, and their Identity Manager associations.
> Point out anything that looks inconsistent.

**Why didn't a user synchronize?**

> Pat Lee was added to the AD group yesterday but it never reached Active Directory. Look at their associations and
> password synchronization status, check the AD driver's state and health, and look at its cache. Tell me the most
> likely reason.

**How are the drivers doing?**

> Give me a health report for the driver set: each driver's state, start option, health, and cache size. List anything
> that is stopped, unhealthy or has a growing cache first.

**What did the jobs do?**

> List the Identity Manager jobs in the driver set with their state and schedule. Which of them are disabled, and which
> ran most recently?

**Group questions:**

> Who is in the group cn=Finance,ou=groups,o=acme? Which of them are disabled accounts?

> Which groups is cn=jsmith,ou=users,o=acme in, and which of those groups have no other members?

**Versions:**

> What version is the Identity Manager engine, and what shim version and base package is each driver on? Put it in a
> table.

**Searching:**

> Find every user under ou=sales,o=acme whose title contains "Manager" and list their names and phone numbers.

## 4. Example prompts: making changes

The key needs the matching role: "Change directory objects" for accounts and groups, "Run Identity Manager
operations" for drivers and jobs. With approval on (the default), each change waits for you:

1. **The agent asks:** it answers with a summary and a link, for example
   `https://console.example.com/agent-keys?change=4c2dbac25ce1`.
2. **You review:** open the link (or Agent keys > Changes agents asked for) and read what it will do.
3. **You approve or decline.** On a production directory you type its name to approve. The change is made then, as
   the key, with your rights.
4. **The agent follows up:** it can check the outcome with `change_status`. A change not decided within an hour
   expires.

**Unlock an account:**

> Jo Smith is locked out by intruder detection. Unlock the account and give me the link to approve it.

**Group membership:**

> Add cn=pat,ou=users,o=acme to cn=Sales Team,ou=groups,o=acme and remove them from cn=Support,ou=groups,o=acme. Show
> me both changes before you ask for them.

**Disable an account:**

> Disable the account of cn=former,ou=users,o=acme. They left today.

**Restart a driver:**

> The LDAP driver is stopped. Check its health and the last thing in its cache, and if nothing looks wrong, ask to
> start it.

**Resynchronize:**

> Resynchronize the AD driver for everything changed since yesterday at 6pm.

**Send one object through a driver:**

> Migrate cn=jsmith,ou=users,o=acme into the application through the AD driver.

**Run a job:**

> Run the "Weekly trigger" job now.

**A good pattern for anything larger:** ask for a plan first, then the changes:

> I want to move everyone in ou=old-sales to the Sales Team group. First list who would be added, and don't change
> anything yet.

then:

> Go ahead and ask for those changes.

**On a production directory without approval:** if an administrator turned approval off, the agent asks you to type
the directory's name before an Identity Manager change, and passes your answer on. Never let it fill that in
itself.

## 5. Example prompts: Identity Applications

These need the directory's Identity Applications address set, and a key made with your password. The key's list
shows "authorized". Everything happens as you in Identity Applications, with your own rights there.

**Your approvals:**

> What approval tasks are waiting for me? Summarize each one: what is requested, for whom, by whom, and since when.

> Approve the request for Pat Lee's VPN access, with the comment "approved after manager check". Deny the other two
> with the comment "please resubmit with a business reason".

Approving and denying tasks are changes, so they wait for your approval in the console. Yes, you approve your
approval: it keeps an agent from acting on your behalf without you seeing it.

**Requests:**

> What happened to my request for the Finance Reports role last week? Show me its history: who it was assigned to and
> who approved or denied it.

> Request the role cn=VPN Users,cn=Level10,cn=RoleDefs,… for cn=pat,ou=users,o=acme with the reason "new starter".

> Retract my request for the Finance Reports role; I no longer need it.

**Who has what:**

> Who holds the Finance Reports role? List their names and when they got it.

> What roles and resources does cn=jsmith,ou=users,o=acme have?

**Clean-up:**

> These three people left the finance team: Pat Lee, Jo Smith and Sam Doe. If they hold the Finance Reports role,
> revoke it with the reason "left the finance team". Show me who actually holds it first.

**Help desk and administrators:**

> Show me the approval tasks waiting for anyone in the sales department, oldest first.

**Starting a request definition:**

> Which request definitions can I start? Then start "Access Request" for cn=pat,ou=users,o=acme with the reason
> "project Atlas".

Things to know:

- **"Who has" only sees people under the Identity Applications' user search root.** Someone elsewhere is left out
  without an error.
- **A definition may be gone:** the catalog can list a request definition that no longer exists. The agent checks
  before starting one.
- **Retracting** stops the workflow, but a role request it was approving can still read "Approval Pending".
- **Keys made with single sign-on** have no Identity Applications tools: the console has no password to sign in with.

## 6. Good habits

- **One key per agent or machine,** with a label that says which, so you know what to revoke.
- **Read-only unless needed:** most questions need no more. Make a separate key with change roles when you need
  them.
- **Ask for the plan first** before anything that changes more than one thing.
- **Read what you approve.** The review dialog shows exactly what will change.
- **Never give the agent a password.** No tool asks for one, and setting passwords is not something agents do.
- **Revoke a key you no longer use.** A key also stops after 14 days unused, and when it expires.
- **On production,** keep approval on, and type the directory's name only for a change you have read.

## 7. When something goes wrong

| The agent reports | What it means | What to do |
|---|---|---|
| `agent-key-invalid` | the key is unknown or was revoked | make a new key |
| `agent-key-expired`, `agent-key-idle` | the key's life ended, or it was unused for 14 days | make a new key |
| `agent-keys-off` | an administrator turned agent keys off for this directory | ask them |
| `locked`, `account-disabled`, `account-expired` | your account can't be used right now | fix the account; the key works again afterwards |
| `no-role` | you have no console role now | ask an administrator |
| `forbidden`, `out-of-scope` | the key's roles don't allow it, or don't reach that object | make a key with the role, or ask an administrator |
| `insufficient-rights` | eDirectory refused: you have no right to change that | the same change would fail for you in the console |
| `authorize-again` | the Identity Applications sign-in stopped working (after 30 days, or revoked) | Agent keys > your key > **Authorize**, and type your password |
| `not-a-holder` | the person doesn't hold that resource, or is outside the user search root | check the name |
| a change reads `expired` | nobody approved it within an hour | ask the agent to ask again |
| `UNABLE_TO_VERIFY_LEAF_SIGNATURE` | the agent's machine doesn't trust the console's certificate | see [Setting up](#1-setting-up) |
| connection refused, or 404, at `/mcp` | a reverse proxy doesn't forward `/mcp` | see [DEPLOYING](DEPLOYING.md#8-behind-a-reverse-proxy-or-load-balancer) |

A console restart drops changes waiting for approval. Ask the agent to ask again.

The console's audit log records every change an agent asks for, approves or makes, every key made or revoked, and
every refused key, with the key's label. Reads are not audited, as in the console itself.
