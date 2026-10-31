package com.pointblue.console.server.http;

import com.pointblue.console.server.audit.AuditLog;
import com.pointblue.console.server.auth.AgentKeys;
import com.pointblue.console.server.auth.DirectLogin;
import com.pointblue.console.server.auth.DirectoryConfig;
import com.pointblue.console.server.auth.Grant;
import com.pointblue.console.server.auth.Role;
import com.pointblue.console.server.auth.Sessions;
import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.dirxml.dev.json.Json;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.naming.NamingException;

/**
 * Agent keys (docs/MCP.md): the routes a signed-in person makes and revokes them with, and how a key becomes a
 * session for the MCP server's calls.
 *
 * <pre>
 * GET    /api/v2/agent-keys          the person's keys, the directory's settings and the MCP address; ?all=true: everyone's (admin)
 * POST   /api/v2/agent-keys          {"label", "days"?, "roles"? ["viewer", "editor", "operator"], "password"? (direct sign-in)}
 *                                    the key, shown once
 * POST   /api/v2/agent-keys/{id}/authorize   {"password"}: Identity Applications for the person's own key (again)
 * DELETE /api/v2/agent-keys/{id}     revoke: the person's own key, or anyone's for an admin
 * </pre>
 *
 * Making a key proves the person is present: direct sign-in types the password again (a bind); single sign-on needs a
 * sign-in within the last 10 minutes. The console then checks it can act as them.
 *
 * <p>A key's calls run as the person the way single sign-on does: the service account's connection with the RFC 4370
 * proxied-authorization control, and Identity Manager's engine opened by the service account acting as them. eDirectory
 * refuses the control for disabled and expired accounts, but accepts it for an account locked by intruder detection,
 * so on every call the console reads the person's account as the service account and refuses a locked, disabled or
 * expired one. Direct sign-in grants come from that same read ({@code groupMembership}), so a role taken away reaches
 * the key at its next call; single sign-on grants are those of the person's last sign-in. A key never carries admin,
 * never counts as a recent sign-in, and carries no task presets.
 */
final class Agents {

    /**
     * Agent keys for a directory: {@code directories.<id>.agentKeys = {"enabled", "maxDays", "approveChanges"}}. Off by
     * default. {@code approveChanges} (true by default): a change an agent asks for waits until the person approves it in
     * the console (see AgentChanges).
     */
    record Settings(boolean enabled, int maxDays, boolean approveChanges) {
        Map<String, Object> json() {
            return Map.of("enabled", enabled, "maxDays", maxDays, "approveChanges", approveChanges);
        }
    }

    /** What the person's account is read for on every call. */
    private static final String[] PERSON = {"cn", "fullName", "groupMembership", "loginDisabled", "loginExpirationTime",
        "lockedByIntruder", "loginIntruderResetTime"};
    private static final DateTimeFormatter GENERALIZED = DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
    /** An unused key's connections are closed after this long. */
    private static final Duration CONTEXT_IDLE = Duration.ofMinutes(5);
    /** A known key refused for the same reason is audited once in this window. */
    private static final Duration REFUSAL_AUDIT = Duration.ofHours(1);
    private static final int MAX_LABEL = 60;

    private final Server server;
    final AgentKeys keys;
    /** Open connections per key id. */
    private final Map<String, Context> contexts = new ConcurrentHashMap<>();
    private final Map<String, Instant> refusalsAudited = new ConcurrentHashMap<>();

    /** A key's connections: the service account plain (to read the person), and acting as the person (for the calls). */
    private static final class Context {
        final Ldap svc;
        final Ldap ldap;
        final com.pointblue.console.server.idm.Engines.Opened engine;
        final String engineProblem;
        volatile Sessions.Session session;
        volatile Instant lastUsed = Instant.now();

        Context(Ldap svc, Ldap ldap, com.pointblue.console.server.idm.Engines.Opened engine, String engineProblem) {
            this.svc = svc;
            this.ldap = ldap;
            this.engine = engine;
            this.engineProblem = engineProblem;
        }

        void close() {
            Sessions.Session s = session;
            if (s != null) {
                s.servers.values().forEach(Sessions.ServerConnection::close);
                s.servers.clear();
            }
            if (engine != null && engine.handle() != null) {
                try {
                    engine.handle().close();
                } catch (Exception ignored) {
                    // already gone
                }
            }
            ldap.close();
            svc.close();
        }
    }

    Agents(Server server, AgentKeys keys) {
        this.server = server;
        this.keys = keys;
    }

    boolean handles(String path) {
        return path.equals("/api/v2/agent-keys") || path.startsWith("/api/v2/agent-keys/");
    }

    Settings settings(String directoryId) {
        Object dirs = server.config.read().get("directories");
        Object d = dirs instanceof Map<?, ?> m ? m.get(directoryId) : null;
        Object a = d instanceof Map<?, ?> dm ? dm.get("agentKeys") : null;
        if (!(a instanceof Map<?, ?> am)) {
            return new Settings(false, AgentKeys.MAX_DAYS, true);
        }
        int max = Math.max(1, Math.min(AgentKeys.MAX_DAYS, Json.asInt(am.get("maxDays"), AgentKeys.MAX_DAYS)));
        return new Settings(Boolean.TRUE.equals(am.get("enabled")), max, !Boolean.FALSE.equals(am.get("approveChanges")));
    }

    String mcpUrl() {
        return server.publicUrl + "/mcp";
    }

    void handle(HttpExchange ex, String method, String path) throws IOException {
        Sessions.Session s = server.session(ex, null);
        if (s.agent != null) {
            throw new Http.Problem(403, "agent-key", "an agent key cannot make or revoke agent keys");
        }
        if (path.equals("/api/v2/agent-keys") && method.equals("GET")) {
            list(ex, s);
        } else if (path.equals("/api/v2/agent-keys") && method.equals("POST")) {
            create(ex, s);
        } else if (method.equals("POST") && path.matches("/api/v2/agent-keys/[0-9a-f]{12}/authorize")) {
            authorize(ex, s, path.substring("/api/v2/agent-keys/".length(), path.length() - "/authorize".length()));
        } else if (method.equals("DELETE") && path.matches("/api/v2/agent-keys/[0-9a-f]{12}")) {
            revoke(ex, s, path.substring("/api/v2/agent-keys/".length()));
        } else {
            throw new Http.Problem(404, "not-found", method + " " + path);
        }
    }

    private void list(HttpExchange ex, Sessions.Session s) throws IOException {
        boolean all = "true".equals(Http.query(ex).get("all"));
        if (all && !s.principal.has(Role.ADMIN)) {
            throw new Http.Problem(403, "forbidden", "everyone's keys are for admins");
        }
        String dir = s.principal.directoryId();
        Instant now = keys.now();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("keys", (all ? keys.all(dir) : keys.of(dir, s.principal.dn())).stream().map(k -> k.json(now)).toList());
        Map<String, Object> st = new LinkedHashMap<>(settings(dir).json());
        DirectoryConfig d = server.directoryOf(s);
        st.put("serviceAccount", d != null && d.serviceAccountDn() != null);
        st.put("longestDays", longest(s, d));
        st.put("apps", server.agentApps.settings(dir).on());
        out.put("settings", st);
        out.put("mcpUrl", mcpUrl());
        Http.json(ex, 200, out);
    }

    /** The longest life a key of this person may have here. */
    private int longest(Sessions.Session s, DirectoryConfig d) {
        int max = d == null ? AgentKeys.MAX_DAYS : settings(d.id()).maxDays();
        return "oidc".equals(s.principal.via()) ? Math.min(max, AgentKeys.SSO_MAX_DAYS) : max;
    }

    private void create(HttpExchange ex, Sessions.Session s) throws IOException {
        Map<String, Object> b = Http.body(ex);
        String client = server.client(ex);
        Sessions.Principal p = s.principal;
        DirectoryConfig d = DirectoryConfig.find(server.config.read(), p.directoryId());
        if (d == null || !(p.via().equals("direct") || p.via().equals("oidc"))) {
            throw new Http.Problem(409, "not-available", "agent keys are for configured directories, signed in directly or with single sign-on");
        }
        if (!settings(d.id()).enabled()) {
            throw new Http.Problem(409, "agent-keys-off", "agent keys are off for this directory; an administrator turns them on in Settings > Directory");
        }
        String svcPw = server.config.secret(d.serviceAccountPasswordPath());
        if (d.serviceAccountDn() == null || svcPw == null) {
            throw new Http.Problem(409, "no-service-account", "agent keys need the directory's service account");
        }
        if (server.oidc.isNeverProxy(d, p.dn())) {
            throw new Http.Problem(409, "never-proxy", "the console never acts as this account (the service account, a break-glass account, or one on the never-proxy list), so it cannot have agent keys");
        }
        String label = Http.string(b, "label", true).trim();
        if (label.length() > MAX_LABEL || !label.matches("[\\p{L}\\p{N} ._()/+-]+")) {
            throw new Http.Problem(400, "bad-field", "the label is up to " + MAX_LABEL + " letters, digits, spaces and . _ ( ) / + -");
        }
        int longest = longest(s, d);
        int days = Http.integer(b, "days", Math.min(AgentKeys.DEFAULT_DAYS, longest));
        if (days < 1 || days > longest) {
            throw new Http.Problem(400, "bad-field", "days is 1 to " + longest + " here");
        }
        Set<Role> roles;
        try {
            roles = AgentKeys.roles(Json.asList(b.get("roles")).stream().map(String::valueOf).toList(), p);
        } catch (IllegalArgumentException e) {
            throw new Http.Problem(400, "bad-field", e.getMessage());
        }
        if (keys.of(d.id(), p.dn()).size() >= AgentKeys.PER_PERSON) {
            throw new Http.Problem(409, "too-many-keys", "you have " + AgentKeys.PER_PERSON + " agent keys here; revoke one first");
        }
        // the person is here now: their password again, or a recent single sign-on
        char[] pw = null;
        try {
            if (p.via().equals("oidc")) {
                server.stepUp(s);
            } else {
                pw = Http.string(b, "password", true).toCharArray();
                checkPassword(s, d, pw, client, "agent-key.create", label);
            }
            createChecked(ex, s, d, svcPw, label, roles, days, client, pw);
        } finally {
            if (pw != null) {
                java.util.Arrays.fill(pw, '\0');
            }
        }
    }

    /** The person's own password, checked by a bind as them (it is not kept). */
    private void checkPassword(Sessions.Session s, DirectoryConfig d, char[] pw, String client, String event, String label) throws IOException {
        if (!server.failedByClient.allowed(client)) {
            throw new Http.Problem(429, "too-many-attempts", "too many failed sign-ins; wait a few minutes");
        }
        try (Ldap ignored = Ldap.connect(server.trust, d.target(), null, s.principal.dn(), pw, Server.T)) {
            server.failedByClient.clear(client);
        } catch (Ldap.BadCredentials e) {
            server.failedByClient.record(client);
            server.audit.log(Server.who(s), event, d.id(), Map.of("label", label, "client", client), "refused");
            throw new Http.Problem(401, "bad-credentials", "the password is incorrect");
        } catch (Ldap.Untrusted | NamingException e) {
            throw new Http.Problem(503, "unavailable", "the directory did not answer: " + e.getMessage());
        }
    }

    private void createChecked(HttpExchange ex, Sessions.Session s, DirectoryConfig d, String svcPw, String label, Set<Role> roles, int days,
                               String client, char[] pw) throws IOException {
        Sessions.Principal p = s.principal;
        // the console can act as them: the same read single sign-on makes before it lets someone in
        try (Ldap svc = Ldap.connect(server.trust, d.target(), null, d.serviceAccountDn(), svcPw.toCharArray(), Server.T)) {
            svc.actAs(p.dn());
            if (svc.read(p.dn(), "cn") == null) {
                throw new NamingException("the account could not be read");
            }
        } catch (Ldap.Untrusted | Ldap.BadCredentials | NamingException e) {
            throw new Http.Problem(409, "proxy-refused", "the console cannot act as you through its service account ("
                + (e instanceof NamingException n ? Ldap.Failure.of(n).getMessage() : e.getMessage())
                + "); it needs Supervisor over your account");
        }
        AgentKeys.Made made = keys.create(label, p, roles, Duration.ofDays(days));
        server.audit.log(Server.who(s), "agent-key.create", made.key().id(), Map.of("label", label, "roles", made.key().roles().stream().map(Role::id).sorted().toList(),
            "days", days, "client", client), "ok");
        AgentKeys.Key key = made.key();
        String apps = null;
        if (pw != null && server.agentApps.settings(d.id()).on()) {
            // the same password, once more: the person's Identity Applications sign-in, whose refresh token the key keeps
            try {
                key = server.agentApps.authorize(key, d, pw);
                server.audit.log(Server.who(s), "agent-key.apps", key.id(), Map.of("label", label), "ok");
            } catch (Http.Problem problem) {
                apps = problem.getMessage();
                server.audit.log(Server.who(s), "agent-key.apps", key.id(), Map.of("label", label, "code", problem.type), "refused");
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("token", made.token());
        out.put("key", key.json(keys.now()));
        out.put("mcpUrl", mcpUrl());
        if (apps != null) {
            out.put("appsProblem", apps);
        }
        Http.json(ex, 201, out);
    }

    /**
     * {@code {"password"}}: authorize the person's own key for Identity Applications (again): a password grant, its
     * refresh token kept. Direct sign-in only (single sign-on gives the console no password to send).
     */
    private void authorize(HttpExchange ex, Sessions.Session s, String id) throws IOException {
        AgentKeys.Key k = keys.byId(id);
        if (k == null || !k.directoryId().equals(s.principal.directoryId()) || !com.pointblue.console.server.ldap.Names.same(k.dn(), s.principal.dn())) {
            throw new Http.Problem(404, "not-found", "no agent key " + id + " of yours");
        }
        if (!"direct".equals(s.principal.via())) {
            throw new Http.Problem(409, "not-available", "authorizing Identity Applications needs your password: sign in with it, not single sign-on");
        }
        DirectoryConfig d = DirectoryConfig.find(server.config.read(), k.directoryId());
        String client = server.client(ex);
        char[] pw = Http.string(Http.body(ex), "password", true).toCharArray();
        try {
            checkPassword(s, d, pw, client, "agent-key.apps", k.label());
            AgentKeys.Key u = server.agentApps.authorize(k, d, pw);
            server.audit.log(Server.who(s), "agent-key.apps", id, Map.of("label", k.label()), "ok");
            Http.json(ex, 200, u.json(keys.now()));
        } finally {
            java.util.Arrays.fill(pw, '\0');
        }
    }

    private void revoke(HttpExchange ex, Sessions.Session s, String id) throws IOException {
        AgentKeys.Key k = keys.byId(id);
        boolean mine = k != null && k.directoryId().equals(s.principal.directoryId()) && com.pointblue.console.server.ldap.Names.same(k.dn(), s.principal.dn());
        boolean admin = k != null && k.directoryId().equals(s.principal.directoryId()) && s.principal.has(Role.ADMIN);
        if (!mine && !admin) {
            throw new Http.Problem(404, "not-found", "no agent key " + id);
        }
        keys.revoke(id);
        close(id);
        server.agentChanges.revoked(id);
        server.agentApps.forget(id);
        server.audit.log(Server.who(s), "agent-key.revoke", id, Map.of("label", k.label(), "owner", k.dn()), "ok");
        Http.json(ex, 204, Map.of());
    }

    /** A directory was removed: its keys go too. */
    void removeDirectory(String directoryId) throws IOException {
        keys.removeDirectory(directoryId).forEach(this::close);
    }

    /** A single sign-on sign-in: the person's keys take its grants. */
    void signedIn(Sessions.Principal p) {
        try {
            keys.signedIn(p);
        } catch (IOException e) {
            // the keys keep their earlier grants; the sign-in goes ahead
        }
    }

    private void close(String id) {
        Context c = contexts.remove(id);
        if (c != null) {
            c.close();
        }
    }

    // ---- a key's calls ----------------------------------------------------------------------------

    /**
     * The session an agent key in {@code Authorization: Bearer} stands for, checked now: the key active, the
     * directory's agent keys on, the person's account active and unlocked, and some role. Refusals are problems
     * (401 for the key itself, with {@code WWW-Authenticate}; 403 for the person or directory).
     */
    Caller resolve(HttpExchange ex) throws IOException {
        String client = server.client(ex);
        String h = ex.getRequestHeaders().getFirst("Authorization");
        String token = h != null && h.regionMatches(true, 0, "Bearer ", 0, 7) ? h.substring(7).trim() : null;
        if (token == null || token.isEmpty()) {
            throw unauthorized("agent-key-required", "send an agent key: Authorization: Bearer dc_… (made in the console, under your name > Agent keys)");
        }
        if (!server.failedByClient.allowed(client)) {
            throw new Http.Problem(429, "too-many-attempts", "too many refused keys from this address; wait a few minutes");
        }
        AgentKeys.Key k = keys.find(token);
        if (k == null) {
            server.failedByClient.record(client);
            throw unauthorized("agent-key-invalid", "this agent key is unknown or was revoked");
        }
        return check(k, client);
    }

    /** {@code k}'s session, checked now as {@link #resolve} checks it: for a call, or for a change its owner approves. */
    Caller check(AgentKeys.Key k, String client) throws IOException {
        Instant now = keys.now();
        if (k.expired(now)) {
            throw refused(k, client, unauthorized("agent-key-expired", "this agent key expired on " + k.expires() + "; make a new one"));
        }
        if (k.idle(now)) {
            throw refused(k, client, unauthorized("agent-key-idle", "this agent key was not used for " + AgentKeys.IDLE.toDays() + " days and stopped working; make a new one"));
        }
        DirectoryConfig d = DirectoryConfig.find(server.config.read(), k.directoryId());
        if (d == null) {
            throw unauthorized("agent-key-invalid", "this agent key's directory was removed");
        }
        if (!settings(d.id()).enabled()) {
            throw refused(k, client, new Http.Problem(403, "agent-keys-off", "agent keys are off for " + d.name()));
        }
        if (server.oidc.isNeverProxy(d, k.dn())) {
            throw refused(k, client, new Http.Problem(403, "never-proxy", "the console never acts as " + k.dn()));
        }
        Context c;
        Ldap.Entry me;
        try {
            c = context(k, d);
            try {
                me = c.svc.read(k.dn(), PERSON);
            } catch (javax.naming.CommunicationException | javax.naming.ServiceUnavailableException e) {
                // the directory closed an idle connection: open it again, once
                close(k.id());
                c = context(k, d);
                me = c.svc.read(k.dn(), PERSON);
            }
        } catch (NamingException e) {
            close(k.id());
            throw new Http.Problem(503, "unavailable", "the directory did not answer: " + Ldap.Failure.of(e).getMessage());
        }
        if (me == null) {
            throw refused(k, client, new Http.Problem(403, "no-account", k.dn() + " is not in the directory"));
        }
        String refusal = inactive(me, now);
        if (refusal != null) {
            throw refused(k, client, new Http.Problem(403, refusal, switch (refusal) {
                case "locked" -> "the account is locked by intruder detection; its agent keys work again once it is unlocked";
                case "account-disabled" -> "the account is disabled";
                default -> "the account has expired";
            }));
        }
        List<Grant> grants = "oidc".equals(k.via()) ? k.grants()
            : DirectLogin.grants(d, me.attributes().getOrDefault("groupmembership", List.of()));
        List<Grant> limited = AgentKeys.limit(grants, k.roles());
        if (limited.isEmpty()) {
            throw refused(k, client, new Http.Problem(403, "no-role", "the account has no Directory Console role now"));
        }
        String name = me.first("fullName") != null ? me.first("fullName") : me.first("cn") != null ? me.first("cn") : k.name();
        Sessions.Principal p = new Sessions.Principal(k.subject(), k.dn(), name, d.id(), DirectLogin.roles(limited), "agent", limited);
        Sessions.Session s = c.session;
        if (s == null || !s.principal.equals(p)) {
            Sessions.Session made = Sessions.agent(p, c.ldap, c.engine, c.engineProblem, k.ref());
            if (s != null) {
                made.servers.putAll(s.servers);
            }
            c.session = made;
            s = made;
        }
        c.lastUsed = now;
        sweep(now);
        return new Caller(s, keys.used(k));
    }

    /** An agent key's call: the session it runs in, and the key. */
    record Caller(Sessions.Session session, AgentKeys.Key key) {
    }

    /** Why the account cannot be acted as now ({@code locked}, {@code account-disabled}, {@code account-expired}), or null. */
    String inactive(Ldap.Entry me, Instant now) {
        if ("TRUE".equalsIgnoreCase(me.first("loginDisabled"))) {
            return "account-disabled";
        }
        String exp = me.first("loginExpirationTime");
        if (exp != null) {
            try {
                if (!Instant.from(GENERALIZED.parse(exp.trim())).isAfter(now)) {
                    return "account-expired";
                }
            } catch (DateTimeParseException e) {
                // eDirectory decides; the proxied control is refused for an expired account
            }
        }
        return server.oidc.locked(me) ? "locked" : null;
    }

    private Context context(AgentKeys.Key k, DirectoryConfig d) throws NamingException {
        Context c = contexts.get(k.id());
        if (c != null) {
            return c;
        }
        synchronized (this) {
            c = contexts.get(k.id());
            if (c != null) {
                return c;
            }
            String pw = server.config.secret(d.serviceAccountPasswordPath());
            if (d.serviceAccountDn() == null || pw == null) {
                throw new Http.Problem(503, "no-service-account", "agent keys need the directory's service account");
            }
            Ldap svc;
            Ldap ldap;
            try {
                svc = Ldap.connect(server.trust, d.target(), null, d.serviceAccountDn(), pw.toCharArray(), Server.T);
            } catch (Ldap.Untrusted | Ldap.BadCredentials e) {
                throw new Http.Problem(503, "unavailable", "the console's service account could not sign in: " + e.getMessage());
            }
            try {
                ldap = Ldap.connect(server.trust, d.target(), null, d.serviceAccountDn(), pw.toCharArray(), Server.T);
            } catch (Ldap.Untrusted | Ldap.BadCredentials e) {
                svc.close();
                throw new Http.Problem(503, "unavailable", "the console's service account could not sign in: " + e.getMessage());
            } catch (NamingException e) {
                svc.close();
                throw e;
            }
            ldap.actAs(k.dn());
            Server.SsoEngine e = server.ssoEngine(d, ldap, d.target(), k.dn(), null);
            c = new Context(svc, ldap, e.engine(), e.problem());
            contexts.put(k.id(), c);
            return c;
        }
    }

    /** Close the connections of keys not used lately. */
    private void sweep(Instant now) {
        for (Map.Entry<String, Context> e : new ArrayList<>(contexts.entrySet())) {
            if (e.getValue().lastUsed.plus(CONTEXT_IDLE).isBefore(now) && contexts.remove(e.getKey(), e.getValue())) {
                e.getValue().close();
            }
        }
    }

    private Http.Problem unauthorized(String code, String detail) {
        return new Http.Problem(401, code, detail);
    }

    /** A known key refused: audited once an hour per key and reason. */
    private Http.Problem refused(AgentKeys.Key k, String client, Http.Problem p) throws IOException {
        Instant now = keys.now();
        String key = k.id() + "|" + p.type;
        Instant last = refusalsAudited.get(key);
        if (last == null || last.plus(REFUSAL_AUDIT).isBefore(now)) {
            refusalsAudited.put(key, now);
            server.audit.log(new AuditLog.Actor(k.subject(), k.dn(), "agent", k.ref()), "agent-key.use", k.id(), Map.of("code", p.type, "client", client), "refused");
        }
        return p;
    }

    /** Close every key's connections (the server stops). */
    void stop() {
        new ArrayList<>(contexts.keySet()).forEach(this::close);
    }
}
