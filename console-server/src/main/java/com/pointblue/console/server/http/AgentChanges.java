package com.pointblue.console.server.http;

import com.pointblue.console.server.auth.AgentKeys;
import com.pointblue.console.server.auth.DirectoryConfig;
import com.pointblue.console.server.auth.Role;
import com.pointblue.console.server.auth.Sessions;
import com.pointblue.console.server.ldap.Names;
import com.pointblue.dirxml.dev.json.Json;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Changes agents asked for, waiting for the person's approval (docs/MCP.md, "Approving agents' changes"): while a
 * directory's {@code approveChanges} is on (the default), a change tool records the API call it would make here and
 * answers with the change's id and a link. The key's owner approves it in the console, typing the directory's name on a
 * production directory, or declines it. Approving makes the call then, as the key (its session checked again: a
 * revoked key, or a locked account, cannot be approved through). A change not decided within an hour expires.
 *
 * <pre>
 * GET  /api/v2/agent-changes                 the person's changes, newest first; ?all=true: everyone's in the directory (admin)
 * POST /api/v2/agent-changes/{id}/approve    {"confirm"?: the directory's name, on production}: the call's answer
 * POST /api/v2/agent-changes/{id}/decline    the key's owner, or an admin
 * </pre>
 *
 * Changes are kept in memory: a restart drops those waiting, and the agent asks again.
 */
final class AgentChanges {

    static final Duration WAIT = Duration.ofHours(1);
    /** Decided changes are listed for this long. */
    private static final Duration KEEP = Duration.ofDays(1);
    private static final SecureRandom RANDOM = new SecureRandom();

    /** What a change tool would call: the API route and body, and what it does in words. */
    record Request(String tool, String summary, String target, String method, String path, Object body) {
    }

    /** One change: {@code state} is pending, approved, declined, expired or failed. */
    static final class Change {
        final String id;
        final String keyId;
        final String keyLabel;
        final String directoryId;
        final String dn;
        final Request request;
        final Instant created;
        volatile String state = "pending";
        volatile Instant decided;
        volatile String decidedBy;
        volatile Mcp.Reply result;

        Change(String id, AgentKeys.Key k, Request request, Instant created) {
            this.id = id;
            this.keyId = k.id();
            this.keyLabel = k.label();
            this.directoryId = k.directoryId();
            this.dn = k.dn();
            this.request = request;
            this.created = created;
        }

        Instant expires() {
            return created.plus(WAIT);
        }

        Map<String, Object> json() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id);
            m.put("state", state);
            m.put("tool", request.tool());
            m.put("summary", request.summary());
            m.put("target", request.target());
            m.put("key", Map.of("id", keyId, "label", keyLabel));
            m.put("dn", dn);
            m.put("created", created.toString());
            m.put("expires", expires().toString());
            if (decided != null) {
                m.put("decided", decided.toString());
                m.put("decidedBy", decidedBy);
            }
            if (result != null) {
                m.put("result", Map.of("status", result.status(), "body", result.body().isBlank() ? Map.of() : Json.parse(result.body())));
            }
            return m;
        }
    }

    private final Server server;
    private final Map<String, Change> changes = new ConcurrentHashMap<>();

    AgentChanges(Server server) {
        this.server = server;
    }

    boolean handles(String path) {
        return path.equals("/api/v2/agent-changes") || path.startsWith("/api/v2/agent-changes/");
    }

    /** Record a change the key's agent asks for; what the agent is told. */
    Map<String, Object> propose(Agents.Caller caller, Request r) throws IOException {
        sweep();
        byte[] b = new byte[6];
        RANDOM.nextBytes(b);
        Change c = new Change(HexFormat.of().formatHex(b), caller.key(), r, Instant.now());
        changes.put(c.id, c);
        server.audit.log(Server.who(caller.session()), "agent-change.request", c.id,
            Map.of("tool", r.tool(), "summary", r.summary(), "object", String.valueOf(r.target())), "pending");
        Map<String, Object> out = new LinkedHashMap<>(c.json());
        out.put("approve", server.publicUrl + "/agent-keys?change=" + c.id);
        out.put("next", "This change waits for " + caller.session().principal.name() + " to approve it in the console (the link above), within an hour. "
            + "Ask them to, then call change_status with this id.");
        return out;
    }

    /** A change's state for the agent that asked for it; null when it is not that key's. */
    Map<String, Object> status(Agents.Caller caller, String id) {
        sweep();
        Change c = changes.get(id);
        return c == null || !c.keyId.equals(caller.key().id()) ? null : c.json();
    }

    void handle(HttpExchange ex, String method, String path) throws IOException {
        Sessions.Session s = server.session(ex, null);
        if (s.agent != null) {
            throw new Http.Problem(403, "agent-key", "an agent key cannot approve or decline changes");
        }
        sweep();
        if (path.equals("/api/v2/agent-changes") && method.equals("GET")) {
            boolean all = "true".equals(Http.query(ex).get("all"));
            if (all && !s.principal.has(Role.ADMIN)) {
                throw new Http.Problem(403, "forbidden", "everyone's changes are for admins");
            }
            List<Map<String, Object>> out = new ArrayList<>();
            changes.values().stream()
                .filter(c -> c.directoryId.equals(s.principal.directoryId()) && (all || Names.same(c.dn, s.principal.dn())))
                .sorted((a, b) -> b.created.compareTo(a.created))
                .forEach(c -> out.add(c.json()));
            Http.json(ex, 200, Map.of("changes", out));
            return;
        }
        String[] p = path.substring("/api/v2/agent-changes/".length()).split("/", -1);
        if (!method.equals("POST") || p.length != 2 || !p[0].matches("[0-9a-f]{12}")) {
            throw new Http.Problem(404, "not-found", method + " " + path);
        }
        Change c = changes.get(p[0]);
        boolean mine = c != null && c.directoryId.equals(s.principal.directoryId()) && Names.same(c.dn, s.principal.dn());
        boolean admin = c != null && c.directoryId.equals(s.principal.directoryId()) && s.principal.has(Role.ADMIN);
        switch (p[1]) {
            case "approve" -> {
                if (!mine) {
                    throw new Http.Problem(404, "not-found", "no change " + p[0] + " for you to approve");
                }
                approve(ex, s, c);
            }
            case "decline" -> {
                if (!mine && !admin) {
                    throw new Http.Problem(404, "not-found", "no change " + p[0]);
                }
                decide(c, "declined", s);
                server.audit.log(Server.who(s), "agent-change.decline", c.id, Map.of("tool", c.request.tool(), "summary", c.request.summary(), "agent", c.keyLabel), "ok");
                Http.json(ex, 200, c.json());
            }
            default -> throw new Http.Problem(404, "not-found", method + " " + path);
        }
    }

    private void approve(HttpExchange ex, Sessions.Session s, Change c) throws IOException {
        synchronized (c) {
            if (!c.state.equals("pending")) {
                throw new Http.Problem(409, "not-pending", "this change is " + c.state);
            }
            String confirm = Http.string(Http.body(ex), "confirm", false);
            DirectoryConfig d = server.directoryOf(s);
            if (d != null && d.production() && (confirm == null || !confirm.trim().equalsIgnoreCase(d.name()))) {
                throw new Http.Problem(409, "confirm-directory", "this changes the production directory " + d.name() + "; type its name to approve");
            }
            AgentKeys.Key k = server.agents.keys.byId(c.keyId);
            if (k == null) {
                decide(c, "failed", s);
                c.result = new Mcp.Reply(410, Json.compact(Map.of("title", "agent-key-revoked", "detail", "the key that asked for this change was revoked")));
                throw new Http.Problem(409, "agent-key-revoked", "the key that asked for this change was revoked");
            }
            // the call is the agent's, made now as its key, so the key's roles and the account's state apply now
            Agents.Caller caller = server.agents.check(k, server.client(ex));
            server.audit.log(Server.who(s), "agent-change.approve", c.id, Map.of("tool", c.request.tool(), "summary", c.request.summary(), "agent", c.keyLabel), "ok");
            Mcp.Reply r = Mcp.execute(server, ex, caller.session(), c.request, d != null && d.production() ? d.name() : null);
            c.result = r;
            decide(c, r.status() < 400 ? "approved" : "failed", s);
            Http.json(ex, 200, c.json());
        }
    }

    private static void decide(Change c, String state, Sessions.Session s) {
        c.state = state;
        c.decided = Instant.now();
        c.decidedBy = s.principal.dn();
    }

    /** Pending changes past their hour expire; decided ones are dropped after a day. */
    private void sweep() {
        Instant now = Instant.now();
        for (Change c : changes.values()) {
            if (c.state.equals("pending") && c.expires().isBefore(now)) {
                c.state = "expired";
                c.decided = c.expires();
            }
        }
        changes.values().removeIf(c -> c.decided != null && c.decided.plus(KEEP).isBefore(now));
    }

    /** A key revoked: its waiting changes cannot be approved. */
    void revoked(String keyId) {
        changes.values().stream().filter(c -> c.keyId.equals(keyId) && c.state.equals("pending")).forEach(c -> {
            c.state = "failed";
            c.decided = Instant.now();
            c.result = new Mcp.Reply(410, Json.compact(Map.of("title", "agent-key-revoked", "detail", "the key was revoked")));
        });
    }
}
