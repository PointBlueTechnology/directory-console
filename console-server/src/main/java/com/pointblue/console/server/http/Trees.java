package com.pointblue.console.server.http;

import com.pointblue.console.server.audit.AuditLog;
import com.pointblue.console.server.auth.DirectoryConfig;
import com.pointblue.console.server.auth.Role;
import com.pointblue.console.server.auth.Sessions;
import com.pointblue.console.server.data.ConfigStore;
import com.pointblue.console.server.tls.TrustStore;
import com.pointblue.dirxml.dev.json.Json;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The trees the console knows (dev, test, production…), for console admins: an admin of any configured
 * tree, signed in within the last 10 minutes, as for the other console-wide settings. People choose a
 * tree from the list at sign-in; each tree keeps its own tier, service account, role mappings, presets,
 * single sign-on and break-glass accounts, managed while signed in to it.
 *
 * <pre>
 * GET    /api/v2/console/trees           [{id, name, host, port, tier, current}]
 * POST   /api/v2/console/trees           {name?, tier?, host, port?, dn, password, accept?}: proven as at first sign-in
 *                                        (see TreeProof); dn becomes the new tree's break-glass account
 * PATCH  /api/v2/console/trees/{id}      {name?, tier?}
 * DELETE /api/v2/console/trees/{id}      {name}: the tree's name, typed; not the tree you are signed in to
 * </pre>
 *
 * Adding a tree needs that tree's own administrator: being an admin of another tree is not enough.
 * Removing one ends its sessions and drops the certificates trusted for it alone.
 */
final class Trees {

    private final Server server;

    Trees(Server server) {
        this.server = server;
    }

    boolean handles(String path) {
        return path.equals("/api/v2/console/trees") || path.startsWith("/api/v2/console/trees/");
    }

    void handle(HttpExchange ex, String method, String path) throws IOException {
        Sessions.Session s = server.session(ex, Role.ADMIN);
        String id = path.length() > "/api/v2/console/trees/".length() ? path.substring("/api/v2/console/trees/".length()) : null;
        if (!method.equals("GET")) {
            server.stepUp(s);
        }
        switch (method + (id == null ? "" : " {id}")) {
            case "GET" -> Http.json(ex, 200, list(s));
            case "POST" -> add(ex, s);
            case "PATCH {id}" -> change(ex, s, id);
            case "DELETE {id}" -> remove(ex, s, id);
            default -> throw new Http.Problem(405, "method-not-allowed", method + " " + path);
        }
    }

    private List<Map<String, Object>> list(Sessions.Session s) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (DirectoryConfig d : DirectoryConfig.all(server.config.read())) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", d.id());
            m.put("name", d.name());
            m.put("host", d.host());
            m.put("port", d.port());
            m.put("tier", d.tier());
            m.put("current", d.id().equals(s.principal.directoryId()));
            out.add(m);
        }
        return out;
    }

    private static AuditLog.Actor actor(Sessions.Session s) {
        return Server.who(s);
    }

    private static String tier(Map<String, Object> b, String dflt) {
        String t = Http.string(b, "tier", false);
        if (t == null) {
            return dflt;
        }
        if (!t.equals("production") && !t.equals("lab")) {
            throw new Http.Problem(400, "bad-field", "tier is production or lab");
        }
        return t;
    }

    private static String name(Map<String, Object> b) {
        String n = Http.string(b, "name", false);
        if (n == null) {
            return null;
        }
        n = n.trim();
        if (n.isEmpty() || n.length() > 64) {
            throw new Http.Problem(400, "bad-field", "a directory's name is 1 to 64 characters");
        }
        return n;
    }

    private void add(HttpExchange ex, Sessions.Session s) throws IOException {
        Map<String, Object> b = Http.body(ex);
        String chosenName = name(b);
        String tier = tier(b, "production");
        String host = Http.string(b, "host", true).trim();
        int port = Http.integer(b, "port", 636);
        for (DirectoryConfig d : DirectoryConfig.all(server.config.read())) {
            if (d.host().equalsIgnoreCase(host) && d.port() == port) {
                throw new Http.Problem(409, "exists", host + ":" + port + " is already the directory " + d.name());
            }
        }
        String provisional = "new-" + Integer.toHexString(System.identityHashCode(s)) + Long.toHexString(System.nanoTime());
        TreeProof.Proven p = TreeProof.prove(server, "trees:" + s.id, provisional, b, actor(s));
        String name = chosenName != null ? chosenName : p.treeName() != null ? p.treeName() : host;
        String id = TreeProof.idFrom(name, "tree");
        List<String> taken = DirectoryConfig.all(server.config.read()).stream().map(DirectoryConfig::id).toList();
        for (int i = 2; taken.contains(id); i++) {
            id = TreeProof.idFrom(name, "tree") + "-" + i;
        }
        String newId = id;
        try {
            server.config.update(server.config.version(), s.principal.dn(), "add tree " + newId, doc -> {
                Map<String, Object> dir = new LinkedHashMap<>();
                dir.put("name", name);
                dir.put("host", p.host());
                dir.put("port", p.port());
                dir.put("tier", tier);
                dir.put("login", new LinkedHashMap<>(Map.of("direct", true, "duplicates", "choose", "searchBases", List.of())));
                dir.put("roles", List.of());
                dir.put("breakGlass", List.of(p.dn()));
                Map<String, Object> all = new LinkedHashMap<>(Json.asMap(doc.get("directories")));
                all.put(newId, dir);
                doc.put("directories", all);
            });
        } catch (ConfigStore.Conflict c) {
            throw new Http.Problem(409, "version-conflict", c.getMessage());
        }
        TreeProof.settle(server, p, newId);
        server.audit.log(actor(s), "tree.add", newId, Map.of("name", name, "directory", p.host() + ":" + p.port(), "tier", tier, "breakGlass", p.dn()), "ok");
        Http.json(ex, 201, list(s).stream().filter(m -> newId.equals(m.get("id"))).findFirst().orElse(Map.of("id", newId)));
    }

    private void change(HttpExchange ex, Sessions.Session s, String id) throws IOException {
        DirectoryConfig d = known(id);
        Map<String, Object> b = Http.body(ex);
        String name = name(b);
        String tier = tier(b, null);
        if (name == null && tier == null) {
            throw new Http.Problem(400, "bad-request", "change the name or the tier");
        }
        try {
            server.config.update(server.config.version(), s.principal.dn(), "change tree " + id, doc -> {
                Map<String, Object> dir = Json.asMap(Json.asMap(doc.get("directories")).get(id));
                if (name != null) {
                    dir.put("name", name);
                }
                if (tier != null) {
                    dir.put("tier", tier);
                }
            });
        } catch (ConfigStore.Conflict c) {
            throw new Http.Problem(409, "version-conflict", c.getMessage());
        }
        Map<String, Object> detail = new LinkedHashMap<>();
        if (name != null) {
            detail.put("name", d.name() + " → " + name);
        }
        if (tier != null) {
            detail.put("tier", d.tier() + " → " + tier);
        }
        server.audit.log(actor(s), "tree.change", id, detail, "ok");
        Http.json(ex, 200, list(s).stream().filter(m -> id.equals(m.get("id"))).findFirst().orElseThrow());
    }

    private void remove(HttpExchange ex, Sessions.Session s, String id) throws IOException {
        DirectoryConfig d = known(id);
        if (id.equals(s.principal.directoryId())) {
            throw new Http.Problem(409, "current-tree", "you are signed in to " + d.name() + "; sign in to another directory to remove it");
        }
        String typed = Http.string(Http.body(ex), "name", true);
        if (!typed.equals(d.name())) {
            throw new Http.Problem(409, "confirm-name", "type the directory's name, " + d.name() + ", to remove it");
        }
        try {
            server.config.update(server.config.version(), s.principal.dn(), "remove tree " + id, doc -> {
                Map<String, Object> all = new LinkedHashMap<>(Json.asMap(doc.get("directories")));
                all.remove(id);
                doc.put("directories", all);
            });
        } catch (ConfigStore.Conflict c) {
            throw new Http.Problem(409, "version-conflict", c.getMessage());
        }
        int ended = server.sessions.removeDirectory(id);
        server.agents.removeDirectory(id);
        int dropped = 0;
        for (TrustStore.Entry e : server.trust.entries()) {
            if (e.scope().equals("directory:" + id) && server.trust.remove(e.key())) {
                dropped++;
            }
        }
        server.audit.log(actor(s), "tree.remove", id, Map.of("name", d.name(), "directory", d.host() + ":" + d.port(), "sessionsEnded", ended,
            "certificatesDropped", dropped), "ok");
        Http.json(ex, 204, Map.of());
    }

    private DirectoryConfig known(String id) {
        DirectoryConfig d = DirectoryConfig.find(server.config.read(), id);
        if (d == null) {
            throw new Http.Problem(404, "unknown-directory", "no directory " + id);
        }
        return d;
    }
}
