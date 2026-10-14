package com.pointblue.console.server.http;

import com.pointblue.console.server.audit.AuditLog;
import com.pointblue.console.server.auth.DirectoryConfig;
import com.pointblue.console.server.auth.Role;
import com.pointblue.console.server.auth.Sessions;
import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.console.server.ldap.Names;
import com.pointblue.dirxml.dev.deploy.Environments;
import com.pointblue.dirxml.dev.deploy.Vault;
import com.pointblue.dirxml.dev.json.Json;
import com.pointblue.dirxml.dev.operate.Operate;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;

/**
 * Identity Manager (Phase 4), on the signed-in person's own engine connection through DirXMLDev's
 * {@code Operate}: the same operations the {@code idm} CLI performs, verified on its labs. Any console
 * role reads; {@code operator} acts. On a production directory {@code Operate} also wants the
 * directory's name typed ({@code X-Confirm-Directory}).
 *
 * <pre>
 * GET  /api/v2/trees/{tree}/idm                                 engine status
 * GET  /api/v2/trees/{tree}/idm/driversets                      driver sets
 * GET  /api/v2/trees/{tree}/idm/driversets/{guid}               its drivers: state, start option, cache, trace
 * GET  /api/v2/trees/{tree}/idm/driversets/{guid}/activation | servers | jobs | log-level
 * GET  /api/v2/trees/{tree}/idm/drivers/{guid}                  status
 * POST /api/v2/trees/{tree}/idm/drivers/{guid}/start | stop | restart
 * PUT  /api/v2/trees/{tree}/idm/drivers/{guid}/start-option     {"option": "auto|manual|disabled"}
 * GET  /api/v2/trees/{tree}/idm/drivers/{guid}/jobs | health | log-level | password-sync
 * GET  /api/v2/trees/{tree}/idm/drivers/{guid}/associations     ?state=&limit=
 * GET  /api/v2/trees/{tree}/idm/drivers/{guid}/cache            ?count=
 * POST /api/v2/trees/{tree}/idm/drivers/{guid}/cache/clear | resync {"since"}
 * PUT  /api/v2/trees/{tree}/idm/drivers/{guid}/log-level        {"level", "events"}
 * GET  /api/v2/trees/{tree}/idm/{drivers|driversets}/{guid}/passwords
 * POST /api/v2/trees/{tree}/idm/{drivers|driversets}/{guid}/passwords   {"kind", "name", "displayName", "value"}
 * DELETE same                                                            {"kind", "name"}
 * POST /api/v2/trees/{tree}/idm/jobs/{guid}/start | abort
 * GET, POST, PATCH, DELETE /api/v2/trees/{tree}/idm/objects/{guid}/associations   the object inspector (see Associations)
 * GET, PUT /api/v2/trees/{tree}/idm/{drivers|driversets}/{guid}/trace                trace settings (see Trace)
 * GET, PATCH /api/v2/trees/{tree}/idm/jobs/{guid}/definition; DELETE …/jobs/{guid}  a job's definition (see Jobs)
 * /api/v2/trees/{tree}/idm/mapping-tables[/{guid}]                                    mapping tables (see MappingTables)
 * </pre>
 */
final class Idm {

    private static final int WAIT_SECONDS = 30;
    private static final List<String> KINDS = List.of("named", "remote-loader", "key", "keystore");

    private final Server server;
    private final Associations associations;
    private final Trace trace;
    private final Jobs jobs;
    private final MappingTables mappingTables;

    Idm(Server server) {
        this.server = server;
        this.associations = new Associations(server);
        this.trace = new Trace(server);
        this.jobs = new Jobs(server);
        this.mappingTables = new MappingTables(server);
    }

    private record Target(String dn, String name, String driverSetDn, boolean isDriverSet) {
    }

    void handle(HttpExchange ex, String path, String method) throws IOException {
        String[] p = path.substring("/api/v2/trees/".length()).split("/", -1);
        boolean write = !method.equals("GET");
        Sessions.Session s = server.session(ex, write ? Role.OPERATOR : null);
        if (s.principal.roles().isEmpty()) {
            throw new Http.Problem(403, "forbidden", "you have no Directory Console role");
        }
        if (!p[0].equals(s.principal.directoryId())) {
            throw new Http.Problem(404, "unknown-tree", "you are signed in to " + s.principal.directoryId() + ", not " + p[0]);
        }
        String route = method + " " + String.join("/", java.util.Arrays.copyOfRange(p, 2, p.length))
            .replaceAll("^(driversets|drivers|jobs|objects)/[0-9a-f]{32}", "$1/{guid}");
        String guid = p.length > 3 ? p[3] : null;
        if (route.equals("GET ")) {
            status(ex, s);
            return;
        }
        // the object inspector works over LDAP alone: no engine connection, and the same on every server
        if (route.endsWith(" objects/{guid}/associations")) {
            associations.handle(ex, s, method, guid);
            return;
        }
        // trace settings are attributes of the driver or driver set: LDAP alone, too
        // mapping tables are resource objects: LDAP alone
        if (p.length > 2 && p[2].equals("mapping-tables")) {
            mappingTables.handle(ex, s, method, p.length > 3 && !p[3].isEmpty() ? p[3] : null);
            return;
        }
        // a job's definition, servers and scope are attributes of the job object; running it stays with the engine
        if (route.matches("(GET|PATCH) jobs/\\{guid}/definition") || route.equals("DELETE jobs/{guid}")) {
            jobs.handle(ex, s, method, guid, route.endsWith("/definition"));
            return;
        }
        if (route.matches("(GET|PUT) (drivers|driversets)/\\{guid}/trace")) {
            trace.handle(ex, s, method, guid, route.contains("driversets/"));
            return;
        }
        String onServer = Http.query(ex).get("server");
        if ("all".equals(onServer)) {
            compare(ex, s, route, guid);
            return;
        }
        Server.On on;
        try {
            on = s.ldap() == null ? null : server.on(s, onServer);
        } catch (javax.naming.NamingException e) {
            throw new Http.Problem(503, "unavailable", "the server could not be reached: " + e.getMessage());
        }
        Ldap l = on == null ? null : on.ldap();
        Operate.Engine engine = on == null ? null : on.engine();
        if (engine == null || l == null) {
            throw new Http.Problem(503, "idm-unavailable", "Identity Manager operations are unavailable: " + (on == null ? s.engineProblem : on.engineProblem()));
        }
        DirectoryConfig d = server.directoryOf(s);
        String confirm = ex.getRequestHeaders().getFirst("X-Confirm-Directory");
        synchronized (l) {   // the person's JNDI context is shared with the engine's reads
            try {
                if (write && guid != null) {
                    // a scoped operator grant reaches only drivers, driver sets and jobs under its containers
                    String dn = server.objects.dnOf(l, guid);
                    if (!s.principal.may(Role.OPERATOR, dn)) {
                        throw new Http.Problem(403, "out-of-scope", "your operator role does not reach " + dn);
                    }
                }
                switch (route) {
                    case "GET driversets" -> driverSets(ex, l);
                    case "GET driversets/{guid}" -> {
                        Target t = target(l, guid, true);
                        Map<String, Object> out = new LinkedHashMap<>(identity(t, guid));
                        out.put("drivers", withGuids(l, t.dn(), Json.parse(Operate.driversetStatus(engine, env(d, t)).json())));
                        Http.json(ex, 200, out);
                    }
                    case "GET driversets/{guid}/activation" -> result(ex, Operate.driversetActivation(engine, env(d, target(l, guid, true))));
                    case "GET driversets/{guid}/servers" -> result(ex, Operate.driversetServers(engine, env(d, target(l, guid, true))));
                    case "GET drivers/{guid}/servers" -> Http.json(ex, 200, runningServers(s, l, engine, d, target(l, guid, false)));
                    // the same choices for a driver set: every driver operation runs on one of these servers
                    case "GET driversets/{guid}/server-choices" -> Http.json(ex, 200, runningServers(s, l, engine, d, target(l, guid, true)));
                    case "GET driversets/{guid}/jobs" -> result(ex, Operate.jobList(engine, env(d, target(l, guid, true)), null));
                    case "GET driversets/{guid}/log-level" -> result(ex, Operate.logLevelShow(engine, env(d, target(l, guid, true)), null));
                    case "GET drivers/{guid}" -> {
                        Target t = target(l, guid, false);
                        Map<String, Object> out = new LinkedHashMap<>(identity(t, guid));
                        out.putAll(Json.asMap(parse(Operate.driverStatus(engine, env(d, t), t.name(), tree(d)))));
                        out.put("servedBy", Map.of("dn", on.serverDn()));
                        Http.json(ex, 200, out);
                    }
                    case "POST drivers/{guid}/start", "POST drivers/{guid}/stop", "POST drivers/{guid}/restart" -> {
                        Target t = target(l, guid, false);
                        String action = p[4];
                        if (!action.equals("stop")) {
                            // the engine does not start a disabled driver: say why rather than report its failure
                            Object option = Json.asMap(parse(Operate.driverStatus(engine, env(d, t), t.name(), tree(d)))).get("startOption");
                            if (String.valueOf(option).toLowerCase(java.util.Locale.ROOT).contains("disabled")) {
                                throw new Http.Problem(409, "driver-disabled", t.name() + " is disabled and cannot start; set its start option to Automatic or Manual first");
                            }
                        }
                        acted(ex, s, "idm.driver." + action, guid, t, Operate.lifecycle(engine, env(d, t), t.name(), action, WAIT_SECONDS, true, confirm, tree(d)));
                    }
                    case "PUT drivers/{guid}/start-option" -> {
                        Target t = target(l, guid, false);
                        String option = Http.string(Http.body(ex), "option", true);
                        acted(ex, s, "idm.driver.start-option", guid, t, Operate.startOption(engine, env(d, t), t.name(), option, true, confirm, tree(d)));
                    }
                    case "GET drivers/{guid}/jobs" -> {
                        Target t = target(l, guid, false);
                        result(ex, Operate.jobList(engine, env(d, t), t.name()));
                    }
                    case "GET drivers/{guid}/health" -> {
                        Target t = target(l, guid, false);
                        result(ex, Operate.driverHealth(engine, env(d, t), t.name()));
                    }
                    case "GET drivers/{guid}/log-level" -> {
                        Target t = target(l, guid, false);
                        result(ex, Operate.logLevelShow(engine, env(d, t), t.name()));
                    }
                    case "PUT drivers/{guid}/log-level" -> {
                        Target t = target(l, guid, false);
                        Map<String, Object> b = Http.body(ex);
                        Integer level = b.get("level") == null ? null : Http.integer(b, "level", 0);
                        int[] events = null;
                        if (b.get("events") instanceof List<?> ev) {
                            events = ev.stream().mapToInt(x -> ((Number) x).intValue()).toArray();
                        }
                        acted(ex, s, "idm.driver.log-level", guid, t, Operate.logLevelSet(engine, env(d, t), t.name(), level, events, null, null, true, confirm, tree(d)));
                    }
                    case "GET drivers/{guid}/password-sync" -> {
                        Target t = target(l, guid, false);
                        result(ex, Operate.passwordSync(engine, env(d, t), t.name()));
                    }
                    case "GET drivers/{guid}/associations" -> {
                        Target t = target(l, guid, false);
                        Map<String, String> q = Http.query(ex);
                        int limit = Math.min(1000, Math.max(1, Integer.parseInt(q.getOrDefault("limit", "200"))));
                        result(ex, Operate.driverAssociations(engine, env(d, t), t.name(), q.get("state"), null, limit));
                    }
                    case "GET drivers/{guid}/cache" -> {
                        Target t = target(l, guid, false);
                        int count = Math.min(500, Math.max(1, Integer.parseInt(Http.query(ex).getOrDefault("count", "50"))));
                        Operate.CachePage page;
                        try {
                            page = engine.viewCache(t.dn(), 0, count);
                        } catch (Vault.VaultException e) {
                            // ig4 (IDM 4.8.7) answers "Other" for a running driver; IDC documents the cache as readable only when stopped
                            throw new Http.Problem(409, "cache-unreadable", "the engine would not show this driver's cache (" + e.getMessage()
                                + "); stop the driver to read it");
                        }
                        Http.json(ex, 200, Map.of("empty", page.empty, "xds", page.xds, "next", page.nextToken));
                    }
                    case "POST drivers/{guid}/cache/clear" -> {
                        Target t = target(l, guid, false);
                        acted(ex, s, "idm.driver.cache-clear", guid, t, Operate.cacheClear(engine, env(d, t), t.name(), true, confirm, tree(d)));
                    }
                    case "POST drivers/{guid}/resync" -> {
                        Target t = target(l, guid, false);
                        Map<String, Object> b = Http.body(ex);
                        Long since = b.get("since") == null ? null : java.time.Instant.parse(Http.string(b, "since", true)).toEpochMilli();
                        acted(ex, s, "idm.driver.resync", guid, t, Operate.resync(engine, env(d, t), t.name(), since, true, confirm, tree(d)));
                    }
                    case "GET drivers/{guid}/passwords", "GET driversets/{guid}/passwords" -> {
                        Target t = target(l, guid, p[2].equals("driversets"));
                        Http.json(ex, 200, Map.of("named", engine.namedPasswords(t.dn())));
                    }
                    case "POST drivers/{guid}/passwords", "POST driversets/{guid}/passwords" -> setPassword(ex, s, d, engine, target(l, guid, p[2].equals("driversets")), guid, confirm);
                    case "DELETE drivers/{guid}/passwords", "DELETE driversets/{guid}/passwords" -> removePassword(ex, s, d, engine, target(l, guid, p[2].equals("driversets")), guid, confirm);
                    case "POST jobs/{guid}/start", "POST jobs/{guid}/abort" -> {
                        Ldap.Entry job = server.objects.byGuid(l, guid, "objectClass", "cn");
                        String parent = Names.parent(job.dn());
                        Ldap.Entry up = l.read(parent, "objectClass");
                        boolean underDriver = up != null && hasClass(up, "DirXML-Driver");
                        String setDn = underDriver ? Names.parent(parent) : parent;
                        String driver = underDriver ? String.valueOf(Names.leaf(parent).getValue()) : null;
                        Target t = new Target(job.dn(), String.valueOf(Names.leaf(job.dn()).getValue()), setDn, false);
                        acted(ex, s, "idm.job." + p[4], guid, t, Operate.jobAction(engine, env(d, t), t.name(), driver, p[4], true, confirm, tree(d)));
                    }
                    default -> throw new Http.Problem(404, "not-found", method + " " + path);
                }
            } catch (Vault.VaultException | UnsupportedOperationException e) {
                throw new Http.Problem(502, "engine-error", String.valueOf(e.getMessage()));
            } catch (NamingException e) {
                throw new Http.Problem(502, "directory-error", Ldap.Failure.of(e).getMessage());
            }
        }
    }

    /**
     * A driver's (or driver set's) per-replica values on every server that runs its driver set: the
     * driver's state and start option, or the named passwords. A server not signed in to yet, or
     * without an engine connection, is reported as such. (On ig4 the engine of a server that does not
     * run the driver set answers "Protocol Error".)
     */
    private void compare(HttpExchange ex, Sessions.Session s, String route, String guid) throws IOException {
        boolean passwords = route.equals("GET drivers/{guid}/passwords") || route.equals("GET driversets/{guid}/passwords");
        if (!passwords && !route.equals("GET drivers/{guid}")) {
            throw new Http.Problem(400, "bad-request", "server=all compares a driver's status or named passwords; change one server at a time");
        }
        DirectoryConfig d = server.directoryOf(s);
        List<Map<String, Object>> results = new ArrayList<>();
        String dn;
        List<Map<String, Object>> running;
        if (s.engine == null) {
            throw new Http.Problem(503, "idm-unavailable", "Identity Manager operations are unavailable: " + s.engineProblem);
        }
        try {
            synchronized (s.ldap()) {
                Target own = target(s.ldap(), guid, route.startsWith("GET driversets"));
                dn = own.dn();
                running = runningServers(s, s.ldap(), s.engine, d, own);
            }
        } catch (javax.naming.NamingException e) {
            throw new Http.Problem(502, "directory-error", Ldap.Failure.of(e).getMessage());
        }
        for (Map<String, Object> h : running) {
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("server", Map.of("guid", h.get("guid"), "dn", h.get("dn"), "name", String.valueOf(h.get("name"))));
            try {
                Server.On on = server.on(s, (String) h.get("guid"));
                if (on.engine() == null) {
                    r.put("status", "idm-unavailable");
                    r.put("detail", on.engineProblem());
                } else {
                    synchronized (on.ldap()) {
                        Target t = target(on.ldap(), guid, route.startsWith("GET driversets"));
                        if (passwords) {
                            r.put("named", on.engine().namedPasswords(t.dn()));
                        } else {
                            Map<String, Object> st = Json.asMap(parse(Operate.driverStatus(on.engine(), env(d, t), t.name(), tree(d))));
                            for (String k : new String[] {"state", "startOption", "cacheSize", "unprocessedSize"}) {
                                r.put(k, st.get(k));
                            }
                        }
                    }
                    r.put("status", "ok");
                }
            } catch (Http.Problem p) {
                r.put("status", p.type);
                r.put("detail", p.getMessage());
            } catch (Exception e) {
                r.put("status", "failed");
                r.put("detail", e.getMessage());
            }
            results.add(r);
        }
        Http.json(ex, 200, Map.of("dn", dn, "servers", results));
    }

    private void status(HttpExchange ex, Sessions.Session s) throws IOException {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("available", s.engine != null);
        if (s.engine == null) {
            out.put("problem", s.engineProblem);
        } else {
            synchronized (s.ldap()) {
                try {
                    out.put("engineVersion", Json.asMap(Json.parse(Operate.engineVersion(s.engine).json())).get("version"));
                } catch (RuntimeException | LinkageError e) {
                    out.put("engineVersion", null);
                    out.put("problem", "the engine did not answer: " + e.getMessage());
                }
            }
        }
        Http.json(ex, 200, out);
    }

    private void driverSets(HttpExchange ex, Ldap l) throws IOException, NamingException {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Ldap.Entry e : l.search("", "(objectClass=DirXML-DriverSet)", null, SearchControls.SUBTREE_SCOPE, new String[] {"GUID", "cn"}, 200)) {
            Map<String, Object> m = new LinkedHashMap<>();
            List<Object> g = e.attributes().get("guid");
            m.put("guid", g == null || g.isEmpty() ? null : Names.guidHex(g.get(0)));
            m.putAll(Names.identity(e.dn()));
            out.add(m);
        }
        out.sort((a, b) -> String.valueOf(a.get("name")).compareToIgnoreCase(String.valueOf(b.get("name"))));
        Http.json(ex, 200, Map.of("items", out));
    }

    /** The driver set or driver with this GUID; 404 when it is something else. */
    /** The servers that run {@code t}'s driver set (its Identity Manager servers), each with its GUID: per-replica driver values live there. */
    private List<Map<String, Object>> runningServers(Sessions.Session s, Ldap l, Operate.Engine engine, DirectoryConfig d, Target t) throws NamingException {
        Target set = new Target(t.driverSetDn(), String.valueOf(Names.leaf(t.driverSetDn()).getValue()), t.driverSetDn(), true);
        Object parsed = parse(Operate.driversetServers(engine, env(d, set)));
        List<Map<String, Object>> out = new ArrayList<>();
        String own = s.ldap().dsaName();
        Object list = parsed instanceof Map<?, ?> m ? m.get("servers") : null;
        if (list instanceof List<?> dns) {
            for (Object dn : dns) {
                Ldap.Entry e = l.read(String.valueOf(dn), "GUID", "cn");
                if (e == null || e.attributes().get("guid") == null) {
                    continue;
                }
                String g = Names.guidHex(e.attributes().get("guid").get(0));
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("guid", g);
                r.put("dn", e.dn());
                r.put("name", e.first("cn"));
                r.put("connected", Names.same(e.dn(), own));
                r.put("signedIn", Names.same(e.dn(), own) || s.servers.containsKey(g) || "oidc".equals(s.principal.via()));
                out.add(r);
            }
        }
        return out;
    }

    private Target target(Ldap l, String guid, boolean driverSet) throws NamingException {
        Ldap.Entry e = server.objects.byGuid(l, guid, "objectClass", "cn");
        String cls = driverSet ? "DirXML-DriverSet" : "DirXML-Driver";
        if (!hasClass(e, cls)) {
            throw new Http.Problem(404, "not-a-" + (driverSet ? "driver-set" : "driver"), guid + " is not a " + cls);
        }
        String name = String.valueOf(Names.leaf(e.dn()).getValue());
        return new Target(e.dn(), name, driverSet ? e.dn() : Names.parent(e.dn()), driverSet);
    }

    private static boolean hasClass(Ldap.Entry e, String cls) {
        return e.attributes().getOrDefault("objectclass", List.of()).stream().anyMatch(c -> String.valueOf(c).equalsIgnoreCase(cls));
    }

    private static Map<String, Object> identity(Target t, String guid) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("guid", guid);
        m.putAll(Names.identity(t.dn()));
        m.put("driverSetDn", t.driverSetDn());
        return m;
    }

    /** Operate's environment: the directory's name (what a production confirmation types), the driver set, the tier. */
    private static Environments.Environment env(DirectoryConfig d, Target t) {
        String tier = d == null ? "production" : d.tier();
        Environments.Tier tr = switch (tier.toLowerCase(Locale.ROOT)) {
            case "lab", "dev", "development", "test" -> Environments.Tier.DEV;
            case "staging", "stg", "qa" -> Environments.Tier.STG;
            default -> Environments.Tier.PRD;
        };
        return Environments.Environment.forService(d == null ? "directory" : d.name(), t.driverSetDn(), tr);
    }

    /** Where Operate keeps its deploy log and cache snapshots for this directory: the console's data volume. */
    private Path tree(DirectoryConfig d) throws IOException {
        Path p = server.data.root().resolve("idm").resolve(d == null ? "directory" : d.id());
        Files.createDirectories(p);
        return p;
    }

    private static Object parse(Operate.Result r) {
        return Json.parse(r.json());
    }

    private static void result(HttpExchange ex, Operate.Result r) throws IOException {
        Object body = parse(r);
        if (!r.ok && body instanceof Map<?, ?> m && m.get("refusal") != null) {
            throw new Http.Problem(409, "confirm-directory", String.valueOf(m.get("refusal")));
        }
        Http.json(ex, r.ok ? 200 : 502, body instanceof Map || body instanceof List ? body : Map.of("value", body));
    }

    /** An operation's result, audited; a refusal (typing the directory name) is a 409. */
    private void acted(HttpExchange ex, Sessions.Session s, String action, String guid, Target t, Operate.Result r) throws IOException {
        Object body = parse(r);
        boolean refused = !r.ok && body instanceof Map<?, ?> m && m.get("refusal") != null;
        server.audit.log(new AuditLog.Actor(s.principal.subject(), s.principal.dn(), s.principal.via()), action, guid,
            Map.of("dn", t.dn(), "directory", s.principal.directoryId()), refused ? "refused" : r.ok ? "ok" : "failed");
        if (refused) {
            throw new Http.Problem(409, "confirm-directory", String.valueOf(((Map<?, ?>) body).get("refusal")));
        }
        Http.json(ex, r.ok ? 200 : 502, body instanceof Map || body instanceof List ? body : Map.of("value", body));
    }

    private static List<Object> withGuids(Ldap l, String driverSetDn, Object drivers) throws NamingException {
        Map<String, String> guids = new LinkedHashMap<>();
        for (Ldap.Entry e : l.search(driverSetDn, "(objectClass=DirXML-Driver)", null, SearchControls.ONELEVEL_SCOPE, new String[] {"GUID"}, 1000)) {
            List<Object> g = e.attributes().get("guid");
            if (g != null && !g.isEmpty()) {
                guids.put(Names.canonical(e.dn()), Names.guidHex(g.get(0)));
            }
        }
        List<Object> out = new ArrayList<>();
        if (drivers instanceof List<?> list) {
            for (Object o : list) {
                Map<String, Object> m = new LinkedHashMap<>(Json.asMap(o));
                m.put("guid", guids.get(Names.canonical(String.valueOf(m.get("dn")))));
                out.add(m);
            }
        }
        return out;
    }

    /** Production directories want their name typed for secret changes, as Operate wants it for other writes. */
    private static void confirmed(DirectoryConfig d, String confirm) {
        if (d != null && d.production() && !d.name().equals(confirm)) {
            throw new Http.Problem(409, "confirm-directory", "'" + d.name() + "' is a production directory: type its name to confirm");
        }
    }

    /** {@code {"kind", "name", "displayName", "value"}}. Values are never read back or logged. */
    private void setPassword(HttpExchange ex, Sessions.Session s, DirectoryConfig d, Operate.Engine engine, Target t, String guid, String confirm) throws IOException {
        Map<String, Object> b = Http.body(ex);
        String kind = kind(b);
        char[] value = Http.string(b, "value", true).toCharArray();
        confirmed(d, confirm);
        String name = Http.string(b, "name", kind.equals("named"));
        try {
            switch (kind) {
                case "named" -> engine.setNamedPassword(t.dn(), name, b.get("displayName") == null ? name : Http.string(b, "displayName", true), value);
                case "remote-loader" -> engine.setRemoteLoaderPassword(t.dn(), value);
                case "key" -> engine.setMutualAuthKeyPassword(t.dn(), value);
                default -> engine.setMutualAuthKeystorePassword(t.dn(), value);
            }
        } finally {
            java.util.Arrays.fill(value, '\0');
        }
        server.audit.log(new AuditLog.Actor(s.principal.subject(), s.principal.dn(), s.principal.via()), "idm.password.set", guid,
            Map.of("dn", t.dn(), "kind", kind, "name", name == null ? "" : name), "ok");
        Http.json(ex, 204, Map.of());
    }

    private void removePassword(HttpExchange ex, Sessions.Session s, DirectoryConfig d, Operate.Engine engine, Target t, String guid, String confirm) throws IOException {
        Map<String, Object> b = Http.body(ex);
        String kind = kind(b);
        confirmed(d, confirm);
        String name = Http.string(b, "name", kind.equals("named"));
        switch (kind) {
            case "named" -> engine.removeNamedPassword(t.dn(), name);
            case "remote-loader" -> engine.clearRemoteLoaderPassword(t.dn());
            case "key" -> engine.clearMutualAuthKeyPassword(t.dn());
            default -> engine.clearMutualAuthKeystorePassword(t.dn());
        }
        server.audit.log(new AuditLog.Actor(s.principal.subject(), s.principal.dn(), s.principal.via()), "idm.password.remove", guid,
            Map.of("dn", t.dn(), "kind", kind, "name", name == null ? "" : name), "ok");
        Http.json(ex, 204, Map.of());
    }

    private static String kind(Map<String, Object> b) {
        String kind = b.get("kind") == null ? "named" : Http.string(b, "kind", true);
        if (!KINDS.contains(kind)) {
            throw new Http.Problem(400, "bad-field", "kind is one of " + KINDS);
        }
        return kind;
    }
}
