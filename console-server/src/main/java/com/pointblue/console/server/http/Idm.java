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
 * Identity Manager, on the signed-in person's own engine connection through DirXMLDev's
 * {@code Operate}: the same operations the {@code idm} CLI performs, verified on its labs. Any console
 * role reads; {@code operator} acts. On a production directory {@code Operate} also wants the
 * directory's name typed ({@code X-Confirm-Directory}).
 *
 * <pre>
 * GET  /api/v2/trees/{tree}/idm                                 engine status
 * GET  /api/v2/trees/{tree}/idm/driversets                      driver sets
 * GET  /api/v2/trees/{tree}/idm/driversets/{guid}               its drivers: state, start option, cache, trace
 * GET  /api/v2/trees/{tree}/idm/driversets/{guid}/activation | servers | jobs | log-level | versions | statistics
 * GET  /api/v2/trees/{tree}/idm/drivers/{guid}                  status
 * POST /api/v2/trees/{tree}/idm/drivers/{guid}/start | stop | restart
 * PUT  /api/v2/trees/{tree}/idm/drivers/{guid}/start-option     {"option": "auto|manual|disabled"}
 * GET  /api/v2/trees/{tree}/idm/drivers/{guid}/jobs | health | log-level | password-sync
 * GET  /api/v2/trees/{tree}/idm/drivers/{guid}/associations     ?state=&limit=
 * GET  /api/v2/trees/{tree}/idm/drivers/{guid}/cache            ?count=
 * GET  /api/v2/trees/{tree}/idm/drivers/{guid}/cache/summary | cache/events ?position=&count=   (see Cache)
 * POST /api/v2/trees/{tree}/idm/drivers/{guid}/cache/delete     {"events": [{"position", "eventId"}]}
 * POST /api/v2/trees/{tree}/idm/drivers/{guid}/cache/clear | resync {"since"}
 * POST /api/v2/trees/{tree}/idm/drivers/{guid}/migrate/to-app     {"base", "class", "filter"?, "max"?, "dryRun"?}
 * POST /api/v2/trees/{tree}/idm/drivers/{guid}/migrate/from-app   {"class", "search"?: [{"attribute", "value"}]}
 * PUT  /api/v2/trees/{tree}/idm/drivers/{guid}/log-level        {"level", "events"}
 * GET  /api/v2/trees/{tree}/idm/{drivers|driversets}/{guid}/passwords
 * POST /api/v2/trees/{tree}/idm/{drivers|driversets}/{guid}/passwords   {"kind", "name", "displayName", "value"}
 * DELETE same                                                            {"kind", "name"}
 * POST /api/v2/trees/{tree}/idm/jobs/{guid}/start | abort
 * GET, POST, DELETE /api/v2/trees/{tree}/idm/jobs/{guid}/passwords      a job's named passwords: {"name", "displayName"?, "value"}, {"name"}
 * GET, POST, PATCH, DELETE /api/v2/trees/{tree}/idm/objects/{guid}/associations   the object inspector (see Associations)
 * GET, PUT /api/v2/trees/{tree}/idm/{drivers|driversets}/{guid}/trace                trace settings (see Trace)
 * GET, PATCH /api/v2/trees/{tree}/idm/jobs/{guid}/definition; DELETE …/jobs/{guid}  a job's definition (see Jobs)
 * GET  /api/v2/trees/{tree}/idm/{drivers|driversets}/{guid}/job-types   the job types the chosen server's engine offers (see JobTypes)
 * POST /api/v2/trees/{tree}/idm/{drivers|driversets}/{guid}/jobs        a new job of one of those types (see Jobs)
 * /api/v2/trees/{tree}/idm/mapping-tables[/{guid}]                                    mapping tables (see MappingTables)
 * GET /api/v2/trees/{tree}/idm/{drivers|driversets}/{guid}/properties                a driver's or driver set's properties, read-only (see DriverProperties)
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
    private final DriverProperties driverProperties;

    Idm(Server server) {
        this.server = server;
        this.associations = new Associations(server);
        this.trace = new Trace(server);
        this.jobs = new Jobs(server);
        this.mappingTables = new MappingTables(server);
        this.driverProperties = new DriverProperties(server);
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
        // a driver's properties, read-only: LDAP alone
        if (route.equals("GET drivers/{guid}/properties") || route.equals("GET driversets/{guid}/properties")) {
            driverProperties.handle(ex, s, guid, route.contains("driversets/"));
            return;
        }
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
                    // the driver set's statistics on the chosen server: the engine's JVM, and each driver's cache and counters
                    case "GET driversets/{guid}/statistics" -> {
                        Target t = target(l, guid, true);
                        Map<String, Object> out = new LinkedHashMap<>();
                        out.put("server", Map.of("dn", on.serverDn(), "name", String.valueOf(Names.identity(on.serverDn()).get("name"))));
                        try {
                            out.put("jvm", Json.asMap(Json.parse(Operate.engineStats(engine, env(d, t), List.of()).json())).get("jvm"));
                        } catch (RuntimeException | LinkageError e) {
                            out.put("jvm", null);
                        }
                        List<Map<String, Object>> drivers = new ArrayList<>();
                        for (Ldap.Entry e : l.search(t.dn(), "(objectClass=DirXML-Driver)", null, SearchControls.ONELEVEL_SCOPE, new String[] {"GUID"}, 500)) {
                            Map<String, Object> m = new LinkedHashMap<>();
                            List<Object> g = e.attributes().get("guid");
                            m.put("guid", g == null || g.isEmpty() ? null : Names.guidHex(g.get(0)));
                            m.put("name", String.valueOf(Names.identity(e.dn()).get("name")));
                            try {
                                m.put("state", com.pointblue.dirxml.dev.deploy.Vault.stateName(engine.driverState(e.dn())));
                                m.putAll(Statistics.driver(engine.driverStats(e.dn(), 0)));
                            } catch (RuntimeException x) {
                                m.put("error", x.getMessage());
                            }
                            drivers.add(m);
                        }
                        drivers.sort((a, b) -> String.valueOf(a.get("name")).compareToIgnoreCase(String.valueOf(b.get("name"))));
                        out.put("drivers", drivers);
                        Http.json(ex, 200, out);
                    }
                    // version discovery on the chosen server: the engine now, and what its statistics job last collected there
                    case "GET driversets/{guid}/versions" -> {
                        Target t = target(l, guid, true);
                        Object engineVersion;
                        try {
                            engineVersion = Json.asMap(Json.parse(Operate.engineVersion(engine).json())).get("version");
                        } catch (RuntimeException | LinkageError e) {
                            engineVersion = null;
                        }
                        Map<String, Object> out = new LinkedHashMap<>(Versions.read(l, t.dn(), engineVersion));
                        out.put("server", Map.of("dn", on.serverDn(), "name", String.valueOf(Names.identity(on.serverDn()).get("name"))));
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
                            // IDM 4.8.7 answers "Other" for a running driver; Identity Console documents the cache as readable only when stopped
                            throw new Http.Problem(409, "cache-unreadable", "the engine would not show this driver's cache (" + e.getMessage()
                                + "); stop the driver to read it");
                        }
                        Http.json(ex, 200, Map.of("empty", page.empty, "xds", page.xds, "next", page.nextToken));
                    }
                    // the cache in summary: from the driver statistics, which the engine gives for a running driver too
                    case "GET drivers/{guid}/cache/summary" -> {
                        Target t = target(l, guid, false);
                        Map<String, Object> sum = Cache.summary(engine.driverStats(t.dn(), 0));
                        Http.json(ex, 200, sum == null ? Map.of() : sum);
                    }
                    // the cached events, each with its position (a stopped driver only)
                    case "GET drivers/{guid}/cache/events" -> {
                        Target t = target(l, guid, false);
                        Map<String, String> q = Http.query(ex);
                        int position = Math.max(0, parseInt(q.get("position"), 0));
                        int count = Math.max(1, Math.min(parseInt(q.get("count"), 25), 100));
                        try {
                            Http.json(ex, 200, Cache.events(engine, t.dn(), position, count));
                        } catch (Vault.VaultException e) {
                            throw new Http.Problem(409, "cache-unreadable", "the engine would not show this driver's cache (" + e.getMessage()
                                + "); stop the driver to read it");
                        }
                    }
                    // delete chosen events: each must still be the event read at its position
                    case "POST drivers/{guid}/cache/delete" -> deleteEvents(ex, s, engine, d, target(l, guid, false), guid, confirm);
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
                    // vault objects to the application: a preview (dryRun) lists them; then each is sent, with its outcome
                    case "POST drivers/{guid}/migrate/to-app" -> {
                        Target t = target(l, guid, false);
                        Map<String, Object> b = Http.body(ex);
                        String base = server.objects.dnOf(l, Http.string(b, "base", true));
                        String cls = Http.string(b, "class", true);
                        String filter = b.get("filter") == null || String.valueOf(b.get("filter")).isBlank()
                            ? "(objectClass=" + cls + ")" : Http.string(b, "filter", true).trim();
                        if (!filter.startsWith("(") || !filter.endsWith(")")) {
                            throw new Http.Problem(400, "bad-filter", "the filter is one parenthesized LDAP filter, such as (sn=Smith)");
                        }
                        if (!filter.toLowerCase(Locale.ROOT).contains("objectclass")) {
                            filter = "(&(objectClass=" + cls + ")" + filter + ")";
                        }
                        int max = Math.max(1, Math.min(Http.integer(b, "max", 100), 1000));
                        boolean dry = Boolean.TRUE.equals(b.get("dryRun"));
                        Operate.Result r = Operate.migrateIntoApp(engine, env(d, t), t.name(), base, filter, cls, max, dry, true, confirm, tree(d));
                        if (dry) {
                            result(ex, r);
                        } else {
                            // objects the driver refused are part of the outcome, not a failure of the request
                            acted(ex, s, "idm.driver.migrate-to-app", guid, t, r, true);
                        }
                    }
                    // the application's objects into the vault: the engine queries the application (asynchronously)
                    case "POST drivers/{guid}/migrate/from-app" -> {
                        Target t = target(l, guid, false);
                        byte[] query = migrateQuery(server.objects.schema(s.principal.directoryId(), l), Http.body(ex));
                        acted(ex, s, "idm.driver.migrate-from-app", guid, t, Operate.migrate(engine, env(d, t), t.name(), query, true, confirm, tree(d)));
                    }
                    case "GET drivers/{guid}/passwords", "GET driversets/{guid}/passwords" -> {
                        Target t = target(l, guid, p[2].equals("driversets"));
                        Http.json(ex, 200, Map.of("named", engine.namedPasswords(t.dn())));
                    }
                    case "POST drivers/{guid}/passwords", "POST driversets/{guid}/passwords" -> setPassword(ex, s, d, engine, target(l, guid, p[2].equals("driversets")), guid, confirm, false);
                    case "DELETE drivers/{guid}/passwords", "DELETE driversets/{guid}/passwords" -> removePassword(ex, s, d, engine, target(l, guid, p[2].equals("driversets")), guid, confirm, false);
                    // a job's named passwords (its password-ref parameters name them) are kept on the job object, as a driver's are on the driver
                    case "GET jobs/{guid}/passwords" -> Http.json(ex, 200, Map.of("named", engine.namedPasswords(jobTarget(l, guid).dn())));
                    case "POST jobs/{guid}/passwords" -> setPassword(ex, s, d, engine, jobTarget(l, guid), guid, confirm, true);
                    case "DELETE jobs/{guid}/passwords" -> removePassword(ex, s, d, engine, jobTarget(l, guid), guid, confirm, true);
                    // the job types this server's engine offers for the driver or driver set
                    case "GET drivers/{guid}/job-types", "GET driversets/{guid}/job-types" -> {
                        boolean set = p[2].equals("driversets");
                        Target t = target(l, guid, set);
                        Map<String, Object> out = new LinkedHashMap<>();
                        out.put("server", Map.of("dn", on.serverDn(), "name", String.valueOf(Names.identity(on.serverDn()).get("name"))));
                        out.put("types", JobTypes.types(server.login.engines().discoverJobs(l, t.dn()), set ? "DirXML-DriverSet" : "DirXML-Driver"));
                        Http.json(ex, 200, out);
                    }
                    // a new job, from the type as this server's engine offers it (the job object itself is written over LDAP)
                    case "POST drivers/{guid}/jobs", "POST driversets/{guid}/jobs" -> {
                        boolean set = p[2].equals("driversets");
                        Target t = target(l, guid, set);
                        Map<String, Object> b = Http.body(ex);
                        String type = Http.string(b, "type", true);
                        String cls = set ? "DirXML-DriverSet" : "DirXML-Driver";
                        byte[] answer = server.login.engines().discoverJobs(l, t.dn());
                        org.w3c.dom.Element agg = JobTypes.aggregation(answer, type, cls);
                        if (agg == null) {
                            throw new Http.Problem(400, "unknown-job-type", "the engine on this server offers no job type " + type + " for a " + (set ? "driver set" : "driver"));
                        }
                        boolean scopeRequired = JobTypes.types(answer, cls).stream().filter(x -> type.equals(x.get("type"))).anyMatch(x -> Boolean.TRUE.equals(x.get("scopeRequired")));
                        Ldap.Entry owner = l.read(t.dn(), "objectClass");
                        Map<String, Object> made = jobs.create(l, s, owner, agg, scopeRequired, b);
                        made.put("notified", server.login.engines().notifyJob(l, String.valueOf(made.get("dn"))));
                        Http.json(ex, 201, made);
                    }
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
                if (refused(e)) {
                    // the engine decided with the person's rights (their own bind, or acting as them under single sign-on)
                    throw new Http.Problem(403, "insufficient-rights", String.valueOf(e.getMessage()));
                }
                throw new Http.Problem(502, "engine-error", String.valueOf(e.getMessage()));
            } catch (IllegalArgumentException e) {
                throw new Http.Problem(400, "bad-request", e.getMessage());
            } catch (NamingException e) {
                throw new Http.Problem(502, "directory-error", Ldap.Failure.of(e).getMessage());
            }
        }
    }

    /** Whether the engine refused for lack of rights (LDAP 50, eDirectory -672). */
    static boolean refused(Throwable e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof com.novell.ldap.LDAPException l && l.getResultCode() == com.novell.ldap.LDAPException.INSUFFICIENT_ACCESS_RIGHTS) {
                return true;
            }
            if (t.getCause() == t) {
                break;
            }
        }
        return false;
    }

    /**
     * A driver's (or driver set's) per-replica values on every server that runs its driver set: the
     * driver's state and start option, or the named passwords. A server not signed in to yet, or
     * without an engine connection, is reported as such. (On a lab tree the engine of a server that does not
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

    /**
     * The query the engine sends the application to migrate its objects into the vault, in eDirectory's
     * names as XDS has them: {@code {"class": "inetOrgPerson", "search": [{"attribute": "sn", "value": "Smith"}]}}
     * becomes {@code <query class-name="User" scope="subtree"><search-class class-name="User"/>
     * <search-attr attr-name="Surname"><value>Smith</value></search-attr><read-attr/></query>}.
     */
    static byte[] migrateQuery(com.pointblue.console.server.ldap.Schema schema, Map<String, Object> b) {
        String cls = Http.string(b, "class", true);
        com.pointblue.console.server.ldap.Schema.ObjectClass oc = schema.objectClass(cls);
        if (oc == null) {
            throw new Http.Problem(400, "unknown-class", "no object class " + cls);
        }
        String ndsClass = oc.ndsName() != null ? oc.ndsName() : oc.name();
        StringBuilder x = new StringBuilder("<nds dtdversion=\"4.0\"><input><query class-name=\"").append(xmlAttr(ndsClass))
            .append("\" scope=\"subtree\"><search-class class-name=\"").append(xmlAttr(ndsClass)).append("\"/>");
        if (b.get("search") instanceof List<?> search) {
            for (Object o : search) {
                Map<String, Object> m = Json.asMap(o);
                String a = Http.string(m, "attribute", true);
                com.pointblue.console.server.ldap.Schema.AttributeType at = schema.attribute(a);
                if (at == null) {
                    throw new Http.Problem(400, "unknown-attribute", "no attribute " + a);
                }
                String nds = at.ndsName() != null ? at.ndsName() : at.name();
                x.append("<search-attr attr-name=\"").append(xmlAttr(nds)).append("\"><value>")
                    .append(xmlAttr(String.valueOf(m.getOrDefault("value", "")))).append("</value></search-attr>");
            }
        }
        x.append("<read-attr/></query></input></nds>");
        return x.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    private static String xmlAttr(String v) {
        return v.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private static int parseInt(String s, int otherwise) {
        try {
            return s == null ? otherwise : Integer.parseInt(s.trim());
        } catch (NumberFormatException x) {
            return otherwise;
        }
    }

    /**
     * {@code {"events": [{"position", "eventId"}…]}}: from the last to the first, each event is read again
     * at its position and must have that event-id, then that one event is deleted. On production the
     * directory's name is confirmed as for the other driver operations.
     */
    private void deleteEvents(HttpExchange ex, Sessions.Session s, Operate.Engine engine, DirectoryConfig d, Target t, String guid, String confirm)
            throws IOException {
        if (d != null && d.production() && (confirm == null || !confirm.trim().equalsIgnoreCase(d.name()))) {
            throw new Http.Problem(409, "confirm-directory", "this changes the production directory " + d.name() + "; type its name to confirm");
        }
        Map<String, Object> b = Http.body(ex);
        if (!(b.get("events") instanceof List<?> list) || list.isEmpty()) {
            throw new Http.Problem(400, "bad-request", "events is a list of {position, eventId}");
        }
        List<Map<String, Object>> chosen = new ArrayList<>();
        for (Object o : list) {
            Map<String, Object> m = Json.asMap(o);
            if (m.get("eventId") == null || Json.asInt(m.get("position"), -1) < 0) {
                throw new Http.Problem(400, "bad-request", "each event has a position and an eventId");
            }
            chosen.add(m);
        }
        chosen.sort((a, c) -> Integer.compare(Json.asInt(c.get("position"), 0), Json.asInt(a.get("position"), 0)));
        List<Map<String, Object>> results = new ArrayList<>();
        for (Map<String, Object> m : chosen) {
            int position = Json.asInt(m.get("position"), 0);
            String id = String.valueOf(m.get("eventId"));
            Map<String, Object> r = new LinkedHashMap<>(Map.of("position", position, "eventId", id));
            String now;
            try {
                now = Cache.eventIdAt(engine, t.dn(), position);
            } catch (RuntimeException x) {
                r.put("status", "failed");
                r.put("detail", "the cache could not be read: " + x.getMessage());
                results.add(r);
                continue;
            }
            if (!id.equals(now)) {
                r.put("status", "skipped");
                r.put("detail", now == null ? "no event is there any more" : "another event is there now");
                results.add(r);
                continue;
            }
            try {
                engine.deleteCacheEntries(t.dn(), position, 1, "", 0);
                r.put("status", "deleted");
            } catch (RuntimeException x) {
                r.put("status", "failed");
                r.put("detail", x.getMessage());
            }
            results.add(r);
        }
        long deleted = results.stream().filter(r -> "deleted".equals(r.get("status"))).count();
        server.audit.log(new AuditLog.Actor(s.principal.subject(), s.principal.dn(), s.principal.via()), "idm.driver.cache-delete", guid,
            Map.of("dn", t.dn(), "directory", s.principal.directoryId(), "events", results), deleted == results.size() ? "ok" : deleted == 0 ? "failed" : "partial");
        Http.json(ex, 200, Map.of("results", results, "deleted", deleted));
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

    private Target jobTarget(Ldap l, String guid) throws NamingException {
        Ldap.Entry e = server.objects.byGuid(l, guid, "objectClass", "cn");
        if (!hasClass(e, "DirXML-Job")) {
            throw new Http.Problem(404, "not-a-job", guid + " is not a job");
        }
        String parent = Names.parent(e.dn());
        Ldap.Entry up = l.read(parent, "objectClass");
        return new Target(e.dn(), String.valueOf(Names.leaf(e.dn()).getValue()), up != null && hasClass(up, "DirXML-Driver") ? Names.parent(parent) : parent, false);
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
        acted(ex, s, action, guid, t, r, false);
    }

    /** {@code perObject}: a result listing each object's outcome is answered 200 even when some failed. */
    private void acted(HttpExchange ex, Sessions.Session s, String action, String guid, Target t, Operate.Result r, boolean perObject) throws IOException {
        Object body = parse(r);
        boolean refused = !r.ok && body instanceof Map<?, ?> m && m.get("refusal") != null;
        server.audit.log(new AuditLog.Actor(s.principal.subject(), s.principal.dn(), s.principal.via()), action, guid,
            Map.of("dn", t.dn(), "directory", s.principal.directoryId()), refused ? "refused" : r.ok ? "ok" : "failed");
        if (refused) {
            throw new Http.Problem(409, "confirm-directory", String.valueOf(((Map<?, ?>) body).get("refusal")));
        }
        boolean listed = perObject && body instanceof Map<?, ?> bm && bm.get("results") instanceof List;
        Http.json(ex, r.ok || listed ? 200 : 502, body instanceof Map || body instanceof List ? body : Map.of("value", body));
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
    private void setPassword(HttpExchange ex, Sessions.Session s, DirectoryConfig d, Operate.Engine engine, Target t, String guid, String confirm, boolean job)
            throws IOException {
        Map<String, Object> b = Http.body(ex);
        String kind = kind(b, job);
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

    private void removePassword(HttpExchange ex, Sessions.Session s, DirectoryConfig d, Operate.Engine engine, Target t, String guid, String confirm, boolean job)
            throws IOException {
        Map<String, Object> b = Http.body(ex);
        String kind = kind(b, job);
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

    private static String kind(Map<String, Object> b, boolean job) {
        String kind = b.get("kind") == null ? "named" : Http.string(b, "kind", true);
        if (job && !kind.equals("named")) {
            throw new Http.Problem(400, "bad-field", "a job has named passwords only");
        }
        if (!KINDS.contains(kind)) {
            throw new Http.Problem(400, "bad-field", "kind is one of " + KINDS);
        }
        return kind;
    }
}
