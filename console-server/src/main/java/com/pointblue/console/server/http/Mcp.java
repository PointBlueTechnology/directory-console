package com.pointblue.console.server.http;

import com.pointblue.console.server.auth.Role;
import com.pointblue.console.server.auth.Sessions;
import com.pointblue.dirxml.dev.json.Json;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpPrincipal;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The console as an MCP server for agents (docs/MCP.md): JSON-RPC 2.0 over HTTP POST at {@code /mcp}, stateless,
 * the Streamable HTTP transport without a server-sent stream ({@code GET} answers 405, as the specification allows).
 * Each call carries an agent key ({@code Authorization: Bearer dc_…}, see {@link Agents}).
 *
 * <p>Every tool is a call to the console's own API, made in-process with the key's session: the same roles, container
 * scopes, eDirectory rights and refusals as the page. Nothing here decides what an agent may do; the API does. The
 * change tools wait for the person's approval unless the directory turns that off (see {@link AgentChanges}).
 */
final class Mcp {

    static final List<String> PROTOCOLS = List.of("2025-06-18", "2025-03-26", "2024-11-05");
    private static final int MAX_TEXT = 200_000;
    private static final String GUID = "[0-9a-fA-F]{32}";

    private static final String INSTRUCTIONS = String.join("\n",
        "Directory Console: eDirectory and Identity Manager administration, as the person who made this agent key, with their own eDirectory rights.",
        "1. Call whoami first: who you act as, the directory (and whether it is production), and what the key may do.",
        "2. Objects, drivers, driver sets and jobs are named by GUID or by DN. list_driver_sets and driver_set give the drivers' GUIDs.",
        "3. Change tools are listed only when the key may make that kind of change. Say what you are about to change before calling one.",
        "4. A change usually waits for the person's approval in the console: the answer is a pending change with a link. Give the person the link, then call change_status.",
        "5. On a production directory without approval, a change needs confirm = the directory's name, typed by the person in chat. Never fill it in yourself.",
        "6. Never ask for a password or print one; tools never return secrets.");

    private final Server server;
    private final List<Tool> tools = new ArrayList<>();

    Mcp(Server server) {
        this.server = server;
        define();
    }

    // ---- the transport ----

    void handle(HttpExchange ex, String method) throws IOException {
        if (!method.equals("POST")) {
            ex.getResponseHeaders().set("Allow", "POST");
            throw new Http.Problem(405, "method-not-allowed", "POST JSON-RPC to this endpoint; no server-sent stream is offered");
        }
        Agents.Caller caller;
        try {
            caller = server.agents.resolve(ex);
        } catch (Http.Problem p) {
            if (p.status == 401) {
                ex.getResponseHeaders().set("WWW-Authenticate", "Bearer realm=\"Directory Console\", error=\"invalid_token\"");
            }
            throw p;
        }
        byte[] raw;
        try (InputStream in = ex.getRequestBody()) {
            raw = in.readNBytes(Http.MAX_BODY + 1);
        }
        if (raw.length > Http.MAX_BODY) {
            throw new Http.Problem(413, "too-large", "the request body is larger than " + Http.MAX_BODY + " bytes");
        }
        Object parsed;
        try {
            parsed = Json.parse(new String(raw, StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            send(ex, 400, error(null, -32700, "not JSON: " + e.getMessage()));
            return;
        }
        if (parsed instanceof List<?> batch) {
            List<Object> out = new ArrayList<>();
            for (Object o : batch) {
                Object r = message(ex, caller, o);
                if (r != null) {
                    out.add(r);
                }
            }
            if (out.isEmpty()) {
                accepted(ex);
            } else {
                send(ex, 200, out);
            }
            return;
        }
        Object r = message(ex, caller, parsed);
        if (r == null) {
            accepted(ex);
        } else {
            send(ex, 200, r);
        }
    }

    /** One JSON-RPC message: a response, or null for a notification. */
    private Object message(HttpExchange ex, Agents.Caller caller, Object o) {
        if (!(o instanceof Map<?, ?>)) {
            return error(null, -32600, "a JSON-RPC message is an object");
        }
        Map<String, Object> m = Json.asMap(o);
        Object id = m.get("id");
        String method = Json.asString(m.get("method"));
        if (method == null) {
            return id == null ? null : error(id, -32600, "no method");
        }
        if (id == null) {
            return null;   // notifications/initialized, notifications/cancelled: nothing to answer
        }
        Map<String, Object> params = m.get("params") instanceof Map<?, ?> p ? Json.asMap(p) : Map.of();
        try {
            switch (method) {
                case "initialize": {
                    String asked = Json.asString(params.get("protocolVersion"));
                    Map<String, Object> r = new LinkedHashMap<>();
                    r.put("protocolVersion", asked != null && PROTOCOLS.contains(asked) ? asked : PROTOCOLS.get(0));
                    r.put("capabilities", Map.of("tools", Map.of("listChanged", false)));
                    r.put("serverInfo", Map.of("name", "directory-console", "version", server.updates.version()));
                    r.put("instructions", INSTRUCTIONS);
                    return result(id, r);
                }
                case "ping":
                    return result(id, Map.of());
                case "tools/list": {
                    List<Object> list = new ArrayList<>();
                    for (Tool t : tools) {
                        if (t.role != null && !caller.session().principal.has(t.role)) {
                            continue;   // a change this key may not make
                        }
                        Map<String, Object> d = new LinkedHashMap<>();
                        d.put("name", t.name);
                        d.put("description", t.description);
                        d.put("inputSchema", t.schema());
                        d.put("annotations", t.role == null ? Map.of("readOnlyHint", true, "openWorldHint", false)
                            : Map.of("readOnlyHint", false, "destructiveHint", true, "idempotentHint", false, "openWorldHint", false));
                        list.add(d);
                    }
                    return result(id, Map.of("tools", list));
                }
                case "tools/call": {
                    String name = Json.asString(params.get("name"));
                    Map<String, Object> args = params.get("arguments") instanceof Map<?, ?> a ? Json.asMap(a) : Map.of();
                    for (Tool t : tools) {
                        if (t.name.equals(name)) {
                            return result(id, run(ex, caller, t, args));
                        }
                    }
                    return error(id, -32602, "no tool '" + name + "'");
                }
                default:
                    return error(id, -32601, "method not found: " + method);
            }
        } catch (RuntimeException | IOException e) {
            return error(id, -32603, String.valueOf(e.getMessage()));
        }
    }

    private Map<String, Object> run(HttpExchange ex, Agents.Caller caller, Tool t, Map<String, Object> args) throws IOException {
        Reply r;
        String missing = t.missing(args);
        if (missing != null) {
            r = new Reply(400, Json.compact(Map.of("title", "missing-field", "detail", missing)));
        } else {
            try {
                r = t.call.run(new Call(ex, caller, args));
            } catch (Refusal f) {
                r = f.reply;
            }
        }
        String text = r.body;
        if (text.length() > MAX_TEXT) {
            text = text.substring(0, MAX_TEXT) + "\n… cut at " + MAX_TEXT + " characters; narrow the request (fewer attributes, a smaller count)";
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("content", List.of(Map.of("type", "text", "text", text)));
        out.put("isError", r.status >= 400);
        return out;
    }

    // ---- the tools: each a call to the console's own API ----

    record Reply(int status, String body) {
        Map<String, Object> json() {
            Object o = body.isBlank() ? Map.of() : Json.parse(body);
            return o instanceof Map<?, ?> ? Json.asMap(o) : Map.of("items", o);
        }
    }

    /** A tool's answer that is a refusal from a step before its own call (an object that is not there). */
    private static final class Refusal extends RuntimeException {
        final Reply reply;

        Refusal(Reply reply) {
            super(null, null, false, false);
            this.reply = reply;
        }
    }

    private interface Body {
        Reply run(Call c) throws IOException;
    }

    /**
     * {@code args}: name → [type, description]; {@code required} are among them. {@code role}: the role a change tool
     * needs (null for a tool that reads).
     */
    private record Tool(String name, String description, Map<String, String[]> args, List<String> required, Role role, Body call) {

        Map<String, Object> schema() {
            Map<String, Object> props = new LinkedHashMap<>();
            args.forEach((k, v) -> {
                Map<String, Object> p = new LinkedHashMap<>();
                if (v[0].equals("string[]")) {
                    p.put("type", "array");
                    p.put("items", Map.of("type", "string"));
                } else {
                    p.put("type", v[0]);
                }
                p.put("description", v[1]);
                props.put(k, p);
            });
            Map<String, Object> s = new LinkedHashMap<>();
            s.put("type", "object");
            s.put("properties", props);
            if (!required.isEmpty()) {
                s.put("required", required);
            }
            s.put("additionalProperties", false);
            return s;
        }

        String missing(Map<String, Object> a) {
            for (String r : required) {
                Object v = a.get(r);
                if (v == null || (v instanceof String str && str.isBlank())) {
                    return r + " is required";
                }
            }
            return null;
        }
    }

    /** One tool call: its arguments, and in-process calls to the API as the key's session. */
    final class Call {
        final HttpExchange ex;
        final Agents.Caller caller;
        final Map<String, Object> args;

        Call(HttpExchange ex, Agents.Caller caller, Map<String, Object> args) {
            this.ex = ex;
            this.caller = caller;
            this.args = args;
        }

        String s(String k) {
            Object v = args.get(k);
            return v == null || String.valueOf(v).isBlank() ? null : String.valueOf(v);
        }

        /** The directory's API base: {@code /api/v2/trees/{id}}. */
        String tree() {
            return "/api/v2/trees/" + enc(caller.session().principal.directoryId());
        }

        /** A query string from the arguments named (those given), with {@code ?} first; empty when none. */
        String query(String... names) {
            StringBuilder q = new StringBuilder();
            for (String n : names) {
                String v = s(n);
                if (v != null) {
                    q.append(q.isEmpty() ? '?' : '&').append(n).append('=').append(enc(v));
                }
            }
            return q.toString();
        }

        /** The GUID the argument names: a GUID as given, or a DN looked up (a refusal when there is no such object). */
        /** The object the argument names (GUID or DN): its GUID, DN and structural class, read as the key. */
        Obj object(String arg) throws IOException {
            String v = s(arg);
            Reply r = v.matches(GUID) ? get(tree() + "/objects/" + v.toLowerCase(java.util.Locale.ROOT)) : get(tree() + "/objects?dn=" + enc(v));
            if (r.status != 200) {
                throw new Refusal(r);
            }
            Map<String, Object> m = r.json();
            return new Obj(String.valueOf(m.get("guid")), String.valueOf(m.get("dn")), Json.asString(m.get("objectClass")));
        }

        String guid(String arg) throws IOException {
            String v = s(arg);
            if (v.matches(GUID)) {
                return v.toLowerCase(java.util.Locale.ROOT);
            }
            Reply r = get(tree() + "/objects?dn=" + enc(v));
            if (r.status != 200) {
                throw new Refusal(r);
            }
            return String.valueOf(r.json().get("guid"));
        }

        Reply get(String path) throws IOException {
            return call("GET", path, null);
        }

        Reply post(String path, Object body) throws IOException {
            return call("POST", path, body);
        }

        private Reply call(String method, String path, Object body) throws IOException {
            byte[] b = body == null ? new byte[0] : Json.compact(body).getBytes(StandardCharsets.UTF_8);
            Local l = new Local(ex, caller.session(), method, URI.create(path), b);
            server.dispatch(l, l.uri.getPath(), method);
            return new Reply(l.status, l.out.toString(StandardCharsets.UTF_8));
        }
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static final String OBJECT = "the object: its GUID, or its DN (cn=jsmith,ou=users,o=acme)";
    private static final String DRIVER = "the driver: its GUID, or its DN (cn=AD,cn=DriverSet,o=system)";
    private static final String DRIVER_SET = "the driver set: its GUID, or its DN (cn=DriverSet,o=system)";
    private static final String SERVER = "optional: an eDirectory server's GUID, to ask that server's replica or engine (object_servers lists them); the key's own server when absent";

    /** An object a tool names. */
    record Obj(String guid, String dn, String objectClass) {
    }

    private void tool(String name, String description, Map<String, String[]> args, List<String> required, Body call) {
        tools.add(new Tool(name, description, args, required, null, call));
    }

    /** What a change tool builds from its arguments: the API call it makes. */
    private interface Builds {
        AgentChanges.Request build(Call c) throws IOException;
    }

    /**
     * A change tool, needing {@code role}. With the directory's approval on (the default) the call is recorded as a
     * pending change for the person to approve; with it off it is made now, with {@code confirm} as the production
     * directory's typed name. Either way the key must have the role, reaching the object, first.
     */
    private void change(String name, String description, Role role, Map<String, String[]> args, List<String> required, Builds builds) {
        Map<String, String[]> all = new LinkedHashMap<>(args);
        all.put("confirm", new String[] {"string", "only on a production directory whose changes need no approval: the directory's name, typed by the person in chat; never fill it in yourself"});
        tools.add(new Tool(name, description, all, required, role, c -> {
            Sessions.Session s = c.caller.session();
            if (!s.principal.has(role)) {
                return problem(403, "forbidden", "this needs the " + role.id() + " role, which this agent key does not have");
            }
            AgentChanges.Request r = builds.build(c);
            if (r.target() != null && !s.principal.may(role, r.target())) {
                return problem(403, "out-of-scope", "the key's " + role.id() + " role does not reach " + r.target());
            }
            if (server.agents.settings(s.principal.directoryId()).approveChanges()) {
                return new Reply(202, Json.compact(server.agentChanges.propose(c.caller, r)));
            }
            return execute(server, c.ex, s, r, c.s("confirm"));
        }));
    }

    private static Reply problem(int status, String title, String detail) {
        return new Reply(status, Json.compact(Map.of("title", title, "status", status, "detail", detail)));
    }

    /**
     * Make a change tool's API call now, in-process, as {@code s} (an agent key's session): when its owner approves it,
     * or straight away without approval. {@code confirm} goes as {@code X-Confirm-Directory}; a PATCH carries
     * {@code If-Match: *} (the change names its values, not a version read earlier).
     */
    static Reply execute(Server server, HttpExchange from, Sessions.Session s, AgentChanges.Request r, String confirm) throws IOException {
        byte[] b = r.body() == null ? new byte[0] : Json.compact(r.body()).getBytes(StandardCharsets.UTF_8);
        Local l = new Local(from, s, r.method(), URI.create(r.path()), b);
        if (confirm != null && !confirm.isBlank()) {
            l.requestHeaders.set("X-Confirm-Directory", confirm.trim());
        }
        if (r.method().equals("PATCH")) {
            l.requestHeaders.set("If-Match", "*");
        }
        server.dispatch(l, l.uri.getPath(), r.method());
        return new Reply(l.status, l.out.toString(StandardCharsets.UTF_8));
    }

    private static Map<String, String[]> args(String... kv) {
        Map<String, String[]> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 3) {
            m.put(kv[i], new String[] {kv[i + 1], kv[i + 2]});
        }
        return m;
    }

    private void define() {
        tool("whoami", "Who this key acts as: the person, the directory and its tier (production or lab), the roles the key may use now, "
                + "and the key's label and expiry.", args(), List.of(), c -> {
            Reply r = c.get("/api/v2/session");
            if (r.status != 200) {
                return r;
            }
            Map<String, Object> me = new LinkedHashMap<>(r.json());
            me.remove("csrf");
            me.remove("session");
            Map<String, Object> key = new LinkedHashMap<>(c.caller.key().json(server.agents.keys.now()));
            key.remove("dn");
            key.remove("name");
            me.put("key", key);
            return new Reply(200, Json.compact(me));
        });

        // ---- directory objects ----
        tool("search_objects", "Search the directory with an LDAP filter, with the person's own rights. Answers a window of matching rows "
                + "(GUID, DN, class) and the attributes asked for, with the total.", args(
                "filter", "string", "one parenthesized LDAP filter, such as (&(objectClass=inetOrgPerson)(sn=Smith*))",
                "base", "string", "optional: the DN to search under; the whole directory when absent",
                "scope", "string", "optional: base, one or subtree (the default)",
                "attributes", "string[]", "optional: attribute names to return with each row",
                "offset", "integer", "optional: the first row, from 1",
                "count", "integer", "optional: how many rows, up to 500 (50 by default)"),
            List.of("filter"), c -> {
                Map<String, Object> b = new LinkedHashMap<>();
                b.put("ldapFilter", c.s("filter"));
                if (c.s("base") != null) {
                    b.put("base", Map.of("dn", c.s("base")));
                }
                b.put("scope", c.s("scope") == null ? "subtree" : c.s("scope"));
                if (c.args.get("attributes") instanceof List<?> a) {
                    b.put("attributes", a);
                }
                Map<String, Object> page = new LinkedHashMap<>();
                page.put("offset", c.args.getOrDefault("offset", 1));
                page.put("count", c.args.getOrDefault("count", 50));
                b.put("page", page);
                return c.post(c.tree() + "/search", b);
            });
        tool("read_object", "Read one object: every attribute the person may read (secret attributes are shown only as set), its identity and "
                + "what the person may do with it.", args("object", "string", OBJECT, "server", "string", SERVER),
            List.of("object"), c -> c.get(c.tree() + "/objects/" + c.guid("object") + c.query("server")));
        tool("list_children", "List the objects in a container, sorted, a window at a time.", args(
                "object", "string", "the container: its GUID or DN",
                "kind", "string", "optional: all (the default), containers or leaves",
                "offset", "integer", "optional: the first row, from 1",
                "count", "integer", "optional: how many rows, up to 500"),
            List.of("object"), c -> c.get(c.tree() + "/objects/" + c.guid("object") + "/children" + c.query("kind", "offset", "count")));
        tool("object_servers", "The eDirectory servers holding a replica of an object, with their GUIDs (for the server argument of other tools).",
            args("object", "string", OBJECT), List.of("object"), c -> c.get(c.tree() + "/objects/" + c.guid("object") + "/servers"));
        tool("account_status", "A user's sign-in status: disabled, intruder lockout, expiry, grace logins, password expiry and the login time "
                + "restrictions. For 'why can this person not sign in'.", args("object", "string", "the user: GUID or DN"),
            List.of("object"), c -> c.get(c.tree() + "/objects/" + c.guid("object") + "/account"));
        tool("group_memberships", "The groups a user is a member of.", args("object", "string", "the user: GUID or DN"),
            List.of("object"), c -> c.get(c.tree() + "/objects/" + c.guid("object") + "/memberships"));
        tool("group_members", "A group's members, a window at a time.", args(
                "object", "string", "the group: GUID or DN",
                "offset", "integer", "optional: the first member, from 1",
                "count", "integer", "optional: how many, up to 500"),
            List.of("object"), c -> c.get(c.tree() + "/objects/" + c.guid("object") + "/members" + c.query("offset", "count")));

        // ---- Identity Manager ----
        tool("object_associations", "The object inspector: an object's Identity Manager associations (driver, state, association value) and its "
                + "password synchronization status. For 'why did this user not synchronize'.", args("object", "string", OBJECT),
            List.of("object"), c -> c.get(c.tree() + "/idm/objects/" + c.guid("object") + "/associations"));
        tool("idm_status", "Whether Identity Manager's engine can be reached as this person, and its version.", args(), List.of(),
            c -> c.get(c.tree() + "/idm"));
        tool("list_driver_sets", "The driver sets in the directory, with their GUIDs.", args("server", "string", SERVER), List.of(),
            c -> c.get(c.tree() + "/idm/driversets" + c.query("server")));
        tool("driver_set", "A driver set's drivers: each one's GUID, state (running, stopped), start option, cache and trace level.",
            args("driver_set", "string", DRIVER_SET, "server", "string", SERVER), List.of("driver_set"),
            c -> c.get(c.tree() + "/idm/driversets/" + c.guid("driver_set") + c.query("server")));
        tool("driver_status", "One driver's status: its state, start option, the server it runs on and more.",
            args("driver", "string", DRIVER, "server", "string", SERVER), List.of("driver"),
            c -> c.get(c.tree() + "/idm/drivers/" + c.guid("driver") + c.query("server")));
        tool("driver_health", "A driver's health: the engine's health state and the conditions behind it.",
            args("driver", "string", DRIVER, "server", "string", SERVER), List.of("driver"),
            c -> c.get(c.tree() + "/idm/drivers/" + c.guid("driver") + "/health" + c.query("server")));
        tool("list_jobs", "The Identity Manager jobs of a driver set, or of one driver, with their state.", args(
                "driver_set", "string", "optional: the driver set (GUID or DN); give it or driver",
                "driver", "string", "optional: one driver (GUID or DN)",
                "server", "string", SERVER), List.of(), c -> {
                if (c.s("driver") != null) {
                    return c.get(c.tree() + "/idm/drivers/" + c.guid("driver") + "/jobs" + c.query("server"));
                }
                if (c.s("driver_set") == null) {
                    return new Reply(400, Json.compact(Map.of("title", "missing-field", "detail", "driver_set or driver is required")));
                }
                return c.get(c.tree() + "/idm/driversets/" + c.guid("driver_set") + "/jobs" + c.query("server"));
            });
        tool("job_definition", "A job's definition: its type, schedule, servers, scope and parameters.",
            args("job", "string", "the job: GUID or DN"), List.of("job"),
            c -> c.get(c.tree() + "/idm/jobs/" + c.guid("job") + "/definition"));
        tool("driver_password_sync", "A driver's password synchronization settings, as the engine reports them.",
            args("driver", "string", DRIVER, "server", "string", SERVER), List.of("driver"),
            c -> c.get(c.tree() + "/idm/drivers/" + c.guid("driver") + "/password-sync" + c.query("server")));
        tool("driver_associations", "The association inspector: the objects a driver is associated with, optionally in one state.", args(
                "driver", "string", DRIVER,
                "state", "string", "optional: disabled, processed, pending, manual or migrate",
                "limit", "integer", "optional: at most this many, up to 1000 (200 by default)",
                "server", "string", SERVER), List.of("driver"),
            c -> c.get(c.tree() + "/idm/drivers/" + c.guid("driver") + "/associations" + c.query("state", "limit", "server")));
        tool("driver_cache", "The cache inspector's summary: a driver's cache size, unprocessed size, oldest and newest transaction and counts "
                + "by type (a running driver too).", args("driver", "string", DRIVER, "server", "string", SERVER), List.of("driver"),
            c -> c.get(c.tree() + "/idm/drivers/" + c.guid("driver") + "/cache/summary" + c.query("server")));
        tool("driver_cache_events", "The events waiting in a driver's cache, each with its position (the engine shows them for a stopped driver only).",
            args("driver", "string", DRIVER,
                "position", "integer", "optional: where to start (0, or a position from an earlier answer)",
                "count", "integer", "optional: how many events, up to 100 (25 by default)",
                "server", "string", SERVER), List.of("driver"),
            c -> c.get(c.tree() + "/idm/drivers/" + c.guid("driver") + "/cache/events" + c.query("position", "count", "server")));
        tool("driver_set_statistics", "A driver set's statistics on one server: the engine's JVM, and each driver's state, cache and operation counters.",
            args("driver_set", "string", DRIVER_SET, "server", "string", SERVER), List.of("driver_set"),
            c -> c.get(c.tree() + "/idm/driversets/" + c.guid("driver_set") + "/statistics" + c.query("server")));
        defineChanges();
        tool("versions", "Versions on one server: the engine's, and each driver's shim version and base package as the statistics job last collected them.",
            args("driver_set", "string", DRIVER_SET, "server", "string", SERVER), List.of("driver_set"),
            c -> c.get(c.tree() + "/idm/driversets/" + c.guid("driver_set") + "/versions" + c.query("server")));
    }

    private void defineChanges() {
        tool("change_status", "A change you asked for: pending (waiting for the person's approval), approved (with the change's answer), declined, "
                + "expired (not decided within an hour) or failed.", args("id", "string", "the change's id, from the change tool's answer"), List.of("id"), c -> {
            Map<String, Object> st = server.agentChanges.status(c.caller, c.s("id"));
            return st == null ? problem(404, "not-found", "no change " + c.s("id") + " from this key") : new Reply(200, Json.compact(st));
        });

        // ---- accounts and groups (editor) ----
        change("enable_account", "Enable a user's account (loginDisabled false).", Role.EDITOR, args("object", "string", "the user: GUID or DN"), List.of("object"), c -> {
            Obj o = c.object("object");
            return new AgentChanges.Request("enable_account", "Enable " + o.dn(), o.dn(), "PATCH", c.tree() + "/objects/" + o.guid() + "/account", Map.of("disabled", false));
        });
        change("disable_account", "Disable a user's account (loginDisabled true): they can no longer sign in.", Role.EDITOR,
            args("object", "string", "the user: GUID or DN"), List.of("object"), c -> {
                Obj o = c.object("object");
                return new AgentChanges.Request("disable_account", "Disable " + o.dn(), o.dn(), "PATCH", c.tree() + "/objects/" + o.guid() + "/account", Map.of("disabled", true));
            });
        change("unlock_account", "Clear a user's intruder lockout.", Role.EDITOR, args("object", "string", "the user: GUID or DN"), List.of("object"), c -> {
            Obj o = c.object("object");
            return new AgentChanges.Request("unlock_account", "Unlock " + o.dn(), o.dn(), "POST", c.tree() + "/objects/" + o.guid() + "/unlock", Map.of());
        });
        change("add_to_group", "Add a user to a group (both sides: the group's member and the user's groupMembership).", Role.EDITOR,
            args("object", "string", "the user: GUID or DN", "group", "string", "the group: GUID or DN"), List.of("object", "group"), c -> {
                Obj o = c.object("object");
                Obj g = c.object("group");
                return new AgentChanges.Request("add_to_group", "Add " + o.dn() + " to " + g.dn(), o.dn(), "POST", c.tree() + "/objects/" + o.guid() + "/memberships",
                    Map.of("add", List.of(g.guid()), "remove", List.of()));
            });
        change("remove_from_group", "Remove a user from a group (both sides).", Role.EDITOR,
            args("object", "string", "the user: GUID or DN", "group", "string", "the group: GUID or DN"), List.of("object", "group"), c -> {
                Obj o = c.object("object");
                Obj g = c.object("group");
                return new AgentChanges.Request("remove_from_group", "Remove " + o.dn() + " from " + g.dn(), o.dn(), "POST", c.tree() + "/objects/" + o.guid() + "/memberships",
                    Map.of("add", List.of(), "remove", List.of(g.guid())));
            });

        // ---- Identity Manager (operator) ----
        for (String action : List.of("start", "stop")) {
            change(action + "_driver", (action.equals("start") ? "Start" : "Stop") + " a driver on one server's engine.", Role.OPERATOR,
                args("driver", "string", DRIVER, "server", "string", SERVER), List.of("driver"), c -> {
                    Obj d = c.object("driver");
                    return new AgentChanges.Request(action + "_driver", (action.equals("start") ? "Start " : "Stop ") + d.dn(), d.dn(), "POST",
                        c.tree() + "/idm/drivers/" + d.guid() + "/" + action + c.query("server"), Map.of());
                });
        }
        for (String action : List.of("start", "abort")) {
            String tool = action.equals("start") ? "run_job" : "abort_job";
            change(tool, action.equals("start") ? "Run an Identity Manager job now." : "Abort a running job.", Role.OPERATOR,
                args("job", "string", "the job: GUID or DN", "server", "string", SERVER), List.of("job"), c -> {
                    Obj j = c.object("job");
                    return new AgentChanges.Request(tool, (action.equals("start") ? "Run " : "Abort ") + j.dn(), j.dn(), "POST",
                        c.tree() + "/idm/jobs/" + j.guid() + "/" + action + c.query("server"), Map.of());
                });
        }
        change("resync_driver", "Resynchronize a driver: the engine sends its objects again (all, or those changed since a time).", Role.OPERATOR,
            args("driver", "string", DRIVER, "since", "string", "optional: an ISO 8601 time, such as 2026-10-30T00:00:00Z; everything when absent",
                "server", "string", SERVER), List.of("driver"), c -> {
                Obj d = c.object("driver");
                Map<String, Object> b = new LinkedHashMap<>();
                if (c.s("since") != null) {
                    b.put("since", c.s("since"));
                }
                return new AgentChanges.Request("resync_driver", "Resynchronize " + d.dn() + (c.s("since") == null ? "" : " since " + c.s("since")), d.dn(), "POST",
                    c.tree() + "/idm/drivers/" + d.guid() + "/resync" + c.query("server"), b);
            });
        change("migrate_object_to_app", "Migrate one object from the vault into the connected application through a driver.", Role.OPERATOR,
            args("driver", "string", DRIVER, "object", "string", OBJECT,
                "class", "string", "optional: the object's class as the driver knows it; the object's structural class when absent",
                "server", "string", SERVER), List.of("driver", "object"), c -> {
                Obj d = c.object("driver");
                Obj o = c.object("object");
                String cls = c.s("class") != null ? c.s("class") : o.objectClass();
                return new AgentChanges.Request("migrate_object_to_app", "Migrate " + o.dn() + " into the application through " + d.dn(), d.dn(), "POST",
                    c.tree() + "/idm/drivers/" + d.guid() + "/migrate/to-app" + c.query("server"),
                    Map.of("base", o.guid(), "class", cls, "filter", "(objectClass=" + cls + ")", "max", 1));
            });
        change("migrate_from_app", "Migrate objects from the connected application into the vault: the engine queries the application for objects of "
                + "a class, optionally matching one attribute value.", Role.OPERATOR,
            args("driver", "string", DRIVER, "class", "string", "the vault class, such as User",
                "attribute", "string", "optional: an attribute to match", "value", "string", "optional: its value",
                "server", "string", SERVER), List.of("driver", "class"), c -> {
                Obj d = c.object("driver");
                Map<String, Object> b = new LinkedHashMap<>();
                b.put("class", c.s("class"));
                if (c.s("attribute") != null) {
                    b.put("search", List.of(Map.of("attribute", c.s("attribute"), "value", String.valueOf(c.s("value")))));
                }
                return new AgentChanges.Request("migrate_from_app", "Migrate " + c.s("class") + " objects from the application through " + d.dn()
                    + (c.s("attribute") == null ? "" : " where " + c.s("attribute") + " = " + c.s("value")), d.dn(), "POST",
                    c.tree() + "/idm/drivers/" + d.guid() + "/migrate/from-app" + c.query("server"), b);
            });
    }

    /** For tests and the docs: the tools' names, in order. */
    List<String> toolNames() {
        return tools.stream().map(Tool::name).toList();
    }

    // ---- an in-process request ----

    /** A request to the API made here, for an agent key's session: {@link Server#session} answers with that session. */
    static final class Local extends HttpExchange {
        final HttpExchange from;
        final Sessions.Session agent;
        final String method;
        final URI uri;
        final Headers requestHeaders = new Headers();
        final Headers responseHeaders = new Headers();
        final InputStream in;
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        private final Map<String, Object> attributes = new HashMap<>();
        int status = 500;

        Local(HttpExchange from, Sessions.Session agent, String method, URI uri, byte[] body) {
            this.from = from;
            this.agent = agent;
            this.method = method;
            this.uri = uri;
            this.in = new ByteArrayInputStream(body);
            if (body.length > 0) {
                requestHeaders.set("Content-Type", "application/json");
            }
            requestHeaders.set("Host", String.valueOf(from.getRequestHeaders().getFirst("Host")));
        }

        @Override public Headers getRequestHeaders() { return requestHeaders; }
        @Override public Headers getResponseHeaders() { return responseHeaders; }
        @Override public URI getRequestURI() { return uri; }
        @Override public String getRequestMethod() { return method; }
        @Override public HttpContext getHttpContext() { return from.getHttpContext(); }
        @Override public void close() { }
        @Override public InputStream getRequestBody() { return in; }
        @Override public OutputStream getResponseBody() { return out; }
        @Override public void sendResponseHeaders(int rCode, long responseLength) { status = rCode; }
        @Override public InetSocketAddress getRemoteAddress() { return from.getRemoteAddress(); }
        @Override public int getResponseCode() { return status; }
        @Override public InetSocketAddress getLocalAddress() { return from.getLocalAddress(); }
        @Override public String getProtocol() { return from.getProtocol(); }
        @Override public Object getAttribute(String name) { return attributes.get(name); }
        @Override public void setAttribute(String name, Object value) { attributes.put(name, value); }
        @Override public void setStreams(InputStream i, OutputStream o) { }
        @Override public HttpPrincipal getPrincipal() { return null; }
    }

    // ---- JSON-RPC ----

    private static Map<String, Object> result(Object id, Object result) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("jsonrpc", "2.0");
        m.put("id", id);
        m.put("result", result);
        return m;
    }

    private static Map<String, Object> error(Object id, int code, String message) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("jsonrpc", "2.0");
        m.put("id", id);
        m.put("error", Map.of("code", code, "message", message));
        return m;
    }

    private static void accepted(HttpExchange ex) throws IOException {
        Http.finishReading(ex);
        ex.sendResponseHeaders(202, -1);
        ex.close();
    }

    private static void send(HttpExchange ex, int status, Object body) throws IOException {
        Http.json(ex, status, body);
    }
}
