package com.pointblue.console.server.live;

import static com.pointblue.console.server.live.LiveSetupCheck.call;

import com.pointblue.console.server.data.DataDir;
import com.pointblue.console.server.http.Server;
import com.pointblue.console.server.http.ServerClient;
import com.pointblue.dirxml.dev.LegacyTls;
import com.pointblue.dirxml.dev.deploy.Environments;
import com.pointblue.dirxml.dev.json.Json;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Live check of agent keys with Identity Applications (docs/MCP.md, phase 3) against a lab: the environment's account
 * is the console's service account and admin; {@code appsUserDn} is an Identity Applications user who signs in to the
 * console directly (its password in {@code APPS_PASSWORD}, the OSP client's secret in {@code APPS_SECRET}, never
 * printed). For the run it is added to a scratch group mapped to the editor role, in a new container under
 * {@code parent}; it makes a key (one OSP password grant), and the agent reads its tasks, requests, assignments and the
 * catalog, then asks to approve a task that does not exist: the change waits, is approved, and Identity Applications
 * refuses it, which proves the path without starting a workflow. The membership, container and key are removed.
 *
 *   APPS_PASSWORD=… APPS_SECRET=… java -cp … LiveAgentsAppsCheck <environments.properties> <env> <parent DN> <apps URL> <apps user DN>
 */
public final class LiveAgentsAppsCheck {

    private static Map<String, String> admin;
    private static final String TREE = "lab";
    private static int rpcId;

    public static void main(String[] args) throws Exception {
        LegacyTls.enable();
        Environments.Environment env = Environments.load(Path.of(args[0])).get(args[1]);
        if (env.tier != null && env.tier.name().equalsIgnoreCase("prd")) {
            throw new IllegalStateException("refusing a prd-tier environment");
        }
        String appsPassword = System.getenv("APPS_PASSWORD");
        String appsSecret = System.getenv("APPS_SECRET") != null ? System.getenv("APPS_SECRET") : appsPassword;
        String appsUser = args[4];
        URI u = URI.create(env.url);
        Path dataPath = Files.createTempDirectory("dc-live-apps-");
        Server server = new Server(new DataDir(dataPath), ServerClient.loopback(), "https://localhost:8443", new PrintStream(new ByteArrayOutputStream()));
        String container = null;
        String userGuid = null;
        String groupGuid = null;
        try {
            server.start();
            LiveSetupCheck.base = "https://127.0.0.1:" + server.port();
            LiveSetupCheck.http = ServerClient.trusting(server);
            setUp(dataPath, u.getHost(), u.getPort() > 0 ? u.getPort() : 636, env.bindDn, env.password);
            System.out.println("# Agent keys with Identity Applications, live: " + args[1] + " as " + appsUser);

            String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
            String parent = (String) call("GET", "/api/v2/trees/" + TREE + "/objects?dn=" + enc(args[2]), null, admin).body().get("guid");
            LiveSetupCheck.Reply c = call("POST", "/api/v2/trees/" + TREE + "/objects/" + parent + "/children",
                Map.of("objectClass", "organizationalUnit", "name", Map.of("type", "ou", "value", "dcapps-" + ts)), admin);
            container = (String) c.body().get("guid");
            ok("create container", c.status() == 201, c.body().get("dn"));
            LiveSetupCheck.Reply g = call("POST", "/api/v2/trees/" + TREE + "/objects/" + container + "/children",
                Map.of("objectClass", "groupOfNames", "name", Map.of("type", "cn", "value", "agent-apps-testers")), admin);
            groupGuid = (String) g.body().get("guid");
            String groupDn = String.valueOf(g.body().get("dn"));
            ok("create a group mapped to the editor role", g.status() == 201, groupDn);
            userGuid = (String) call("GET", "/api/v2/trees/" + TREE + "/objects?dn=" + enc(appsUser), null, admin).body().get("guid");
            LiveSetupCheck.Reply add = call("POST", "/api/v2/trees/" + TREE + "/objects/" + userGuid + "/memberships", Map.of("add", List.of(groupGuid), "remove", List.of()), admin);
            ok("add " + appsUser + " to it (removed at the end)", add.status() == 200 || add.status() == 207, add.status() + detail(add));
            LiveSetupCheck.Reply roles = call("PUT", "/api/v2/directories/" + TREE + "/roles", List.of(Map.of("group", groupDn, "role", "editor")), admin);
            ok("role mapping", roles.status() == 200, roles.status() + detail(roles));
            ok("agent keys on", call("PUT", "/api/v2/directories/" + TREE + "/agent-keys", Map.of("enabled", true, "maxDays", 30), admin).status() == 200, "");
            LiveSetupCheck.Reply apps = call("PUT", "/api/v2/directories/" + TREE + "/apps", Map.of("url", args[3], "clientId", "rbpmrest", "clientSecret", appsSecret), admin);
            ok("Identity Applications set for the directory", apps.status() == 200, Json.asMap(apps.body().getOrDefault("apps", Map.of())));

            LiveSetupCheck.Reply in = call("POST", "/api/v2/session", Map.of("directory", TREE, "name", appsUser, "password", appsPassword), Map.of());
            ok("the apps user signs in directly", in.status() == 200, in.status() + detail(in) + " roles " + in.body().get("roles"));
            String cookie = in.raw().headers().firstValue("Set-Cookie").orElse("");
            Map<String, String> me = new HashMap<>(Map.of("Cookie", cookie.substring(0, cookie.indexOf(';'))));
            me.put("X-CSRF-Token", String.valueOf(in.body().get("csrf")));
            LiveSetupCheck.Reply made = call("POST", "/api/v2/agent-keys", Map.of("label", "apps live check", "days", 1, "password", appsPassword, "roles", List.of("editor")), me);
            Map<String, Object> keyJson = made.status() == 201 ? Json.asMap(made.body().get("key")) : Map.of();
            ok("make a key: Identity Applications authorized with one password grant", made.status() == 201 && "authorized".equals(keyJson.get("apps")),
                made.status() + detail(made) + " apps=" + keyJson.get("apps") + (made.body().get("appsProblem") == null ? "" : " problem: " + made.body().get("appsProblem")));
            String key = String.valueOf(made.body().get("token"));
            String keyId = String.valueOf(keyJson.get("id"));

            List<?> names = Json.asList(Json.asMap(mcp(key, "tools/list", Map.of()).body().get("result")).get("tools"));
            ok("the Identity Applications tools are offered", names.stream().anyMatch(t -> "my_tasks".equals(Json.asMap(t).get("name")))
                && names.stream().anyMatch(t -> "approve_tasks".equals(Json.asMap(t).get("name"))), names.size() + " tools");
            Map<String, Object> tasks = tool(key, "my_tasks", Map.of());
            ok("my_tasks", !tasks.containsKey("_error"), tasks.containsKey("_error") ? tasks : Json.asList(tasks.getOrDefault("tasks", List.of())).size() + " tasks");
            Map<String, Object> reqs = tool(key, "my_requests", Map.of("size", 5));
            ok("my_requests", !reqs.containsKey("_error"), reqs.containsKey("_error") ? reqs : Json.asList(reqs.getOrDefault("requests", List.of())).size() + " shown");
            Map<String, Object> assigned = tool(key, "assignments", Map.of());
            ok("assignments (the person's own)", !assigned.containsKey("_error"), assigned.containsKey("_error") ? assigned : "total " + assigned.get("total"));
            Map<String, Object> defs = tool(key, "request_definitions", Map.of());
            ok("request_definitions (the catalog)", !defs.containsKey("_error"), defs.containsKey("_error") ? defs : Json.asList(defs.getOrDefault("requestDefs", List.of())).size() + " PRDs");

            Map<String, Object> asked = tool(key, "approve_tasks", Map.of("task_ids", List.of("00000000000000000000000000000000"), "comment", "live check"));
            ok("approve_tasks waits for approval", "pending".equals(asked.get("state")), asked.get("summary"));
            LiveSetupCheck.Reply approved = call("POST", "/api/v2/agent-changes/" + asked.get("id") + "/approve", Map.of(), me);
            Map<String, Object> result = Json.asMap(approved.body().getOrDefault("result", Map.of()));
            ok("approved: made in Identity Applications as the person, which refuses a task that does not exist",
                approved.status() == 200 && "failed".equals(approved.body().get("state")), approved.body().get("state") + " " + result.get("status") + " "
                    + String.valueOf(result.get("body")).replaceAll("\\s+", " ").substring(0, Math.min(200, String.valueOf(result.get("body")).length())));

            ok("revoke the key", call("DELETE", "/api/v2/agent-keys/" + keyId, null, me).status() == 204, "");
            String keys = Files.readString(dataPath.resolve("agents/keys.json"));
            ok("no token or password in the console's files", !keys.contains(appsPassword) && !keys.contains(key.substring(3)), "");
        } finally {
            if (userGuid != null && groupGuid != null) {
                LiveSetupCheck.Reply rm = call("POST", "/api/v2/trees/" + TREE + "/objects/" + userGuid + "/memberships", Map.of("add", List.of(), "remove", List.of(groupGuid)), admin);
                ok("cleanup: remove the membership", rm.status() == 200 || rm.status() == 207, rm.status() + detail(rm));
            }
            if (container != null) {
                LiveSetupCheck.Reply count = call("GET", "/api/v2/trees/" + TREE + "/objects/" + container + "/subtree", null, admin);
                Map<String, String> h = new HashMap<>(admin);
                h.put("If-Match", "*");
                h.put("X-Confirm-Count", String.valueOf(count.body().get("count")));
                LiveSetupCheck.Reply d = call("DELETE", "/api/v2/trees/" + TREE + "/objects/" + container + "?subtree=true", null, h);
                ok("cleanup: subtree delete", d.status() == 200, "deleted=" + d.body().get("deleted") + detail(d));
            }
            server.stop();
            try (var s = Files.walk(dataPath)) {
                s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    private static LiveSetupCheck.Reply mcp(String key, String method, Map<String, Object> params) throws Exception {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("jsonrpc", "2.0");
        m.put("id", ++rpcId);
        m.put("method", method);
        m.put("params", params);
        return call("POST", "/mcp", m, Map.of("Authorization", "Bearer " + key));
    }

    /** A tool's answer, parsed; a refusal carries {@code _error}. */
    private static Map<String, Object> tool(String key, String name, Map<String, Object> args) throws Exception {
        LiveSetupCheck.Reply r = mcp(key, "tools/call", Map.of("name", name, "arguments", args));
        if (r.status() != 200 || r.body().get("result") == null) {
            return Map.of("_error", r.status() + " " + r.body());
        }
        Map<String, Object> result = Json.asMap(r.body().get("result"));
        Object o = Json.parse(String.valueOf(Json.asMap(Json.asList(result.get("content")).get(0)).get("text")));
        Map<String, Object> out = new LinkedHashMap<>(o instanceof Map ? Json.asMap(o) : Map.of("items", o));
        if (Boolean.TRUE.equals(result.get("isError"))) {
            out.put("_error", true);
        }
        return out;
    }

    private static void setUp(Path dataPath, String host, int port, String dn, String pw) throws Exception {
        Matcher m = Pattern.compile("Setup token: ([0-9a-f]{32})").matcher(Files.readString(dataPath.resolve("bootstrap.txt")));
        m.find();
        Map<String, String> t = Map.of("X-Setup-Token", m.group(1));
        call("PUT", "/api/v2/setup/directory", Map.of("id", TREE, "name", TREE, "host", host, "port", port, "tier", "lab"), t);
        LiveSetupCheck.Reply probe = call("POST", "/api/v2/setup/probe", Map.of(), t);
        int rec = Json.asInt(probe.body().get("recommended"), 0);
        String sha = (String) Json.asMap(((List<?>) probe.body().get("chain")).get(rec)).get("sha256");
        String tail = sha.replace(":", "").toLowerCase();
        call("POST", "/api/v2/setup/trust", Map.of("probeId", probe.body().get("probeId"), "index", rec, "confirm", tail.substring(tail.length() - 8)), t);
        call("POST", "/api/v2/setup/authority", Map.of("dn", dn, "password", pw), t);
        call("PUT", "/api/v2/setup/service-account", Map.of("dn", dn, "password", pw), t);
        call("POST", "/api/v2/setup/finish", Map.of(), t);
        LiveSetupCheck.Reply in = call("POST", "/api/v2/session", Map.of("directory", TREE, "name", dn, "password", pw), Map.of());
        String cookie = in.raw().headers().firstValue("Set-Cookie").orElse("");
        admin = new HashMap<>(Map.of("Cookie", cookie.substring(0, cookie.indexOf(';'))));
        admin.put("X-CSRF-Token", String.valueOf(in.body().get("csrf")));
    }

    private static String enc(String s) {
        return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8);
    }

    private static String detail(LiveSetupCheck.Reply r) {
        return r.status() / 100 == 2 ? "" : " " + r.body().get("title") + ": " + r.body().get("detail");
    }

    private static void ok(String what, boolean ok, Object detail) {
        System.out.println("[" + (ok ? "ok" : "FAIL") + "] " + what + ": " + detail);
    }
}
