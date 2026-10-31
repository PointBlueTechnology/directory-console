package com.pointblue.console.server.live;

import static com.pointblue.console.server.live.LiveSetupCheck.call;

import com.pointblue.console.server.auth.FakeIdp;
import com.pointblue.console.server.data.DataDir;
import com.pointblue.console.server.http.Phase3Access;
import com.pointblue.console.server.http.Server;
import com.pointblue.console.server.http.ServerClient;
import com.pointblue.dirxml.dev.LegacyTls;
import com.pointblue.dirxml.dev.deploy.Environments;
import com.pointblue.dirxml.dev.json.Json;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
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
 * Live check of agent keys and the MCP server against a lab tree (docs/MCP.md, phase 1). As {@link LivePhase3Check}:
 * the environment's account is the console's service account and admin, and a fake identity provider on loopback
 * vouches for a test user made for the run in a new container under {@code parent} (no password is set or used). The
 * admin turns agent keys on; the test user makes a key and its agent calls {@code /mcp}: who it is, reads under the
 * user's own rights, Identity Manager, then refusals for a locked and a disabled account and a revoked key. The key
 * is never printed. The container is deleted at the end. Not a JUnit test.
 *
 *   java -cp … LiveAgentsCheck <environments.properties> <env> <parent DN>
 */
public final class LiveAgentsCheck {

    private static Map<String, String> admin;
    private static final String TREE = "lab";
    private static int rpcId;

    public static void main(String[] args) throws Exception {
        LegacyTls.enable();
        Environments.Environment env = Environments.load(Path.of(args[0])).get(args[1]);
        if (env.tier != null && env.tier.name().equalsIgnoreCase("prd")) {
            throw new IllegalStateException("refusing a prd-tier environment");
        }
        URI u = URI.create(env.url);
        Path dataPath = Files.createTempDirectory("dc-live-agents-");
        Server server = new Server(new DataDir(dataPath), ServerClient.loopback(), "https://localhost:8443", new PrintStream(new ByteArrayOutputStream()));
        String container = null;
        try (FakeIdp idp = new FakeIdp()) {
            server.start();
            LiveSetupCheck.base = "https://127.0.0.1:" + server.port();
            LiveSetupCheck.http = ServerClient.trusting(server);
            setUp(dataPath, u.getHost(), u.getPort() > 0 ? u.getPort() : 636, env.bindDn, env.password);
            System.out.println("# Agent keys live check: " + args[1] + " (service account and admin: the environment's account)");

            String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
            String uid = "dcag-" + ts;
            String parent = (String) call("GET", "/api/v2/trees/" + TREE + "/objects?dn=" + enc(args[2]), null, admin).body().get("guid");
            LiveSetupCheck.Reply c = call("POST", "/api/v2/trees/" + TREE + "/objects/" + parent + "/children",
                Map.of("objectClass", "organizationalUnit", "name", Map.of("type", "ou", "value", uid)), admin);
            container = (String) c.body().get("guid");
            ok("create container", c.status() == 201, c.body().get("dn"));
            LiveSetupCheck.Reply user = call("POST", "/api/v2/trees/" + TREE + "/objects/" + container + "/children",
                Map.of("objectClass", "inetOrgPerson", "name", Map.of("type", "cn", "value", "agent-tester"),
                    "attributes", Map.of("sn", List.of("Tester"), "uid", List.of(uid))), admin);
            String userDn = String.valueOf(user.body().get("dn"));
            String userGuid = (String) user.body().get("guid");
            ok("create the test user (no password)", user.status() == 201, userDn);

            Phase3Access.singleSignOn(server, idp.issuer, List.of(args[2]));
            idp.person("tester", Map.of("name", "Agent Tester", "preferred_username", uid, "groups", List.of("testers")));

            LiveSetupCheck.Reply on = call("PUT", "/api/v2/directories/" + TREE + "/agent-keys", Map.of("enabled", true, "maxDays", 30), admin);
            ok("the admin turns agent keys on", on.status() == 200, Json.asMap(on.body().get("agentKeys")));

            LiveSetupCheck.Reply cb = sso(idp, "tester");
            Map<String, String> me = cookie(cb);
            Map<String, Object> who = call("GET", "/api/v2/session", null, me).body();
            me.put("X-CSRF-Token", String.valueOf(who.get("csrf")));
            ok("the test user signs in with single sign-on", userDn.equalsIgnoreCase(String.valueOf(who.get("dn"))), who.get("dn") + " via " + who.get("via"));

            LiveSetupCheck.Reply long_ = call("POST", "/api/v2/agent-keys", Map.of("label", "live check", "days", 15), me);
            ok("a single sign-on key lives at most 14 days", long_.status() == 400, long_.status() + detail(long_));
            LiveSetupCheck.Reply made = call("POST", "/api/v2/agent-keys", Map.of("label", "live check", "days", 1, "roles", List.of("editor")), me);
            ok("make a key (viewer and editor)", made.status() == 201, made.status() + detail(made) + " roles " + (made.status() == 201 ? Json.asMap(made.body().get("key")).get("roles") : ""));
            String key = String.valueOf(made.body().get("token"));
            String keyId = made.status() == 201 ? String.valueOf(Json.asMap(made.body().get("key")).get("id")) : "";

            LiveSetupCheck.Reply init = mcp(key, "initialize", Map.of("protocolVersion", "2025-06-18"));
            ok("MCP initialize", init.status() == 200, init.status() == 200 ? Json.asMap(init.body().get("result")).get("serverInfo") : init.status() + detail(init));
            List<?> tools = Json.asList(Json.asMap(mcp(key, "tools/list", Map.of()).body().get("result")).get("tools"));
            ok("tools/list", tools.size() >= 20, tools.size() + " tools");

            Map<String, Object> whoami = tool(key, "whoami", Map.of());
            ok("whoami: the test user, via agent", userDn.equalsIgnoreCase(String.valueOf(whoami.get("dn"))) && "agent".equals(whoami.get("via")),
                whoami.get("dn") + " via " + whoami.get("via") + " roles " + whoami.get("roles"));
            Map<String, Object> self = tool(key, "read_object", Map.of("object", userDn));
            ok("read_object: its own entry, by DN, under the control", userGuid.equals(self.get("guid")), "attributes=" + Json.asMap(self.getOrDefault("attributes", Map.of())).keySet());
            Map<String, Object> found = tool(key, "search_objects", Map.of("filter", "(uid=" + uid + ")", "base", args[2]));
            ok("search_objects finds the test user", Json.asList(found.get("items")).size() == 1, "total " + found.get("total"));
            Map<String, Object> account = tool(key, "account_status", Map.of("object", userGuid));
            ok("account_status", !account.containsKey("_error"), account.containsKey("_error") ? account : "disabled=" + account.get("disabled") + " locked=" + account.get("locked"));
            Map<String, Object> groups = tool(key, "group_memberships", Map.of("object", userGuid));
            ok("group_memberships", !groups.containsKey("_error"), groups.containsKey("_error") ? groups : "total " + groups.get("total"));
            Map<String, Object> assoc = tool(key, "object_associations", Map.of("object", userGuid));
            ok("object_associations (the object inspector)", !assoc.containsKey("_error"), assoc.containsKey("_error") ? assoc : assoc.keySet());

            Map<String, Object> idm = tool(key, "idm_status", Map.of());
            ok("idm_status: the engine, acting as the test user", Boolean.TRUE.equals(idm.get("available")), "engine " + idm.get("engineVersion")
                + (idm.get("problem") == null ? "" : " problem: " + idm.get("problem")));
            Map<String, Object> sets = tool(key, "list_driver_sets", Map.of());
            ok("list_driver_sets (as the test user)", !sets.containsKey("_error"), sets.containsKey("_error") ? sets : Json.asList(sets.get("items")).size() + " visible to the user");
            List<?> adminSets = (List<?>) call("GET", "/api/v2/trees/" + TREE + "/idm/driversets", null, admin).body().get("items");
            if (adminSets != null && !adminSets.isEmpty()) {
                Map<String, Object> set = Json.asMap(adminSets.get(0));
                Map<String, Object> asKey = tool(key, "driver_set", Map.of("driver_set", String.valueOf(set.get("dn"))));
                ok("driver_set by DN: answered with the user's rights (refused, or the drivers they may see)", true,
                    asKey.containsKey("_error") ? "refused: " + asKey.get("title") : Json.asList(asKey.get("drivers")).size() + " drivers");
            }

            // changes: wait for the person's approval, then made as the key, decided by eDirectory with the user's rights
            LiveSetupCheck.Reply other = call("POST", "/api/v2/trees/" + TREE + "/objects/" + container + "/children",
                Map.of("objectClass", "inetOrgPerson", "name", Map.of("type", "cn", "value", "change-target"), "attributes", Map.of("sn", List.of("Target"))), admin);
            String otherDn = String.valueOf(other.body().get("dn"));
            ok("create a second user to change", other.status() == 201, otherDn);
            List<?> named = Json.asList(Json.asMap(mcp(key, "tools/list", Map.of()).body().get("result")).get("tools"));
            ok("an editor key is offered the account and group tools", named.stream().anyMatch(t -> "disable_account".equals(Json.asMap(t).get("name"))), "");
            Map<String, Object> asked = tool(key, "disable_account", Map.of("object", otherDn));
            String changeId = String.valueOf(asked.get("id"));
            ok("disable_account waits for approval", "pending".equals(asked.get("state")), asked.get("summary") + " -> " + asked.get("approve"));
            LiveSetupCheck.Reply approved = call("POST", "/api/v2/agent-changes/" + changeId + "/approve", Map.of(), me);
            Map<String, Object> result = Json.asMap(approved.body().get("result"));
            ok("the person approves; the change is made as the key, with the user's rights (eDirectory refuses: the user has no rights over it)",
                approved.status() == 200 && ("failed".equals(approved.body().get("state")) || "approved".equals(approved.body().get("state"))),
                approved.body().get("state") + " " + result.get("status") + " " + Json.asMap(result.getOrDefault("body", Map.of())).get("title"));
            Map<String, Object> st = tool(key, "change_status", Map.of("id", changeId));
            ok("change_status tells the agent", String.valueOf(approved.body().get("state")).equals(st.get("state")), st.get("state"));
            String declineId = String.valueOf(tool(key, "unlock_account", Map.of("object", otherDn)).get("id"));
            LiveSetupCheck.Reply declined = call("POST", "/api/v2/agent-changes/" + declineId + "/decline", Map.of(), me);
            ok("the person declines another", "declined".equals(declined.body().get("state")), declined.body().get("state"));
            call("PUT", "/api/v2/directories/" + TREE + "/agent-keys", Map.of("enabled", true, "maxDays", 30, "approveChanges", false), admin);
            Map<String, Object> direct = tool(key, "enable_account", Map.of("object", otherDn));
            ok("approval off: the change is made at once (and eDirectory decides)", !"pending".equals(direct.get("state")),
                direct.containsKey("_error") ? "refused: " + direct.get("title") : "done");
            call("PUT", "/api/v2/directories/" + TREE + "/agent-keys", Map.of("enabled", true, "maxDays", 30, "approveChanges", true), admin);

            // eDirectory accepts the control for an account locked by intruder detection; the console refuses the key
            String future = DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").format(java.time.ZonedDateTime.now(java.time.ZoneOffset.UTC).plusHours(1));
            LiveSetupCheck.Reply lock = call("PATCH", "/api/v2/trees/" + TREE + "/objects/" + userGuid, Map.of("changes", List.of(
                Map.of("op", "replace", "attribute", "lockedByIntruder", "values", List.of("TRUE")),
                Map.of("op", "replace", "attribute", "loginIntruderResetTime", "values", List.of(future)))), withEtag(admin, userGuid));
            ok("lock the test user until " + future, lock.status() == 200, lock.status() + detail(lock));
            LiveSetupCheck.Reply locked = mcp(key, "tools/list", Map.of());
            ok("a locked account's key is refused", locked.status() == 403 && "locked".equals(locked.body().get("title")), locked.status() + detail(locked));
            LiveSetupCheck.Reply unlock = call("POST", "/api/v2/trees/" + TREE + "/objects/" + userGuid + "/unlock", Map.of(), admin);
            ok("unlock the test user", unlock.status() == 200, unlock.status() + detail(unlock));
            ok("unlocked, the key works again", mcp(key, "tools/list", Map.of()).status() == 200, "");

            LiveSetupCheck.Reply acct = call("GET", "/api/v2/trees/" + TREE + "/objects/" + userGuid + "/account", null, admin);
            Map<String, String> h = new HashMap<>(admin);
            h.put("If-Match", acct.raw().headers().firstValue("ETag").orElse("*"));
            ok("disable the test user", call("PATCH", "/api/v2/trees/" + TREE + "/objects/" + userGuid + "/account", Map.of("disabled", true), h).status() == 200, "");
            LiveSetupCheck.Reply disabled = mcp(key, "tools/list", Map.of());
            ok("a disabled account's key is refused", disabled.status() == 403 && "account-disabled".equals(disabled.body().get("title")), disabled.status() + detail(disabled));

            LiveSetupCheck.Reply revoke = call("DELETE", "/api/v2/agent-keys/" + keyId, null, admin);
            ok("the admin revokes the key", revoke.status() == 204, revoke.status() + detail(revoke));
            ok("a revoked key is refused", mcp(key, "tools/list", Map.of()).status() == 401, "");

            String audit = audit(dataPath);
            ok("audited: key made, changes asked for, approved and declined, refusals, revoked", audit.contains("\"agent-key.create\"") && audit.contains("\"agent-change.request\"")
                && audit.contains("\"agent-change.approve\"") && audit.contains("\"agent-change.decline\"") && audit.contains("\"agent-key.use\"") && audit.contains("\"agent-key.revoke\""), "");
            ok("the key is not in the console's files", !Files.readString(dataPath.resolve("agents/keys.json")).contains(key.substring(3)) && !audit.contains(key.substring(3)), "");
        } finally {
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

    private static String audit(Path dataPath) throws Exception {
        StringBuilder b = new StringBuilder();
        try (var files = Files.list(dataPath.resolve("audit"))) {
            for (Path p : files.toList()) {
                b.append(Files.readString(p));
            }
        }
        return b.toString();
    }

    private static Map<String, String> withEtag(Map<String, String> h, String guid) throws Exception {
        Map<String, String> out = new HashMap<>(h);
        out.put("If-Match", call("GET", "/api/v2/trees/" + TREE + "/objects/" + guid, null, h).raw().headers().firstValue("ETag").orElse("*"));
        return out;
    }

    private static LiveSetupCheck.Reply sso(FakeIdp idp, String person) throws Exception {
        idp.signInAs = person;
        LiveSetupCheck.Reply start = call("GET", "/api/v2/oidc/start?directory=" + TREE + "&next=/", null, Map.of());
        String state = start.raw().headers().allValues("Set-Cookie").stream().filter(c -> c.startsWith("__Host-console-oidc=")).findFirst().orElseThrow();
        HttpResponse<String> atIdp = LiveSetupCheck.http.send(HttpRequest.newBuilder(URI.create(start.raw().headers().firstValue("Location").orElseThrow())).GET().build(),
            HttpResponse.BodyHandlers.ofString());
        String back = atIdp.headers().firstValue("Location").orElseThrow();
        return call("GET", back.substring("https://localhost:8443".length()), null, Map.of("Cookie", state.substring(0, state.indexOf(';'))));
    }

    private static Map<String, String> cookie(LiveSetupCheck.Reply r) {
        String c = r.raw().headers().allValues("Set-Cookie").stream().filter(x -> x.startsWith("__Host-console=")).findFirst().orElse("x=;");
        return new HashMap<>(Map.of("Cookie", c.substring(0, c.indexOf(';'))));
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
