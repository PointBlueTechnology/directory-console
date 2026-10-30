package com.pointblue.console.server.http;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.pointblue.console.server.auth.FakeIdp;
import com.pointblue.console.server.data.Backup;
import com.pointblue.console.server.data.DataDir;
import com.pointblue.console.server.idm.FakeEngine;
import com.pointblue.console.server.ldap.FakeEdir;
import com.pointblue.console.server.tls.Certs;
import com.pointblue.dirxml.dev.deploy.Vault;
import com.pointblue.dirxml.dev.json.Json;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/** Agent keys and the MCP server: a key made by a signed-in person, used over /mcp, acting with that person's rights. */
public class AgentsTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private FakeEdir edir;
    private FakeEngine engine;
    private FakeIdp idp;
    private Server server;
    private HttpClient http;
    private String base;
    private Path dataPath;

    record Reply(int status, Map<String, Object> body, HttpResponse<String> raw) {
    }

    @Before
    public void start() throws Exception {
        edir = new FakeEdir(
            "dn: cn=admin,o=system\nobjectClass: inetOrgPerson\ncn: admin\nsn: a\nuid: admin\nuserPassword: admin-pw",
            "dn: cn=console,o=system\nobjectClass: inetOrgPerson\ncn: console\nsn: c\nuserPassword: console-pw",
            "dn: ou=Sales,o=acme\nobjectClass: organizationalUnit\nou: Sales",
            "dn: ou=Groups,o=acme\nobjectClass: organizationalUnit\nou: Groups",
            "dn: cn=Editors,ou=Groups,o=acme\nobjectClass: groupOfNames\ncn: Editors\nmember: cn=ed,ou=Sales,o=acme",
            "dn: cn=ed,ou=Sales,o=acme\nobjectClass: inetOrgPerson\ncn: ed\nsn: Editor\nfullName: Ed Editor\nuserPassword: ed-pw\ngroupMembership: cn=Editors,ou=Groups,o=acme",
            "dn: cn=alice,ou=Sales,o=acme\nobjectClass: inetOrgPerson\ncn: alice\nsn: Ali\nuid: alice\ntitle: Rep",
            "dn: cn=Reps,ou=Sales,o=acme\nobjectClass: groupOfNames\ncn: Reps",
            "dn: cn=Operators,ou=Groups,o=acme\nobjectClass: groupOfNames\ncn: Operators\nmember: cn=op,ou=Groups,o=acme",
            "dn: cn=op,ou=Groups,o=acme\nobjectClass: inetOrgPerson\ncn: op\nsn: Operator\nuserPassword: op-pw\ngroupMembership: cn=Operators,ou=Groups,o=acme",
            "dn: cn=Driver Set,o=system\nobjectClass: DirXML-DriverSet\ncn: Driver Set",
            "dn: cn=AD,cn=Driver Set,o=system\nobjectClass: DirXML-Driver\ncn: AD\nDirXML-TraceLevel: 3");
        engine = new FakeEngine(edir);
        engine.states.put("cn=ad,cn=driverset,o=system", Vault.STATE_RUNNING);
        idp = new FakeIdp().person("alice", Map.of("name", "Alice Ali", "preferred_username", "alice", "groups", List.of("sales-editors")));
        dataPath = tmp.newFolder("data").toPath();
        server = new Server(new DataDir(dataPath), ServerClient.loopback(), "https://localhost:8443", new PrintStream(new ByteArrayOutputStream()));
        server.login.engines(engine.engines());
        server.start();
        base = "https://127.0.0.1:" + server.port();
        http = ServerClient.trusting(server);
        Matcher m = Pattern.compile("Setup token: ([0-9a-f]{32})").matcher(Files.readString(dataPath.resolve("bootstrap.txt")));
        assertTrue(m.find());
        Map<String, String> t = Map.of("X-Setup-Token", m.group(1));
        call("PUT", "/api/v2/setup/directory", Map.of("id", "acme", "name", "Acme", "host", "127.0.0.1", "port", edir.port(), "tier", "lab"), t);
        Reply probe = call("POST", "/api/v2/setup/probe", Map.of(), t);
        call("POST", "/api/v2/setup/trust", Map.of("probeId", probe.body().get("probeId"), "confirm", Certs.tail(edir.pki.ca, 8)), t);
        call("POST", "/api/v2/setup/authority", Map.of("dn", "cn=admin,o=system", "password", "admin-pw"), t);
        call("PUT", "/api/v2/setup/service-account", Map.of("dn", "cn=console,o=system", "password", "console-pw"), t);
        assertEquals(200, call("POST", "/api/v2/setup/finish", Map.of(), t).status());
        server.config.update(server.config.version(), "test", "agents", doc -> {
            Map<String, Object> d = Json.asMap(Json.asMap(doc.get("directories")).get("acme"));
            d.put("roles", List.of(Map.of("group", "cn=Editors,ou=Groups,o=acme", "role", "editor", "scopes", List.of("ou=Sales,o=acme")),
                Map.of("group", "cn=Operators,ou=Groups,o=acme", "role", "operator")));
            d.put("oidc", Map.of("issuer", idp.issuer, "clientId", "console", "label", "Acme SSO", "claim", "preferred_username",
                "attribute", "uid", "searchBases", List.of("o=acme"),
                "roles", List.of(Map.of("group", "sales-editors", "role", "editor", "scopes", List.of("ou=Sales,o=acme")))));
        });
    }

    @After
    public void stop() {
        server.stop();
        edir.close();
        idp.close();
    }

    private Reply call(String method, String path, Object body, Map<String, String> headers) throws Exception {
        HttpRequest.Builder b = ServerClient.request(URI.create(path.startsWith("http") ? path : base + path))
            .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(Json.compact(body)));
        if (body != null) {
            b.header("Content-Type", "application/json");
        }
        headers.forEach(b::header);
        HttpResponse<String> r = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
        Object parsed = r.body().isBlank() ? Map.of() : r.body().startsWith("[") || r.body().startsWith("{") ? Json.parse(r.body()) : Map.of();
        return new Reply(r.statusCode(), parsed instanceof Map ? Json.asMap(parsed) : Map.of("list", parsed), r);
    }

    private Map<String, String> signIn(String dn, String pw) throws Exception {
        Reply r = call("POST", "/api/v2/session", Map.of("directory", "acme", "name", dn, "password", pw), Map.of());
        assertEquals(String.valueOf(r.body()), 200, r.status());
        return withCsrf(cookie(r));
    }

    private static Map<String, String> cookie(Reply r) {
        String c = r.raw().headers().allValues("Set-Cookie").stream().filter(x -> x.startsWith(Server.COOKIE + "=")).findFirst().orElseThrow();
        Map<String, String> h = new HashMap<>();
        h.put("Cookie", c.substring(0, c.indexOf(';')));
        return h;
    }

    private Map<String, String> withCsrf(Map<String, String> h) throws Exception {
        Map<String, String> out = new HashMap<>(h);
        out.put("X-CSRF-Token", String.valueOf(call("GET", "/api/v2/session", null, h).body().get("csrf")));
        return out;
    }

    private void agentKeys(boolean enabled) throws Exception {
        agentKeys(enabled, true);
    }

    private void agentKeys(boolean enabled, boolean approve) throws Exception {
        Map<String, String> admin = signIn("cn=admin,o=system", "admin-pw");
        Reply r = call("PUT", "/api/v2/directories/acme/agent-keys", Map.of("enabled", enabled, "maxDays", 60, "approveChanges", approve), admin);
        assertEquals(String.valueOf(r.body()), 200, r.status());
        Map<String, Object> a = Json.asMap(r.body().get("agentKeys"));
        assertEquals(enabled, a.get("enabled"));
        assertEquals(60, Json.asInt(a.get("maxDays"), 0));
        assertEquals(approve, a.get("approveChanges"));
    }

    private String makeKey(Map<String, String> h, Map<String, Object> body) throws Exception {
        Reply r = call("POST", "/api/v2/agent-keys", body, h);
        assertEquals(String.valueOf(r.body()), 201, r.status());
        assertEquals("https://localhost:8443/mcp", r.body().get("mcpUrl"));
        return String.valueOf(r.body().get("token"));
    }

    private int rpcId;

    /** One JSON-RPC call to /mcp with {@code key}. */
    private Reply mcp(String key, String method, Map<String, Object> params) throws Exception {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("jsonrpc", "2.0");
        m.put("id", ++rpcId);
        m.put("method", method);
        m.put("params", params);
        return call("POST", "/mcp", m, key == null ? Map.of() : Map.of("Authorization", "Bearer " + key));
    }

    /** A tool's result: its text parsed, and whether it is an error. */
    private record Result(boolean error, Map<String, Object> body) {
    }

    private Result tool(String key, String name, Map<String, Object> args) throws Exception {
        Reply r = mcp(key, "tools/call", Map.of("name", name, "arguments", args));
        assertEquals(String.valueOf(r.body()), 200, r.status());
        Map<String, Object> result = Json.asMap(r.body().get("result"));
        String text = String.valueOf(Json.asMap(Json.asList(result.get("content")).get(0)).get("text"));
        Object o = Json.parse(text);
        return new Result(Boolean.TRUE.equals(result.get("isError")), o instanceof Map ? Json.asMap(o) : Map.of("items", o));
    }

    private String audit() throws Exception {
        StringBuilder b = new StringBuilder();
        try (var files = Files.list(dataPath.resolve("audit"))) {
            for (Path p : files.toList()) {
                b.append(Files.readString(p));
            }
        }
        return b.toString();
    }

    @Test
    public void keysAreOffUntilAnAdminTurnsThemOn() throws Exception {
        Map<String, String> ed = signIn("cn=ed,ou=Sales,o=acme", "ed-pw");
        Reply r = call("POST", "/api/v2/agent-keys", Map.of("label", "laptop", "password", "ed-pw"), ed);
        assertEquals(409, r.status());
        assertEquals("agent-keys-off", r.body().get("title"));
        Map<String, Object> list = call("GET", "/api/v2/agent-keys", null, ed).body();
        assertEquals(false, Json.asMap(list.get("settings")).get("enabled"));
        assertEquals("approval is required by default", true, Json.asMap(list.get("settings")).get("approveChanges"));
    }

    @Test
    public void aKeyReadsAsThePersonOverMcp() throws Exception {
        agentKeys(true);
        Map<String, String> ed = signIn("cn=ed,ou=Sales,o=acme", "ed-pw");
        Reply wrong = call("POST", "/api/v2/agent-keys", Map.of("label", "laptop", "password", "nope"), ed);
        assertEquals("the password proves the person is here", 401, wrong.status());
        String key = makeKey(ed, Map.of("label", "laptop", "password", "ed-pw", "roles", List.of("editor")));
        assertTrue(key.startsWith("dc_"));
        List<Object> mine = Json.asList(call("GET", "/api/v2/agent-keys", null, ed).body().get("keys"));
        assertEquals(1, mine.size());
        assertEquals(List.of("editor", "viewer"), Json.asMap(mine.get(0)).get("roles"));
        assertFalse(String.valueOf(mine).contains(key));

        Reply init = mcp(key, "initialize", Map.of("protocolVersion", "2025-06-18"));
        assertEquals(200, init.status());
        assertEquals("2025-06-18", Json.asMap(init.body().get("result")).get("protocolVersion"));
        List<Object> tools = Json.asList(Json.asMap(mcp(key, "tools/list", Map.of()).body().get("result")).get("tools"));
        assertTrue(tools.size() >= 20);
        Map<String, Object> hints = new HashMap<>();
        tools.forEach(t -> hints.put(String.valueOf(Json.asMap(t).get("name")), Json.asMap(Json.asMap(t).get("annotations")).get("readOnlyHint")));
        assertEquals(true, hints.get("read_object"));
        assertEquals("a change tool says so", false, hints.get("disable_account"));

        Result who = tool(key, "whoami", Map.of());
        assertFalse(who.error());
        assertEquals("cn=ed,ou=Sales,o=acme", who.body().get("dn"));
        assertEquals("agent", who.body().get("via"));
        assertEquals("Ed Editor", who.body().get("name"));
        assertFalse("no CSRF token for an agent", who.body().containsKey("csrf"));
        assertEquals("laptop", Json.asMap(who.body().get("key")).get("label"));

        edir.lastProxiedSearch = null;
        Result alice = tool(key, "read_object", Map.of("object", "cn=alice,ou=Sales,o=acme"));
        assertFalse(String.valueOf(alice.body()), alice.error());
        assertEquals("cn=alice,ou=Sales,o=acme", alice.body().get("dn"));
        assertEquals("it acts as the person, on the service account's connection", "dn:cn=ed,ou=Sales,o=acme", edir.lastProxiedSearch);
        Result byGuid = tool(key, "read_object", Map.of("object", alice.body().get("guid")));
        assertEquals(alice.body().get("dn"), byGuid.body().get("dn"));

        Result found = tool(key, "search_objects", Map.of("filter", "(sn=Ali)", "base", "o=acme"));
        assertFalse(String.valueOf(found.body()), found.error());
        assertEquals(1, Json.asList(found.body().get("items")).size());

        Result missing = tool(key, "read_object", Map.of("object", "cn=nobody,ou=Sales,o=acme"));
        assertTrue(missing.error());
        assertEquals("no-such-object", missing.body().get("title"));
        Result noArg = tool(key, "read_object", Map.of());
        assertTrue(noArg.error());

        Result set = tool(key, "driver_set", Map.of("driver_set", "cn=Driver Set,o=system"));
        assertFalse(String.valueOf(set.body()), set.error());
        assertTrue(engine.actions.contains("act-as cn=ed,ou=Sales,o=acme"));
        assertTrue(audit().contains("\"agent-key.create\""));
    }

    @Test
    public void refusals() throws Exception {
        agentKeys(true);
        Map<String, String> ed = signIn("cn=ed,ou=Sales,o=acme", "ed-pw");
        String key = makeKey(ed, Map.of("label", "laptop", "password", "ed-pw"));

        Reply none = mcp(null, "tools/list", Map.of());
        assertEquals(401, none.status());
        assertTrue(none.raw().headers().firstValue("WWW-Authenticate").orElse("").startsWith("Bearer"));
        assertEquals(401, mcp("dc_" + "x".repeat(43), "tools/list", Map.of()).status());
        assertEquals(405, call("GET", "/mcp", null, Map.of("Authorization", "Bearer " + key)).status());
        Reply rest = call("GET", "/api/v2/session", null, Map.of("Authorization", "Bearer " + key));
        assertEquals("a key works at /mcp only, not on the API directly", 401, rest.status());

        // the account locked by intruder detection: eDirectory would still accept the control, the console does not
        edir.server.modify("cn=ed,ou=Sales,o=acme", List.of(
            new com.unboundid.ldap.sdk.Modification(com.unboundid.ldap.sdk.ModificationType.REPLACE, "lockedByIntruder", "TRUE"),
            new com.unboundid.ldap.sdk.Modification(com.unboundid.ldap.sdk.ModificationType.REPLACE, "loginIntruderResetTime", "20991231000000Z")));
        Reply locked = mcp(key, "tools/list", Map.of());
        assertEquals(403, locked.status());
        assertEquals("locked", locked.body().get("title"));
        assertTrue(audit().contains("\"agent-key.use\""));
        edir.server.modify("cn=ed,ou=Sales,o=acme", List.of(
            new com.unboundid.ldap.sdk.Modification(com.unboundid.ldap.sdk.ModificationType.REPLACE, "lockedByIntruder", "FALSE")));
        assertEquals(200, mcp(key, "tools/list", Map.of()).status());

        // a role taken away reaches the key at its next call
        edir.server.modify("cn=ed,ou=Sales,o=acme", List.of(
            new com.unboundid.ldap.sdk.Modification(com.unboundid.ldap.sdk.ModificationType.DELETE, "groupMembership")));
        Reply noRole = mcp(key, "tools/list", Map.of());
        assertEquals(403, noRole.status());
        assertEquals("no-role", noRole.body().get("title"));
        edir.server.modify("cn=ed,ou=Sales,o=acme", List.of(
            new com.unboundid.ldap.sdk.Modification(com.unboundid.ldap.sdk.ModificationType.ADD, "groupMembership", "cn=Editors,ou=Groups,o=acme")));

        edir.server.modify("cn=ed,ou=Sales,o=acme", List.of(
            new com.unboundid.ldap.sdk.Modification(com.unboundid.ldap.sdk.ModificationType.REPLACE, "loginDisabled", "TRUE")));
        assertEquals("account-disabled", mcp(key, "tools/list", Map.of()).body().get("title"));
        edir.server.modify("cn=ed,ou=Sales,o=acme", List.of(
            new com.unboundid.ldap.sdk.Modification(com.unboundid.ldap.sdk.ModificationType.DELETE, "loginDisabled")));

        agentKeys(false);
        assertEquals("agent-keys-off", mcp(key, "tools/list", Map.of()).body().get("title"));
        agentKeys(true);
        assertEquals("on again, the key works again", 200, mcp(key, "tools/list", Map.of()).status());

        String id = String.valueOf(Json.asMap(Json.asList(call("GET", "/api/v2/agent-keys", null, ed).body().get("keys")).get(0)).get("id"));
        assertEquals(204, call("DELETE", "/api/v2/agent-keys/" + id, null, ed).status());
        assertEquals("a revoked key stops at once", 401, mcp(key, "tools/list", Map.of()).status());
        assertTrue(audit().contains("\"agent-key.revoke\""));
    }

    @Test
    public void whatAKeyMayCarry() throws Exception {
        agentKeys(true);
        Map<String, String> ed = signIn("cn=ed,ou=Sales,o=acme", "ed-pw");
        Reply op = call("POST", "/api/v2/agent-keys", Map.of("label", "x", "password", "ed-pw", "roles", List.of("operator")), ed);
        assertEquals("not a role the person has", 400, op.status());
        Reply admin = call("POST", "/api/v2/agent-keys", Map.of("label", "x", "password", "ed-pw", "roles", List.of("admin")), ed);
        assertEquals(400, admin.status());
        Reply long_ = call("POST", "/api/v2/agent-keys", Map.of("label", "x", "password", "ed-pw", "days", 61), ed);
        assertEquals("longer than the directory allows", 400, long_.status());

        Map<String, String> root = signIn("cn=admin,o=system", "admin-pw");
        Reply breakGlass = call("POST", "/api/v2/agent-keys", Map.of("label", "x", "password", "admin-pw"), root);
        assertEquals("a break-glass sign-in makes no keys", 409, breakGlass.status());
        assertEquals("an admin lists everyone's keys", 200, call("GET", "/api/v2/agent-keys?all=true", null, root).status());
        assertEquals(403, call("GET", "/api/v2/agent-keys?all=true", null, ed).status());
    }

    @Test
    public void aSingleSignOnPersonGetsShorterKeys() throws Exception {
        agentKeys(true);
        idp.signInAs = "alice";
        Reply start = call("GET", "/api/v2/oidc/start?directory=acme&next=%2F", null, Map.of());
        String state = start.raw().headers().allValues("Set-Cookie").stream().filter(c -> c.startsWith(Server.OIDC_COOKIE + "=")).findFirst().orElseThrow();
        Reply atIdp = call("GET", start.raw().headers().firstValue("Location").orElseThrow(), null, Map.of());
        String back = atIdp.raw().headers().firstValue("Location").orElseThrow();
        Reply cb = call("GET", base + back.substring("https://localhost:8443".length()), null, Map.of("Cookie", state.substring(0, state.indexOf(';'))));
        Map<String, String> alice = withCsrf(cookie(cb));
        assertEquals(14, Json.asInt(Json.asMap(call("GET", "/api/v2/agent-keys", null, alice).body().get("settings")).get("longestDays"), 0));
        assertEquals(400, call("POST", "/api/v2/agent-keys", Map.of("label", "x", "days", 15), alice).status());
        String key = makeKey(alice, Map.of("label", "sso laptop", "days", 14));
        Result who = tool(key, "whoami", Map.of());
        assertEquals("cn=alice,ou=Sales,o=acme", who.body().get("dn"));
        assertNotNull(who.body().get("roles"));
    }

    private List<String> toolNames(String key) throws Exception {
        return Json.asList(Json.asMap(mcp(key, "tools/list", Map.of()).body().get("result")).get("tools")).stream()
            .map(t -> String.valueOf(Json.asMap(t).get("name"))).toList();
    }

    private String attr(String dn, String name) throws Exception {
        com.unboundid.ldap.sdk.Entry e = edir.server.getEntry(dn, name);
        return e == null ? null : e.getAttributeValue(name);
    }

    @Test
    public void aChangeWaitsForThePersonsApproval() throws Exception {
        agentKeys(true);
        Map<String, String> ed = signIn("cn=ed,ou=Sales,o=acme", "ed-pw");
        String viewer = makeKey(ed, Map.of("label", "reader", "password", "ed-pw"));
        assertFalse("a read-only key is offered no change tools", toolNames(viewer).contains("disable_account"));
        Result refused = tool(viewer, "disable_account", Map.of("object", "cn=alice,ou=Sales,o=acme"));
        assertTrue(refused.error());
        assertEquals("forbidden", refused.body().get("title"));

        String key = makeKey(ed, Map.of("label", "editor", "password", "ed-pw", "roles", List.of("editor")));
        List<String> names = toolNames(key);
        assertTrue(names.containsAll(List.of("disable_account", "enable_account", "unlock_account", "add_to_group", "remove_from_group", "change_status")));
        assertFalse("operator tools need the operator role", names.contains("start_driver"));

        Result out = tool(key, "disable_account", Map.of("object", "cn=admin,o=system"));
        assertEquals("the key's scoped editor role does not reach o=system", "out-of-scope", out.body().get("title"));

        Result asked = tool(key, "disable_account", Map.of("object", "cn=alice,ou=Sales,o=acme"));
        assertFalse(String.valueOf(asked.body()), asked.error());
        assertEquals("pending", asked.body().get("state"));
        String id = String.valueOf(asked.body().get("id"));
        assertTrue(String.valueOf(asked.body().get("approve")).endsWith("/agent-keys?change=" + id));
        assertNull("nothing changed yet", attr("cn=alice,ou=Sales,o=acme", "loginDisabled"));
        assertEquals("pending", tool(key, "change_status", Map.of("id", id)).body().get("state"));

        List<Object> mine = Json.asList(call("GET", "/api/v2/agent-changes", null, ed).body().get("changes"));
        assertEquals(1, mine.size());
        assertEquals("Disable cn=alice,ou=Sales,o=acme", Json.asMap(mine.get(0)).get("summary"));
        Map<String, String> op = signIn("cn=op,ou=Groups,o=acme", "op-pw");
        assertEquals("only the key's owner approves", 404, call("POST", "/api/v2/agent-changes/" + id + "/approve", Map.of(), op).status());

        Reply approved = call("POST", "/api/v2/agent-changes/" + id + "/approve", Map.of(), ed);
        assertEquals(String.valueOf(approved.body()), 200, approved.status());
        assertEquals("approved", approved.body().get("state"));
        assertEquals("TRUE", attr("cn=alice,ou=Sales,o=acme", "loginDisabled"));
        assertEquals("approved", tool(key, "change_status", Map.of("id", id)).body().get("state"));
        assertEquals(409, call("POST", "/api/v2/agent-changes/" + id + "/approve", Map.of(), ed).status());
        String audit = audit();
        assertTrue(audit.contains("\"agent-change.request\"") && audit.contains("\"agent-change.approve\""));
        assertTrue("the change itself is audited as the agent", audit.contains("\"via\":\"agent\",\"agent\":\"editor ("));

        Result group = tool(key, "add_to_group", Map.of("object", "cn=alice,ou=Sales,o=acme", "group", "cn=Reps,ou=Sales,o=acme"));
        String gid = String.valueOf(group.body().get("id"));
        Reply declined = call("POST", "/api/v2/agent-changes/" + gid + "/decline", Map.of(), ed);
        assertEquals("declined", declined.body().get("state"));
        assertNull(attr("cn=alice,ou=Sales,o=acme", "groupMembership"));

        Result again = tool(key, "enable_account", Map.of("object", "cn=alice,ou=Sales,o=acme"));
        String eid = String.valueOf(again.body().get("id"));
        String keyId = String.valueOf(Json.asMap(Json.asList(call("GET", "/api/v2/agent-keys", null, ed).body().get("keys")).get(0)).get("id"));
        call("DELETE", "/api/v2/agent-keys/" + keyId, null, ed);
        Reply afterRevoke = call("POST", "/api/v2/agent-changes/" + eid + "/approve", Map.of(), ed);
        assertEquals("a revoked key's change cannot be approved", 409, afterRevoke.status());
    }

    @Test
    public void withoutApprovalAChangeIsMadeAtOnce() throws Exception {
        agentKeys(true, false);
        Map<String, String> op = signIn("cn=op,ou=Groups,o=acme", "op-pw");
        String key = makeKey(op, Map.of("label", "ops", "password", "op-pw", "roles", List.of("operator")));
        assertTrue(toolNames(key).containsAll(List.of("start_driver", "stop_driver", "run_job", "abort_job", "resync_driver", "migrate_object_to_app", "migrate_from_app")));
        assertFalse("no editor role: no account tools", toolNames(key).contains("disable_account"));
        Result started = tool(key, "start_driver", Map.of("driver", "cn=AD,cn=Driver Set,o=system"));
        assertFalse(String.valueOf(started.body()), started.error());
        assertTrue(engine.actions.stream().anyMatch(a -> a.startsWith("start ") && a.toLowerCase().contains("cn=ad")));

        // a production directory without approval: the directory's name, typed by the person
        server.config.update(server.config.version(), "test", "production", doc -> Json.asMap(Json.asMap(doc.get("directories")).get("acme")).put("tier", "production"));
        Result unconfirmed = tool(key, "stop_driver", Map.of("driver", "cn=AD,cn=Driver Set,o=system"));
        assertTrue(unconfirmed.error());
        assertEquals("confirm-directory", unconfirmed.body().get("title"));
        Result confirmed = tool(key, "stop_driver", Map.of("driver", "cn=AD,cn=Driver Set,o=system", "confirm", "Acme"));
        assertFalse(String.valueOf(confirmed.body()), confirmed.error());
    }

    @Test
    public void approvingOnProductionNeedsTheDirectorysName() throws Exception {
        agentKeys(true);
        server.config.update(server.config.version(), "test", "production", doc -> Json.asMap(Json.asMap(doc.get("directories")).get("acme")).put("tier", "production"));
        Map<String, String> ed = signIn("cn=ed,ou=Sales,o=acme", "ed-pw");
        String key = makeKey(ed, Map.of("label", "editor", "password", "ed-pw", "roles", List.of("editor")));
        String id = String.valueOf(tool(key, "disable_account", Map.of("object", "cn=alice,ou=Sales,o=acme")).body().get("id"));
        assertEquals(409, call("POST", "/api/v2/agent-changes/" + id + "/approve", Map.of(), ed).status());
        assertEquals(200, call("POST", "/api/v2/agent-changes/" + id + "/approve", Map.of("confirm", "Acme"), ed).status());
        assertEquals("TRUE", attr("cn=alice,ou=Sales,o=acme", "loginDisabled"));
    }

    /** A stand-in for OSP and Identity Applications, as the lab answered (DirXMLDev docs/idapps-rest.md). */
    private static final class FakeApps implements AutoCloseable {
        final com.sun.net.httpserver.HttpServer server;
        final List<String> seen = new java.util.concurrent.CopyOnWriteArrayList<>();
        volatile boolean refreshWorks = true;
        volatile int grants;

        FakeApps() throws Exception {
            server = com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/osp/a/idm/auth/oauth2/token", ex -> {
                String form = java.net.URLDecoder.decode(new String(ex.getRequestBody().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8), java.nio.charset.StandardCharsets.UTF_8);
                boolean client = ("Basic " + java.util.Base64.getEncoder().encodeToString("rbpmrest:apps-secret".getBytes())).equals(ex.getRequestHeaders().getFirst("Authorization"));
                grants++;
                seen.add("grant " + (form.contains("grant_type=password") ? "password " + form.replaceAll(".*username=([^&]*).*", "$1") : "refresh"));
                if (client && form.contains("grant_type=password") && form.contains("password=ed-pw")) {
                    send(ex, 200, Map.of("access_token", "a" + grants, "expires_in", 1, "refresh_token", "r-ed"));
                } else if (client && refreshWorks && form.contains("refresh_token=r-ed")) {
                    send(ex, 200, Map.of("access_token", "a" + grants, "expires_in", 1));
                } else {
                    send(ex, 400, Map.of("error", "invalid_grant"));
                }
            });
            server.createContext("/IDMProv/rest/", ex -> {
                String body = new String(ex.getRequestBody().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                String path = ex.getRequestURI().getPath();
                seen.add(ex.getRequestMethod() + " " + path + " " + body);
                if (path.endsWith("/tasks/list")) {
                    send(ex, 200, Map.of("tasks", List.of(Map.of("taskId", "t1", "processName", "Access", "recipientName", "Alice Ali")), "arraySize", 1));
                } else if (path.endsWith("/tasks/item")) {
                    send(ex, 200, Map.of("taskId", "t1", "processName", "Access", "recipientName", "Alice Ali"));
                } else if (path.endsWith("/assignments/list")) {
                    send(ex, 200, Map.of("total", 1, "assignments", List.of(Map.of("id", "cn=Sales Role,o=system", "entityType", "role"))));
                } else {
                    send(ex, 200, Map.of("success", true));
                }
            });
            server.start();
        }

        String url() {
            return "http://127.0.0.1:" + server.getAddress().getPort();
        }

        static void send(com.sun.net.httpserver.HttpExchange ex, int status, Object body) throws java.io.IOException {
            byte[] b = Json.compact(body).getBytes(java.nio.charset.StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(status, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }

    @Test
    public void identityApplicationsAsThePerson() throws Exception {
        agentKeys(true);
        try (FakeApps apps = new FakeApps()) {
            Map<String, String> admin = signIn("cn=admin,o=system", "admin-pw");
            assertEquals("a client secret is required", 400, call("PUT", "/api/v2/directories/acme/apps", Map.of("url", apps.url()), admin).status());
            Reply set = call("PUT", "/api/v2/directories/acme/apps", Map.of("url", apps.url(), "clientSecret", "apps-secret"), admin);
            assertEquals(String.valueOf(set.body()), 200, set.status());
            assertEquals(Map.of("url", apps.url(), "clientId", "rbpmrest", "clientSecretSet", true), Json.asMap(set.body().get("apps")));
            assertFalse("the secret is never returned", set.raw().body().contains("apps-secret"));

            Map<String, String> ed = signIn("cn=ed,ou=Sales,o=acme", "ed-pw");
            Reply made = call("POST", "/api/v2/agent-keys", Map.of("label", "apps", "password", "ed-pw", "roles", List.of("editor")), ed);
            assertEquals(String.valueOf(made.body()), 201, made.status());
            assertEquals("authorized", Json.asMap(made.body().get("key")).get("apps"));
            assertTrue("one password grant, with the person's DN", apps.seen.contains("grant password cn=ed,ou=Sales,o=acme"));
            assertFalse("the refresh token is kept sealed", Files.readString(dataPath.resolve("agents/keys.json")).contains("r-ed"));
            String key = String.valueOf(made.body().get("token"));
            String viewer = makeKey(ed, Map.of("label", "reader", "password", "ed-pw"));

            assertTrue(toolNames(key).containsAll(List.of("my_tasks", "task", "my_requests", "assignments", "approve_tasks", "start_request", "request_role")));
            assertTrue(toolNames(viewer).contains("my_tasks"));
            assertFalse("a read-only key makes no Identity Applications changes", toolNames(viewer).contains("approve_tasks"));

            Result tasks = tool(key, "my_tasks", Map.of());
            assertFalse(String.valueOf(tasks.body()), tasks.error());
            assertEquals(1, Json.asList(tasks.body().get("tasks")).size());
            assertTrue("the access token is renewed with the refresh token, never a second password sign-in",
                apps.seen.stream().filter(x -> x.startsWith("grant password")).count() == 2 && apps.seen.contains("grant refresh"));
            assertTrue(tool(key, "assignments", Map.of()).body().toString().contains("cn=Sales Role,o=system"));

            Result asked = tool(key, "approve_tasks", Map.of("task_ids", List.of("t1"), "comment", "fine"));
            assertEquals("pending", asked.body().get("state"));
            assertEquals("Approve Access for Alice Ali", asked.body().get("summary"));
            assertTrue("nothing approved yet", apps.seen.stream().noneMatch(x -> x.startsWith("POST /IDMProv/rest/access/tasks ")));
            Reply approved = call("POST", "/api/v2/agent-changes/" + asked.body().get("id") + "/approve", Map.of(), ed);
            assertEquals(String.valueOf(approved.body()), "approved", approved.body().get("state"));
            assertTrue(apps.seen.stream().anyMatch(x -> x.startsWith("POST /IDMProv/rest/access/tasks ") && x.contains("\"action\":\"approve\"") && x.contains("\"t1\"")));
            assertTrue(audit().contains("\"apps.approve_tasks\""));

            // the refresh token stops working: the key's Identity Applications tools ask for its owner again
            apps.refreshWorks = false;
            Result again = tool(key, "my_tasks", Map.of());
            assertTrue(again.error());
            assertEquals("authorize-again", again.body().get("title"));
            String id = String.valueOf(Json.asMap(made.body().get("key")).get("id"));
            Map<String, Object> listed = Json.asList(call("GET", "/api/v2/agent-keys", null, ed).body().get("keys")).stream().map(Json::asMap)
                .filter(k -> id.equals(k.get("id"))).findFirst().orElseThrow();
            assertEquals("authorize-again", listed.get("apps"));
            assertEquals("still offered, so the agent can say what is needed", true, toolNames(key).contains("my_tasks"));
            assertEquals(401, call("POST", "/api/v2/agent-keys/" + id + "/authorize", Map.of("password", "nope"), ed).status());
            Reply reauth = call("POST", "/api/v2/agent-keys/" + id + "/authorize", Map.of("password", "ed-pw"), ed);
            assertEquals(String.valueOf(reauth.body()), "authorized", reauth.body().get("apps"));
            apps.refreshWorks = true;
            assertFalse(tool(key, "my_tasks", Map.of()).error());
        }
    }

    @Test
    public void keysAreNotInBackups() throws Exception {
        agentKeys(true);
        makeKey(signIn("cn=ed,ou=Sales,o=acme", "ed-pw"), Map.of("label", "laptop", "password", "ed-pw"));
        assertTrue(Files.exists(dataPath.resolve("agents/keys.json")));
        byte[] b = Backup.create(new DataDir(dataPath), "a long passphrase".toCharArray(), true, "test");
        assertTrue(Backup.open(b, "a long passphrase".toCharArray()).keySet().stream().noneMatch(f -> f.startsWith("agents")));
    }
}
