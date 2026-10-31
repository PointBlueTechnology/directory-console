package com.pointblue.console.server.http;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
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
            d.put("roles", List.of(Map.of("group", "cn=Editors,ou=Groups,o=acme", "role", "editor", "scopes", List.of("ou=Sales,o=acme"))));
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
        Map<String, String> admin = signIn("cn=admin,o=system", "admin-pw");
        Reply r = call("PUT", "/api/v2/directories/acme/agent-keys", Map.of("enabled", enabled, "maxDays", 60), admin);
        assertEquals(String.valueOf(r.body()), 200, r.status());
        Map<String, Object> a = Json.asMap(r.body().get("agentKeys"));
        assertEquals(enabled, a.get("enabled"));
        assertEquals(60, Json.asInt(a.get("maxDays"), 0));
        assertEquals(true, a.get("approveChanges"));
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
        assertTrue("every tool of this version reads", tools.stream().allMatch(t -> Json.asMap(Json.asMap(t).get("annotations")).get("readOnlyHint").equals(true)));

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

    @Test
    public void keysAreNotInBackups() throws Exception {
        agentKeys(true);
        makeKey(signIn("cn=ed,ou=Sales,o=acme", "ed-pw"), Map.of("label", "laptop", "password", "ed-pw"));
        assertTrue(Files.exists(dataPath.resolve("agents/keys.json")));
        byte[] b = Backup.create(new DataDir(dataPath), "a long passphrase".toCharArray(), true, "test");
        assertTrue(Backup.open(b, "a long passphrase".toCharArray()).keySet().stream().noneMatch(f -> f.startsWith("agents")));
    }
}
