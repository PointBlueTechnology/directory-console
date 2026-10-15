package com.pointblue.console.server.http;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.pointblue.console.server.auth.FakeIdp;
import com.pointblue.console.server.data.DataDir;
import com.pointblue.console.server.ldap.FakeEdir;
import com.pointblue.console.server.tls.Certs;
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
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/** Access: scoped roles, task presets, OpenID Connect sign-in acting through the service account, and their settings. */
public class Phase3Test {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private FakeEdir edir;
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
            "dn: ou=Engineering,o=acme\nobjectClass: organizationalUnit\nou: Engineering",
            "dn: ou=Groups,o=acme\nobjectClass: organizationalUnit\nou: Groups",
            "dn: cn=Editors,ou=Groups,o=acme\nobjectClass: groupOfNames\ncn: Editors\nmember: cn=ed,ou=Sales,o=acme",
            "dn: cn=Help Desk,ou=Groups,o=acme\nobjectClass: groupOfNames\ncn: Help Desk\nmember: cn=help,ou=Sales,o=acme",
            "dn: cn=Sales Team,ou=Sales,o=acme\nobjectClass: groupOfNames\ncn: Sales Team\nmember: cn=ed,ou=Sales,o=acme",
            "dn: cn=ed,ou=Sales,o=acme\nobjectClass: inetOrgPerson\ncn: ed\nsn: Editor\nuserPassword: ed-pw\ngroupMembership: cn=Editors,ou=Groups,o=acme",
            "dn: cn=help,ou=Sales,o=acme\nobjectClass: inetOrgPerson\ncn: help\nsn: Desk\nuserPassword: help-pw\ngroupMembership: cn=Help Desk,ou=Groups,o=acme",
            "dn: cn=alice,ou=Sales,o=acme\nobjectClass: inetOrgPerson\ncn: alice\nsn: Ali\nuid: alice\ntitle: Rep\nlockedByIntruder: TRUE\nloginIntruderAttempts: 5",
            "dn: cn=bob,ou=Engineering,o=acme\nobjectClass: inetOrgPerson\ncn: bob\nsn: Bob\nuid: bob",
            "dn: cn=gone,ou=Sales,o=acme\nobjectClass: inetOrgPerson\ncn: gone\nsn: Gone\nuid: gone\nloginDisabled: TRUE");
        idp = new FakeIdp()
            .person("alice", Map.of("name", "Alice Ali", "preferred_username", "alice", "groups", List.of("sales-editors")))
            .person("bob", Map.of("preferred_username", "bob", "groups", List.of("nobody")))
            .person("root", Map.of("preferred_username", "admin", "groups", List.of("sales-editors")))
            .person("ghost", Map.of("preferred_username", "nobody-here", "groups", List.of("sales-editors")))
            .person("gone", Map.of("preferred_username", "gone", "groups", List.of("sales-editors")));
        dataPath = tmp.newFolder("data").toPath();
        server = new Server(new DataDir(dataPath), 0, "https://localhost:8443", new PrintStream(new ByteArrayOutputStream()));
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

        server.config.update(server.config.version(), "test", "phase 3", doc -> {
            Map<String, Object> d = Json.asMap(Json.asMap(doc.get("directories")).get("acme"));
            d.put("roles", List.of(
                Map.of("group", "cn=Editors,ou=Groups,o=acme", "role", "editor", "scopes", List.of("ou=Sales,o=acme")),
                Map.of("group", "cn=Help Desk,ou=Groups,o=acme", "presets", List.of("reset", "hr"), "scopes", List.of("ou=Sales,o=acme"))));
            d.put("presets", Map.of(
                "reset", Map.of("name", "Reset password and unlock", "objectClass", "inetOrgPerson", "actions", List.of("password", "unlock")),
                "hr", Map.of("name", "Edit title", "actions", List.of("attributes"), "attributes", List.of(
                    Map.of("name", "title", "required", true, "pattern", "[A-Za-z ]{2,40}"),
                    Map.of("name", "sn", "readOnly", true),
                    Map.of("name", "description", "value", "changed by HR")))));
            d.put("oidc", Map.of("issuer", idp.issuer, "clientId", "console", "label", "Acme SSO", "claim", "preferred_username",
                "attribute", "uid", "searchBases", List.of("o=acme", "o=system"),
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
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(path.startsWith("http") ? path : base + path))
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
        return headers(r);
    }

    private static Map<String, String> headers(Reply r) {
        String cookie = r.raw().headers().allValues("Set-Cookie").stream().filter(c -> c.startsWith(Server.COOKIE + "=")).findFirst().orElseThrow();
        Map<String, String> h = new HashMap<>();
        h.put("Cookie", cookie.substring(0, cookie.indexOf(';')));
        return h;
    }

    private Map<String, String> withCsrf(Map<String, String> h) throws Exception {
        Map<String, String> out = new HashMap<>(h);
        out.put("X-CSRF-Token", String.valueOf(call("GET", "/api/v2/session", null, h).body().get("csrf")));
        return out;
    }

    private String guid(Map<String, String> h, String dn) throws Exception {
        Reply r = call("GET", "/api/v2/trees/acme/objects?dn=" + java.net.URLEncoder.encode(dn, "UTF-8"), null, h);
        assertEquals(String.valueOf(r.body()), 200, r.status());
        return (String) r.body().get("guid");
    }

    /** A PATCH with the object's current ETag. */
    private Reply patch(Map<String, String> h, String guid, Object body) throws Exception {
        String etag = call("GET", "/api/v2/trees/acme/objects/" + guid, null, h).raw().headers().firstValue("ETag").orElse("\"none\"");
        Map<String, String> hh = new HashMap<>(h);
        hh.put("If-Match", etag);
        return call("PATCH", "/api/v2/trees/acme/objects/" + guid, body, hh);
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

    // ---- scoped roles ---------------------------------------------------------------------------

    @Test
    public void aScopedEditorChangesOnlyObjectsUnderItsContainers() throws Exception {
        Map<String, String> h = withCsrf(signIn("cn=ed,ou=Sales,o=acme", "ed-pw"));
        Map<String, Object> me = call("GET", "/api/v2/session", null, h).body();
        assertEquals(List.of("editor"), me.get("roles"));
        assertEquals(List.of("ou=Sales,o=acme"), Json.asMap(((List<?>) me.get("grants")).get(0)).get("scopes"));

        String alice = guid(h, "cn=alice,ou=Sales,o=acme");
        String bob = guid(h, "cn=bob,ou=Engineering,o=acme");
        assertEquals(true, Json.asMap(call("GET", "/api/v2/trees/acme/objects/" + alice, null, h).body().get("allowed")).get("edit"));
        assertEquals("reading outside the scope is eDirectory's business", false,
            Json.asMap(call("GET", "/api/v2/trees/acme/objects/" + bob, null, h).body().get("allowed")).get("edit"));

        Map<String, Object> patch = Map.of("changes", List.of(Map.of("op", "replace", "attribute", "title", "values", List.of("Lead"))));
        assertEquals(200, patch(h, alice, patch).status());
        Reply refused = patch(h, bob, patch);
        assertEquals(403, refused.status());
        assertEquals("out-of-scope", refused.body().get("title"));
        Map<String, String> hm = new HashMap<>(h);
        hm.put("If-Match", call("GET", "/api/v2/trees/acme/objects/" + alice, null, h).raw().headers().firstValue("ETag").orElseThrow());
        Reply move = call("POST", "/api/v2/trees/acme/objects/" + alice + "/move", Map.of("newParent", guid(h, "ou=Engineering,o=acme")), hm);
        assertEquals("a move out of the scope", "out-of-scope", move.body().get("title"));
        assertEquals("a search is a read", 200, call("POST", "/api/v2/trees/acme/search", Map.of("filter", Map.of("eq", Map.of("cn", "bob"))), h).status());

        // membership writes both sides: a group outside the scope is refused for that pair only
        Reply groups = call("POST", "/api/v2/trees/acme/objects/" + alice + "/memberships",
            Map.of("add", List.of(Map.of("dn", "cn=Sales Team,ou=Sales,o=acme"), Map.of("dn", "cn=Editors,ou=Groups,o=acme"))), h);
        assertEquals(207, groups.status());
        List<?> results = (List<?>) groups.body().get("results");
        assertEquals("ok", Json.asMap(results.get(0)).get("status"));
        assertEquals("refused", Json.asMap(results.get(1)).get("status"));
    }

    @Test
    public void eDirectoryAdministrationNeedsAWholeTreeEditorAndOnProductionTheName() throws Exception {
        Map<String, String> ed = withCsrf(signIn("cn=ed,ou=Sales,o=acme", "ed-pw"));
        assertEquals("reads are open to any role", 200, call("GET", "/api/v2/trees/acme/edir/servers", null, ed).status());
        Reply scoped = call("POST", "/api/v2/trees/acme/edir/schema/attributes", Map.of("name", "x", "syntax", "1.3.6.1.4.1.1466.115.121.1.15"), ed);
        assertEquals("a scoped editor cannot change the schema", 403, scoped.status());

        Map<String, String> admin = withCsrf(signIn("cn=admin,o=system", "admin-pw"));
        server.config.update(server.config.version(), "test", "production", doc ->
            Json.asMap(Json.asMap(doc.get("directories")).get("acme")).put("tier", "production"));
        Reply unconfirmed = call("POST", "/api/v2/trees/acme/edir/schema/attributes", Map.of("name", "x", "syntax", "1.3.6.1.4.1.1466.115.121.1.15"), admin);
        assertEquals(409, unconfirmed.status());
        assertEquals("confirm-directory", unconfirmed.body().get("title"));
        assertEquals("bad input is still refused after the confirmation", 400, call("POST", "/api/v2/trees/acme/edir/schema/attributes",
            Map.of("name", "1bad", "syntax", "1.3.6.1.4.1.1466.115.121.1.15"), withHeader(admin, "X-Confirm-Directory", "Acme")).status());
    }

    private static Map<String, String> withHeader(Map<String, String> h, String k, String v) {
        Map<String, String> out = new HashMap<>(h);
        out.put(k, v);
        return out;
    }

    // ---- task presets ---------------------------------------------------------------------------

    @Test
    public void aHelpDeskRunsOnlyItsPresetsWithinItsScope() throws Exception {
        Map<String, String> h = withCsrf(signIn("cn=help,ou=Sales,o=acme", "help-pw"));
        assertEquals(List.of(), call("GET", "/api/v2/session", null, h).body().get("roles"));
        List<?> presets = (List<?>) call("GET", "/api/v2/trees/acme/presets", null, h).body().get("list");
        assertEquals(2, presets.size());
        String alice = guid(h, "cn=alice,ou=Sales,o=acme");
        String bob = guid(h, "cn=bob,ou=Engineering,o=acme");
        assertEquals(List.of("hr", "reset"), Json.asMap(call("GET", "/api/v2/trees/acme/objects/" + alice, null, h).body().get("allowed")).get("presets"));

        Reply ran = call("POST", "/api/v2/trees/acme/objects/" + alice + "/presets/reset", Map.of("password", "N3w-secret!", "unlock", true), h);
        assertEquals(String.valueOf(ran.body()), 200, ran.status());
        assertEquals("FALSE", edir.server.getEntry("cn=alice,ou=Sales,o=acme").getAttributeValue("lockedByIntruder"));
        assertFalse(edir.server.getEntry("cn=alice,ou=Sales,o=acme").hasAttribute("loginIntruderAttempts"));

        assertEquals("not this preset's action", 403,
            call("POST", "/api/v2/trees/acme/objects/" + alice + "/presets/reset", Map.of("attributes", Map.of("title", "Boss")), h).status());
        assertEquals("outside the scope", 403,
            call("POST", "/api/v2/trees/acme/objects/" + bob + "/presets/reset", Map.of("unlock", true), h).status());
        assertEquals("wrong class", 409,
            call("POST", "/api/v2/trees/acme/objects/" + guid(h, "cn=Sales Team,ou=Sales,o=acme") + "/presets/reset", Map.of("unlock", true), h).status());
        assertEquals("no editor role", 403, patch(h, alice,
            Map.of("changes", List.of(Map.of("op", "replace", "attribute", "title", "values", List.of("x"))))).status());

        // field rules
        assertEquals(400, call("POST", "/api/v2/trees/acme/objects/" + alice + "/presets/hr", Map.of("attributes", Map.of("title", "B0ss!")), h).status());
        assertEquals("required", 400, call("POST", "/api/v2/trees/acme/objects/" + alice + "/presets/hr", Map.of("attributes", Map.of("title", "")), h).status());
        assertEquals("read-only", 403, call("POST", "/api/v2/trees/acme/objects/" + alice + "/presets/hr", Map.of("attributes", Map.of("sn", "X")), h).status());
        assertEquals("not in the preset", 403, call("POST", "/api/v2/trees/acme/objects/" + alice + "/presets/hr", Map.of("attributes", Map.of("mail", "x@y")), h).status());
        Reply hr = call("POST", "/api/v2/trees/acme/objects/" + alice + "/presets/hr", Map.of("attributes", Map.of("title", "Sales Lead")), h);
        assertEquals(String.valueOf(hr.body()), 200, hr.status());
        assertEquals("Sales Lead", edir.server.getEntry("cn=alice,ou=Sales,o=acme").getAttributeValue("title"));
        assertEquals("the preset value rides along", "changed by HR", edir.server.getEntry("cn=alice,ou=Sales,o=acme").getAttributeValue("description"));
        String a = audit();
        assertTrue(a.contains("preset.run"));
        assertFalse("no password in the audit log", a.contains("N3w-secret!"));
    }

    // ---- OpenID Connect -------------------------------------------------------------------------

    /** The browser's part: start, follow the provider back, and present the callback with the state cookie. */
    private Reply sso(String person, String next) throws Exception {
        idp.signInAs = person;
        Reply start = call("GET", "/api/v2/oidc/start?directory=acme&next=" + java.net.URLEncoder.encode(next, "UTF-8"), null, Map.of());
        assertEquals(302, start.status());
        String state = start.raw().headers().allValues("Set-Cookie").stream().filter(c -> c.startsWith(Server.OIDC_COOKIE + "=")).findFirst().orElseThrow();
        assertTrue(state.contains("SameSite=Lax"));
        Reply atIdp = call("GET", start.raw().headers().firstValue("Location").orElseThrow(), null, Map.of());
        assertEquals(302, atIdp.status());
        String back = atIdp.raw().headers().firstValue("Location").orElseThrow();
        assertTrue(back, back.startsWith("https://localhost:8443/api/v2/oidc/callback?"));
        return call("GET", base + back.substring("https://localhost:8443".length()), null, Map.of("Cookie", state.substring(0, state.indexOf(';'))));
    }

    @Test
    public void singleSignOnActsAsTheMappedPerson() throws Exception {
        assertEquals("Acme SSO", Json.asMap(((List<?>) call("GET", "/api/v2/directories", null, Map.of()).body().get("list")).get(0)).get("sso"));
        Reply cb = sso("alice", "/browse");
        assertEquals(302, cb.status());
        assertEquals("/browse", cb.raw().headers().firstValue("Location").orElseThrow());
        Map<String, String> h = withCsrf(headers(cb));
        Map<String, Object> me = call("GET", "/api/v2/session", null, h).body();
        assertEquals("oidc", me.get("via"));
        assertEquals("cn=alice,ou=Sales,o=acme", me.get("dn"));
        assertEquals("Alice Ali", me.get("name"));
        assertEquals(List.of("editor"), me.get("roles"));

        // operations go through the service account's connection, as alice
        String bob = guid(h, "cn=bob,ou=Engineering,o=acme");
        String self = guid(h, "cn=alice,ou=Sales,o=acme");
        Map<String, Object> patch = Map.of("changes", List.of(Map.of("op", "replace", "attribute", "title", "values", List.of("Lead"))));
        assertEquals(200, patch(h, self, patch).status());
        assertEquals("the scope still applies", 403, patch(h, bob, patch).status());
        assertEquals("the modify carried the proxied-authorization control", "dn:cn=alice,ou=Sales,o=acme", edir.lastProxied);
        Reply idm = call("GET", "/api/v2/trees/acme/idm", null, h);
        assertEquals(false, idm.body().get("available"));
        assertTrue(String.valueOf(idm.body().get("problem")).contains("direct sign-in"));
        assertTrue(audit().contains("\"via\":\"oidc\""));
    }

    @Test
    public void singleSignOnRefusals() throws Exception {
        assertEquals("/?sso-error=no-role", sso("bob", "/").raw().headers().firstValue("Location").orElseThrow());
        assertEquals("the tree admin is never acted as", "/?sso-error=never-proxy", sso("root", "/").raw().headers().firstValue("Location").orElseThrow());
        assertEquals("/?sso-error=no-account", sso("ghost", "/").raw().headers().firstValue("Location").orElseThrow());
        assertEquals("a disabled account", "/?sso-error=no-account", sso("gone", "/").raw().headers().firstValue("Location").orElseThrow());
        assertEquals("an outside next becomes /", "/", sso("alice", "//evil.example/").raw().headers().firstValue("Location").orElseThrow());

        // a callback without the browser's state cookie (started elsewhere) is refused
        idp.signInAs = "alice";
        Reply start = call("GET", "/api/v2/oidc/start?directory=acme", null, Map.of());
        Reply atIdp = call("GET", start.raw().headers().firstValue("Location").orElseThrow(), null, Map.of());
        String back = atIdp.raw().headers().firstValue("Location").orElseThrow();
        Reply cb = call("GET", base + back.substring("https://localhost:8443".length()), null, Map.of());
        assertEquals("/?sso-error=state", cb.raw().headers().firstValue("Location").orElseThrow());
        assertTrue(cb.raw().headers().allValues("Set-Cookie").stream().noneMatch(c -> c.startsWith(Server.COOKIE + "=")));
    }

    // ---- settings -------------------------------------------------------------------------------

    @Test
    public void adminsChangeSignInAndAuthorizationSettings() throws Exception {
        Map<String, String> h = withCsrf(signIn("cn=admin,o=system", "admin-pw"));
        Reply s = call("GET", "/api/v2/directories/acme/settings", null, h);
        assertEquals(200, s.status());
        assertEquals("https://localhost:8443/api/v2/oidc/callback", s.body().get("redirectUri"));
        assertEquals(false, Json.asMap(s.body().get("oidc")).get("clientSecretSet"));

        Map<String, Object> o = new HashMap<>(Json.asMap(s.body().get("oidc")));
        o.put("clientSecret", "Very-secret-1");
        Reply saved = call("PUT", "/api/v2/directories/acme/oidc", o, h);
        assertEquals(String.valueOf(saved.body()), 200, saved.status());
        assertEquals(true, Json.asMap(saved.body().get("oidc")).get("clientSecretSet"));
        o.remove("clientSecret");
        o.put("label", "Acme login");
        assertEquals("an absent secret is kept", true, Json.asMap(call("PUT", "/api/v2/directories/acme/oidc", o, h).body().get("oidc")).get("clientSecretSet"));
        assertFalse(Files.readString(dataPath.resolve("config/current.json")).contains("Very-secret-1"));
        assertFalse(audit().contains("Very-secret-1"));

        assertEquals("admin cannot be scoped", 400, call("PUT", "/api/v2/directories/acme/roles",
            List.of(Map.of("group", "cn=Editors,ou=Groups,o=acme", "role", "admin", "scopes", List.of("ou=Sales,o=acme"))), h).status());
        assertEquals("an unknown preset", 400, call("PUT", "/api/v2/directories/acme/roles",
            List.of(Map.of("group", "cn=Editors,ou=Groups,o=acme", "presets", List.of("nope"))), h).status());
        assertEquals("a granted preset cannot be removed", 400, call("PUT", "/api/v2/directories/acme/presets", Map.of(), h).status());
        Reply exported = call("GET", "/api/v2/directories/acme/presets", null, h);
        assertEquals(200, call("PUT", "/api/v2/directories/acme/presets", exported.body(), h).status());
        assertEquals(400, call("PUT", "/api/v2/directories/acme/presets",
            Map.of("reset", Map.of("actions", List.of("password")), "hr", Map.of("actions", List.of("teleport"))), h).status());

        Reply test = call("POST", "/api/v2/directories/acme/oidc/test", Map.of("value", "alice"), h);
        assertEquals(List.of("cn=alice,ou=Sales,o=acme"), test.body().get("matches"));
        assertEquals(true, call("POST", "/api/v2/directories/acme/oidc/test", Map.of("value", "admin"), h).body().get("neverProxy"));

        Map<String, String> ed = withCsrf(signIn("cn=ed,ou=Sales,o=acme", "ed-pw"));
        assertEquals(403, call("GET", "/api/v2/directories/acme/settings", null, ed).status());

        // step-up: a wrong password is refused without ending the session; the right one refreshes it
        assertEquals(401, call("POST", "/api/v2/session/step-up", Map.of("password", "wrong"), h).status());
        assertEquals(200, call("GET", "/api/v2/session", null, h).status());
        assertEquals(204, call("POST", "/api/v2/session/step-up", Map.of("password", "admin-pw"), h).status());
        assertTrue(audit().contains("settings.oidc"));
    }
}
