package com.pointblue.console.server.http;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.pointblue.console.server.data.DataDir;
import com.pointblue.console.server.idm.Engines;
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
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/** The Identity Manager API end to end, with a fake engine over the in-memory directory. */
public class IdmTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private FakeEdir edir;
    private FakeEngine engine;
    private Server server;
    private HttpClient http;
    private String base;
    private Path dataPath;

    record Reply(int status, Map<String, Object> body) {
    }

    @Before
    public void start() throws Exception {
        edir = new FakeEdir(
            "dn: cn=admin,o=system\nobjectClass: inetOrgPerson\ncn: admin\nsn: a\nuserPassword: admin-pw",
            "dn: cn=console,o=system\nobjectClass: inetOrgPerson\ncn: console\nsn: c\nuserPassword: console-pw",
            "dn: cn=Driver Set,o=system\nobjectClass: DirXML-DriverSet\ncn: Driver Set",
            "dn: cn=AD,cn=Driver Set,o=system\nobjectClass: DirXML-Driver\ncn: AD\nDirXML-TraceLevel: 3",
            "dn: cn=LDAP\\, primary,cn=Driver Set,o=system\nobjectClass: DirXML-Driver\ncn: LDAP, primary");
        engine = new FakeEngine(edir);
        engine.states.put("cn=ad,cn=driverset,o=system", Vault.STATE_RUNNING);
        dataPath = tmp.newFolder("data").toPath();
        server = new Server(new DataDir(dataPath), 0, "https://localhost:8443", new PrintStream(new ByteArrayOutputStream()));
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
    }

    @After
    public void stop() {
        server.stop();
        edir.close();
    }

    private Reply call(String method, String path, Object body, Map<String, String> headers) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path))
            .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(Json.compact(body)));
        if (body != null) {
            b.header("Content-Type", "application/json");
        }
        headers.forEach(b::header);
        HttpResponse<String> r = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
        Object parsed = r.body().isBlank() ? Map.of() : Json.parse(r.body());
        return new Reply(r.statusCode(), parsed instanceof Map ? Json.asMap(parsed) : Map.of("list", parsed));
    }

    private Map<String, String> signIn() throws Exception {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(base + "/api/v2/session")).header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(Json.compact(Map.of("directory", "acme", "name", "cn=admin,o=system", "password", "admin-pw")))).build(),
            HttpResponse.BodyHandlers.ofString());
        assertEquals(200, r.statusCode());
        String cookie = r.headers().firstValue("Set-Cookie").orElseThrow();
        Map<String, String> h = new HashMap<>();
        h.put("Cookie", cookie.substring(0, cookie.indexOf(';')));
        h.put("X-CSRF-Token", (String) Json.asMap(Json.parse(r.body())).get("csrf"));
        return h;
    }

    /** DirXMLDev's Vault class loads only with the engine's jars (mvn test -Dengine.lib=…); CI has none. */
    static boolean engineJars() {
        try {
            Class.forName("com.novell.ldap.LDAPExtendedOperation");
            Class.forName("com.novell.nds.dirxml.ldap.GetDriverStateRequest");
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    @Test
    public void driverSetsDriversAndTheirOperations() throws Exception {
        org.junit.Assume.assumeTrue("needs -Dengine.lib (the engine's jars)", engineJars());
        Map<String, String> h = signIn();
        assertEquals(true, call("GET", "/api/v2/trees/acme/idm", null, h).body().get("available"));
        List<?> sets = (List<?>) call("GET", "/api/v2/trees/acme/idm/driversets", null, h).body().get("items");
        assertEquals(1, sets.size());
        String set = (String) Json.asMap(sets.get(0)).get("guid");
        Reply status = call("GET", "/api/v2/trees/acme/idm/driversets/" + set, null, h);
        assertEquals(String.valueOf(status.body()), 200, status.status());
        List<?> drivers = (List<?>) status.body().get("drivers");
        assertEquals(2, drivers.size());
        Map<String, Object> ad = Json.asMap(drivers.get(0));
        assertEquals("AD", ad.get("name"));
        assertEquals("running", ad.get("state"));
        assertEquals("3", ad.get("traceLevel"));
        Map<String, Object> ldap = Json.asMap(drivers.get(1));
        assertEquals("a driver whose name has a comma", "LDAP, primary", ldap.get("name"));
        String ldapGuid = (String) ldap.get("guid");
        assertTrue(ldapGuid.matches("[0-9a-f]{32}"));

        Reply started = call("POST", "/api/v2/trees/acme/idm/drivers/" + ldapGuid + "/start", Map.of(), h);
        assertEquals(200, started.status());
        assertEquals("running", started.body().get("after"));
        assertTrue(engine.actions.contains("start cn=LDAP\\, primary,cn=Driver Set,o=system"));
        assertEquals(200, call("PUT", "/api/v2/trees/acme/idm/drivers/" + ldapGuid + "/start-option", Map.of("option", "auto"), h).status());
        assertEquals(Vault.START_AUTO, engine.driverStartOption("cn=LDAP\\, primary,cn=Driver Set,o=system"));
        // a disabled driver cannot start (and queues no events meanwhile): refused, with the reason
        assertEquals(200, call("PUT", "/api/v2/trees/acme/idm/drivers/" + ldapGuid + "/start-option", Map.of("option", "disabled"), h).status());
        call("POST", "/api/v2/trees/acme/idm/drivers/" + ldapGuid + "/stop", Map.of(), h);
        Reply disabled = call("POST", "/api/v2/trees/acme/idm/drivers/" + ldapGuid + "/start", Map.of(), h);
        assertEquals(String.valueOf(disabled.body()), 409, disabled.status());
        assertEquals("driver-disabled", disabled.body().get("title"));
        assertEquals(200, call("PUT", "/api/v2/trees/acme/idm/drivers/" + ldapGuid + "/start-option", Map.of("option", "auto"), h).status());
        assertEquals(404, call("GET", "/api/v2/trees/acme/idm/drivers/" + set, null, h).status());

        assertEquals(204, call("POST", "/api/v2/trees/acme/idm/drivers/" + ldapGuid + "/passwords",
            Map.of("kind", "named", "name", "api-key", "value", "S3cret-named!"), h).status());
        assertEquals(List.of("api-key"), call("GET", "/api/v2/trees/acme/idm/drivers/" + ldapGuid + "/passwords", null, h).body().get("named"));
        assertEquals(204, call("DELETE", "/api/v2/trees/acme/idm/drivers/" + ldapGuid + "/passwords", Map.of("kind", "named", "name", "api-key"), h).status());
        assertEquals(204, call("POST", "/api/v2/trees/acme/idm/drivers/" + ldapGuid + "/passwords",
            Map.of("kind", "remote-loader", "value", "rl-S3cret"), h).status());
        assertEquals(400, call("POST", "/api/v2/trees/acme/idm/drivers/" + ldapGuid + "/passwords", Map.of("kind", "bogus", "value", "x"), h).status());
        String auditText;
        try (var files = Files.list(dataPath.resolve("audit"))) {
            StringBuilder b = new StringBuilder();
            for (Path p : files.toList()) {
                b.append(Files.readString(p));
            }
            auditText = b.toString();
        }
        assertTrue(auditText.contains("idm.driver.start") && auditText.contains("idm.password.set"));
        assertFalse("no secret reaches the audit log", auditText.contains("S3cret-named!") || auditText.contains("rl-S3cret"));

        // a production directory wants its name typed
        server.config.update(server.config.version(), "test", "production", doc ->
            Json.asMap(Json.asMap(doc.get("directories")).get("acme")).put("tier", "production"));
        Reply refused = call("POST", "/api/v2/trees/acme/idm/drivers/" + ldapGuid + "/stop", Map.of(), h);
        assertEquals(409, refused.status());
        assertEquals("confirm-directory", refused.body().get("title"));
        Map<String, String> confirmed = new HashMap<>(h);
        confirmed.put("X-Confirm-Directory", "Acme");
        assertEquals(200, call("POST", "/api/v2/trees/acme/idm/drivers/" + ldapGuid + "/stop", Map.of(), confirmed).status());
        assertEquals(409, call("POST", "/api/v2/trees/acme/idm/drivers/" + ldapGuid + "/passwords", Map.of("name", "x", "value", "y"), h).status());
    }

    @Test
    public void withoutTheEngineIdmSaysWhy() throws Exception {
        server.login.engines(Engines.none("the Identity Manager engine jars are not mounted at /engine"));
        Map<String, String> h = signIn();
        Reply st = call("GET", "/api/v2/trees/acme/idm", null, h);
        assertEquals(false, st.body().get("available"));
        assertTrue(String.valueOf(st.body().get("problem")).contains("/engine"));
        assertEquals(503, call("GET", "/api/v2/trees/acme/idm/driversets", null, h).status());
        assertEquals("the rest of the console still works", 200, call("GET", "/api/v2/trees/acme/roots", null, h).status());
    }
}
