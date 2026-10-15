package com.pointblue.console.server.http;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/** The real server over HTTPS: bootstrap from the printed token to the first sign-in, and the guards. */
public class ServerTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private FakeEdir edir;
    private Path dataPath;
    private Server server;
    private HttpClient http;
    private String base;
    private final ByteArrayOutputStream log = new ByteArrayOutputStream();

    @Before
    public void start() throws Exception {
        System.setProperty("jdk.httpclient.allowRestrictedHeaders", "host");
        edir = new FakeEdir(
            "dn: cn=admin,o=system\nobjectClass: inetOrgPerson\ncn: admin\nsn: a\nuserPassword: admin-pw",
            "dn: cn=console,o=system\nobjectClass: inetOrgPerson\ncn: console\nsn: c\nuserPassword: console-pw");
        dataPath = tmp.newFolder("data").toPath();
        boot();
    }

    private void boot() throws Exception {
        server = new Server(new DataDir(dataPath), 0, "https://localhost:8443", new PrintStream(log, true, StandardCharsets.UTF_8));
        server.start();
        base = "https://127.0.0.1:" + server.port();
        // trust exactly the console's own certificate, as a person does after checking its fingerprint
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setCertificateEntry("console", server.tls.certificate());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tmf.getTrustManagers(), null);
        http = HttpClient.newBuilder().sslContext(ctx).build();
    }

    @After
    public void stop() {
        server.stop();
        edir.close();
    }

    record Reply(int status, Map<String, Object> body, HttpResponse<String> raw) {
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
        return new Reply(r.statusCode(), parsed instanceof Map ? Json.asMap(parsed) : Map.of("list", parsed), r);
    }

    private String token() throws Exception {
        Matcher m = Pattern.compile("Setup token: ([0-9a-f]{32})").matcher(Files.readString(dataPath.resolve("bootstrap.txt")));
        assertTrue(m.find());
        return m.group(1);
    }

    @Test
    public void bootstrapToFirstSignIn() throws Exception {
        // bootstrap mode: only health and the token-guarded setup API
        assertEquals(200, call("GET", "/api/v2/health/live", null, Map.of()).status());
        assertEquals(503, call("GET", "/api/v2/health/ready", null, Map.of()).status());
        assertEquals(503, call("GET", "/api/v2/session", null, Map.of()).status());
        assertEquals(401, call("GET", "/api/v2/setup", null, Map.of("X-Setup-Token", "0".repeat(32))).status());
        String token = token();
        String printed = log.toString(StandardCharsets.UTF_8);
        assertTrue("the log shows the token and the console's fingerprint", printed.contains(token) && printed.contains(Certs.sha256(server.tls.certificate())));
        Map<String, String> t = Map.of("X-Setup-Token", token);

        assertEquals(200, call("PUT", "/api/v2/setup/directory", Map.of("id", "prod", "name", "Production", "host", "127.0.0.1", "port", edir.port(), "tier", "lab"), t).status());
        Reply probe = call("POST", "/api/v2/setup/probe", Map.of(), t);
        assertEquals("untrusted", probe.body().get("status"));
        assertEquals(1, Json.asInt(probe.body().get("recommended"), -1));
        String probeId = (String) probe.body().get("probeId");
        assertEquals("a wrong confirmation is refused", 400, call("POST", "/api/v2/setup/trust", Map.of("probeId", probeId, "confirm", "00000000"), t).status());
        Reply trusted = call("POST", "/api/v2/setup/trust", Map.of("probeId", probeId, "confirm", Certs.tail(edir.pki.ca, 8)), t);
        assertEquals(200, trusted.status());
        assertEquals(true, Json.asMap(trusted.body().get("connection")).get("trusted"));

        assertEquals(409, call("POST", "/api/v2/setup/finish", Map.of(), t).status());
        assertEquals(401, call("POST", "/api/v2/setup/authority", Map.of("dn", "cn=admin,o=system", "password", "wrong"), t).status());
        assertEquals(200, call("POST", "/api/v2/setup/authority", Map.of("dn", "cn=admin,o=system", "password", "admin-pw"), t).status());
        assertEquals(200, call("PUT", "/api/v2/setup/service-account", Map.of("dn", "cn=console,o=system", "password", "console-pw"), t).status());
        assertEquals(200, call("PUT", "/api/v2/setup/login", Map.of("duplicates", "error", "searchBases", List.of("o=acme")), t).status());
        assertEquals(200, call("POST", "/api/v2/setup/finish", Map.of(), t).status());

        // bootstrap is over for good
        assertFalse(server.bootstrapping());
        assertFalse(Files.exists(dataPath.resolve("bootstrap.txt")));
        assertEquals(404, call("GET", "/api/v2/setup", null, t).status());
        assertEquals(200, call("GET", "/api/v2/health/ready", null, Map.of()).status());
        assertFalse("the service account's password is sealed on disk",
            Files.readString(dataPath.resolve("config/current.json")).contains("console-pw"));

        // the bootstrap admin signs in (break-glass)
        assertEquals(401, call("POST", "/api/v2/session", Map.of("directory", "prod", "name", "cn=admin,o=system", "password", "nope"), Map.of()).status());
        Reply in = call("POST", "/api/v2/session", Map.of("directory", "prod", "name", "cn=admin,o=system", "password", "admin-pw"), Map.of());
        assertEquals(200, in.status());
        String cookie = in.raw().headers().firstValue("Set-Cookie").orElseThrow();
        assertTrue(cookie, cookie.startsWith("__Host-console=") && cookie.contains("Secure") && cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"));
        Map<String, String> session = Map.of("Cookie", cookie.substring(0, cookie.indexOf(';')));
        String csrf = (String) in.body().get("csrf");
        assertEquals(List.of("admin"), in.body().get("roles"));

        Reply cfg = call("GET", "/api/v2/config", null, session);
        assertEquals(200, cfg.status());
        assertFalse(Json.compact(cfg.body()).contains("console-pw"));
        assertFalse(Json.compact(cfg.body()).contains("v1:"));
        assertEquals(1, ((List<?>) Json.asMap(call("GET", "/api/v2/trust/certificates", null, session).body()).get("certificates")).size());
        assertEquals(true, call("GET", "/api/v2/audit/verify", null, session).body().get("intact"));

        // guards
        assertEquals("a write without the CSRF token", 403,
            call("POST", "/api/v2/trust/probe", Map.of("directory", "prod"), session).status());
        assertEquals(200, call("POST", "/api/v2/trust/probe", Map.of("directory", "prod"), Map.of("Cookie", session.get("Cookie"), "X-CSRF-Token", csrf)).status());
        Map<String, String> w = Map.of("Cookie", session.get("Cookie"), "X-CSRF-Token", csrf);
        Reply other = call("POST", "/api/v2/trust/probe", Map.of("directory", "prod", "host", "localhost", "port", edir.port()), w);
        assertEquals("another server of the directory, by a name its certificate lacks: judged with the directory's CA",
            "hostname", other.body().get("status"));
        assertEquals("localhost", other.body().get("host"));
        assertEquals("the same address without the directory: its CA is not trusted globally", "untrusted",
            call("POST", "/api/v2/trust/probe", Map.of("host", "localhost", "port", edir.port()), w).body().get("status"));
        String leaf = ((String) Json.asMap(((List<?>) other.body().get("chain")).get(0)).get("sha256")).replace(":", "");
        assertEquals(201, call("POST", "/api/v2/trust/host-exceptions", Map.of("probeId", other.body().get("probeId"), "confirm", leaf.substring(56)), w).status());
        List<?> exceptions = (List<?>) call("GET", "/api/v2/trust/certificates", null, session).body().get("hostExceptions");
        assertEquals(1, exceptions.size());
        assertEquals(other.body().get("chain") instanceof List<?> c ? Json.asMap(c.get(0)).get("sha256") : null, Json.asMap(exceptions.get(0)).get("sha256"));
        assertEquals("trusted at that address now", "trusted",
            call("POST", "/api/v2/trust/probe", Map.of("directory", "prod", "host", "localhost", "port", edir.port()), w).body().get("status"));
        Map<String, Object> where = Map.of("host", "localhost", "port", edir.port());
        assertEquals(204, call("DELETE", "/api/v2/trust/host-exceptions", where, w).status());
        assertEquals(404, call("DELETE", "/api/v2/trust/host-exceptions", where, w).status());
        assertEquals(List.of(), call("GET", "/api/v2/trust/certificates", null, session).body().get("hostExceptions"));
        assertEquals(List.of(), call("GET", "/api/v2/trust/certificates", null, session).body().get("alerts"));
        assertEquals("no alert to dismiss", 404, call("DELETE", "/api/v2/trust/alerts", where, w).status());
        Map<String, Object> listed = Json.asMap(((List<?>) call("GET", "/api/v2/trust/certificates", null, session).body().get("certificates")).get(0));
        assertTrue(listed.containsKey("notBefore") && listed.containsKey("names") && listed.containsKey("selfSigned"));
        assertEquals("another site's page", 403, call("POST", "/api/v2/trust/probe", Map.of("directory", "prod"),
            Map.of("Cookie", session.get("Cookie"), "X-CSRF-Token", csrf, "Origin", "https://evil.example")).status());
        assertEquals("DNS rebinding", 421, call("GET", "/api/v2/session", null, Map.of("Host", "evil.example")).status());
        Reply headers = call("GET", "/api/v2/session", null, session);
        assertNotNull(headers.raw().headers().firstValue("Content-Security-Policy").orElse(null));
        assertEquals("no-store", headers.raw().headers().firstValue("Cache-Control").orElse(""));

        assertEquals(204, call("DELETE", "/api/v2/session", null, Map.of("Cookie", session.get("Cookie"), "X-CSRF-Token", csrf)).status());
        assertEquals(401, call("GET", "/api/v2/session", null, session).status());

        // a restart comes up configured, with the same certificate
        String fp = Certs.sha256(server.tls.certificate());
        server.stop();
        boot();
        assertFalse(server.bootstrapping());
        assertEquals(fp, Certs.sha256(server.tls.certificate()));
    }

    @Test
    public void firstSignInSetsUpInOneStep() throws Exception {
        Map<String, String> t = Map.of("X-Setup-Token", token());
        Map<String, Object> body = new java.util.HashMap<>(Map.of("host", "127.0.0.1", "port", edir.port(), "dn", "cn=admin,o=system", "password", "admin-pw"));

        // the tree's certificate is not trusted yet: offered, with the probe
        Reply offered = call("POST", "/api/v2/setup/first-sign-in", body, t);
        assertEquals(String.valueOf(offered.body()), 409, offered.status());
        assertEquals("untrusted-certificate", offered.body().get("title"));
        Map<String, Object> probe = Json.asMap(offered.body().get("probe"));
        String probeId = (String) probe.get("probeId");

        body.put("accept", Map.of("probeId", probeId, "confirm", "00000000"));
        assertEquals("a wrong confirmation", 400, call("POST", "/api/v2/setup/first-sign-in", body, t).status());
        body.put("accept", Map.of("probeId", probeId, "confirm", Certs.tail(edir.pki.ca, 8)));
        body.put("password", "wrong");
        assertEquals(401, call("POST", "/api/v2/setup/first-sign-in", body, t).status());
        assertTrue("a refused sign-in leaves no trust behind", server.trust.entries().isEmpty());
        assertTrue(server.bootstrapping());

        body.put("password", "admin-pw");
        Reply done = call("POST", "/api/v2/setup/first-sign-in", body, t);
        assertEquals(String.valueOf(done.body()), 200, done.status());
        String id = (String) done.body().get("directory");
        assertFalse(server.bootstrapping());
        assertEquals("the CA is trusted for that tree", List.of("directory:" + id), server.trust.entries().stream().map(e -> e.scope()).toList());

        // then the browser signs in as usual, as the break-glass administrator
        Reply in = call("POST", "/api/v2/session", Map.of("directory", id, "name", "cn=admin,o=system", "password", "admin-pw"), Map.of());
        assertEquals(200, in.status());
        assertEquals(List.of("admin"), in.body().get("roles"));
        Map<String, Object> dir = Json.asMap(Json.asMap(Json.asMap(Json.parse(Files.readString(dataPath.resolve("config/current.json")))).get("directories")).get(id));
        assertEquals("production", dir.get("tier"));
        assertEquals(List.of("cn=admin,o=system"), dir.get("breakGlass"));
        String cookie = in.raw().headers().firstValue("Set-Cookie").orElseThrow();
        Map<String, String> w = Map.of("Cookie", cookie.substring(0, cookie.indexOf(';')), "X-CSRF-Token", (String) in.body().get("csrf"));

        // what first sign-in leaves for later, in Settings
        String at = "/api/v2/directories/" + id;
        assertEquals("lab", call("PUT", at + "/tier", Map.of("tier", "lab"), w).body().get("tier"));
        assertEquals(400, call("PUT", at + "/tier", Map.of("tier", "staging"), w).status());
        Map<String, Object> login = Json.asMap(call("PUT", at + "/login", Map.of("searchBases", List.of("o=system", " "), "duplicates", "error"), w).body().get("login"));
        assertEquals(List.of("o=system"), login.get("searchBases"));
        assertEquals("error", login.get("duplicates"));
        assertEquals(401, call("PUT", at + "/service-account", Map.of("dn", "cn=console,o=system", "password", "nope"), w).status());
        assertEquals("cn=console,o=system", call("PUT", at + "/service-account", Map.of("dn", "cn=console,o=system", "password", "console-pw"), w).body().get("serviceAccount"));
        assertFalse("sealed on disk", Files.readString(dataPath.resolve("config/current.json")).contains("console-pw"));
        // with the service account and a search base, a bare name signs in
        assertEquals(200, call("POST", "/api/v2/session", Map.of("directory", id, "name", "admin", "password", "admin-pw"), Map.of()).status());
        assertEquals(null, call("PUT", at + "/service-account", null, w).body().get("serviceAccount"));

        // session limits for this tree: shown to the UI, refused outside the allowed range
        assertEquals(1800, Json.asInt(Json.asMap(call("GET", "/api/v2/session", null, w).body().get("session")).get("idleSeconds"), 0));
        assertEquals(400, call("PUT", at + "/session", Map.of("idleMinutes", 2, "maxHours", 8), w).status());
        assertEquals(400, call("PUT", at + "/session", Map.of("idleMinutes", 15, "maxHours", 48), w).status());
        Map<String, Object> saved = Json.asMap(call("PUT", at + "/session", Map.of("idleMinutes", 15, "maxHours", 8), w).body().get("session"));
        assertEquals(15, Json.asInt(saved.get("idleMinutes"), 0));
        assertEquals(8, Json.asInt(saved.get("maxHours"), 0));
        Map<String, Object> now = Json.asMap(call("GET", "/api/v2/session", null, w).body().get("session"));
        assertEquals("applies to this session at once", 900, Json.asInt(now.get("idleSeconds"), 0));
        Reply any = call("GET", "/api/v2/session", null, w);
        assertEquals("every signed-in answer carries the limits", "900", any.raw().headers().firstValue("X-Session-Idle-Seconds").orElse(null));
        assertEquals(now.get("expiresAt"), any.raw().headers().firstValue("X-Session-Expires").orElse(null));
        assertTrue(String.valueOf(now.get("expiresAt")).matches("\\d{4}-.*Z"));
    }

    /** First sign-in to {@code edir}, accepting its CA; the new tree's id. */
    private String firstSignIn() throws Exception {
        Map<String, String> t = Map.of("X-Setup-Token", token());
        Map<String, Object> body = new java.util.HashMap<>(Map.of("host", "127.0.0.1", "port", edir.port(), "dn", "cn=admin,o=system", "password", "admin-pw"));
        String probeId = (String) Json.asMap(call("POST", "/api/v2/setup/first-sign-in", body, t).body().get("probe")).get("probeId");
        body.put("accept", Map.of("probeId", probeId, "confirm", Certs.tail(edir.pki.ca, 8)));
        return (String) call("POST", "/api/v2/setup/first-sign-in", body, t).body().get("directory");
    }

    private Map<String, String> signedIn(String directory, String dn, String pw) throws Exception {
        Reply in = call("POST", "/api/v2/session", Map.of("directory", directory, "name", dn, "password", pw), Map.of());
        assertEquals(String.valueOf(in.body()), 200, in.status());
        String cookie = in.raw().headers().firstValue("Set-Cookie").orElseThrow();
        return Map.of("Cookie", cookie.substring(0, cookie.indexOf(';')), "X-CSRF-Token", (String) in.body().get("csrf"));
    }

    @Test
    public void severalTrees() throws Exception {
        String prod = firstSignIn();
        Map<String, String> w = signedIn(prod, "cn=admin,o=system", "admin-pw");
        try (FakeEdir test = new FakeEdir("dn: cn=testadmin,o=system\nobjectClass: inetOrgPerson\ncn: testadmin\nsn: t\nuserPassword: test-pw")) {
            Map<String, Object> add = new java.util.HashMap<>(Map.of("name", "Test", "tier", "lab", "host", "localhost", "port", test.port(),
                "dn", "cn=testadmin,o=system", "password", "test-pw"));
            Reply offered = call("POST", "/api/v2/console/trees", add, w);
            assertEquals(String.valueOf(offered.body()), "untrusted-certificate", offered.body().get("title"));
            add.put("accept", Map.of("probeId", Json.asMap(offered.body().get("probe")).get("probeId"), "confirm", Certs.tail(test.pki.ca, 8)));
            add.put("password", "wrong");
            assertEquals("the new tree's own administrator is needed", 401, call("POST", "/api/v2/console/trees", add, w).status());
            add.put("password", "test-pw");
            Reply added = call("POST", "/api/v2/console/trees", add, w);
            assertEquals(String.valueOf(added.body()), 201, added.status());
            assertEquals("test", added.body().get("id"));
            assertEquals("lab", added.body().get("tier"));
            assertEquals("the same address again", 409, call("POST", "/api/v2/console/trees", add, w).status());

            // the sign-in list offers both; each tree has its own break-glass administrator
            List<?> dirs = (List<?>) call("GET", "/api/v2/directories", null, Map.of()).body().get("list");
            assertEquals(2, dirs.size());
            assertEquals(401, call("POST", "/api/v2/session", Map.of("directory", "test", "name", "cn=admin,o=system", "password", "admin-pw"), Map.of()).status());
            Map<String, String> onTest = signedIn("test", "cn=testadmin,o=system", "test-pw");
            Map<String, Object> me = call("GET", "/api/v2/session", null, onTest).body();
            assertEquals("test", me.get("directory"));
            assertEquals(List.of("admin"), me.get("roles"));
            List<?> trees = (List<?>) call("GET", "/api/v2/console/trees", null, onTest).body().get("list");
            assertEquals(List.of(false, true), trees.stream().map(x -> Json.asMap(x).get("current")).toList());

            assertEquals("Test (lab)", call("PATCH", "/api/v2/console/trees/test", Map.of("name", "Test (lab)"), w).body().get("name"));
            assertEquals("not the tree you are signed in to", 409, call("DELETE", "/api/v2/console/trees/" + prod, Map.of("name", "x"), w).status());
            assertEquals("the name typed", 409, call("DELETE", "/api/v2/console/trees/test", Map.of("name", "Test"), w).status());
            assertEquals(204, call("DELETE", "/api/v2/console/trees/test", Map.of("name", "Test (lab)"), w).status());
            assertEquals("its sessions end", 401, call("GET", "/api/v2/session", null, onTest).status());
            assertEquals(1, ((List<?>) call("GET", "/api/v2/directories", null, Map.of()).body().get("list")).size());
            assertTrue("its certificates go", server.trust.entries().stream().noneMatch(e -> e.scope().equals("directory:test")));
        }
    }

    @Test
    public void setupTokenAttemptsAreLimited() throws Exception {
        int limited = 0;
        for (int i = 0; i < 8; i++) {
            if (call("GET", "/api/v2/setup", null, Map.of("X-Setup-Token", "f".repeat(32))).status() == 429) {
                limited++;
            }
        }
        assertTrue("after five failures a minute the address is limited", limited >= 3);
    }
}
