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
        base = "https://localhost:" + server.port();
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
