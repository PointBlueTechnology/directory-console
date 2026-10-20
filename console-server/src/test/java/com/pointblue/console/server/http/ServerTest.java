package com.pointblue.console.server.http;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.pointblue.console.server.data.DataDir;
import com.pointblue.console.server.ldap.FakeEdir;
import com.pointblue.console.server.tls.Certs;
import com.pointblue.dirxml.dev.json.Json;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.SocketTimeoutException;
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
import javax.net.ssl.SSLSocket;
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
        server = new Server(new DataDir(dataPath), ServerClient.loopback(), "https://localhost:8443", new PrintStream(log, true, StandardCharsets.UTF_8));
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
        http = HttpClient.newBuilder().sslContext(ctx).connectTimeout(ServerClient.TIMEOUT).build();
    }

    @After
    public void stop() {
        server.stop();
        edir.close();
    }

    record Reply(int status, Map<String, Object> body, HttpResponse<String> raw) {
    }

    private Reply call(String method, String path, Object body, Map<String, String> headers) throws Exception {
        HttpRequest.Builder b = ServerClient.request(URI.create(base + path))
            .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(Json.compact(body)));
        if (body != null) {
            b.header("Content-Type", "application/json");
        }
        headers.forEach(b::header);
        HttpResponse<String> r = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
        Object parsed = r.body().isBlank() ? Map.of() : Json.parse(r.body());
        return new Reply(r.statusCode(), parsed instanceof Map ? Json.asMap(parsed) : Map.of("list", parsed), r);
    }

    @Test
    public void aRequestIsAnsweredOnlyOnceItsBodyIsInSoTheConnectionServesTheNextRequest() throws Exception {
        // an answer without a body (HEAD, 204, 302) is complete once its headers are out; the JDK's server would send
        // it and only then read the request's unread body, and that read can take the client's next request into a
        // buffer the server never looks at again: the request goes unanswered until the idle timer drops the connection
        try (SSLSocket s = (SSLSocket) ServerClient.trustingContext(server).getSocketFactory().createSocket("127.0.0.1", server.port())) {
            s.setSoTimeout((int) ServerClient.TIMEOUT.toMillis());
            s.startHandshake();
            OutputStream out = s.getOutputStream();
            InputStream in = s.getInputStream();
            byte[] body = "ignored".getBytes(StandardCharsets.US_ASCII);
            out.write(("HEAD / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: " + body.length + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            out.flush();
            s.setSoTimeout(500);
            try {
                fail("answered before the body was read: " + in.read());
            } catch (SocketTimeoutException expected) {
                // still reading the body
            }
            s.setSoTimeout((int) ServerClient.TIMEOUT.toMillis());
            out.write(body);
            out.flush();
            assertEquals(200, status(in, false));
            out.write("GET /api/v2/health/live HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
            out.flush();
            assertEquals("the same connection answers the next request", 200, status(in, true));
        }
    }

    /** One HTTP/1.1 response's status, its body (if it has one) read and dropped. */
    private static int status(InputStream in, boolean hasBody) throws IOException {
        StringBuilder head = new StringBuilder();
        while (!head.toString().endsWith("\r\n\r\n")) {
            int c = in.read();
            assertTrue("the connection closed mid-response: " + head, c != -1);
            head.append((char) c);
        }
        Matcher m = Pattern.compile("(?i)content-length: *(\\d+)").matcher(head);
        if (hasBody) {
            in.readNBytes(m.find() ? Integer.parseInt(m.group(1)) : 0);
        }
        return Integer.parseInt(head.substring(9, 12));
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
        assertEquals("a probe by IP address is answered", 200, call("GET", "/api/v2/health/live", null, Map.of("Host", "10.42.0.92:8443")).status());
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

    /** A minimal SMTP server on loopback that accepts one message and keeps it. */
    private static Thread smtpStub(java.net.ServerSocket ss, StringBuilder got) {
        Thread t = new Thread(() -> {
            try (java.net.Socket c = ss.accept()) {
                java.io.BufferedReader in = new java.io.BufferedReader(new java.io.InputStreamReader(c.getInputStream(), StandardCharsets.UTF_8));
                java.io.OutputStream out = c.getOutputStream();
                java.util.function.Consumer<String> say = l -> {
                    try {
                        out.write((l + "\r\n").getBytes(StandardCharsets.UTF_8));
                        out.flush();
                    } catch (java.io.IOException e) {
                        throw new java.io.UncheckedIOException(e);
                    }
                };
                say.accept("220 stub");
                String line;
                boolean data = false;
                while ((line = in.readLine()) != null) {
                    if (data) {
                        if (line.equals(".")) {
                            data = false;
                            say.accept("250 queued");
                        } else {
                            got.append(line).append('\n');
                        }
                    } else if (line.startsWith("EHLO")) {
                        say.accept("250-stub");
                        say.accept("250 OK");
                    } else if (line.equals("DATA")) {
                        data = true;
                        say.accept("354 go");
                    } else if (line.equals("QUIT")) {
                        say.accept("221 bye");
                        return;
                    } else {
                        got.append(line).append('\n');
                        say.accept("250 OK");
                    }
                }
            } catch (java.io.IOException e) {
                // the test sees what arrived
            }
        });
        t.setDaemon(true);
        t.start();
        return t;
    }

    /** Reads octet-counted syslog frames (RFC 6587) from one connection into {@code got}. */
    private static Thread frames(java.net.ServerSocket ss, List<String> got) {
        Thread t = new Thread(() -> {
            try (java.net.Socket c = ss.accept()) {
                java.io.InputStream in = c.getInputStream();
                while (true) {
                    StringBuilder len = new StringBuilder();
                    int ch;
                    while ((ch = in.read()) != ' ') {
                        if (ch < 0) {
                            return;
                        }
                        len.append((char) ch);
                    }
                    got.add(new String(in.readNBytes(Integer.parseInt(len.toString())), StandardCharsets.UTF_8));
                }
            } catch (java.io.IOException | NumberFormatException e) {
                // the test sees what arrived
            }
        });
        t.setDaemon(true);
        t.start();
        return t;
    }

    private static void waitFor(List<String> got, String part) throws InterruptedException {
        for (int i = 0; i < 50 && got.stream().noneMatch(m -> m.contains(part)); i++) {
            Thread.sleep(100);
        }
    }

    @Test
    public void auditEntriesGoToSyslogAsCefOverTcpTlsAndUdp() throws Exception {
        String id = firstSignIn();
        Map<String, String> w = signedIn(id, "cn=admin,o=system", "admin-pw");
        assertEquals(400, call("PUT", "/api/v2/console/syslog", Map.of("enabled", true), w).status());
        assertEquals(400, call("PUT", "/api/v2/console/syslog", Map.of("enabled", true, "host", "127.0.0.1", "transport", "sctp"), w).status());

        // TCP: every audit entry, octet-counted
        List<String> got = java.util.Collections.synchronizedList(new java.util.ArrayList<>());
        try (java.net.ServerSocket tcp = new java.net.ServerSocket(0, 5, java.net.InetAddress.getLoopbackAddress())) {
            frames(tcp, got);
            Reply on = call("PUT", "/api/v2/console/syslog", Map.of("enabled", true, "host", "127.0.0.1", "port", tcp.getLocalPort(), "transport", "tcp", "facility", "local3"), w);
            assertEquals(String.valueOf(on.body()), 200, on.status());
            call("PUT", "/api/v2/console/updates", Map.of("enabled", false), w);
            waitFor(got, "settings.update-check");
            String m = got.stream().filter(x -> x.contains("settings.update-check")).findFirst().orElseThrow();
            // local3 (19) x 8 + notice (5)
            assertTrue(m, m.startsWith("<157>1 "));
            assertTrue(m, m.contains(" directory-console ") && m.contains("CEF:0|Point Blue|Directory Console|development|settings.update-check|settings update check|3|"));
            assertTrue(m, m.contains("suser=cn\\=admin,o\\=system") && m.contains("outcome=ok") && m.contains("cs3Label=details"));
        }

        // TLS: the server's certificate is from a CA the console trusts for every directory
        com.pointblue.console.server.tls.TestPki pki = new com.pointblue.console.server.tls.TestPki("LOGS");
        com.pointblue.console.server.tls.TestPki.Server cert = pki.server("localhost", List.of("localhost"));
        server.trust.add(pki.ca, com.pointblue.console.server.tls.TrustStore.Kind.CA, "global", "test", "test");
        got.clear();
        java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("s", cert.key().getPrivate(), "pw".toCharArray(), new java.security.cert.Certificate[] {cert.cert(), pki.ca});
        javax.net.ssl.KeyManagerFactory kmf = javax.net.ssl.KeyManagerFactory.getInstance(javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "pw".toCharArray());
        javax.net.ssl.SSLContext ctx = javax.net.ssl.SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);
        try (java.net.ServerSocket tls = ctx.getServerSocketFactory().createServerSocket(0, 5, java.net.InetAddress.getLoopbackAddress())) {
            frames(tls, got);
            assertEquals(200, call("PUT", "/api/v2/console/syslog", Map.of("enabled", true, "host", "localhost", "port", tls.getLocalPort(), "transport", "tls"), w).status());
            Map<String, Object> test = call("POST", "/api/v2/console/syslog/test", Map.of(), w).body();
            assertEquals(String.valueOf(test), true, test.get("ok"));
            waitFor(got, "syslog.test");
            assertTrue(String.valueOf(got), got.stream().anyMatch(x -> x.contains("syslog.test") && x.startsWith("<85>1 ")));
        }

        // UDP: one datagram per entry
        try (java.net.DatagramSocket udp = new java.net.DatagramSocket(0, java.net.InetAddress.getLoopbackAddress())) {
            udp.setSoTimeout(5000);
            assertEquals(200, call("PUT", "/api/v2/console/syslog", Map.of("enabled", true, "host", "127.0.0.1", "port", udp.getLocalPort(), "transport", "udp"), w).status());
            assertEquals(true, call("POST", "/api/v2/console/syslog/test", Map.of(), w).body().get("ok"));
            java.net.DatagramPacket p = new java.net.DatagramPacket(new byte[9000], 9000);
            String m = "";
            for (int i = 0; i < 5 && !m.contains("syslog.test"); i++) {
                udp.receive(p);
                m = new String(p.getData(), 0, p.getLength(), StandardCharsets.UTF_8);
            }
            assertTrue(m, m.contains("CEF:0|Point Blue|Directory Console|") && m.contains("syslog.test"));
        }
        Map<String, Object> st = call("GET", "/api/v2/console/syslog", null, w).body();
        assertTrue(String.valueOf(st), ((Number) st.get("sent")).longValue() > 0);
        assertEquals(200, call("PUT", "/api/v2/console/syslog", Map.of("enabled", false, "host", "127.0.0.1"), w).status());
    }

    private HttpResponse<byte[]> callBytes(String method, String path, Object body, Map<String, String> headers) throws Exception {
        HttpRequest.Builder b = ServerClient.request(URI.create(base + path))
            .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(Json.compact(body)));
        if (body != null) {
            b.header("Content-Type", "application/json");
        }
        headers.forEach(b::header);
        return http.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    @Test
    public void theAuditLogConfigurationHistoryAndABackupAreTheAdminsToReadAndRestore() throws Exception {
        String id = firstSignIn();
        Map<String, String> w = signedIn(id, "cn=admin,o=system", "admin-pw");

        // the audit log: newest first, filtered, paged, exported
        call("PUT", "/api/v2/console/updates", Map.of("enabled", false), w);
        call("PUT", "/api/v2/console/updates", Map.of("enabled", true), w);
        List<Map<String, Object>> page = ((List<?>) call("GET", "/api/v2/audit?event=settings.update&limit=1", null, w).body().get("entries")).stream().map(Json::asMap).toList();
        assertEquals(1, page.size());
        assertEquals("the newest first", true, Json.asMap(page.get(0).get("details")).get("enabled"));
        Reply older = call("GET", "/api/v2/audit?event=settings.update&limit=1&before=" + page.get(0).get("seq"), null, w);
        assertEquals(false, Json.asMap(Json.asMap(((List<?>) older.body().get("entries")).get(0)).get("details")).get("enabled"));
        assertEquals(true, call("GET", "/api/v2/audit?limit=1", null, w).body().get("more"));
        assertEquals(400, call("GET", "/api/v2/audit?from=yesterday", null, w).status());
        String csv = new String(callBytes("GET", "/api/v2/audit/export?format=csv&event=settings.update", null, w).body(), StandardCharsets.UTF_8);
        assertTrue(csv, csv.startsWith("seq,time,event,outcome,actor,via,target,details") && csv.contains("settings.update-check"));

        // configuration history: versions, what changed, and going back to one
        List<Map<String, Object>> versions = ((List<?>) call("GET", "/api/v2/config/history", null, w).body().get("versions")).stream().map(Json::asMap).toList();
        assertEquals(true, versions.get(0).get("current"));
        int last = ((Number) versions.get(0).get("version")).intValue();
        Map<String, Object> v = call("GET", "/api/v2/config/history/" + last, null, w).body();
        assertTrue(String.valueOf(v.get("changes")), String.valueOf(v.get("changes")).contains("updateCheck.enabled"));
        assertEquals("the current one cannot be restored", 409, call("POST", "/api/v2/config/history/" + last + "/restore", Map.of(), w).status());
        assertEquals(200, call("POST", "/api/v2/config/history/" + (last - 1) + "/restore", Map.of(), w).status());
        assertEquals("the switch is as it was before the last change", false,
            Json.asMap(call("GET", "/api/v2/config", null, w).body().get("updateCheck")).get("enabled"));
        assertEquals(404, call("GET", "/api/v2/config/history/99999", null, w).status());

        // a backup: a passphrase of at least 12, then restored at the next start
        assertEquals(400, callBytes("POST", "/api/v2/console/backup", Map.of("passphrase", "short"), w).statusCode());
        HttpResponse<byte[]> backup = callBytes("POST", "/api/v2/console/backup", Map.of("passphrase", "a long passphrase"), w);
        assertEquals(200, backup.statusCode());
        assertTrue(backup.headers().firstValue("Content-Disposition").orElse("").contains(".dcbackup"));
        String file = java.util.Base64.getEncoder().encodeToString(backup.body());
        call("PUT", "/api/v2/console/updates", Map.of("enabled", true), w);
        assertEquals("a wrong passphrase", 400, call("POST", "/api/v2/console/restore", Map.of("backup", file, "passphrase", "not the passphrase"), w).status());
        Reply staged = call("POST", "/api/v2/console/restore", Map.of("backup", file, "passphrase", "a long passphrase"), w);
        assertEquals(String.valueOf(staged.body()), 200, staged.status());
        assertTrue(staged.body().get("pending") != null);
        server.stop();
        boot();
        Map<String, String> again = signedIn(id, "cn=admin,o=system", "admin-pw");
        assertEquals("the backup's setting is back", false, Json.asMap(call("GET", "/api/v2/config", null, again).body().get("updateCheck")).get("enabled"));
        assertEquals("nothing is staged any more", null, call("GET", "/api/v2/console/restore", null, again).body().get("pending"));
        assertEquals("the restore is in the audit log", 1, ((List<?>) call("GET", "/api/v2/audit?event=console.restored", null, again).body().get("entries")).size());
        assertEquals("the audit log was not rewritten", true, ((List<?>) call("GET", "/api/v2/audit?event=console.restore.stage", null, again).body().get("entries")).size() == 1);
    }

    @Test
    public void acmeSettingsAreCheckedAndADnsServerThatCannotBeReachedIsReported() throws Exception {
        String id = firstSignIn();
        Map<String, String> w = signedIn(id, "cn=admin,o=system", "admin-pw");
        String t = "/api/v2/console/acme";
        Map<String, Object> dns = Map.of("host", "127.0.0.1", "port", 9, "zone", "acme.test", "keyName", "acme-key", "secret", "c2VjcmV0c2VjcmV0c2VjcmV0");
        assertEquals("only https", 400, call("PUT", t, Map.of("directoryUrl", "http://ca.test/dir", "names", List.of("console.acme.test"), "dns", dns), w).status());
        assertEquals("a name outside the zone", 400, call("PUT", t, Map.of("names", List.of("console.other.test"), "dns", dns), w).status());
        assertEquals("not a DNS name", 400, call("PUT", t, Map.of("names", List.of("not a name"), "dns", dns), w).status());
        assertEquals("names to turn it on", 400, call("PUT", t, Map.of("enabled", true, "dns", dns), w).status());
        assertEquals(409, call("POST", t + "/dns-test", Map.of(), w).status());
        Reply saved = call("PUT", t, Map.of("names", List.of("console.acme.test", "*.acme.test"), "dns", dns, "email", "ops@acme.test"), w);
        assertEquals(String.valueOf(saved.body()), 200, saved.status());
        assertEquals("the secret is not shown", Map.of("set", true), Json.asMap(saved.body().get("dns")).get("secret"));
        assertEquals(AcmeService.LETS_ENCRYPT, saved.body().get("directoryUrl"));
        Map<String, Object> test = call("POST", t + "/dns-test", Map.of(), w).body();
        assertEquals(false, test.get("ok"));
        assertTrue(String.valueOf(test), test.get("error") != null);
    }

    @Test
    public void certificateExpiryIsFoundAndNotifiedOncePerLevel() throws Exception {
        List<String> hooks = java.util.Collections.synchronizedList(new java.util.ArrayList<>());
        com.sun.net.httpserver.HttpServer hook = com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1", 0), 0);
        hook.createContext("/hook", ex -> {
            hooks.add(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8) + "|" + ex.getRequestHeaders().getFirst("X-Console-Signature"));
            ex.sendResponseHeaders(204, -1);
            ex.close();
        });
        hook.start();
        try (java.net.ServerSocket smtp = new java.net.ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) {
            String id = firstSignIn();
            Map<String, String> w = signedIn(id, "cn=admin,o=system", "admin-pw");
            String url = "http://127.0.0.1:" + hook.getAddress().getPort() + "/hook";
            assertEquals("not plain http elsewhere", 400, call("PUT", "/api/v2/console/expiry", Map.of("webhooks", List.of(Map.of("url", "http://example.test/hook"))), w).status());
            assertEquals(400, call("PUT", "/api/v2/console/expiry", Map.of("email", Map.of("host", "127.0.0.1", "security", "none", "user", "u", "password", "p",
                "from", "console@example.test", "to", List.of("ops@example.test"))), w).status());
            Map<String, Object> mail = new java.util.HashMap<>(Map.of("host", "127.0.0.1", "port", smtp.getLocalPort(), "security", "none",
                "from", "console@example.test", "to", List.of("ops@example.test")));
            Reply saved = call("PUT", "/api/v2/console/expiry", Map.of("warnDays", 30, "email", mail, "webhooks", List.of(Map.of("url", url, "secret", "s3cret"))), w);
            assertEquals(String.valueOf(saved.body()), 200, saved.status());
            Map<String, Object> settings = Json.asMap(saved.body().get("settings"));
            assertEquals("the secret is not shown", Map.of("set", true), Json.asMap(((List<?>) settings.get("webhooks")).get(0)).get("secret"));

            StringBuilder got = new StringBuilder();
            Thread stub = smtpStub(smtp, got);
            List<?> results = (List<?>) call("POST", "/api/v2/console/expiry/test", Map.of(), w).body().get("results");
            stub.join(5000);
            assertTrue(String.valueOf(results), results.stream().map(Json::asMap).allMatch(r -> Boolean.TRUE.equals(r.get("ok"))));
            assertTrue(got.toString(), got.toString().contains("RCPT TO:<ops@example.test>") && got.toString().contains("Subject: Directory Console: a test notification"));
            String test = hooks.get(0);
            String body = test.substring(0, test.lastIndexOf('|'));
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec("s3cret".getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            assertEquals("signed with the secret", "sha256=" + java.util.HexFormat.of().formatHex(mac.doFinal(body.getBytes(StandardCharsets.UTF_8))),
                test.substring(test.lastIndexOf('|') + 1));

            // a trusted CA that expires in 3 days: found, notified once, not again the next day
            com.pointblue.console.server.tls.TestPki soon = new com.pointblue.console.server.tls.TestPki("SOON", java.time.Duration.ofDays(3));
            server.trust.add(soon.ca, com.pointblue.console.server.tls.TrustStore.Kind.CA, "global", "test", "test");
            hooks.clear();
            got.setLength(0);
            stub = smtpStub(smtp, got);
            server.expiry.check(true);
            stub.join(5000);
            Map<String, Object> st = call("GET", "/api/v2/console/expiry", null, w).body();
            Map<String, Object> f = ((List<?>) st.get("findings")).stream().map(Json::asMap).filter(x -> "trusted".equals(x.get("kind"))).findFirst().orElseThrow();
            assertEquals("7days", f.get("level"));
            assertEquals(1, hooks.size());
            assertTrue(hooks.get(0), hooks.get(0).contains("certificates.expiring") && hooks.get(0).contains("SOON"));
            assertTrue(got.toString(), got.toString().contains("expires"));
            server.expiry.check(true);
            assertEquals("not again at the same level", 1, hooks.size());
        } finally {
            hook.stop(0);
        }
    }

    @Test
    public void updateCheckReportsANewerReleaseAndSurvivesAnUnreachableServer() throws Exception {
        com.sun.net.httpserver.HttpServer releases = com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1", 0), 0);
        releases.createContext("/latest", ex -> {
            byte[] b = "{\"tag_name\":\"v99.0.0\",\"html_url\":\"https://example.test/r/v99.0.0\",\"published_at\":\"2026-12-01T00:00:00Z\"}"
                .getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        releases.start();
        try {
            System.setProperty("console.updateUrl", "http://127.0.0.1:" + releases.getAddress().getPort() + "/latest");
            server.stop();
            boot();
            String id = firstSignIn();
            Map<String, String> w = signedIn(id, "cn=admin,o=system", "admin-pw");
            Map<String, Object> st = Json.asMap(call("POST", "/api/v2/console/updates/check", Map.of(), w).body());
            assertEquals("99.0.0", st.get("latest"));
            assertEquals("https://example.test/r/v99.0.0", st.get("url"));
            assertEquals(true, st.get("enabled"));
            assertNull("no error", st.get("error"));
            assertEquals("the version is in the health check", "development",
                call("GET", "/api/v2/health/live", null, Map.of()).body().get("version"));
            Map<String, Object> v = call("GET", "/api/v2/console/version", null, w).body();
            assertEquals("development", v.get("version"));
            assertEquals("99.0.0", Json.asMap(v.get("update")).get("latest"));

            // the release server cannot be reached: recorded, nothing else changes
            releases.stop(0);
            Map<String, Object> down = Json.asMap(call("POST", "/api/v2/console/updates/check", Map.of(), w).body());
            assertTrue(String.valueOf(down.get("error")), down.get("error") != null);
            assertEquals("the last good answer is kept", "99.0.0", down.get("latest"));
            assertEquals(200, call("GET", "/api/v2/session", null, w).status());

            assertEquals(false, Json.asMap(call("PUT", "/api/v2/console/updates", Map.of("enabled", false), w).body()).get("enabled"));
            assertEquals(400, call("PUT", "/api/v2/console/updates", Map.of("enabled", "no"), w).status());
        } finally {
            System.clearProperty("console.updateUrl");
            releases.stop(0);
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
