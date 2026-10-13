package com.pointblue.console.server.http;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
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

/**
 * Directories a person enters at sign-in: off until an administrator allows it; a configured
 * directory's address is refused; an untrusted certificate is shown, accepted with its fingerprint for
 * the bind, and kept as the person's own only when the bind succeeds; the session works with the
 * person's own rights. The fake directory's certificate names 127.0.0.1 only, so "localhost" is a
 * second address with a name mismatch, as behind NAT.
 */
public class OtherDirectoryTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private FakeEdir edir;
    private Server server;
    private HttpClient http;
    private String base;

    record Reply(int status, Map<String, Object> body, HttpResponse<String> raw) {
    }

    @Before
    public void start() throws Exception {
        edir = new FakeEdir(
            "dn: cn=admin,o=system\nobjectClass: inetOrgPerson\ncn: admin\nsn: a\nuserPassword: admin-pw",
            "dn: cn=console,o=system\nobjectClass: inetOrgPerson\ncn: console\nsn: c\nuserPassword: console-pw",
            "dn: cn=Pat Lee,o=system\nobjectClass: inetOrgPerson\ncn: Pat Lee\nsn: Lee\nuserPassword: pat-pw");
        Path dataPath = tmp.newFolder("data").toPath();
        server = new Server(new DataDir(dataPath), 0, "https://localhost:8443", new PrintStream(new ByteArrayOutputStream()));
        server.start();
        base = "https://localhost:" + server.port();
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
        return new Reply(r.statusCode(), parsed instanceof Map ? Json.asMap(parsed) : Map.of("list", parsed), r);
    }

    private static Map<String, String> cookie(Reply r) {
        String c = r.raw().headers().firstValue("Set-Cookie").orElseThrow();
        Map<String, String> h = new HashMap<>();
        h.put("Cookie", c.substring(0, c.indexOf(';')));
        h.put("X-CSRF-Token", String.valueOf(r.body().get("csrf")));
        return h;
    }

    private Map<String, String> admin() throws Exception {
        Reply r = call("POST", "/api/v2/session", Map.of("directory", "acme", "name", "cn=admin,o=system", "password", "admin-pw"), Map.of());
        assertEquals(200, r.status());
        return cookie(r);
    }

    private Map<String, Object> other(String name, String password, Map<String, Object> accept) {
        Map<String, Object> b = new HashMap<>(Map.of("host", "localhost", "port", edir.port(), "name", name, "password", password));
        if (accept != null) {
            b.put("accept", accept);
        }
        return b;
    }

    @Test
    public void aPersonSignsInToADirectoryTheyEnterAndKeepsTheCertificateTheyAccepted() throws Exception {
        assertEquals(false, call("GET", "/api/v2/sign-in/options", null, Map.of()).body().get("otherDirectories"));
        assertEquals("off until an administrator allows it", 403, call("POST", "/api/v2/session/other", other("cn=Pat Lee,o=system", "pat-pw", null), Map.of()).status());

        Map<String, String> a = admin();
        assertEquals(200, call("PUT", "/api/v2/console/settings", Map.of("otherDirectories", true), a).status());
        assertEquals(true, call("GET", "/api/v2/sign-in/options", null, Map.of()).body().get("otherDirectories"));

        Map<String, Object> configured = new HashMap<>(other("cn=Pat Lee,o=system", "pat-pw", null));
        configured.put("host", "127.0.0.1");
        Reply refused = call("POST", "/api/v2/session/other", configured, Map.of());
        assertEquals("a configured directory has its own sign-in", 409, refused.status());
        assertEquals("acme", refused.body().get("directory"));
        assertEquals(400, call("POST", "/api/v2/session/other", other("pat", "pat-pw", null), Map.of()).status());

        // the CA is trusted for Acme only: here it is not, and the leaf names 127.0.0.1, not localhost
        Reply untrusted = call("POST", "/api/v2/session/other", other("cn=Pat Lee,o=system", "pat-pw", null), Map.of());
        assertEquals(409, untrusted.status());
        assertEquals("untrusted-certificate", untrusted.body().get("title"));
        Map<String, Object> probe = Json.asMap(untrusted.body().get("probe"));
        assertEquals(false, probe.get("hostnameMatches"));
        int recommended = Json.asInt(probe.get("recommended"), -1);
        String sha = (String) Json.asMap(((List<?>) probe.get("chain")).get(recommended)).get("sha256");
        String tail = sha.replace(":", "").substring(56);
        Map<String, Object> accept = Map.of("probeId", probe.get("probeId"), "confirm", tail);

        assertEquals(400, call("POST", "/api/v2/session/other", other("cn=Pat Lee,o=system", "pat-pw", Map.of("probeId", probe.get("probeId"), "confirm", "00000000")), Map.of()).status());
        Reply wrong = call("POST", "/api/v2/session/other", other("cn=Pat Lee,o=system", "wrong", accept), Map.of());
        assertEquals("a wrong password: " + wrong.body(), 401, wrong.status());
        Map<String, Object> list = call("GET", "/api/v2/trust/certificates", null, a).body();
        assertFalse("nothing kept after a failed bind", list.toString().contains("user:"));

        Reply in = call("POST", "/api/v2/session/other", other("cn=Pat Lee,o=system", "pat-pw", accept), Map.of());
        assertEquals(String.valueOf(in.body()), 200, in.status());
        assertEquals("user-directory", in.body().get("via"));
        assertEquals(List.of("editor"), in.body().get("roles"));
        String tree = (String) in.body().get("directory");
        assertTrue(tree.matches("u-[0-9a-f]{12}"));
        Map<String, String> pat = cookie(in);
        assertEquals("works with the person's own rights", 200, call("GET", "/api/v2/trees/" + tree + "/roots", null, pat).status());
        assertEquals(403, call("GET", "/api/v2/trust/certificates", null, pat).status());

        list = call("GET", "/api/v2/trust/certificates", null, a).body();
        String scope = "user:" + OtherDirectory.subject("cn=Pat Lee,o=system", "localhost", edir.port());
        assertTrue("the CA is kept as Pat's", ((List<?>) list.get("certificates")).stream().anyMatch(c -> scope.equals(Json.asMap(c).get("scope"))));
        assertTrue("and the name, as Pat's host exception", ((List<?>) list.get("hostExceptions")).stream().anyMatch(h -> scope.equals(Json.asMap(h).get("scope"))));

        assertEquals("the next sign-in needs no acceptance", 200, call("POST", "/api/v2/session/other", other("cn=Pat Lee,o=system", "pat-pw", null), Map.of()).status());
        assertEquals("another person's trust is their own", 409, call("POST", "/api/v2/session/other", other("cn=admin,o=system", "admin-pw", null), Map.of()).status());
        assertEquals("step-up uses the person's trust", 204, call("POST", "/api/v2/session/step-up", Map.of("password", "pat-pw"), pat).status());

        assertEquals(200, call("PUT", "/api/v2/console/settings", Map.of("otherDirectories", false), a).status());
        assertEquals(403, call("POST", "/api/v2/session/other", other("cn=Pat Lee,o=system", "pat-pw", null), Map.of()).status());
    }
}
