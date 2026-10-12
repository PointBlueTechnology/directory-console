package com.pointblue.console.server.http;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
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

/** Security services over the fake directory: secrets withheld, password policies, assignments, challenge sets. */
public class SecurityTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private FakeEdir edir;
    private Server server;
    private HttpClient http;
    private String base;
    private Map<String, String> h;

    record Reply(int status, Map<String, Object> body) {
    }

    @Before
    public void start() throws Exception {
        edir = new FakeEdir(
            "dn: cn=admin,o=system\nobjectClass: inetOrgPerson\ncn: admin\nsn: a\nuserPassword: admin-pw",
            "dn: cn=console,o=system\nobjectClass: inetOrgPerson\ncn: console\nsn: c\nuserPassword: console-pw",
            "dn: cn=Security,o=system\nobjectClass: sASSecurity\ncn: Security",
            "dn: ou=Sales,o=acme\nobjectClass: organizationalUnit\nou: Sales",
            "dn: cn=pat,ou=Sales,o=acme\nobjectClass: inetOrgPerson\ncn: pat\nsn: Lee\nsASLoginSecret: c2VjcmV0\nnspmDistributionPassword: x");
        // eDirectory's Security container is at the tree root; the fake's naming contexts are o=acme and o=system
        Path data = tmp.newFolder("data").toPath();
        server = new Server(new DataDir(data), 0, "https://localhost:8443", new PrintStream(new ByteArrayOutputStream()));
        server.start();
        base = "https://localhost:" + server.port();
        http = ServerClient.trusting(server);
        Matcher m = Pattern.compile("Setup token: ([0-9a-f]{32})").matcher(Files.readString(data.resolve("bootstrap.txt")));
        assertTrue(m.find());
        Map<String, String> t = Map.of("X-Setup-Token", m.group(1));
        call("PUT", "/api/v2/setup/directory", Map.of("id", "acme", "name", "Acme", "host", "127.0.0.1", "port", edir.port(), "tier", "lab"), t);
        Reply probe = call("POST", "/api/v2/setup/probe", Map.of(), t);
        call("POST", "/api/v2/setup/trust", Map.of("probeId", probe.body().get("probeId"), "confirm", Certs.tail(edir.pki.ca, 8)), t);
        call("POST", "/api/v2/setup/authority", Map.of("dn", "cn=admin,o=system", "password", "admin-pw"), t);
        call("PUT", "/api/v2/setup/service-account", Map.of("dn", "cn=console,o=system", "password", "console-pw"), t);
        assertEquals(200, call("POST", "/api/v2/setup/finish", Map.of(), t).status());
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(base + "/api/v2/session")).header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(Json.compact(Map.of("directory", "acme", "name", "cn=admin,o=system", "password", "admin-pw")))).build(),
            HttpResponse.BodyHandlers.ofString());
        String cookie = r.headers().firstValue("Set-Cookie").orElseThrow();
        h = new HashMap<>(Map.of("Cookie", cookie.substring(0, cookie.indexOf(';')), "X-CSRF-Token", (String) Json.asMap(Json.parse(r.body())).get("csrf")));
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

    private String guid(String dn) throws Exception {
        return (String) call("GET", "/api/v2/trees/acme/objects?dn=" + java.net.URLEncoder.encode(dn, "UTF-8"), null, h).body().get("guid");
    }

    @Test
    public void secretsAreNeverReturned() throws Exception {
        Map<String, Object> attrs = Json.asMap(call("GET", "/api/v2/trees/acme/objects/" + guid("cn=pat,ou=Sales,o=acme"), null, h).body().get("attributes"));
        assertEquals("[{withheld=1}]", String.valueOf(attrs.get("sASLoginSecret")));
        assertEquals("[{withheld=1}]", String.valueOf(attrs.get("nspmDistributionPassword")));
        assertFalse(String.valueOf(attrs).contains("c2VjcmV0"));
        Reply search = call("POST", "/api/v2/trees/acme/search", Map.of("filter", Map.of("eq", Map.of("cn", "pat")), "attributes", List.of("sASLoginSecret")), h);
        assertFalse("not through search either", String.valueOf(search.body()).contains("c2VjcmV0"));
    }

    @Test
    public void optionsDecodeAsIdentityConsoleDoes() {
        // 884 = 0x374, ig4's Sample Password Policy: two of the bits mean "do not synchronize"
        Map<String, Object> o = Security.options(884);
        assertEquals(true, o.get("universalPassword"));
        assertEquals(true, o.get("advancedRules"));
        assertEquals(true, o.get("syncNds"));
        assertEquals(false, o.get("syncSimple"));
        assertEquals(884, Security.optionsValue(0, o));
        assertEquals(0x300 | 0x04, Security.optionsValue(0, Map.of("universalPassword", true, "advancedRules", true, "syncSimple", false, "syncNds", true)));
    }

    @Test
    public void challengeSetQuestionsRoundTrip() {
        String xml = Security.questionsXml("RequiredQuestions", List.of(Map.of("kind", "admin", "text", "Tricky ]]> text?", "min", 2, "max", 40),
            Map.of("kind", "user", "min", 4, "max", 64)));
        List<Map<String, Object>> back = Security.questions(xml);
        assertEquals("user-defined slots come first, as iManager writes them", "user", back.get(0).get("kind"));
        assertEquals("Tricky ]]> text?", back.get(1).get("text").toString().replace("]]]]><![CDATA[>", "]]>"));
        String ig4 = "<RequiredQuestions><UserDefined MaxLength=\"255\" MinLength=\"2\"/><AdminDefined><Question MaxLength=\"255\" MinLength=\"2\"><![CDATA[What is your mother's maiden name?]]></Question></AdminDefined></RequiredQuestions>";
        assertEquals(2, Security.questions(ig4).size());
        assertEquals("What is your mother's maiden name?", Security.questions(ig4).get(1).get("text"));
    }

    @Test
    public void policiesAreAssignedOnBothSides() throws Exception {
        // eDirectory keeps cn=Security at the tree root; the fake's naming contexts are o=acme and o=system
        edir.add("dn: cn=Password Policies,cn=Security,o=system", "objectClass: nspmPasswordPolicyContainer", "cn: Password Policies");
        Reply set = call("POST", "/api/v2/trees/acme/security/challenge-sets", Map.of("name", "Basics",
            "required", List.of(Map.of("kind", "admin", "text", "First school?", "min", 2, "max", 40)), "random", List.of(), "randomCount", 0), h);
        assertEquals(String.valueOf(set.body()), 201, set.status());
        Reply p = call("POST", "/api/v2/trees/acme/security/password-policies", Map.of("name", "Staff",
            "rules", Map.of("minLength", 10, "expirationDays", 90), "challengeSet", set.body().get("guid")), h);
        assertEquals(String.valueOf(p.body()), 201, p.status());
        assertEquals("cn=Staff,cn=Password Policies,cn=Security,o=system", p.body().get("dn"));
        assertEquals(true, Json.asMap(p.body().get("options")).get("universalPassword"));
        assertEquals(90, Json.asInt(Json.asMap(p.body().get("rules")).get("expirationDays"), -1));
        assertEquals("7776000", edir.server.getEntry("cn=Staff,cn=Password Policies,cn=Security,o=system").getAttributeValue("passwordExpirationInterval"));
        String policy = (String) p.body().get("guid");
        String sales = guid("ou=Sales,o=acme");

        Reply as = call("POST", "/api/v2/trees/acme/security/password-policies/" + policy + "/assignments", Map.of("target", sales), h);
        assertEquals(200, as.status());
        assertEquals("cn=Staff,cn=Password Policies,cn=Security,o=system", edir.server.getEntry("ou=Sales,o=acme").getAttributeValue("nspmPasswordPolicyDN"));
        assertTrue(edir.server.getEntry("cn=Staff,cn=Password Policies,cn=Security,o=system").hasAttributeValue("nsimAssignments", "ou=Sales,o=acme"));
        Reply seen = call("GET", "/api/v2/trees/acme/security/objects/" + guid("cn=pat,ou=Sales,o=acme") + "/password-policy", null, h);
        assertTrue(String.valueOf(seen.body().get("containers")).contains("cn=Staff"));

        assertEquals(409, call("DELETE", "/api/v2/trees/acme/security/challenge-sets/" + set.body().get("guid"), null, h).status());
        Reply refused = call("DELETE", "/api/v2/trees/acme/security/password-policies/" + policy, null, h);
        assertEquals(409, refused.status());
        assertEquals("confirm-count", refused.body().get("title"));
        assertEquals(200, call("DELETE", "/api/v2/trees/acme/security/password-policies/" + policy + "/assignments/" + sales, null, h).status());
        assertNull(edir.server.getEntry("ou=Sales,o=acme").getAttributeValue("nspmPasswordPolicyDN"));
        assertEquals(204, call("DELETE", "/api/v2/trees/acme/security/password-policies/" + policy, null, h).status());
        assertEquals(400, call("POST", "/api/v2/trees/acme/security/password-policies", Map.of("name", "Bad", "rules", Map.of("teleport", 1)), h).status());
        assertNull("a refused create leaves nothing behind", edir.server.getEntry("cn=Bad,cn=Password Policies,cn=Security,o=system"));
    }
}
