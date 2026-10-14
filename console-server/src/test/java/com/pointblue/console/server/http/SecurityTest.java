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
            "dn: cn=Security,o=system\nobjectClass: sASSecurity\ncn: Security\nsASLoginPolicyDN: cn=Login Policy,cn=Security,o=system\n"
                + "nDSPKITreeCADN: cn=TREE CA,cn=Security,o=system",
            "dn: cn=TREE CA,cn=Security,o=system\nobjectClass: nDSPKICertificateAuthority\ncn: TREE CA\n"
                + "ndspkiCRLConfigurationDNList: cn=One - Configuration,cn=Security,o=system#0#\n"
                + "ndspkiCRLECConfigurationDNList: cn=One - Configuration EC,cn=Security,o=system#0#",
            "dn: cn=One - Configuration,cn=Security,o=system\nobjectClass: ndspkiCRLConfiguration\ncn: One - Configuration\nndspkiNextIssueTime: 20261024224900Z",
            "dn: cn=One - Configuration EC,cn=Security,o=system\nobjectClass: ndspkiCRLConfiguration\ncn: One - Configuration EC\nndspkiNextIssueTime: 20261024224900Z",
            "dn: cn=Login Policy,cn=Security,o=system\nobjectClass: sASLoginPolicy\ncn: Login Policy\nsasDefaultLoginSequence: NDS\nsASLoginPolicyUpdate: 6\n"
                + "sASLoginSequence: NDS;Password;NDS\nsASLoginSequence: Challenge Response;Password;Challenge Response",
            "dn: cn=Authorized Login Methods,cn=Security,o=system\nobjectClass: sASLoginMethodContainer\ncn: Authorized Login Methods",
            "dn: cn=NDS,cn=Authorized Login Methods,cn=Security,o=system\nobjectClass: sASNMASLoginMethod\ncn: NDS",
            "dn: cn=Challenge Response,cn=Authorized Login Methods,cn=Security,o=system\nobjectClass: sASNMASLoginMethod\ncn: Challenge Response",
            "dn: ou=Sales,o=acme\nobjectClass: organizationalUnit\nou: Sales",
            "dn: cn=lee,ou=Sales,o=acme\nobjectClass: inetOrgPerson\ncn: lee\nsn: Lee\nsasDefaultLoginSequence: Challenge Response",
            "dn: cn=pat,ou=Sales,o=acme\nobjectClass: inetOrgPerson\ncn: pat\nsn: Lee\nmail: pat@acme.example\nsASLoginSecret: c2VjcmV0\nnspmDistributionPassword: x",
            "dn: ou=servers,o=system\nobjectClass: organizationalUnit\nou: servers",
            "dn: cn=edir1,ou=servers,o=system\nobjectClass: ncpServer\ncn: edir1",
            "dn: cn=LDAP Server - edir1,ou=servers,o=system\nobjectClass: ldapServer\ncn: LDAP Server - edir1\nldapHostServer: cn=edir1,ou=servers,o=system\nldapKeyMaterialName: ldap3");
        // eDirectory's Security container is at the tree root; the fake's naming contexts are o=acme and o=system
        Path data = tmp.newFolder("data").toPath();
        server = new Server(new DataDir(data), 0, "https://localhost:8443", new PrintStream(new ByteArrayOutputStream()));
        server.start();
        base = "https://127.0.0.1:" + server.port();
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

    private String guidOf(String dn) throws Exception {
        return (String) call("GET", "/api/v2/trees/acme/objects?dn=" + java.net.URLEncoder.encode(dn, "UTF-8"), null, h).body().get("guid");
    }

    @Test
    public void serverAndUserCertificatesThroughThePkiOperations() throws Exception {
        String t = "/api/v2/trees/acme/security";
        String edir1 = guidOf("cn=edir1,ou=servers,o=system");
        Reply made = call("POST", t + "/pki/servers/" + edir1 + "/certificates",
            Map.of("name", "web1", "algorithm", "rsa", "rsaBits", 2048, "validityYears", 2, "names", List.of("dns:edir1.acme.example", "ip:192.0.2.10")), h);
        assertEquals(String.valueOf(made.body()), 201, made.status());
        assertEquals("web1 - edir1", made.body().get("name"));
        Map<String, Object> req = edir.pkiOps.requests.get(edir.pkiOps.requests.size() - 1);
        assertEquals("createCertificate", req.get("verb"));
        assertEquals("cn=edir1.ou=servers.o=system", req.get("serverDN"));
        assertEquals("RSA, SHA-256", 8, Json.asInt(req.get("signatureAlgorithm"), 0));
        assertEquals("digital signature and key encipherment", 0xA000, Json.asInt(req.get("keyUsage"), 0));
        assertEquals("cn=edir1", req.get("subjectDN"));
        assertEquals(2, ((List<?>) req.get("subjectAltNames")).size());
        assertTrue("the certificate is read back", made.body().get("certificate") instanceof Map);

        assertEquals("one name per server", 409, call("POST", t + "/pki/servers/" + edir1 + "/certificates", Map.of("name", "web1"), h).status());
        assertEquals(400, call("POST", t + "/pki/servers/" + edir1 + "/certificates", Map.of("name", "web2", "algorithm", "dsa"), h).status());
        assertEquals(400, call("POST", t + "/pki/servers/" + edir1 + "/certificates", Map.of("name", "web2", "names", List.of("ftp:x")), h).status());
        edir.pkiOps.refuseNext = -1212;
        Reply refused = call("POST", t + "/pki/servers/" + edir1 + "/certificates", Map.of("name", "web2", "algorithm", "ec384"), h);
        assertEquals(409, refused.status());
        assertEquals("pki-refused", refused.body().get("title"));
        assertEquals(-1212, Json.asInt(refused.body().get("code"), 0));
        Map<String, Object> ec = edir.pkiOps.requests.get(edir.pkiOps.requests.size() - 1);
        assertEquals("ECDSA P-384", 4, Json.asInt(ec.get("keyAlgorithm"), 0));
        assertEquals("ECDSA with SHA-256", 64, Json.asInt(ec.get("signatureAlgorithm"), 0));

        // the LDAP server uses ldap3: that certificate cannot be deleted; web1 can
        assertEquals(201, call("POST", t + "/pki/servers/" + edir1 + "/certificates", Map.of("name", "ldap3"), h).status());
        Reply inUse = call("DELETE", t + "/pki/server-certificates/" + guidOf("cn=ldap3 - edir1,ou=servers,o=system"), null, h);
        assertEquals(409, inUse.status());
        assertEquals(List.of("LDAP Server - edir1"), inUse.body().get("usedBy"));
        String web1 = (String) made.body().get("guid");
        assertEquals(204, call("DELETE", t + "/pki/server-certificates/" + web1, null, h).status());
        assertEquals(404, call("DELETE", t + "/pki/server-certificates/" + web1, null, h).status());
        assertEquals("only a key material object", 404, call("DELETE", t + "/pki/server-certificates/" + edir1, null, h).status());

        String pat = guidOf("cn=pat,ou=Sales,o=acme");
        assertEquals(List.of(), call("GET", t + "/objects/" + pat + "/certificates", null, h).body().get("items"));
        Reply user = call("POST", t + "/objects/" + pat + "/certificates", Map.of("name", "smime", "algorithm", "ec256"), h);
        assertEquals(String.valueOf(user.body()), 201, user.status());
        // the create, not the list that follows it
        Map<String, Object> ureq = edir.pkiOps.requests.stream().filter(r -> "createCertificate".equals(r.get("verb")) && r.containsKey("userDN"))
            .reduce((a, b) -> b).orElseThrow();
        assertEquals("cn=pat.ou=Sales.o=acme", ureq.get("userDN"));
        assertEquals("the user's mail address", "pat@acme.example", ureq.get("emailAddress"));
        assertEquals("user authentication and e-mail protection", 0x14, Json.asInt(ureq.get("extendedKeyUsage"), 0));
        assertEquals(0, Json.asInt(ureq.get("allowExportPrivateKey"), -1));
        List<?> items = (List<?>) user.body().get("items");
        assertEquals(1, items.size());
        assertEquals("smime", Json.asMap(items.get(0)).get("name"));
        assertTrue(String.valueOf(Json.asMap(items.get(0)).get("notAfter")).matches("\\d{4}-.*Z"));
        assertEquals("a duplicate name is eDirectory's refusal", 409, call("POST", t + "/objects/" + pat + "/certificates", Map.of("name", "smime"), h).status());

        // revocation: on the CA's CRL configuration for the certificate's key (the fake's keys are EC: its EC list)
        assertEquals(400, call("POST", t + "/objects/" + pat + "/certificates/smime/revoke", Map.of("reason", 7), h).status());
        assertEquals(404, call("POST", t + "/objects/" + pat + "/certificates/nope/revoke", Map.of("reason", 4), h).status());
        Reply userRevoked = call("POST", t + "/objects/" + pat + "/certificates/smime/revoke", Map.of("reason", 1), h);
        assertEquals(String.valueOf(userRevoked.body()), 200, userRevoked.status());
        assertEquals("cn=One - Configuration EC,cn=Security,o=system", userRevoked.body().get("crlConfiguration"));
        String web = (String) call("POST", t + "/pki/servers/" + edir1 + "/certificates", Map.of("name", "web9"), h).body().get("guid");
        edir.pkiOps.revoked.clear();
        Reply rv = call("POST", t + "/pki/server-certificates/" + web + "/revoke", Map.of("reason", 4, "comment", "replaced"), h);
        assertEquals(String.valueOf(rv.body()), 200, rv.status());
        assertEquals("cn=One - Configuration EC,cn=Security,o=system", rv.body().get("crlConfiguration"));
        assertEquals("2026-10-24T22:49:00Z", rv.body().get("listedFrom"));
        assertEquals(List.of("cn=edir1.ou=servers.o=system / web9 / 4"), edir.pkiOps.revoked);
        Map<String, Object> rreq = edir.pkiOps.requests.get(edir.pkiOps.requests.size() - 1);
        assertEquals("cn=One - Configuration EC.cn=Security.o=system", rreq.get("crlConfigurationDN"));
        assertEquals("replaced", rreq.get("comment"));
    }

    @Test
    public void loginSequencesAreAddedChangedAndRemovedWithoutTouchingTheOthers() throws Exception {
        String t = "/api/v2/trees/acme/security/login-policy";
        Map<String, Object> before = call("GET", t, null, h).body();
        assertEquals(2, ((List<?>) before.get("sequences")).size());

        Reply made = call("POST", t + "/sequences", Map.of("name", "Two factor", "methods", List.of("NDS", "Challenge Response")), h);
        assertEquals(String.valueOf(made.body()), 201, made.status());
        Map<String, Object> two = Json.asMap(((List<?>) made.body().get("sequences")).get(2));
        assertEquals("Two factor", two.get("name"));
        assertEquals(List.of("NDS", "Challenge Response"), two.get("methods"));
        assertEquals(false, two.get("any"));
        com.unboundid.ldap.sdk.Entry lp = edir.entry("cn=Login Policy,cn=Security,o=system");
        assertTrue(java.util.Arrays.asList(lp.getAttributeValues("sASLoginSequence")).contains("Two factor;Password;NDS;Challenge Response"));
        assertEquals("the policy's change counter moves", "7", lp.getAttributeValue("sASLoginPolicyUpdate"));

        assertEquals(409, call("POST", t + "/sequences", Map.of("name", "Two factor", "methods", List.of("NDS")), h).status());
        assertEquals(400, call("POST", t + "/sequences", Map.of("name", "x;y", "methods", List.of("NDS")), h).status());
        assertEquals("only installed methods", 400, call("POST", t + "/sequences", Map.of("name", "z", "methods", List.of("Smart Card")), h).status());

        Reply changed = call("PATCH", t + "/sequences/Two%20factor", Map.of("methods", List.of("Challenge Response", "NDS"), "any", true), h);
        assertEquals(String.valueOf(changed.body()), 200, changed.status());
        lp = edir.entry("cn=Login Policy,cn=Security,o=system");
        assertTrue(java.util.Arrays.asList(lp.getAttributeValues("sASLoginSequence")).contains("Two factor;Password;Challenge Response|NDS"));
        assertEquals("the others untouched", 3, lp.getAttributeValues("sASLoginSequence").length);

        assertEquals("the default", 409, call("DELETE", t + "/sequences/NDS", null, h).status());
        Reply named = call("DELETE", t + "/sequences/Challenge%20Response", null, h);
        assertEquals("a sequence objects name", 409, named.status());
        assertEquals(1, Json.asInt(named.body().get("count"), 0));
        Map<String, String> counted = new HashMap<>(h);
        counted.put("X-Confirm-Count", "1");
        assertEquals(200, call("PATCH", t + "/sequences/Challenge%20Response", Map.of("methods", List.of("Challenge Response")), counted).status());

        assertEquals(200, call("DELETE", t + "/sequences/Two%20factor", null, h).status());
        assertEquals(404, call("DELETE", t + "/sequences/Two%20factor", null, h).status());
        lp = edir.entry("cn=Login Policy,cn=Security,o=system");
        assertEquals(List.of("NDS;Password;NDS", "Challenge Response;Password;Challenge Response"), List.of(lp.getAttributeValues("sASLoginSequence")));
    }

    @Test
    public void defaultCertificatesGetSuccessorsNeverDeletesAndAnLdapServerIsMovedSeparately() throws Exception {
        String sec = "/api/v2/trees/acme/security/pki";
        String t = sec + "/servers/" + guidOf("cn=edir1,ou=servers,o=system") + "/default-certificates";
        edir.server.modify("cn=TREE CA,cn=Security,o=system", new com.unboundid.ldap.sdk.Modification(
            com.unboundid.ldap.sdk.ModificationType.REPLACE, "nDSPKIPublicKeyCertificate", edir.pki.ca.getEncoded()));
        // "9#" (TCP): port 524, then 10.0.0.9
        edir.server.modify("cn=edir1,ou=servers,o=system", new com.unboundid.ldap.sdk.Modification(com.unboundid.ldap.sdk.ModificationType.ADD, "networkAddress",
            new byte[] {'9', '#', 0x02, 0x0c, 10, 0, 0, 9}));

        Map<String, Object> state = call("GET", t, null, h).body();
        assertEquals(String.valueOf(state), List.of("10.0.0.9"), state.get("ips"));
        assertEquals("no certificate yet: the server's own name", List.of("edir1"), state.get("dnsNames"));
        assertEquals("the fake CA has no EC key", false, state.get("ecAvailable"));
        assertEquals("LDAP Server - edir1", Json.asMap(((List<?>) state.get("ldapServers")).get(0)).get("name"));
        assertEquals(List.of("missing"), Json.asMap(((List<?>) state.get("certificates")).get(0)).get("problems"));

        // missing: made under the standard names
        Reply made = call("POST", t, Map.of("kinds", List.of("dns", "ec", "ip"), "dnsNames", List.of("edir1.acme.example")), h);
        assertEquals(String.valueOf(made.body()), 200, made.status());
        List<?> results = (List<?>) made.body().get("results");
        assertEquals("EC is left out without an EC CA key", 2, results.size());
        assertEquals("SSL CertificateDNS", Json.asMap(results.get(0)).get("name"));
        assertEquals("ok", Json.asMap(results.get(1)).get("status"));
        Map<String, Object> req = edir.pkiOps.requests.get(edir.pkiOps.requests.size() - 2);
        assertEquals("dots in a name are escaped in the dotted form", "o=ACME_TREE.cn=edir1\\.acme\\.example", req.get("subjectDN"));
        assertEquals("the DNS certificate names the DNS name and the address", 2, ((List<?>) req.get("subjectAltNames")).size());
        assertEquals("o=ACME_TREE.cn=10\\.0\\.0\\.9", edir.pkiOps.requests.get(edir.pkiOps.requests.size() - 1).get("subjectDN"));

        int before = edir.pkiOps.requests.size();
        results = (List<?>) call("POST", t, Map.of("kinds", List.of("dns", "ip")), h).body().get("results");
        assertEquals("nothing wrong: nothing made", "kept", Json.asMap(results.get(0)).get("action"));
        assertEquals(before, edir.pkiOps.requests.size());

        // the server moved: a successor is made beside the old certificate, which stays
        edir.server.modify("cn=edir1,ou=servers,o=system", new com.unboundid.ldap.sdk.Modification(com.unboundid.ldap.sdk.ModificationType.REPLACE, "networkAddress",
            new byte[] {'9', '#', 0x02, 0x0c, 10, 0, 0, 10}));
        state = call("GET", t, null, h).body();
        Map<String, Object> dns = Json.asMap(((List<?>) state.get("certificates")).get(0));
        assertEquals(List.of("does not name 10.0.0.10"), dns.get("problems"));
        String oldGuid = (String) dns.get("guid");
        results = (List<?>) call("POST", t, Map.of("kinds", List.of("dns")), h).body().get("results");
        Map<String, Object> r = Json.asMap(results.get(0));
        String successor = "SSL CertificateDNS " + java.time.LocalDate.now(java.time.ZoneOffset.UTC);
        assertEquals(String.valueOf(r), successor, r.get("name"));
        assertEquals("SSL CertificateDNS", r.get("replaces"));
        assertTrue("the old one is still there", edir.entry("cn=SSL CertificateDNS - edir1,ou=servers,o=system") != null);
        state = call("GET", t, null, h).body();
        dns = Json.asMap(((List<?>) state.get("certificates")).get(0));
        assertEquals(oldGuid, dns.get("guid"));
        List<?> successors = (List<?>) dns.get("successors");
        assertEquals(successor, Json.asMap(successors.get(0)).get("name"));
        // a second the same day takes the next free name
        results = (List<?>) call("POST", t, Map.of("kinds", List.of("dns")), h).body().get("results");
        assertEquals(successor + "-2", Json.asMap(results.get(0)).get("name"));

        // the LDAP server is given the successor as a step of its own
        String ldap = guidOf("cn=LDAP Server - edir1,ou=servers,o=system");
        Reply used = call("PUT", sec + "/ldap-servers/" + ldap + "/certificate", Map.of("certificate", Json.asMap(successors.get(0)).get("guid")), h);
        assertEquals(String.valueOf(used.body()), 200, used.status());
        assertEquals(successor, edir.entry("cn=LDAP Server - edir1,ou=servers,o=system").getAttributeValue("ldapKeyMaterialName"));
        assertEquals("ldap3", used.body().get("previous"));
        state = call("GET", t, null, h).body();
        assertEquals(List.of("LDAP Server - edir1"), Json.asMap(((List<?>) Json.asMap(((List<?>) state.get("certificates")).get(0)).get("successors")).get(1)).get("usedBy"));

        assertEquals(400, call("POST", t, Map.of("replace", "some"), h).status());
        assertEquals(400, call("POST", t, Map.of("kinds", List.of("dns"), "dnsNames", List.of("bad name")), h).status());
    }

    @Test
    public void caConfigurationBitsAreChangedOneByOneAndUnknownBitsKept() throws Exception {
        String t = "/api/v2/trees/acme/security/pki";
        Map<String, Object> ca = Json.asMap(call("GET", t, null, h).body().get("ca"));
        assertEquals("not set: all off", false, Json.asMap(ca.get("configuration")).get("serverSelfProvisioning"));

        assertEquals("force health check needs server self-provisioning", false,
            call("PUT", t + "/ca/configuration", Map.of("forceHealthCheck", true), h).body().get("forceHealthCheck"));
        Reply r = call("PUT", t + "/ca/configuration", Map.of("serverSelfProvisioning", true, "forceHealthCheck", true), h);
        assertEquals(String.valueOf(r.body()), 200, r.status());
        assertEquals("12", edir.entry("cn=TREE CA,cn=Security,o=system").getAttributeValue("ndspkiSecurityRightsLevel"));
        // a bit the console does not know is kept
        edir.server.modify("cn=TREE CA,cn=Security,o=system", new com.unboundid.ldap.sdk.Modification(
            com.unboundid.ldap.sdk.ModificationType.REPLACE, "ndspkiSecurityRightsLevel", String.valueOf(12 | 0x100)));
        r = call("PUT", t + "/ca/configuration", Map.of("serverSelfProvisioning", false), h);
        assertEquals(false, r.body().get("forceHealthCheck"));
        assertEquals("the unknown bit stays; turning off self-provisioning clears force health check",
            String.valueOf(0x100), edir.entry("cn=TREE CA,cn=Security,o=system").getAttributeValue("ndspkiSecurityRightsLevel"));
        assertEquals(400, call("PUT", t + "/ca/configuration", Map.of("requireReadRights", "yes"), h).status());

        // Suite B: refused for a CA with an RSA certificate
        edir.server.modify("cn=TREE CA,cn=Security,o=system", new com.unboundid.ldap.sdk.Modification(
            com.unboundid.ldap.sdk.ModificationType.REPLACE, "nDSPKIPublicKeyCertificate", edir.pki.ca.getEncoded()));
        assertEquals(409, call("PUT", t + "/ca/configuration", Map.of("suiteB", true), h).status());
    }

    @Test
    public void ebaIsFoundAmongTheServersNcpAddresses() throws Exception {
        String t = "/api/v2/trees/acme/security/eba";
        assertEquals("no server answers as the EBA CA", false, call("GET", t, null, h).body().get("available"));
        // "9#" (TCP), then port 524 and 127.0.0.9, as eDirectory sends networkAddress over LDAP
        byte[] tcp = {'9', '#', 0x02, 0x0c, 127, 0, 0, 9};
        edir.server.modify("cn=edir1,ou=servers,o=system", new com.unboundid.ldap.sdk.Modification(com.unboundid.ldap.sdk.ModificationType.ADD, "networkAddress", tcp));
        edir.pkiOps.ebaCa = "127.0.0.9:524";
        String uid = com.pointblue.console.server.ldap.FakePki.uid(edir.entry("cn=edir1,ou=servers,o=system").getAttributeValueBytes("GUID"));
        edir.pkiOps.ncp.put(uid, "127.0.0.9:524");
        Map<String, Object> eba = call("GET", t, null, h).body();
        assertEquals(String.valueOf(eba), true, eba.get("available"));
        assertEquals("127.0.0.9:524", eba.get("caAddress"));
        assertEquals("2036-09-20T17:26:56Z", Json.asMap(eba.get("ca")).get("notAfter"));
        assertEquals(true, Json.asMap(eba.get("ca")).get("renewable"));
        Map<String, Object> ncp = Json.asMap(((List<?>) eba.get("ncpCertificates")).get(0));
        assertEquals("the NCP certificate's UID is the server's GUID", "edir1", Json.asMap(ncp.get("server")).get("name"));
        assertEquals("ncp://127.0.0.9:524", ncp.get("address"));
        assertEquals(List.of(), eba.get("pendingRequests"));
    }
}
