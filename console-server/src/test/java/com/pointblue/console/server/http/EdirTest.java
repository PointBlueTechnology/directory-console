package com.pointblue.console.server.http;

import static org.junit.Assert.assertEquals;
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

/** The eDirectory administration API end to end over the fake directory and its fake partition operations. */
public class EdirTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private FakeEdir edir;
    private Server server;
    private HttpClient http;
    private String base;
    private Map<String, String> h;

    record Reply(int status, Map<String, Object> body) {
    }

    static final String S1 = "cn=edir1,ou=servers,o=system";
    static final String S2 = "cn=edir2,ou=servers,o=system";

    @Before
    public void start() throws Exception {
        edir = new FakeEdir(
            "dn: cn=admin,o=system\nobjectClass: inetOrgPerson\ncn: admin\nsn: a\nuserPassword: admin-pw",
            "dn: cn=console,o=system\nobjectClass: inetOrgPerson\ncn: console\nsn: c\nuserPassword: console-pw",
            "dn: ou=servers,o=system\nobjectClass: organizationalUnit\nou: servers",
            "dn: " + S1 + "\nobjectClass: ncpServer\ncn: edir1\nversion: eDirectory for Linux x86_64 v9.2.8.0000 [DS]\nstatus: 2\n"
                + "indexDefinition: 0$CN$0$0$1$1$CN\nindexDefinition: 0$GnSnIndex$0$0$0$1$Given Name$Surname",
            "dn: " + S2 + "\nobjectClass: ncpServer\ncn: edir2\nversion: eDirectory for Linux x86_64 v9.3.2.0000 [DS]\nstatus: 2",
            "dn: cn=LDAP Server - edir1,ou=servers,o=system\nobjectClass: ldapServer\ncn: LDAP Server - edir1\nldapHostServer: " + S1,
            "dn: ou=Sales,o=acme\nobjectClass: organizationalUnit\nou: Sales");
        edir.server.modify(S1, new com.unboundid.ldap.sdk.Modification(com.unboundid.ldap.sdk.ModificationType.ADD, "networkAddress",
            concat("9#".getBytes(), java.util.HexFormat.of().parseHex("020c7f000001"))));
        edir.partitions.partition("", Map.of(S1, 0, S2, 1)).partition("o=acme", Map.of(S1, 0, S2, 1));
        Path data = tmp.newFolder("data").toPath();
        server = new Server(new DataDir(data), ServerClient.loopback(), "https://localhost:8443", new PrintStream(new ByteArrayOutputStream()));
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
        HttpResponse<String> r = http.send(ServerClient.request(URI.create(base + "/api/v2/session")).header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(Json.compact(Map.of("directory", "acme", "name", "cn=admin,o=system", "password", "admin-pw")))).build(),
            HttpResponse.BodyHandlers.ofString());
        String cookie = r.headers().firstValue("Set-Cookie").orElseThrow();
        h = new HashMap<>(Map.of("Cookie", cookie.substring(0, cookie.indexOf(';')), "X-CSRF-Token", (String) Json.asMap(Json.parse(r.body())).get("csrf")));
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = java.util.Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    @After
    public void stop() {
        server.stop();
        edir.close();
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
        return new Reply(r.statusCode(), parsed instanceof Map ? Json.asMap(parsed) : Map.of("list", parsed));
    }

    private List<Map<String, Object>> list(Reply r) {
        return ((List<?>) r.body().get("list")).stream().map(Json::asMap).toList();
    }

    private Map<String, Object> partition(String name) throws Exception {
        return list(call("GET", "/api/v2/trees/acme/edir/partitions", null, h)).stream().filter(p -> name.equals(p.get("name"))).findFirst().orElse(null);
    }

    private String typeOn(Map<String, Object> p, String server) {
        return ((List<?>) p.get("replicas")).stream().map(Json::asMap).filter(r -> server.equals(Json.asMap(r.get("server")).get("dn")))
            .map(r -> String.valueOf(r.get("type"))).findFirst().orElse(null);
    }

    @Test
    public void serversPartitionsAndReplicaOperations() throws Exception {
        List<Map<String, Object>> servers = list(call("GET", "/api/v2/trees/acme/edir/servers", null, h));
        assertEquals(2, servers.size());
        Map<String, Object> s1 = servers.get(0);
        assertEquals("edir1", s1.get("name"));
        assertEquals("up", s1.get("status"));
        assertEquals(List.of("tcp 127.0.0.1:524"), s1.get("addresses"));
        assertEquals("cn=LDAP Server - edir1,ou=servers,o=system", Json.asMap(s1.get("ldapServer")).get("dn"));
        String g1 = (String) s1.get("guid");
        String g2 = (String) servers.get(1).get("guid");

        Map<String, Object> detail = call("GET", "/api/v2/trees/acme/edir/servers/" + g1, null, h).body();
        assertEquals(2, ((List<?>) detail.get("replicas")).size());
        List<Map<String, Object>> indexes = ((List<?>) detail.get("indexes")).stream().map(Json::asMap).toList();
        assertEquals(List.of("Given Name", "Surname"), indexes.get(1).get("attributes"));

        Map<String, Object> acme = partition("acme");
        assertEquals("master", typeOn(acme, S1));
        assertEquals("read-write", typeOn(acme, S2));
        assertEquals(false, acme.get("busy"));

        String sales = (String) call("GET", "/api/v2/trees/acme/objects?dn=ou%3DSales%2Co%3Dacme", null, h).body().get("guid");
        assertEquals(202, call("POST", "/api/v2/trees/acme/edir/partitions", Map.of("container", sales), h).status());
        assertEquals("read-write", typeOn(partition("Sales"), S2));
        assertEquals(202, call("DELETE", "/api/v2/trees/acme/edir/partitions/" + sales + "/replicas/" + g2, null, h).status());
        assertEquals("subordinate-reference", typeOn(partition("Sales"), S2));
        assertEquals(202, call("POST", "/api/v2/trees/acme/edir/partitions/" + sales + "/replicas", Map.of("server", g2, "type", "read-only"), h).status());
        assertEquals("read-only", typeOn(partition("Sales"), S2));
        assertEquals(202, call("PUT", "/api/v2/trees/acme/edir/partitions/" + sales + "/replicas/" + g2, Map.of("type", "read-write"), h).status());
        assertEquals("read-write", typeOn(partition("Sales"), S2));
        assertEquals(400, call("PUT", "/api/v2/trees/acme/edir/partitions/" + sales + "/replicas/" + g2, Map.of("type", "teleport"), h).status());
        assertEquals(202, call("POST", "/api/v2/trees/acme/edir/partitions/" + sales + "/merge", Map.of(), h).status());
        assertEquals(null, partition("Sales"));

        assertEquals(204, call("POST", "/api/v2/trees/acme/edir/servers/" + g2 + "/background", Map.of("process", "limber"), h).status());
        assertTrue("the trigger names the server", edir.partitions.triggered.contains("2.16.840.1.113719.1.27.100.49 " + S2));
        assertEquals(400, call("POST", "/api/v2/trees/acme/edir/servers/" + g2 + "/background", Map.of("process", "defrag"), h).status());
    }

    @Test
    public void serverTargetedOperations() throws Exception {
        String sales = (String) call("GET", "/api/v2/trees/acme/objects?dn=ou%3DSales%2Co%3Dacme", null, h).body().get("guid");
        List<Map<String, Object>> holders = list(call("GET", "/api/v2/trees/acme/objects/" + sales + "/servers", null, h));
        assertEquals(2, holders.size());
        Map<String, Object> s1 = holders.stream().filter(x -> S1.equals(x.get("dn"))).findFirst().orElseThrow();
        Map<String, Object> s2 = holders.stream().filter(x -> S2.equals(x.get("dn"))).findFirst().orElseThrow();
        assertEquals("the fake's dsaName is edir1", true, s1.get("connected"));
        assertEquals(false, s2.get("signedIn"));

        Reply own = call("GET", "/api/v2/trees/acme/objects/" + sales + "?server=" + s1.get("guid"), null, h);
        assertEquals("the connected server needs no second sign-in", 200, own.status());
        assertEquals(S1, Json.asMap(own.body().get("servedBy")).get("dn"));
        Reply needs = call("GET", "/api/v2/trees/acme/objects/" + sales + "?server=" + s2.get("guid"), null, h);
        assertEquals(409, needs.status());
        assertEquals("server-sign-in-required", needs.body().get("title"));
        assertEquals(404, call("GET", "/api/v2/trees/acme/objects/" + sales + "?server=00000000000000000000000000000000", null, h).status());
        assertEquals(400, call("GET", "/api/v2/trees/acme/objects/" + sales + "?server=nope", null, h).status());
        assertEquals("all is for reads", 400, call("PATCH", "/api/v2/trees/acme/objects/" + sales + "?server=all", Map.of("changes", List.of()), h).status());

        // edir2 publishes no address; with one set in the directory's settings, its certificate is checked like any other
        Reply noAddress = call("POST", "/api/v2/session/servers", Map.of("server", s2.get("guid"), "password", "admin-pw"), h);
        assertEquals(503, noAddress.status());
        try (FakeEdir other = new FakeEdir()) {
            server.config.update(server.config.version(), "test", "address", doc -> Json.asMap(Json.asMap(doc.get("directories")).get("acme"))
                .put("serverAddresses", Map.of(S2, "127.0.0.1:" + other.port())));
            Reply untrusted = call("POST", "/api/v2/session/servers", Map.of("server", s2.get("guid"), "password", "admin-pw"), h);
            assertEquals("a server whose certificate is not trusted", 409, untrusted.status());
            assertEquals("untrusted-certificate", untrusted.body().get("title"));
        }

        Reply compare = call("GET", "/api/v2/trees/acme/objects/" + sales + "?server=all", null, h);
        assertEquals(200, compare.status());
        List<Map<String, Object>> results = ((List<?>) compare.body().get("servers")).stream().map(Json::asMap).toList();
        assertEquals("ok", results.stream().filter(r -> S1.equals(Json.asMap(r.get("server")).get("dn"))).findFirst().orElseThrow().get("status"));
        assertEquals("server-sign-in-required", results.stream().filter(r -> S2.equals(Json.asMap(r.get("server")).get("dn"))).findFirst().orElseThrow().get("status"));
    }

    @Test
    public void perReplicaAttributesAreMarked() throws Exception {
        assertEquals(true, call("GET", "/api/v2/trees/acme/schema/attributes/DirXML-DriverStartOption", null, h).body().get("perReplica"));
        assertEquals(false, call("GET", "/api/v2/trees/acme/schema/attributes/description", null, h).body().get("perReplica"));
    }

    @Test
    public void indexesAndSchemaChanges() throws Exception {
        String g1 = (String) list(call("GET", "/api/v2/trees/acme/edir/servers", null, h)).get(0).get("guid");
        assertEquals(201, call("POST", "/api/v2/trees/acme/edir/schema/attributes", Map.of("name", "acmeBadge", "syntax", "1.3.6.1.4.1.1466.115.121.1.15", "singleValue", true), h).status());
        assertEquals(201, call("POST", "/api/v2/trees/acme/edir/schema/attributes", Map.of("name", "acmeFloor", "syntax", "1.3.6.1.4.1.1466.115.121.1.27"), h).status());
        assertEquals(201, call("POST", "/api/v2/trees/acme/edir/schema/classes", Map.of("name", "acmeAux", "kind", "auxiliary", "may", List.of("acmeBadge")), h).status());
        assertEquals(201, call("POST", "/api/v2/trees/acme/edir/schema/classes/acmeAux/may", Map.of("attributes", List.of("acmeFloor")), h).status());
        Map<String, Object> aux = call("GET", "/api/v2/trees/acme/schema/classes/acmeAux", null, h).body();
        assertTrue(String.valueOf(aux), String.valueOf(aux.get("may")).contains("acmeFloor") && String.valueOf(aux.get("may")).contains("acmeBadge"));
        assertEquals(400, call("POST", "/api/v2/trees/acme/edir/schema/attributes", Map.of("name", "x y", "syntax", "1.3"), h).status());

        Reply ix = call("POST", "/api/v2/trees/acme/edir/servers/" + g1 + "/indexes", Map.of("name", "badges", "attributes", List.of("acmeBadge"), "rule", "substring"), h);
        assertEquals(201, ix.status());
        assertTrue(edir.server.getEntry(EdirTest.S1).getAttribute("indexDefinition").hasValue("0$badges$0$2$0$1$acmeBadge"));
        assertEquals(409, call("POST", "/api/v2/trees/acme/edir/servers/" + g1 + "/indexes", Map.of("name", "badges", "attributes", List.of("acmeBadge")), h).status());
        assertEquals(400, call("POST", "/api/v2/trees/acme/edir/servers/" + g1 + "/indexes", Map.of("name", "nope", "attributes", List.of("noSuchAttr")), h).status());
        assertEquals("a system index stays", 409, call("DELETE", "/api/v2/trees/acme/edir/servers/" + g1 + "/indexes/CN", null, h).status());
        assertEquals(200, call("DELETE", "/api/v2/trees/acme/edir/servers/" + g1 + "/indexes/badges", null, h).status());

        assertEquals(200, call("DELETE", "/api/v2/trees/acme/edir/schema/classes/acmeAux", null, h).status());
        assertEquals(200, call("DELETE", "/api/v2/trees/acme/edir/schema/attributes/acmeBadge", null, h).status());
        assertEquals(404, call("GET", "/api/v2/trees/acme/schema/attributes/acmeBadge", null, h).status());
    }
}
