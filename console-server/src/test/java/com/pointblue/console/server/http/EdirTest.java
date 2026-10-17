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
                + "indexDefinition: 0$CN$0$0$1$1$CN\nindexDefinition: 0$GnSnIndex$0$0$0$1$Given Name$Surname\nindexDefinition: 0$GUID$0$0$2$1$GUID",
            "dn: " + S2 + "\nobjectClass: ncpServer\ncn: edir2\nversion: eDirectory for Linux x86_64 v9.3.2.0000 [DS]\nstatus: 2",
            "dn: cn=LDAP Server - edir1,ou=servers,o=system\nobjectClass: ldapServer\ncn: LDAP Server - edir1\nldapHostServer: " + S1
                + "\nldapGroupDN: cn=LDAP Group - edir1,ou=servers,o=system\nldapInterfaces: ldap://:389\nldapInterfaces: ldaps://:636\nldapTLSRequired: FALSE\nsearchSizeLimit: 0",
            "dn: cn=LDAP Group - edir1,ou=servers,o=system\nobjectClass: ldapGroup\ncn: LDAP Group - edir1\nldapServerList: cn=LDAP Server - edir1,ou=servers,o=system"
                + "\nldapClassList: NDSName=Group$LDAPNames=groupOfNames\\24group\nldapAllowClearTextPassword: FALSE",
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
        assertEquals(201, call("POST", "/api/v2/trees/acme/edir/schema/attributes", Map.of("name", "acmeDesk", "syntax", "1.3.6.1.4.1.1466.115.121.1.15",
            "flags", List.of("publicRead", "notSyncImmediate")), h).status());
        String desk = String.valueOf(call("GET", "/api/v2/trees/acme/schema/attributes/acmeDesk", null, h).body());
        assertTrue(desk, desk.contains("X-NDS_PUBLIC_READ") && desk.contains("X-NDS_NOT_SCHED_SYNC_IMMEDIATE"));
        assertEquals(400, call("POST", "/api/v2/trees/acme/edir/schema/attributes", Map.of("name", "acmeBad", "syntax", "1.3.6.1.4.1.1466.115.121.1.15",
            "flags", List.of("everything")), h).status());

        Reply ix = call("POST", "/api/v2/trees/acme/edir/servers/" + g1 + "/indexes", Map.of("name", "badges", "attributes", List.of("acmeBadge"), "rule", "substring"), h);
        assertEquals(201, ix.status());
        assertTrue(edir.server.getEntry(EdirTest.S1).getAttribute("indexDefinition").hasValue("0$badges$0$2$0$1$acmeBadge"));
        assertEquals(409, call("POST", "/api/v2/trees/acme/edir/servers/" + g1 + "/indexes", Map.of("name", "badges", "attributes", List.of("acmeBadge")), h).status());
        assertEquals(400, call("POST", "/api/v2/trees/acme/edir/servers/" + g1 + "/indexes", Map.of("name", "nope", "attributes", List.of("noSuchAttr")), h).status());
        assertEquals("a system index stays", 409, call("DELETE", "/api/v2/trees/acme/edir/servers/" + g1 + "/indexes/CN", null, h).status());
        // online and offline: only that value's state changes; eDirectory's own indexes stay online
        Reply off = call("PUT", "/api/v2/trees/acme/edir/servers/" + g1 + "/indexes/badges/state", Map.of("state", "offline"), h);
        assertEquals(String.valueOf(off.body()), 200, off.status());
        Map<String, Object> badges = ((List<?>) off.body().get("indexes")).stream().map(Json::asMap).filter(i -> "badges".equals(i.get("name"))).findFirst().orElseThrow();
        assertEquals("offline", badges.get("state"));
        assertEquals("0$badges$1$2$0$1$acmeBadge", badges.get("raw"));
        Reply on = call("PUT", "/api/v2/trees/acme/edir/servers/" + g1 + "/indexes/badges/state", Map.of("state", "online"), h);
        assertTrue(String.valueOf(on.body().get("indexes")).contains("0$badges$0$2$0$1$acmeBadge"));
        assertEquals(400, call("PUT", "/api/v2/trees/acme/edir/servers/" + g1 + "/indexes/badges/state", Map.of("state", "asleep"), h).status());
        assertEquals("a system index stays online", 409, call("PUT", "/api/v2/trees/acme/edir/servers/" + g1 + "/indexes/GUID/state", Map.of("state", "offline"), h).status());
        assertEquals(404, call("PUT", "/api/v2/trees/acme/edir/servers/" + g1 + "/indexes/nope/state", Map.of("state", "offline"), h).status());
        // copying to another server: the same definition, online, and limber there
        String g2 = (String) list(call("GET", "/api/v2/trees/acme/edir/servers", null, h)).get(1).get("guid");
        edir.partitions.triggered.clear();
        Reply copied = call("POST", "/api/v2/trees/acme/edir/servers/" + g1 + "/indexes/badges/copy", Map.of("servers", List.of(g2)), h);
        assertEquals(String.valueOf(copied.body()), 200, copied.status());
        assertEquals("copied", Json.asMap(((List<?>) copied.body().get("results")).get(0)).get("status"));
        String s2 = String.valueOf(call("GET", "/api/v2/trees/acme/edir/servers/" + g2, null, h).body().get("indexes"));
        assertTrue(s2, s2.contains("0$badges$0$2$0$1$acmeBadge"));
        assertEquals(1, edir.partitions.triggered.size());
        Reply again = call("POST", "/api/v2/trees/acme/edir/servers/" + g1 + "/indexes/badges/copy", Map.of("servers", List.of(g2)), h);
        assertEquals("already-there", Json.asMap(((List<?>) again.body().get("results")).get(0)).get("status"));
        assertEquals("eDirectory makes its own indexes", 409, call("POST", "/api/v2/trees/acme/edir/servers/" + g1 + "/indexes/CN/copy", Map.of("servers", List.of(g2)), h).status());
        assertEquals(400, call("POST", "/api/v2/trees/acme/edir/servers/" + g1 + "/indexes/badges/copy", Map.of("servers", List.of("nope")), h).status());
        assertEquals(200, call("DELETE", "/api/v2/trees/acme/edir/servers/" + g2 + "/indexes/badges", null, h).status());
        assertEquals(200, call("DELETE", "/api/v2/trees/acme/edir/servers/" + g1 + "/indexes/badges", null, h).status());

        assertEquals(200, call("DELETE", "/api/v2/trees/acme/edir/schema/classes/acmeAux", null, h).status());
        assertEquals(200, call("DELETE", "/api/v2/trees/acme/edir/schema/attributes/acmeBadge", null, h).status());
        assertEquals(404, call("GET", "/api/v2/trees/acme/schema/attributes/acmeBadge", null, h).status());
    }

    @Test
    public void ldapServerAndGroupSettingsAreCheckedWrittenAndRefreshed() throws Exception {
        String t = "/api/v2/trees/acme/edir/ldap";
        Map<String, Object> all = call("GET", t, null, h).body();
        Map<String, Object> srv = ((List<?>) all.get("servers")).stream().map(Json::asMap).findFirst().orElseThrow();
        assertEquals(List.of("ldap://:389", "ldaps://:636"), srv.get("interfaces"));
        assertEquals("edir1", Json.asMap(srv.get("host")).get("name"));
        String sg = (String) srv.get("guid");
        String gg = (String) Json.asMap(srv.get("group")).get("guid");

        Map<String, Object> settings = Json.asMap(call("GET", t + "/servers/" + sg, null, h).body().get("settings"));
        assertEquals(false, settings.get("ldapTLSRequired"));
        assertEquals(0, Json.asInt(settings.get("searchSizeLimit"), -1));
        Reply changed = call("PATCH", t + "/servers/" + sg, Map.of("settings", Map.of("ldapTLSRequired", true, "searchSizeLimit", 500,
            "ldapInterfaces", List.of("ldaps://:636"), "ldapSSLConfig", Map.of("protocol", "+TLSv1.2+TLSv1.3", "ciphers", "HIGH"))), h);
        assertEquals(String.valueOf(changed.body()), 200, changed.status());
        settings = Json.asMap(changed.body().get("settings"));
        assertEquals(true, settings.get("ldapTLSRequired"));
        assertEquals(500, Json.asInt(settings.get("searchSizeLimit"), -1));
        assertEquals(List.of("ldaps://:636"), settings.get("ldapInterfaces"));
        assertEquals(Map.of("protocol", "+TLSv1.2+TLSv1.3", "ciphers", "HIGH", "ciphersuites", ""), settings.get("ldapSSLConfig"));
        assertEquals("{\"Version\":1,\"Info\":{\"Protocol\":\"+TLSv1.2+TLSv1.3\",\"Ciphers\":\"HIGH\",\"Ciphersuites\":\"\"}}",
            edir.server.getEntry("cn=LDAP Server - edir1,ou=servers,o=system").getAttributeValue("ldapSSLConfig"));
        assertEquals("an unknown setting", 400, call("PATCH", t + "/servers/" + sg, Map.of("settings", Map.of("cn", "x")), h).status());
        assertEquals(400, call("PATCH", t + "/servers/" + sg, Map.of("settings", Map.of("searchSizeLimit", -1)), h).status());
        assertEquals(400, call("PATCH", t + "/servers/" + sg, Map.of("settings", Map.of("ldapTLSVerifyClientCertificate", 7)), h).status());
        assertEquals(400, call("PATCH", t + "/servers/" + sg, Map.of("settings", Map.of("ldapInterfaces", List.of("http://:80"))), h).status());
        assertEquals("a removal of a setting that is not there is fine", 200,
            call("PATCH", t + "/servers/" + sg, Map.of("settings", java.util.Collections.singletonMap("searchTimeLimit", null)), h).status());
        assertEquals("a group is not a server", 404, call("GET", t + "/servers/" + gg, null, h).status());

        Map<String, Object> group = call("GET", t + "/groups/" + gg, null, h).body();
        assertEquals(List.of(Map.of("eDirectory", "Group", "ldap", List.of("groupOfNames", "group"))), Json.asMap(group.get("settings")).get("ldapClassList"));
        assertEquals("not withheld: it is a setting, not a password", false, Json.asMap(group.get("settings")).get("ldapAllowClearTextPassword"));
        Reply mapped = call("PATCH", t + "/groups/" + gg, Map.of("settings", Map.of("ldapClassList", List.of(
            Map.of("eDirectory", "Group", "ldap", List.of("groupOfNames", "group")), Map.of("eDirectory", "User", "ldap", List.of("inetOrgPerson"))))), h);
        assertEquals(String.valueOf(mapped.body()), 200, mapped.status());
        assertTrue(edir.server.getEntry("cn=LDAP Group - edir1,ou=servers,o=system").hasAttributeValue("ldapClassList", "NDSName=User$LDAPNames=inetOrgPerson"));
        assertEquals(400, call("PATCH", t + "/groups/" + gg, Map.of("settings", Map.of("ldapClassList", List.of(Map.of("eDirectory", "User", "ldap", List.of())))), h).status());

        // packed and flag settings: only what eDirectory defines
        assertEquals("no binds restricted, high ciphers", 200, call("PATCH", t + "/servers/" + sg, Map.of("settings", Map.of("ldapBindRestrictions", 48)), h).status());
        assertEquals("cipher level 7 does not exist", 400, call("PATCH", t + "/servers/" + sg, Map.of("settings", Map.of("ldapBindRestrictions", 112)), h).status());
        assertEquals("errors only", 200, call("PATCH", t + "/servers/" + sg, Map.of("settings", Map.of("ldapTraceLevel", 12288)), h).status());
        assertEquals(400, call("PATCH", t + "/servers/" + sg, Map.of("settings", Map.of("ldapTraceLevel", 2)), h).status());
        assertEquals(400, call("PATCH", t + "/servers/" + sg, Map.of("settings", Map.of("ldapSSLConfig", Map.of("protocol", "SSLv3"))), h).status());
        Reply tls = call("PATCH", t + "/servers/" + sg, Map.of("settings", Map.of("ldapTLSRequired", false)), h);
        assertEquals("TLS changes need the LDAP module reloaded", "reload", tls.body().get("needs"));
        assertEquals("refresh", call("PATCH", t + "/servers/" + sg, Map.of("settings", Map.of("searchSizeLimit", 100)), h).body().get("needs"));

        // a mapping keeps Identity Console's extra fields (spelt as it spells them)
        Reply described = call("PATCH", t + "/groups/" + gg, Map.of("settings", Map.of("ldapAttributeList", List.of(
            Map.of("eDirectory", "Surname", "ldap", List.of("sn", "surname"), "obsolete", false, "description", "family name")))), h);
        assertEquals(String.valueOf(described.body()), 200, described.status());
        assertTrue(edir.server.getEntry("cn=LDAP Group - edir1,ou=servers,o=system").hasAttributeValue("ldapAttributeList",
            "NDSName=Surname$LDAPNames=sn\\24surname$Obselete=false$Description=family name"));
        assertEquals(List.of(Map.of("eDirectory", "Surname", "ldap", List.of("sn", "surname"), "obsolete", false, "description", "family name")),
            Json.asMap(described.body().get("settings")).get("ldapAttributeList"));

        assertEquals(204, call("POST", t + "/servers/" + sg + "/refresh", Map.of(), h).status());
        edir.partitions.triggered.clear();
        assertEquals(204, call("POST", t + "/servers/" + sg + "/reload", Map.of(), h).status());
        assertEquals(List.of("2.16.840.1.113719.1.27.100.127 reloadModule"), edir.partitions.triggered);
        assertEquals(404, call("POST", t + "/servers/" + gg + "/refresh", Map.of(), h).status());
    }
}
