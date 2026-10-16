package com.pointblue.console.server.http;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.pointblue.console.server.data.DataDir;
import com.pointblue.console.server.ldap.FakeEdir;
import com.pointblue.console.server.tls.Certs;
import com.pointblue.dirxml.dev.json.Json;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
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

/** The object API end to end: a configured server, a signed-in person, and the fake directory. */
public class ObjectsTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private FakeEdir edir;
    private Path dataPath;
    private Server server;
    private HttpClient http;
    private String base;

    record Reply(int status, Map<String, Object> body, HttpResponse<String> raw) {
        String etag() {
            return raw.headers().firstValue("ETag").orElse(null);
        }

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> items() {
            return (List<Map<String, Object>>) body.get("items");
        }

        List<String> names() {
            return items().stream().map(i -> String.valueOf(i.get("name"))).toList();
        }
    }

    @Before
    public void start() throws Exception {
        List<String> ldif = new ArrayList<>(List.of(
            "dn: cn=admin,o=system\nobjectClass: inetOrgPerson\ncn: admin\nsn: a\nuserPassword: admin-pw",
            "dn: cn=console,o=system\nobjectClass: inetOrgPerson\ncn: console\nsn: c\nuserPassword: console-pw",
            "dn: ou=Users,o=acme\nobjectClass: organizationalUnit\nou: Users",
            "dn: ou=Groups,o=acme\nobjectClass: organizationalUnit\nou: Groups",
            "dn: cn=Viewers,ou=Groups,o=acme\nobjectClass: groupOfNames\ncn: Viewers\nmember: cn=viewer,ou=Users,o=acme",
            "dn: cn=viewer,ou=Users,o=acme\nobjectClass: inetOrgPerson\ncn: viewer\nsn: v\nuserPassword: viewer-pw\ngroupMembership: cn=Viewers,ou=Groups,o=acme",
            "dn: cn=Smith\\, John,ou=Users,o=acme\nobjectClass: inetOrgPerson\ncn: Smith, John\nsn: Smith\ndescription: before",
            "dn: cn=Smith (Admin),ou=Users,o=acme\nobjectClass: inetOrgPerson\ncn: Smith (Admin)\nsn: Smith",
            "dn: ou=Sales,ou=Users,o=acme\nobjectClass: organizationalUnit\nou: Sales"));
        edir = new FakeEdir(ldif.toArray(new String[0]));
        dataPath = tmp.newFolder("data").toPath();
        server = new Server(new DataDir(dataPath), ServerClient.loopback(), "https://localhost:8443", new PrintStream(new ByteArrayOutputStream()));
        server.start();
        base = "https://127.0.0.1:" + server.port();
        http = ServerClient.trusting(server);

        Matcher m = Pattern.compile("Setup token: ([0-9a-f]{32})").matcher(Files.readString(dataPath.resolve("bootstrap.txt")));
        assertTrue(m.find());
        Map<String, String> t = Map.of("X-Setup-Token", m.group(1));
        call("PUT", "/api/v2/setup/directory", Map.of("id", "acme", "name", "Acme", "host", "127.0.0.1", "port", edir.port(), "tier", "lab"), t);
        Reply probe = call("POST", "/api/v2/setup/probe", Map.of(), t);
        assertEquals(200, call("POST", "/api/v2/setup/trust", Map.of("probeId", probe.body().get("probeId"), "confirm", Certs.tail(edir.pki.ca, 8)), t).status());
        assertEquals(200, call("POST", "/api/v2/setup/authority", Map.of("dn", "cn=admin,o=system", "password", "admin-pw"), t).status());
        call("PUT", "/api/v2/setup/service-account", Map.of("dn", "cn=console,o=system", "password", "console-pw"), t);
        assertEquals(200, call("POST", "/api/v2/setup/finish", Map.of(), t).status());
        server.config.update(server.config.version(), "test", "role mapping", doc -> {
            Map<String, Object> dir = Json.asMap(Json.asMap(doc.get("directories")).get("acme"));
            dir.put("roles", List.of(Map.of("group", "cn=Viewers,ou=Groups,o=acme", "role", "viewer")));
        });
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
        return new Reply(r.statusCode(), parsed instanceof Map ? Json.asMap(parsed) : Map.of("list", parsed), r);
    }

    /** Sign in; the returned headers carry the cookie and the CSRF token. */
    private Map<String, String> signIn(String dn, String password) throws Exception {
        Reply in = call("POST", "/api/v2/session", Map.of("directory", "acme", "name", dn, "password", password), Map.of());
        assertEquals(200, in.status());
        String cookie = in.raw().headers().firstValue("Set-Cookie").orElseThrow();
        Map<String, String> h = new HashMap<>();
        h.put("Cookie", cookie.substring(0, cookie.indexOf(';')));
        h.put("X-CSRF-Token", (String) in.body().get("csrf"));
        return h;
    }

    private static Map<String, String> with(Map<String, String> h, String ifMatch) {
        Map<String, String> out = new HashMap<>(h);
        out.put("If-Match", ifMatch);
        return out;
    }

    private Reply resolve(Map<String, String> h, String dn) throws Exception {
        return call("GET", "/api/v2/trees/acme/objects?dn=" + URLEncoder.encode(dn, StandardCharsets.UTF_8), null, h);
    }

    @Test
    public void objectInspectorReadsAndChangesAssociations() throws Exception {
        edir.add("dn: cn=Set1,o=system", "objectClass: DirXML-DriverSet", "cn: Set1");
        edir.add("dn: cn=AD,cn=Set1,o=system", "objectClass: DirXML-Driver", "cn: AD");
        edir.add("dn: cn=HR,cn=Set1,o=system", "objectClass: DirXML-Driver", "cn: HR");
        edir.server.modify("cn=viewer,ou=Users,o=acme", new com.unboundid.ldap.sdk.Modification(com.unboundid.ldap.sdk.ModificationType.ADD,
            "DirXML-Associations", "cn=AD,cn=Set1,o=system#1#{abc-123}", "cn=Gone,cn=Set1,o=system#0#x"));
        Map<String, String> h = signIn("cn=admin,o=system", "admin-pw");
        String user = (String) resolve(h, "cn=viewer,ou=Users,o=acme").body().get("guid");
        String t = "/api/v2/trees/acme/idm/objects/" + user + "/associations";

        Map<String, Object> got = call("GET", t, null, h).body();
        List<?> list = (List<?>) got.get("associations");
        assertEquals(String.valueOf(got), 2, list.size());
        Map<String, Object> ad = Json.asMap(list.get(0));
        assertEquals("processed", ad.get("state"));
        assertEquals("{abc-123}", ad.get("value"));
        assertEquals("AD", Json.asMap(ad.get("driver")).get("name"));
        assertEquals("a driver that no longer exists", null, Json.asMap(list.get(1)).get("driver"));
        assertEquals("disabled", Json.asMap(list.get(1)).get("state"));
        assertEquals(2, ((List<?>) got.get("drivers")).size());
        String hr = (String) ((List<?>) got.get("drivers")).stream().map(Json::asMap).filter(d -> "HR".equals(d.get("name"))).findFirst().orElseThrow().get("guid");
        assertEquals(List.of(), got.get("passwordSync"));
        // the engine's record of each driver's last password synchronization (as the engine writes it)
        edir.server.modify("cn=viewer,ou=Users,o=acme", new com.unboundid.ldap.sdk.Modification(com.unboundid.ldap.sdk.ModificationType.ADD,
            "DirXML-PasswordSyncStatus", hr.toUpperCase() + "20261007155444953000000000001Code(-8032) Operation vetoed by policy.",
            "0123456789ABCDEF0123456789ABCDEF20261008010203004000000000005Password Synchronization is pending."));
        List<?> sync = (List<?>) call("GET", t, null, h).body().get("passwordSync");
        Map<String, Object> first = Json.asMap(sync.get(0));
        assertEquals(String.valueOf(sync), "failed", first.get("status"));
        assertEquals("2026-10-07T15:54:44.953Z", first.get("when"));
        assertEquals("Code(-8032) Operation vetoed by policy.", first.get("message"));
        assertEquals("HR", Json.asMap(first.get("driver")).get("name"));
        assertEquals("pending", Json.asMap(sync.get(1)).get("status"));
        assertEquals("a driver not in the tree", null, Json.asMap(sync.get(1)).get("driver"));

        // a viewer reads but does not change
        Map<String, String> v = signIn("cn=viewer,ou=Users,o=acme", "viewer-pw");
        assertEquals(200, call("GET", t, null, v).status());
        assertEquals(403, call("DELETE", t, Map.of("raw", ad.get("raw")), v).status());

        Reply added = call("POST", t, Map.of("driver", hr, "state", "manual", "value", "E1234"), h);
        assertEquals(String.valueOf(added.body()), 200, added.status());
        assertTrue(edir.entry("cn=viewer,ou=Users,o=acme").hasAttributeValue("DirXML-Associations", "cn=HR,cn=Set1,o=system#3#E1234"));
        assertEquals("one association per driver", 409, call("POST", t, Map.of("driver", hr, "state", "processed", "value", "x"), h).status());
        assertEquals(400, call("POST", t, Map.of("driver", hr, "state", "lost"), h).status());

        Reply changed = call("PATCH", t, Map.of("raw", ad.get("raw"), "state", "migrate"), h);
        assertEquals(200, changed.status());
        assertTrue(edir.entry("cn=viewer,ou=Users,o=acme").hasAttributeValue("DirXML-Associations", "cn=AD,cn=Set1,o=system#4#{abc-123}"));
        assertEquals("the value read is gone: refused, not applied to what is there now", 409,
            call("PATCH", t, Map.of("raw", ad.get("raw"), "state", "disabled"), h).status());

        assertEquals(200, call("DELETE", t, Map.of("raw", "cn=Gone,cn=Set1,o=system#0#x"), h).status());
        assertEquals(2, edir.entry("cn=viewer,ou=Users,o=acme").getAttributeValues("DirXML-Associations").length);
    }

    @Test
    public void traceSettingsOfADriverAndItsDriverSet() throws Exception {
        edir.add("dn: cn=Set1,o=system", "objectClass: DirXML-DriverSet", "cn: Set1", "DirXML-DriverTraceLevel: 3", "DirXML-JavaTraceFile: /opt/novell/java.trace");
        edir.add("dn: cn=AD,cn=Set1,o=system", "objectClass: DirXML-Driver", "cn: AD", "DirXML-TraceLevel: 10", "DirXML-TraceSizeLimit: 100000");
        Map<String, String> h = signIn("cn=admin,o=system", "admin-pw");
        String driver = (String) resolve(h, "cn=AD,cn=Set1,o=system").body().get("guid");
        String set = (String) resolve(h, "cn=Set1,o=system").body().get("guid");
        String t = "/api/v2/trees/acme/idm/drivers/" + driver + "/trace";

        Map<String, Object> got = call("GET", t, null, h).body();
        assertEquals(String.valueOf(got), 10, Json.asInt(got.get("level"), -1));
        assertEquals(null, got.get("file"));
        assertEquals("what the driver set's would give", "/opt/novell/java.trace", Json.asMap(got.get("driverSet")).get("file"));

        Reply put = call("PUT", t, Map.of("level", 5), h);
        assertEquals(String.valueOf(put.body()), 200, put.status());
        com.unboundid.ldap.sdk.Entry ad = edir.entry("cn=AD,cn=Set1,o=system");
        assertEquals("5", ad.getAttributeValue("DirXML-TraceLevel"));
        Map<String, Object> inherit = new HashMap<>();
        inherit.put("level", null);
        assertEquals(200, call("PUT", t, inherit, h).status());
        assertEquals("null: use the driver set's", null, edir.entry("cn=AD,cn=Set1,o=system").getAttributeValue("DirXML-TraceLevel"));

        assertEquals("only the level is changed here", 403, call("PUT", t, Map.of("file", "/var/trace/ad.trace"), h).status());
        assertEquals(400, call("PUT", t, Map.of("level", 11), h).status());
        assertEquals(400, call("PUT", t, Map.of("xslLevel", 1), h).status());

        Reply s2 = call("PUT", "/api/v2/trees/acme/idm/driversets/" + set + "/trace", Map.of("level", 4), h);
        assertEquals(String.valueOf(s2.body()), 200, s2.status());
        assertEquals("4", edir.entry("cn=Set1,o=system").getAttributeValue("DirXML-DriverTraceLevel"));
        assertEquals(403, call("PUT", "/api/v2/trees/acme/idm/driversets/" + set + "/trace", Map.of("javaDebugPort", 9200), h).status());
        assertEquals(404, call("GET", "/api/v2/trees/acme/idm/driversets/" + driver + "/trace", null, h).status());

        Map<String, String> v = signIn("cn=viewer,ou=Users,o=acme", "viewer-pw");
        assertEquals(200, call("GET", t, null, v).status());
        assertEquals(403, call("PUT", t, Map.of("level", 1), v).status());
    }

    @Test
    public void aJobsDefinitionIsChangedInPlaceAndGuardedByItsVersion() throws Exception {
        String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><job-aggregation>\n\t<job-definition auto-delete=\"false\" disabled=\"true\" "
            + "display-name=\"xlfid(job-display-name)Subscriber channel trigger\" scope-required=\"false\" type=\"java\">\n"
            + "\t\t<description>xlfid(job-description)Submits trigger documents.</description>\n"
            + "\t\t<java-class>com.novell.nds.dirxml.job.trigger.Trigger</java-class>\n"
            + "\t\t<configuration-values><definitions><definition display-name=\"xlfid(x)Use Job CN?\" name=\"use-job-cn\" type=\"boolean\"><value>true</value></definition>"
            + "<definition name=\"objs\" type=\"list\"><value><item>Group</item><item>Organizational Unit</item></value></definition></definitions></configuration-values>\n"
            + "\t</job-definition>\n</job-aggregation>";
        edir.add("dn: ou=servers,o=system", "objectClass: organizationalUnit", "ou: servers");
        edir.add("dn: cn=edir1,ou=servers,o=system", "objectClass: ncpServer", "cn: edir1");
        edir.add("dn: cn=edir2,ou=servers,o=system", "objectClass: ncpServer", "cn: edir2");
        edir.add("dn: cn=Set1,o=system", "objectClass: DirXML-DriverSet", "cn: Set1");
        edir.add("dn: cn=AD,cn=Set1,o=system", "objectClass: DirXML-Driver", "cn: AD");
        edir.add("dn: cn=refs,cn=AD,cn=Set1,o=system", "objectClass: DirXML-Job", "cn: refs", "DirXML-ServerList: cn=edir1,ou=servers,o=system",
            "DirXML-Scope: ou=users,o=acme#0#<scope-def scope=\"subtree\"/>");
        edir.server.modify("cn=refs,cn=AD,cn=Set1,o=system", new com.unboundid.ldap.sdk.Modification(com.unboundid.ldap.sdk.ModificationType.ADD,
            "XmlData", xml.getBytes(StandardCharsets.UTF_8)));
        Map<String, String> h = signIn("cn=admin,o=system", "admin-pw");
        String job = (String) resolve(h, "cn=refs,cn=AD,cn=Set1,o=system").body().get("guid");
        String t = "/api/v2/trees/acme/idm/jobs/" + job + "/definition";

        Map<String, Object> got = call("GET", t, null, h).body();
        assertEquals(String.valueOf(got), true, got.get("disabled"));
        assertEquals("Subscriber channel trigger", got.get("displayName"));
        assertEquals("Submits trigger documents.", got.get("description"));
        assertEquals(null, got.get("schedule"));
        assertEquals("driver", Json.asMap(got.get("owner")).get("kind"));
        assertEquals("subtree", Json.asMap(((List<?>) got.get("scope")).get(0)).get("scope"));
        assertEquals("Group; Organizational Unit", Json.asMap(((List<?>) got.get("parameters")).get(1)).get("value"));
        String version = (String) got.get("version");

        Reply changed = call("PATCH", t, Map.of("version", version, "disabled", false, "schedule", "0  2 * * 6",
            "servers", List.of("cn=edir1,ou=servers,o=system", "cn=edir2,ou=servers,o=system")), h);
        assertEquals(String.valueOf(changed.body()), 200, changed.status());
        String now = new String(edir.entry("cn=refs,cn=AD,cn=Set1,o=system").getAttributeValueBytes("XmlData"), StandardCharsets.UTF_8);
        assertEquals("only the start tag's attributes changed",
            xml.replace("disabled=\"true\"", "disabled=\"false\"").replace("type=\"java\">", "type=\"java\" schedule=\"0 2 * * 6\">"), now);
        assertEquals(2, edir.entry("cn=refs,cn=AD,cn=Set1,o=system").getAttributeValues("DirXML-ServerList").length);

        assertEquals("the version read is stale", 409, call("PATCH", t, Map.of("version", version, "disabled", true), h).status());
        String v2 = (String) changed.body().get("version");
        assertEquals(400, call("PATCH", t, Map.of("version", v2, "schedule", "every day"), h).status());
        assertEquals(400, call("PATCH", t, Map.of("version", v2, "servers", List.of("ou=Users,o=acme")), h).status());
        Reply none = call("PATCH", t, Map.of("version", v2, "schedule", ""), h);
        assertEquals(null, none.body().get("schedule"));

        Map<String, String> v = signIn("cn=viewer,ou=Users,o=acme", "viewer-pw");
        assertEquals(200, call("GET", t, null, v).status());
        String jobPath = "/api/v2/trees/acme/idm/jobs/" + job;
        assertEquals(403, call("DELETE", jobPath, Map.of("name", "refs"), v).status());
        assertEquals("the name typed", 409, call("DELETE", jobPath, Map.of("name", "ref"), h).status());
        assertEquals(204, call("DELETE", jobPath, Map.of("name", "refs"), h).status());
        assertEquals(null, edir.entry("cn=refs,cn=AD,cn=Set1,o=system"));
    }

    @Test
    public void mappingTablesAreReadEditedCreatedAndDeleted() throws Exception {
        // Designer writes each column definition among the rows, as on a lab tree
        String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><mapping-table>\n\t<col-def name=\"key\" type=\"nocase\"/>\n\t<row>\n\t\t<col>dept1</col>\n"
            + "\t\t<col>Sales &amp; Marketing</col>\n\t</row>\n\t<col-def name=\"value\" type=\"case\"/>\n\t<row>\n\t\t<col>dept2</col>\n\t\t<col>Support</col>\n\t</row>\n</mapping-table>";
        edir.add("dn: cn=Set1,o=system", "objectClass: DirXML-DriverSet", "cn: Set1");
        edir.add("dn: cn=AD,cn=Set1,o=system", "objectClass: DirXML-Driver", "cn: AD");
        edir.add("dn: cn=Depts,cn=AD,cn=Set1,o=system", "objectClass: DirXML-Resource", "cn: Depts",
            "DirXML-ContentType: application/vnd.novell.dirxml.mapping-table+xml ;charset=UTF-8", "DirXML-pkgGUID: X;com.example;1.0;Example Package;EXPKG");
        edir.add("dn: cn=Script,cn=AD,cn=Set1,o=system", "objectClass: DirXML-Resource", "cn: Script", "DirXML-ContentType: text/ecmascript;charset=UTF-8");
        edir.server.modify("cn=Depts,cn=AD,cn=Set1,o=system", new com.unboundid.ldap.sdk.Modification(com.unboundid.ldap.sdk.ModificationType.ADD,
            "DirXML-Data", xml.getBytes(StandardCharsets.UTF_8)));
        Map<String, String> h = signIn("cn=admin,o=system", "admin-pw");
        String set = (String) resolve(h, "cn=Set1,o=system").body().get("guid");
        String base = "/api/v2/trees/acme/idm/mapping-tables";

        List<?> items = (List<?>) call("GET", base + "?under=" + set, null, h).body().get("items");
        assertEquals("only the mapping table, not the script", 1, items.size());
        Map<String, Object> listed = Json.asMap(items.get(0));
        assertEquals("driver", Json.asMap(listed.get("owner")).get("kind"));
        assertEquals("Example Package", listed.get("package"));
        String guid = (String) listed.get("guid");

        Map<String, Object> got = call("GET", base + "/" + guid, null, h).body();
        assertEquals(List.of(Map.of("name", "key", "type", "nocase"), Map.of("name", "value", "type", "case")), got.get("columns"));
        assertEquals(List.of(List.of("dept1", "Sales & Marketing"), List.of("dept2", "Support")), got.get("rows"));

        Map<String, Object> body = new HashMap<>(Map.of("version", got.get("version"), "columns", got.get("columns"),
            "rows", List.of(List.of("dept1", "Sales & Marketing"), List.of("dept3", "R<&>D"))));
        Reply saved = call("PUT", base + "/" + guid, body, h);
        assertEquals(String.valueOf(saved.body()), 200, saved.status());
        String now = new String(edir.entry("cn=Depts,cn=AD,cn=Set1,o=system").getAttributeValueBytes("DirXML-Data"), StandardCharsets.UTF_8);
        assertTrue(now, now.contains("<col-def name=\"value\" type=\"case\"/>") && now.contains("<col>R&lt;&amp;&gt;D</col>"));
        assertEquals(List.of("dept3", "R<&>D"), ((List<?>) saved.body().get("rows")).get(1));
        assertEquals("the version read is stale", 409, call("PUT", base + "/" + guid, body, h).status());

        Map<String, Object> bad = new HashMap<>(body);
        bad.put("version", saved.body().get("version"));
        bad.put("rows", List.of(List.of("only one")));
        assertEquals(400, call("PUT", base + "/" + guid, bad, h).status());
        bad.put("rows", List.of());
        bad.put("columns", List.of(Map.of("name", "a", "type", "fuzzy")));
        assertEquals(400, call("PUT", base + "/" + guid, bad, h).status());

        String driver = (String) resolve(h, "cn=AD,cn=Set1,o=system").body().get("guid");
        Reply made = call("POST", base, Map.of("parent", driver, "name", "Locations", "columns", List.of(Map.of("name", "code", "type", "nocase"),
            Map.of("name", "city", "type", "nocase")), "rows", List.of(List.of("CHI", "Chicago"))), h);
        assertEquals(String.valueOf(made.body()), 201, made.status());
        assertEquals(List.of(List.of("CHI", "Chicago")), made.body().get("rows"));
        assertEquals(409, call("POST", base, Map.of("parent", driver, "name", "Locations", "columns", List.of(Map.of("name", "a"))), h).status());

        Map<String, String> v = signIn("cn=viewer,ou=Users,o=acme", "viewer-pw");
        assertEquals(200, call("GET", base + "/" + guid, null, v).status());
        assertEquals(403, call("DELETE", base + "/" + guid, Map.of("name", "Depts"), v).status());
        assertEquals(409, call("DELETE", base + "/" + guid, Map.of("name", "depts"), h).status());
        assertEquals(204, call("DELETE", base + "/" + guid, Map.of("name", "Depts"), h).status());
        assertEquals(null, edir.entry("cn=Depts,cn=AD,cn=Set1,o=system"));
    }

    @Test
    public void aDriversPropertiesAreReadAsSections() throws Exception {
        String shim = "<?xml version=\"1.0\"?><driver-config name=\"AD\"><driver-options><configuration-values><definitions>"
            + "<header display-name=\"Authentication Options\"/>"
            + "<group><definition display-name=\"Show authentication options\" name=\"show\" type=\"enum\"><enum-choice display-name=\"show\">show</enum-choice>"
            + "<enum-choice display-name=\"hide\">hide</enum-choice><value>hide</value></definition>"
            + "<subordinates active-value=\"show\"><definition display-name=\"xlfid(m)Authentication Method\" name=\"m\" type=\"string\"><value>Negotiate</value></definition></subordinates></group>"
            + "</definitions></configuration-values></driver-options><subscriber-options/><publisher-options><configuration-values><definitions>"
            + "<definition display-name=\"Polling interval\" name=\"poll\" type=\"integer\"><value>60</value></definition></definitions></configuration-values></publisher-options></driver-config>";
        String gcvs = "<configuration-values><definitions><definition display-name=\"Domain\" name=\"d\" type=\"string\"><value>acme.example</value></definition>"
            + "<definition display-name=\"Groups\" name=\"g\" type=\"list\"><value><item>a</item><item>b</item></value></definition></definitions></configuration-values>";
        String filter = "<filter><filter-class class-name=\"User\" publisher=\"sync\" subscriber=\"sync\"><filter-attr attr-name=\"Surname\" publisher=\"sync\" subscriber=\"notify\"/>"
            + "</filter-class></filter>";
        edir.add("dn: cn=Set1,o=system", "objectClass: DirXML-DriverSet", "cn: Set1");
        edir.add("dn: cn=AD,cn=Set1,o=system", "objectClass: DirXML-Driver", "cn: AD", "DirXML-JavaModule: com.novell.nds.dirxml.remote.driver.DriverShimImpl",
            "DirXML-ShimAuthID: ACME\\idm", "DirXML-ShimAuthServer: REMOTE(hostname=dc1.acme.example port=8090 kmo=idm)dc1.acme.example",
            "DirXML-Policies: cn=pkg-GCVs,cn=AD,cn=Set1,o=system#0#14", "DirXML-Policies: cn=sub-mp,cn=AD,cn=Set1,o=system#1#6",
            "DirXML-Policies: cn=first-mp,cn=AD,cn=Set1,o=system#0#6", "DirXML-Policies: cn=smp,cn=AD,cn=Set1,o=system#0#0");
        edir.add("dn: cn=pkg-GCVs,cn=AD,cn=Set1,o=system", "objectClass: DirXML-GlobalConfigDef", "cn: pkg-GCVs");
        for (String[] a : new String[][] {{"cn=AD,cn=Set1,o=system", "DirXML-ShimConfigInfo", shim}, {"cn=AD,cn=Set1,o=system", "DirXML-DriverFilter", filter},
                {"cn=pkg-GCVs,cn=AD,cn=Set1,o=system", "DirXML-ConfigValues", gcvs}}) {
            edir.server.modify(a[0], new com.unboundid.ldap.sdk.Modification(com.unboundid.ldap.sdk.ModificationType.ADD, a[1], a[2].getBytes(StandardCharsets.UTF_8)));
        }
        Map<String, String> h = signIn("cn=admin,o=system", "admin-pw");
        String driver = (String) resolve(h, "cn=AD,cn=Set1,o=system").body().get("guid");
        Map<String, Object> p = call("GET", "/api/v2/trees/acme/idm/drivers/" + driver + "/properties", null, h).body();

        Map<String, Object> auth = Json.asMap(p.get("authentication"));
        assertEquals(String.valueOf(p), "dc1.acme.example", Json.asMap(auth.get("remoteLoader")).get("hostname"));
        assertEquals(false, auth.get("passwordSet"));
        List<?> params = (List<?>) p.get("parameters");
        assertEquals("the subscriber has none", 2, params.size());
        List<?> driverItems = (List<?>) Json.asMap(params.get(0)).get("items");
        assertEquals("header", Json.asMap(driverItems.get(0)).get("kind"));
        assertEquals("an enum shows its choice's label", "hide", Json.asMap(driverItems.get(1)).get("value"));
        Map<String, Object> sub = Json.asMap(driverItems.get(2));
        assertEquals("Authentication Method", sub.get("label"));
        assertEquals(1, Json.asInt(sub.get("depth"), 0));
        assertEquals("under hide, the show subordinates are inactive", true, sub.get("inactive"));
        Map<String, Object> pkg = Json.asMap(((List<?>) p.get("gcvs")).get(0));
        assertEquals("pkg-GCVs", pkg.get("source"));
        assertEquals("a; b", Json.asMap(((List<?>) pkg.get("items")).get(1)).get("value"));
        Map<String, Object> user = Json.asMap(((List<?>) p.get("filter")).get(0));
        assertEquals("notify", Json.asMap(((List<?>) user.get("attributes")).get(0)).get("subscriber"));
        List<?> policies = (List<?>) p.get("policies");
        assertEquals(List.of("smp", "first-mp", "sub-mp", "pkg-GCVs"), policies.stream().map(x -> Json.asMap(x).get("name")).toList());
        assertEquals("Subscriber matching", Json.asMap(policies.get(1)).get("set"));
    }

    @Test
    public void driverSetProperties() throws Exception {
        String gcvs = "<configuration-values><definitions><definition display-name=\"Vault\" name=\"vault\" type=\"string\"><value>idv</value></definition>"
            + "</definitions></configuration-values>";
        edir.add("dn: cn=Set1,o=system", "objectClass: DirXML-DriverSet", "cn: Set1", "DirXML-JavaEnvironmentParameters: DHOST_JVM_MAX_HEAP$3G",
            "DirXML-ServerList: cn=idm1,o=system", "DirXML-LogLimit: 500", "DirXML-Policies: cn=set-GCVs,cn=Set1,o=system#0#14");
        edir.add("dn: cn=set-GCVs,cn=Set1,o=system", "objectClass: DirXML-GlobalConfigDef", "cn: set-GCVs");
        for (String dn : new String[] {"cn=Set1,o=system", "cn=set-GCVs,cn=Set1,o=system"}) {
            edir.server.modify(dn, new com.unboundid.ldap.sdk.Modification(com.unboundid.ldap.sdk.ModificationType.ADD, "DirXML-ConfigValues", gcvs.getBytes(StandardCharsets.UTF_8)));
        }
        Map<String, String> h = signIn("cn=admin,o=system", "admin-pw");
        String set = (String) resolve(h, "cn=Set1,o=system").body().get("guid");
        Map<String, Object> p = call("GET", "/api/v2/trees/acme/idm/driversets/" + set + "/properties", null, h).body();

        assertEquals(String.valueOf(p), List.of(Map.of("name", "DHOST_JVM_MAX_HEAP", "value", "3G")), p.get("javaEnvironment"));
        assertEquals(List.of("cn=idm1,o=system"), p.get("servers"));
        assertEquals("500", p.get("logLimit"));
        List<?> g = (List<?>) p.get("gcvs");
        assertEquals("its own, then the linked GCV object's", List.of("the driver set", "set-GCVs"), g.stream().map(x -> Json.asMap(x).get("source")).toList());
        assertEquals("idv", Json.asMap(((List<?>) Json.asMap(g.get(0)).get("items")).get(0)).get("value"));
        assertEquals("set-GCVs", Json.asMap(((List<?>) p.get("policies")).get(0)).get("name"));
    }

    @Test
    public void browseReadAndSchema() throws Exception {
        Map<String, String> h = signIn("cn=admin,o=system", "admin-pw");
        Reply roots = call("GET", "/api/v2/trees/acme/roots", null, h);
        assertEquals(200, roots.status());
        assertTrue(roots.names().containsAll(List.of("acme", "system")));

        Reply users = resolve(h, "ou=Users,o=acme");
        String usersGuid = (String) users.body().get("guid");
        assertTrue(usersGuid.matches("[0-9a-f]{32}"));
        assertEquals("organizationalUnit", users.body().get("objectClass"));
        assertEquals("the schema says container; no positive count", "maybe", users.body().get("children"));
        assertNotNull(users.etag());

        Reply smith = resolve(h, "cn=Smith\\2c John,ou=Users,o=acme");
        assertEquals("another spelling of the DN finds the same entry", 200, smith.status());
        assertEquals("Smith, John", smith.body().get("name"));
        assertEquals("no", smith.body().get("children"));
        Reply byGuid = call("GET", "/api/v2/trees/acme/objects/" + smith.body().get("guid"), null, h);
        assertEquals(200, byGuid.status());
        assertEquals(smith.etag(), byGuid.etag());
        assertEquals(List.of("before"), Json.asMap(byGuid.body().get("attributes")).get("description"));
        assertFalse("GUID is the identity, not an attribute", Json.asMap(byGuid.body().get("attributes")).containsKey("GUID"));

        Reply all = call("GET", "/api/v2/trees/acme/objects/" + usersGuid + "/children", null, h);
        assertEquals(200, all.status());
        assertEquals(4, Json.asInt(all.body().get("total"), -1));
        assertEquals("sorted by name across naming attributes", List.of("Sales", "Smith (Admin)", "Smith, John", "viewer"), all.names());
        assertEquals(List.of("Sales"), call("GET", "/api/v2/trees/acme/objects/" + usersGuid + "/children?kind=containers", null, h).names());
        Reply leaves = call("GET", "/api/v2/trees/acme/objects/" + usersGuid + "/children?kind=leaves&offset=2&count=1", null, h);
        assertEquals(List.of("Smith, John"), leaves.names());
        assertEquals(3, Json.asInt(leaves.body().get("total"), -1));
        assertEquals(List.of("viewer"), call("GET", "/api/v2/trees/acme/objects/" + usersGuid + "/children?kind=leaves&startAt=t", null, h).names());

        Reply rights = call("GET", "/api/v2/trees/acme/objects/" + usersGuid + "/rights", null, h);
        assertEquals(List.of("browse", "add", "delete", "rename", "supervisor"), rights.body().get("entry"));

        Reply ou = call("GET", "/api/v2/trees/acme/schema/classes/organizationalUnit", null, h);
        assertEquals(true, ou.body().get("container"));
        assertTrue(((List<?>) ou.body().get("allMust")).contains("ou"));
        assertEquals("member", call("GET", "/api/v2/trees/acme/schema/attributes/uniqueMember", null, h).body().get("name"));
        assertEquals(404, call("GET", "/api/v2/trees/acme/schema/classes/nope", null, h).status());

        assertEquals(404, call("GET", "/api/v2/trees/acme/objects/" + "0".repeat(32), null, h).status());
        assertEquals("not a GUID: no route", 404, call("GET", "/api/v2/trees/acme/objects/cn=x", null, h).status());
        assertEquals("another tree", 404, call("GET", "/api/v2/trees/other/roots", null, h).status());
        assertEquals("signed out", 401, call("GET", "/api/v2/trees/acme/roots", null, Map.of()).status());
    }

    @Test
    public void searchValuesAreText() throws Exception {
        Map<String, String> h = signIn("cn=admin,o=system", "admin-pw");
        Reply r = call("POST", "/api/v2/trees/acme/search", Map.of("filter", Map.of("prefix", Map.of("cn", "Smith (")), "attributes", List.of("sn")), h);
        assertEquals(200, r.status());
        assertEquals(List.of("Smith (Admin)"), r.names());
        assertEquals(List.of("Smith"), Json.asMap(r.items().get(0).get("attributes")).get("sn"));
        Reply inject = call("POST", "/api/v2/trees/acme/search", Map.of("filter", Map.of("eq", Map.of("cn", "*)(objectClass=*"))), h);
        assertEquals(0, Json.asInt(inject.body().get("total"), -1));
        Reply under = call("POST", "/api/v2/trees/acme/search", Map.of("base", Map.of("dn", "ou=Users,o=acme"), "scope", "one",
            "filter", Map.of("eq", Map.of("objectClass", "inetOrgPerson")), "sort", Map.of("attribute", "cn", "order", "desc")), h);
        assertEquals(List.of("viewer", "Smith, John", "Smith (Admin)"), under.names());
        Reply adv = call("POST", "/api/v2/trees/acme/search", Map.of("ldapFilter", "(&(objectClass=organizationalUnit)(ou=S*))"), h);
        assertEquals(List.of("Sales"), adv.names());
        assertEquals(400, call("POST", "/api/v2/trees/acme/search", Map.of("ldapFilter", "(ou=a)(ou=b)"), h).status());
        assertEquals(400, call("POST", "/api/v2/trees/acme/search", Map.of("filter", Map.of("eq", Map.of("cn)(x", "y"))), h).status());
    }

    @Test
    public void writesNeedTheEditorRoleAndACurrentEtag() throws Exception {
        Map<String, String> h = signIn("cn=admin,o=system", "admin-pw");
        String users = (String) resolve(h, "ou=Users,o=acme").body().get("guid");
        String sales = (String) resolve(h, "ou=Sales,ou=Users,o=acme").body().get("guid");
        String viewersGroup = (String) resolve(h, "cn=Viewers,ou=Groups,o=acme").body().get("guid");

        Reply made = call("POST", "/api/v2/trees/acme/objects/" + users + "/children", Map.of("objectClass", "groupOfNames",
            "name", Map.of("type", "cn", "value", "Team #1, (x)+y"),
            "attributes", Map.of("description", "new", "member", List.of(Map.of("guid", viewersGroup)))), h);
        assertEquals(201, made.status());
        String guid = (String) made.body().get("guid");
        assertEquals("Team #1, (x)+y", made.body().get("name"));
        assertEquals(List.of(Map.of("dn", "cn=Viewers,ou=Groups,o=acme", "name", "Viewers")), Json.asMap(made.body().get("attributes")).get("member"));
        assertTrue(made.raw().headers().firstValue("Location").orElse("").endsWith("/objects/" + guid));
        assertEquals(409, call("POST", "/api/v2/trees/acme/objects/" + users + "/children", Map.of("objectClass", "groupOfNames",
            "name", Map.of("type", "cn", "value", "Team #1, (x)+y")), h).status());

        Map<String, Object> change = Map.of("changes", List.of(Map.of("op", "replace", "attribute", "description", "values", List.of("changed"))));
        assertEquals(428, call("PATCH", "/api/v2/trees/acme/objects/" + guid, change, h).status());
        Reply patched = call("PATCH", "/api/v2/trees/acme/objects/" + guid, change, with(h, made.etag()));
        assertEquals(200, patched.status());
        assertEquals(List.of("changed"), Json.asMap(patched.body().get("attributes")).get("description"));
        assertNotEquals(made.etag(), patched.etag());
        Reply stale = call("PATCH", "/api/v2/trees/acme/objects/" + guid, change, with(h, made.etag()));
        assertEquals(412, stale.status());
        assertEquals(patched.etag(), stale.body().get("etag"));
        assertEquals("GUID is maintained by the directory", 400, call("PATCH", "/api/v2/trees/acme/objects/" + guid,
            Map.of("changes", List.of(Map.of("op", "replace", "attribute", "GUID", "values", List.of("x")))), with(h, "*")).status());

        Reply renamed = call("POST", "/api/v2/trees/acme/objects/" + guid + "/rename", Map.of("name", "Team, renamed"), with(h, patched.etag()));
        assertEquals(200, renamed.status());
        assertEquals("cn=Team\\, renamed,ou=Users,o=acme", renamed.body().get("dn"));
        assertEquals(guid, renamed.body().get("guid"));
        Reply moved = call("POST", "/api/v2/trees/acme/objects/" + guid + "/move", Map.of("newParent", sales), with(h, renamed.etag()));
        assertEquals(200, moved.status());
        assertEquals("cn=Team\\, renamed,ou=Sales,ou=Users,o=acme", moved.body().get("dn"));
        assertEquals("a container cannot move under itself", 409,
            call("POST", "/api/v2/trees/acme/objects/" + users + "/move", Map.of("newParent", sales), with(h, "*")).status());
        Reply nonLeaf = call("DELETE", "/api/v2/trees/acme/objects/" + sales, null, with(h, "*"));
        assertEquals(409, nonLeaf.status());
        assertEquals(66, Json.asInt(nonLeaf.body().get("ldapResultCode"), -1));
        assertEquals(204, call("DELETE", "/api/v2/trees/acme/objects/" + guid, null, with(h, moved.etag())).status());
        assertEquals(404, call("GET", "/api/v2/trees/acme/objects/" + guid, null, h).status());

        // secrets are not written through the generic editor; the password task is audited without the value
        String smith = (String) resolve(h, "cn=Smith\\, John,ou=Users,o=acme").body().get("guid");
        Reply generic = call("PATCH", "/api/v2/trees/acme/objects/" + smith,
            Map.of("changes", List.of(Map.of("op", "replace", "attribute", "userPassword", "values", List.of("S3cret-value!")))), with(h, "*"));
        assertEquals(400, generic.status());
        assertEquals("secret-attribute", generic.body().get("title"));
        assertEquals(204, call("POST", "/api/v2/trees/acme/objects/" + smith + "/password", Map.of("password", "S3cret-value!"), h).status());
        String auditText;
        try (var files = Files.list(dataPath.resolve("audit"))) {
            StringBuilder b = new StringBuilder();
            for (Path p : files.toList()) {
                b.append(Files.readString(p));
            }
            auditText = b.toString();
        }
        assertTrue(auditText.contains("object.create") && auditText.contains("object.move") && auditText.contains("object.password"));
        assertFalse("no value reaches the audit log", auditText.contains("S3cret-value!") || auditText.contains("changed\""));

        // a viewer reads but cannot write
        Map<String, String> v = signIn("cn=viewer,ou=Users,o=acme", "viewer-pw");
        assertEquals(200, call("GET", "/api/v2/trees/acme/objects/" + smith, null, v).status());
        assertEquals(403, call("PATCH", "/api/v2/trees/acme/objects/" + smith, change, with(v, "*")).status());
        assertEquals("a write needs the CSRF token", 403, call("PATCH", "/api/v2/trees/acme/objects/" + smith, change,
            Map.of("Cookie", h.get("Cookie"), "If-Match", "*")).status());
    }

    @Test
    public void largeListsUseSortedWindowsAcrossNamingAttributes() throws Exception {
        for (int i = 0; i < 1100; i++) {
            edir.add("dn: cn=user" + String.format("%04d", i) + ",ou=Users,o=acme", "objectClass: inetOrgPerson", "cn: user" + String.format("%04d", i), "sn: u");
        }
        Map<String, String> h = signIn("cn=admin,o=system", "admin-pw");
        String users = (String) resolve(h, "ou=Users,o=acme").body().get("guid");
        Reply first = call("GET", "/api/v2/trees/acme/objects/" + users + "/children?count=3", null, h);
        assertEquals(200, first.status());
        assertEquals("cn entries, then the OU (no cn), in one total", 1104, Json.asInt(first.body().get("total"), -1));
        assertEquals(List.of("Smith (Admin)", "Smith, John", "user0000"), first.names());
        Reply across = call("GET", "/api/v2/trees/acme/objects/" + users + "/children?offset=1102&count=5", null, h);
        assertEquals("the window runs from the cn segment into the ou segment", List.of("user1099", "viewer", "Sales"), across.names());
        Reply jump = call("GET", "/api/v2/trees/acme/objects/" + users + "/children?count=2&startAt=user05", null, h);
        assertEquals(List.of("user0500", "user0501"), jump.names());
        assertEquals(503, Json.asInt(jump.body().get("offset"), -1));
    }

    @Test
    public void passwordAndAccountTasks() throws Exception {
        Map<String, String> h = signIn("cn=admin,o=system", "admin-pw");
        String smith = (String) resolve(h, "cn=Smith\\, John,ou=Users,o=acme").body().get("guid");
        assertEquals(204, call("POST", "/api/v2/trees/acme/objects/" + smith + "/password", Map.of("password", "N3w-secret!", "mustChange", true), h).status());
        Reply in = call("POST", "/api/v2/session", Map.of("directory", "acme", "name", "cn=Smith\\, John,ou=Users,o=acme", "password", "N3w-secret!"), Map.of());
        assertEquals("the new password is accepted (a wrong one is 401); the person just has no console role", "no-role", in.body().get("title"));

        Reply acct = call("GET", "/api/v2/trees/acme/objects/" + smith + "/account", null, h);
        assertEquals(200, acct.status());
        assertNotNull("must-change expired the password", acct.body().get("passwordExpires"));
        Map<String, Object> change = new HashMap<>();
        change.put("disabled", true);
        change.put("loginExpires", "2030-12-31T23:00:00Z");
        change.put("passwordMinimumLength", 8);
        change.put("passwordExpirationDays", 90);
        change.put("timeMap", "ff".repeat(42));
        change.put("maxConnections", null);
        Reply updated = call("PATCH", "/api/v2/trees/acme/objects/" + smith + "/account", change, with(h, acct.etag()));
        assertEquals(200, updated.status());
        assertEquals(true, updated.body().get("disabled"));
        assertEquals("2030-12-31T23:00:00Z", updated.body().get("loginExpires"));
        assertEquals(90, Json.asInt(updated.body().get("passwordExpirationDays"), -1));
        assertEquals("ff".repeat(42), updated.body().get("timeMap"));
        assertEquals(400, call("PATCH", "/api/v2/trees/acme/objects/" + smith + "/account", Map.of("timeMap", "ff"), with(h, "*")).status());
        assertEquals(400, call("PATCH", "/api/v2/trees/acme/objects/" + smith + "/account", Map.of("disabled", "yes"), with(h, "*")).status());
        assertEquals(412, call("PATCH", "/api/v2/trees/acme/objects/" + smith + "/account", Map.of("disabled", false), with(h, acct.etag())).status());

        call("PATCH", "/api/v2/trees/acme/objects/" + smith + "/account", Map.of("disabled", false), with(h, "*"));
        call("PATCH", "/api/v2/trees/acme/objects/" + smith, Map.of("changes", List.of(
            Map.of("op", "replace", "attribute", "lockedByIntruder", "values", List.of("TRUE")),
            Map.of("op", "replace", "attribute", "loginIntruderAttempts", "values", List.of("3")))), with(h, "*"));
        assertEquals(true, call("GET", "/api/v2/trees/acme/objects/" + smith + "/account", null, h).body().get("lockedByIntruder"));
        Reply unlocked = call("POST", "/api/v2/trees/acme/objects/" + smith + "/unlock", Map.of(), h);
        assertEquals(200, unlocked.status());
        assertEquals(false, unlocked.body().get("lockedByIntruder"));
        assertEquals(null, unlocked.body().get("intruderAttempts"));
    }

    @Test
    public void membershipIsWrittenOnBothSides() throws Exception {
        Map<String, String> h = signIn("cn=admin,o=system", "admin-pw");
        String smith = (String) resolve(h, "cn=Smith\\, John,ou=Users,o=acme").body().get("guid");
        String viewers = (String) resolve(h, "cn=Viewers,ou=Groups,o=acme").body().get("guid");
        Reply r = call("POST", "/api/v2/trees/acme/objects/" + smith + "/memberships", Map.of("add", List.of(viewers)), h);
        assertEquals(200, r.status());
        Map<String, Object> group = Json.asMap(resolve(h, "cn=Viewers,ou=Groups,o=acme").body().get("attributes"));
        Map<String, Object> user = Json.asMap(resolve(h, "cn=Smith\\, John,ou=Users,o=acme").body().get("attributes"));
        assertTrue(String.valueOf(group.get("member")).contains("Smith"));
        assertTrue(String.valueOf(group.get("equivalentToMe")).contains("Smith"));
        assertTrue(String.valueOf(user.get("groupMembership")).contains("Viewers"));
        assertTrue(String.valueOf(user.get("securityEquals")).contains("Viewers"));
        Reply again = call("POST", "/api/v2/trees/acme/objects/" + smith + "/memberships", Map.of("add", List.of(viewers)), h);
        assertEquals("unchanged", Json.asMap(((List<?>) again.body().get("results")).get(0)).get("status"));

        Reply groups = call("GET", "/api/v2/trees/acme/objects/" + smith + "/memberships", null, h);
        assertEquals(List.of("Viewers"), ((List<?>) groups.body().get("items")).stream().map(i -> Json.asMap(i).get("name")).toList());
        Reply members = call("GET", "/api/v2/trees/acme/objects/" + viewers + "/members", null, h);
        assertEquals(List.of("Smith, John", "viewer"), ((List<?>) members.body().get("items")).stream().map(i -> Json.asMap(i).get("name")).toList());
        assertEquals(false, members.body().get("dynamic"));

        assertEquals(200, call("POST", "/api/v2/trees/acme/objects/" + viewers + "/members",
            Map.of("remove", List.of(Map.of("dn", "cn=Smith\\, John,ou=Users,o=acme"))), h).status());
        user = Json.asMap(resolve(h, "cn=Smith\\, John,ou=Users,o=acme").body().get("attributes"));
        assertFalse(user.containsKey("groupMembership") && String.valueOf(user.get("groupMembership")).contains("Viewers"));
        assertFalse(user.containsKey("securityEquals") && String.valueOf(user.get("securityEquals")).contains("Viewers"));
    }

    @Test
    public void aliasSubtreeDeleteAndTheLockoutGuard() throws Exception {
        Map<String, String> h = signIn("cn=admin,o=system", "admin-pw");
        String users = (String) resolve(h, "ou=Users,o=acme").body().get("guid");
        String groups = (String) resolve(h, "ou=Groups,o=acme").body().get("guid");
        Reply sales = resolve(h, "ou=Sales,ou=Users,o=acme");
        Reply moved = call("POST", "/api/v2/trees/acme/objects/" + sales.body().get("guid") + "/move",
            Map.of("newParent", groups, "leaveAlias", true), with(h, sales.etag()));
        assertEquals(200, moved.status());
        assertEquals("created", moved.raw().headers().firstValue("X-Alias").orElse(""));
        Map<String, Object> alias = Json.asMap(resolve(h, "ou=Sales,ou=Users,o=acme").body().get("attributes"));
        assertEquals(List.of(Map.of("dn", "ou=Sales,ou=Groups,o=acme", "name", "Sales")), alias.get("aliasedObjectName"));

        Reply count = call("GET", "/api/v2/trees/acme/objects/" + users + "/subtree", null, h);
        int n = Json.asInt(count.body().get("count"), -1);
        assertEquals("Users, three users and the alias", 5, n);
        assertEquals(409, call("DELETE", "/api/v2/trees/acme/objects/" + users + "?subtree=true", null, with(h, "*")).status());
        Map<String, String> confirm = with(h, "*");
        confirm.put("X-Confirm-Count", String.valueOf(n + 1));
        assertEquals("a stale count", 409, call("DELETE", "/api/v2/trees/acme/objects/" + users + "?subtree=true", null, confirm).status());
        confirm.put("X-Confirm-Count", String.valueOf(n));
        Reply gone = call("DELETE", "/api/v2/trees/acme/objects/" + users + "?subtree=true", null, confirm);
        assertEquals(200, gone.status());
        assertEquals(n, Json.asInt(gone.body().get("deleted"), -1));
        assertEquals(404, resolve(h, "ou=Users,o=acme").status());

        // an IRF that blocks Supervisor needs an explicit Supervisor trustee first
        Map<String, Object> irf = Map.of("privileges", List.of("browse"), "scope", "subtree", "trustee", Map.of("special", "[Inheritance Mask]"), "attribute", "[Entry Rights]");
        Reply refused = call("PATCH", "/api/v2/trees/acme/objects/" + groups, Map.of("changes", List.of(Map.of("op", "add", "attribute", "ACL", "values", List.of(irf)))), with(h, "*"));
        assertEquals(409, refused.status());
        assertEquals("would-lock-out", refused.body().get("title"));
        Map<String, Object> explicit = Map.of("privileges", List.of("supervisor"), "scope", "subtree", "trustee", Map.of("dn", "cn=admin,o=system"), "attribute", "[Entry Rights]");
        assertEquals(200, call("PATCH", "/api/v2/trees/acme/objects/" + groups, Map.of("changes", List.of(
            Map.of("op", "add", "attribute", "ACL", "values", List.of(explicit, irf)))), with(h, "*")).status());
        Map<String, Object> acl = Json.asMap(resolve(h, "ou=Groups,o=acme").body().get("attributes"));
        assertEquals(2, ((List<?>) acl.get("ACL")).size());

        Reply rights = call("GET", "/api/v2/trees/acme/objects/" + groups + "/rights?trustee=" + URLEncoder.encode("cn=viewer,ou=Groups,o=acme", StandardCharsets.UTF_8) + "&attribute=member", null, h);
        assertEquals(200, rights.status());
        assertEquals("viewer", Json.asMap(rights.body().get("trustee")).get("name"));
        assertNotNull(rights.body().get("attribute"));
        assertEquals("the trustee asked about", "cn=viewer,ou=Groups,o=acme", edir.privilegeRequests.get(edir.privilegeRequests.size() - 1)[1]);
    }
}
