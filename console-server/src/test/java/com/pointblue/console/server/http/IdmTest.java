package com.pointblue.console.server.http;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
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
        server = new Server(new DataDir(dataPath), ServerClient.loopback(), "https://localhost:8443", new PrintStream(new ByteArrayOutputStream()));
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

    private Map<String, String> signIn() throws Exception {
        HttpResponse<String> r = http.send(ServerClient.request(URI.create(base + "/api/v2/session")).header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(Json.compact(Map.of("directory", "acme", "name", "cn=admin,o=system", "password", "admin-pw")))).build(),
            HttpResponse.BodyHandlers.ofString());
        assertEquals(200, r.statusCode());
        String cookie = r.headers().firstValue("Set-Cookie").orElseThrow();
        Map<String, String> h = new HashMap<>();
        h.put("Cookie", cookie.substring(0, cookie.indexOf(';')));
        h.put("X-CSRF-Token", (String) Json.asMap(Json.parse(r.body())).get("csrf"));
        return h;
    }

    @Test
    public void driverSetsDriversAndTheirOperations() throws Exception {
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
        var app = call("POST", "/api/v2/trees/acme/idm/drivers/" + ldapGuid + "/passwords", Map.of("kind", "app", "value", "app-S3cret"), h);
        assertEquals(200, app.status());
        assertEquals(false, app.body().get("repaired"));
        // what such passwords hold: spaces at both ends, quotes, backslashes, JSON and LDAP specials, accents, CJK, emoji (a surrogate pair)
        String special = " p\u00e4ss \"q\" \\ / <>&%+;,=*()#{}[]|`~^$!? \u20ac\u00df\u00f1 \u5bc6\u7801 \ud83d\udd11\t ";
        assertEquals(200, call("POST", "/api/v2/trees/acme/idm/drivers/" + ldapGuid + "/passwords", Map.of("kind", "app", "value", special), h).status());
        assertEquals("the engine gets the password exactly as typed", special, engine.lastAppPassword);
        assertEquals("spaces are a password", 200,
            call("POST", "/api/v2/trees/acme/idm/drivers/" + ldapGuid + "/passwords", Map.of("kind", "app", "value", "   "), h).status());
        assertEquals("   ", engine.lastAppPassword);
        // as a browser sends them: JSON.stringify escapes a lone surrogate, which UTF-8 would otherwise turn into "?"
        Map<String, Object> lone = Json.asMap(Json.parse("{\"kind\":\"app\",\"value\":\"ab\\ud83dcd\"}"));
        assertEquals("a broken character is refused, not changed", "bad-field",
            assertThrows(Http.Problem.class, () -> Idm.passwordValue(lone)).type);
        assertEquals("cd\ud83d\udd11", new String(Idm.passwordValue(Json.asMap(Json.parse("{\"value\":\"cd\\ud83d\\udd11\"}")))));
        assertEquals(400, call("POST", "/api/v2/trees/acme/idm/drivers/" + ldapGuid + "/passwords", Map.of("kind", "app", "value", "ab\u0000cd"), h).status());
        assertEquals(400, call("POST", "/api/v2/trees/acme/idm/drivers/" + ldapGuid + "/passwords", Map.of("kind", "app", "value", ""), h).status());
        engine.clearTextAppPassword = true;
        assertEquals("a clear-text value the engine cannot read is deleted first, and the reply says so", true,
            call("DELETE", "/api/v2/trees/acme/idm/drivers/" + ldapGuid + "/passwords", Map.of("kind", "app"), h).body().get("repaired"));
        String auditText;
        try (var files = Files.list(dataPath.resolve("audit"))) {
            StringBuilder b = new StringBuilder();
            for (Path p : files.toList()) {
                b.append(Files.readString(p));
            }
            auditText = b.toString();
        }
        assertTrue(auditText.contains("idm.driver.start") && auditText.contains("idm.password.set"));
        assertTrue(auditText.contains("idm.password.remove") && auditText.contains("was deleted first"));
        assertTrue(engine.actions.contains("app-set cn=LDAP\\, primary,cn=Driver Set,o=system"));
        assertFalse("no secret reaches the audit log", auditText.contains("S3cret-named!") || auditText.contains("rl-S3cret") || auditText.contains("app-S3cret"));

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
    @SuppressWarnings("unchecked")
    public void jobTypesAndANewJob() throws Exception {
        edir.add("dn: cn=idm1,o=system", "objectClass: ncpServer", "cn: idm1");
        edir.add("dn: ou=staff,o=system", "objectClass: organizationalUnit", "ou: staff");
        Map<String, String> h = signIn();
        String set = (String) Json.asMap(((List<?>) call("GET", "/api/v2/trees/acme/idm/driversets", null, h).body().get("items")).get(0)).get("guid");
        String ad = (String) Json.asMap(((List<?>) call("GET", "/api/v2/trees/acme/idm/driversets/" + set, null, h).body().get("drivers")).get(0)).get("guid");

        List<Map<String, Object>> types = (List<Map<String, Object>>) call("GET", "/api/v2/trees/acme/idm/drivers/" + ad + "/job-types", null, h).body().get("types");
        assertEquals(List.of("Subscriber channel trigger"), types.stream().map(t -> t.get("displayName")).toList());
        List<Map<String, Object>> setTypes = (List<Map<String, Object>>) call("GET", "/api/v2/trees/acme/idm/driversets/" + set + "/job-types", null, h).body().get("types");
        assertEquals(List.of("Driver Health"), setTypes.stream().map(t -> t.get("displayName")).toList());

        String trigger = "com.novell.nds.dirxml.job.trigger.Trigger";
        Map<String, Object> job = new HashMap<>(Map.of("type", trigger, "name", "Nightly trigger", "schedule", "0 2 * * *", "servers", List.of("cn=idm1,o=system"),
            "scope", List.of(Map.of("dn", "ou=staff,o=system", "scope", "subtree")), "parameters", Map.of("submit-method", "submit-direct")));
        Reply made = call("POST", "/api/v2/trees/acme/idm/drivers/" + ad + "/jobs", job, h);
        assertEquals(String.valueOf(made.body()), 201, made.status());
        assertEquals("Nightly trigger", made.body().get("name"));
        assertEquals("0 2 * * *", made.body().get("schedule"));
        assertEquals(false, made.body().get("disabled"));
        assertEquals(true, made.body().get("notified"));
        assertTrue(engine.actions.contains("notify-job cn=Nightly trigger,cn=AD,cn=Driver Set,o=system"));
        Map<String, Object> scope = Json.asMap(((List<?>) made.body().get("scope")).get(0));
        assertEquals("ou=staff,o=system", scope.get("dn"));
        assertEquals("subtree", scope.get("scope"));
        String guid = (String) made.body().get("guid");
        Map<String, Object> read = call("GET", "/api/v2/trees/acme/idm/jobs/" + guid + "/definition", null, h).body();
        Map<String, Object> method = ((List<Map<String, Object>>) read.get("parameters")).stream().filter(p -> "submit-method".equals(p.get("name"))).findFirst().orElseThrow();
        assertEquals("submit-direct", method.get("value"));

        // the job's named password, on the job object through the engine; a job has no other kind
        String pw = "/api/v2/trees/acme/idm/jobs/" + guid + "/passwords";
        assertEquals(204, call("POST", pw, Map.of("name", "pw", "displayName", "Password", "value", "s3cret"), h).status());
        assertEquals(List.of("pw"), call("GET", pw, null, h).body().get("named"));
        assertEquals(400, call("POST", pw, Map.of("kind", "remote-loader", "value", "x"), h).status());
        assertEquals(204, call("DELETE", pw, Map.of("name", "pw"), h).status());
        assertEquals(List.of(), call("GET", pw, null, h).body().get("named"));
        assertEquals("a driver is not a job", 404, call("GET", "/api/v2/trees/acme/idm/jobs/" + ad + "/passwords", null, h).status());

        assertEquals("the name is taken", 409, call("POST", "/api/v2/trees/acme/idm/drivers/" + ad + "/jobs", job, h).status());
        job.put("name", "Another");
        job.put("parameters", Map.of("submit-method", "sideways"));
        assertEquals(400, call("POST", "/api/v2/trees/acme/idm/drivers/" + ad + "/jobs", job, h).status());
        job.put("parameters", Map.of());
        job.put("servers", List.of("ou=staff,o=system"));
        assertEquals("not a server", 400, call("POST", "/api/v2/trees/acme/idm/drivers/" + ad + "/jobs", job, h).status());
        job.put("servers", List.of("cn=idm1,o=system"));
        job.put("type", "com.novell.nds.dirxml.job.ckdrvhealth.CheckDriverHealthJob");
        Reply wrong = call("POST", "/api/v2/trees/acme/idm/drivers/" + ad + "/jobs", job, h);
        assertEquals("a driver set's type is not offered for a driver", "unknown-job-type", wrong.body().get("title"));
        job.put("scope", List.of());
        assertEquals("Driver Health needs a scope", 400, call("POST", "/api/v2/trees/acme/idm/driversets/" + set + "/jobs", job, h).status());
    }

    @Test
    public void withoutTheEngineIdmSaysWhy() throws Exception {
        server.login.engines(Engines.none("the engine could not be reached"));
        Map<String, String> h = signIn();
        Reply st = call("GET", "/api/v2/trees/acme/idm", null, h);
        assertEquals(false, st.body().get("available"));
        assertTrue(String.valueOf(st.body().get("problem")).contains("could not be reached"));
        assertEquals(503, call("GET", "/api/v2/trees/acme/idm/driversets", null, h).status());
        assertEquals("the rest of the console still works", 200, call("GET", "/api/v2/trees/acme/roots", null, h).status());
    }

    @Test
    public void roleBasedEntitlementPolicies() throws Exception {
        Map<String, String> h = signIn();
        String set = (String) Json.asMap(((List<?>) call("GET", "/api/v2/trees/acme/idm/driversets", null, h).body().get("items")).get(0)).get("guid");
        String rbe = "/api/v2/trees/acme/idm/driversets/" + set + "/rbe";
        Reply none = call("GET", rbe, null, h);
        assertEquals(String.valueOf(none.body()), 200, none.status());
        assertEquals("no container yet", null, none.body().get("container"));

        String c = "cn=Entitlement Policies,cn=Driver Set,o=system";
        edir.add("dn: cn=Entitlements,cn=Driver Set,o=system", "objectClass: DirXML-Driver", "cn: Entitlements",
            "DirXML-JavaModule: com.novell.nds.dirxml.driver.entitlement.EntitlementServiceDriver");
        edir.add("dn: cn=UserAccount,cn=AD,cn=Driver Set,o=system", "objectClass: DirXML-Entitlement", "cn: UserAccount");
        edir.add("dn: " + c, "objectClass: DirXML-SharedProfileSet", "cn: Entitlement Policies",
            "DirXML-SPPriority: cn=Staff," + c + "#0#0", "DirXML-SPPriority: cn=Managers," + c + "#1#0");
        edir.add("dn: cn=Staff," + c, "objectClass: DirXML-SharedProfile", "cn: Staff", "description: everyone on staff",
            "memberQueryURL: ldap:///ou=Users,o=acme??sub?(title=staff)?x-sparse", "dgIdentity: cn=console,o=system",
            "member: cn=admin,o=system", "excludedMember: cn=console,o=system",
            "DirXML-EntitlementRef: cn=UserAccount,cn=AD,cn=Driver Set,o=system#0#<ref/>",
            "DirXML-SPFilterXML: <selection-criterion/>");
        edir.add("dn: cn=Managers," + c, "objectClass: DirXML-SharedProfile", "cn: Managers", "member: cn=admin,o=system");

        Reply list = call("GET", rbe, null, h);
        assertEquals(String.valueOf(list.body()), 200, list.status());
        List<?> policies = (List<?>) list.body().get("policies");
        assertEquals("in priority order", List.of("Staff", "Managers"), policies.stream().map(p -> Json.asMap(p).get("name")).toList());
        assertEquals(List.of(), list.body().get("problems"));
        assertEquals("Entitlements", Json.asMap(((List<?>) list.body().get("serviceDrivers")).get(0)).get("name"));
        Map<String, Object> staff = Json.asMap(policies.get(0));
        assertEquals(0, Json.asInt(staff.get("priority"), -1));
        Map<String, Object> grant = Json.asMap(((List<?>) staff.get("grants")).get(0));
        assertEquals("UserAccount", grant.get("entitlement"));
        assertEquals("AD", grant.get("driver"));
        assertEquals("(title=staff)", Json.asMap(staff.get("membership")).get("filter"));
        assertEquals("sub", Json.asMap(staff.get("membership")).get("scope"));
        assertEquals("ou=Users,o=acme", Json.asMap(staff.get("membership")).get("base"));
        String staffGuid = (String) staff.get("guid");
        String managersGuid = (String) Json.asMap(policies.get(1)).get("guid");

        Reply one = call("GET", "/api/v2/trees/acme/idm/rbe/policies/" + staffGuid, null, h);
        assertEquals(String.valueOf(one.body()), 200, one.status());
        assertEquals("console", Json.asMap(one.body().get("identity")).get("name"));
        assertEquals(1, ((List<?>) one.body().get("excludedMembers")).size());
        assertEquals(true, Json.asMap(((List<?>) one.body().get("grants")).get(0)).get("exists"));
        assertEquals("<selection-criterion/>", one.body().get("criteria"));
        assertEquals(1, Json.asInt(call("GET", "/api/v2/trees/acme/idm/rbe/policies/" + staffGuid + "/members", null, h).body().get("total"), 0));
        assertEquals("a driver is not a policy", 404, call("GET", "/api/v2/trees/acme/idm/rbe/policies/" + set, null, h).status());

        // reorder: from the version read, naming every policy once
        String version = (String) list.body().get("version");
        assertEquals(400, call("PUT", rbe + "/priorities", Map.of("version", version, "order", List.of(managersGuid)), h).status());
        assertEquals(409, call("PUT", rbe + "/priorities", Map.of("version", "stale", "order", List.of(managersGuid, staffGuid)), h).status());
        Reply moved = call("PUT", rbe + "/priorities", Map.of("version", version, "order", List.of(managersGuid, staffGuid)), h);
        assertEquals(String.valueOf(moved.body()), 200, moved.status());
        assertEquals(List.of("Managers", "Staff"), ((List<?>) moved.body().get("policies")).stream().map(p -> Json.asMap(p).get("name")).toList());
        assertEquals(java.util.Set.of("cn=Managers," + c + "#0#0", "cn=Staff," + c + "#1#0"),
            java.util.Set.of(edir.entry(c).getAttributeValues("DirXML-SPPriority")));

        // delete: the name typed; the rest renumbered without a gap
        assertEquals(400, call("DELETE", "/api/v2/trees/acme/idm/rbe/policies/" + managersGuid, Map.of("name", "managers?"), h).status());
        Reply refused = call("DELETE", "/api/v2/trees/acme/idm/rbe/policies/" + managersGuid, Map.of("name", "Managers"), h);
        assertEquals("the shim ignores a deleted policy, so one with members is emptied first", 409, refused.status());
        assertEquals("not-emptied", refused.body().get("title"));
        assertEquals(200, call("POST", "/api/v2/trees/acme/idm/rbe/policies/" + managersGuid + "/empty", Map.of(), h).status());
        assertEquals(true, call("GET", "/api/v2/trees/acme/idm/rbe/policies/" + managersGuid, null, h).body().get("emptied"));
        assertEquals(200, call("DELETE", "/api/v2/trees/acme/idm/rbe/policies/" + managersGuid, Map.of("name", "Managers"), h).status());
        assertEquals(List.of("cn=Staff," + c + "#0#0"), List.of(edir.entry(c).getAttributeValues("DirXML-SPPriority")));
        String audit;
        try (var files = Files.list(dataPath.resolve("audit"))) {
            StringBuilder all = new StringBuilder();
            for (Path f : files.toList()) {
                all.append(Files.readString(f));
            }
            audit = all.toString();
        }
        assertTrue(audit.contains("idm.rbe.priorities"));
        assertTrue(audit.contains("idm.rbe.delete"));

        // priorities the Entitlements Service driver would refuse are reported
        edir.server.modify(c, new com.unboundid.ldap.sdk.Modification(com.unboundid.ldap.sdk.ModificationType.REPLACE, "DirXML-SPPriority", "cn=Staff," + c + "#2#0"));
        assertEquals(List.of("the priorities are not 0, 1, 2 … without gaps or repeats"), call("GET", rbe, null, h).body().get("problems"));
    }

    @Test
    public void roleBasedEntitlementPoliciesAreCreatedAndChanged() throws Exception {
        Map<String, String> h = signIn();
        String set = (String) Json.asMap(((List<?>) call("GET", "/api/v2/trees/acme/idm/driversets", null, h).body().get("items")).get(0)).get("guid");
        String rbe = "/api/v2/trees/acme/idm/driversets/" + set + "/rbe";
        String es = "cn=Entitlements,cn=Driver Set,o=system";
        edir.add("dn: " + es, "objectClass: DirXML-Driver", "cn: Entitlements", "DirXML-JavaModule: com.novell.nds.dirxml.driver.entitlement.EntitlementServiceDriver");
        edir.add("dn: cn=UserAccount,cn=AD,cn=Driver Set,o=system", "objectClass: DirXML-Entitlement", "cn: UserAccount");
        edir.add("dn: cn=Group,cn=AD,cn=Driver Set,o=system", "objectClass: DirXML-Entitlement", "cn: Group",
            "XmlData: <entitlement conflict-resolution=\"union\"><values multi-valued=\"true\"><value>g1</value><value>g2</value></values></entitlement>");
        edir.add("dn: cn=Mail,cn=AD,cn=Driver Set,o=system", "objectClass: DirXML-Entitlement", "cn: Mail",
            "XmlData: <entitlement><values multi-valued=\"false\"/></entitlement>");
        edir.add("dn: ou=People,o=system", "objectClass: organizationalUnit", "ou: People");
        edir.add("dn: cn=p1,ou=People,o=system", "objectClass: inetOrgPerson", "cn: p1", "sn: One", "title: staff");
        edir.add("dn: cn=p2,ou=People,o=system", "objectClass: inetOrgPerson", "cn: p2", "sn: Two", "title: other");

        Reply ents = call("GET", rbe + "/entitlements", null, h);
        assertEquals(String.valueOf(ents.body()), 200, ents.status());
        List<?> drivers = (List<?>) ents.body().get("drivers");
        assertEquals("the service driver's own are left out", 1, drivers.size());
        List<?> ad = (List<?>) Json.asMap(drivers.get(0)).get("entitlements");
        assertEquals(List.of("Group", "Mail", "UserAccount"), ad.stream().map(e -> Json.asMap(e).get("name")).toList());
        assertEquals(List.of("list", "input", "none"), ad.stream().map(e -> Json.asMap(e).get("kind")).toList());

        Map<String, Object> membership = Map.of("base", "ou=People,o=system", "scope", "sub", "filter", "(title=staff)");
        Reply found = call("POST", rbe + "/test", membership, h);
        assertEquals(List.of("cn=p1,ou=People,o=system"), ((List<?>) found.body().get("items")).stream().map(e -> Json.asMap(e).get("dn")).toList());

        String crit = "<selection-criterion><group><group-op>and</group-op><row><attribute>Title</attribute><operation>AS.Op.isEqual</operation><value>staff</value><row-op>and</row-op></row></group></selection-criterion>";
        Map<String, Object> staff = new java.util.HashMap<>(Map.of("name", "Staff", "description", "everyone on staff", "membership", membership,
            "members", List.of("cn=p2,ou=People,o=system"), "criteria", crit,
            "grants", List.of(Map.of("entitlement", "cn=UserAccount,cn=AD,cn=Driver Set,o=system"),
                Map.of("entitlement", "cn=Group,cn=AD,cn=Driver Set,o=system", "values", List.of("g1", "g2")))));
        Reply made = call("POST", rbe + "/policies", staff, h);
        assertEquals(String.valueOf(made.body()), 201, made.status());
        String c = "cn=Entitlement Policies,cn=Driver Set,o=system";
        com.unboundid.ldap.sdk.Entry p = edir.entry("cn=Staff," + c);
        assertEquals("the container is made, and the priorities written after the policy", List.of("cn=Staff," + c + "#0#0"),
            List.of(edir.entry(c).getAttributeValues("DirXML-SPPriority")));
        assertEquals("ldap:///ou=People,o=system??sub?(title=staff)?x-sparse", p.getAttributeValue("memberQueryURL"));
        assertEquals("the search identity defaults to the service driver", es, p.getAttributeValue("dgIdentity"));
        assertEquals(java.util.Set.of("cn=UserAccount,cn=AD,cn=Driver Set,o=system#0#<ref/>",
            "cn=Group,cn=AD,cn=Driver Set,o=system#0#<ref><param>g1</param></ref>", "cn=Group,cn=AD,cn=Driver Set,o=system#0#<ref><param>g2</param></ref>"),
            java.util.Set.of(p.getAttributeValues("DirXML-EntitlementRef")));
        assertEquals(crit, p.getAttributeValue("DirXML-SPFilterXML"));
        assertTrue(new String(p.getAttributeValueBytes("DirXML-SPDisplayEntitlements"), java.nio.charset.StandardCharsets.UTF_8).contains("<InputValues><value>g1</value><value>g2</value></InputValues>"));
        assertEquals(409, call("POST", rbe + "/policies", staff, h).status());

        // a second one goes last; grants must fit their entitlement
        assertEquals(201, call("POST", rbe + "/policies", Map.of("name", "Two", "members", List.of("cn=p1,ou=People,o=system")), h).status());
        assertEquals(List.of("cn=Staff," + c + "#0#0", "cn=Two," + c + "#1#0"), List.of(edir.entry(c).getAttributeValues("DirXML-SPPriority")));
        assertEquals("static members only: a query that matches nobody, as the shim needs every policy to have one",
            "ldap:///" + c + "??base?(!(objectClass=*))?x-sparse", edir.entry("cn=Two," + c).getAttributeValue("memberQueryURL"));
        assertNull("and it reads back as no query", Json.asMap(((List<?>) call("GET", rbe, null, h).body().get("policies")).get(1)).get("membership"));
        assertEquals("not in the list", 400, call("POST", rbe + "/policies", Map.of("name", "Bad", "grants",
            List.of(Map.of("entitlement", "cn=Group,cn=AD,cn=Driver Set,o=system", "values", List.of("g9")))), h).status());
        assertEquals("single-valued", 400, call("POST", rbe + "/policies", Map.of("name", "Bad", "grants",
            List.of(Map.of("entitlement", "cn=Mail,cn=AD,cn=Driver Set,o=system", "values", List.of("a", "b")))), h).status());
        assertEquals("takes no values", 400, call("POST", rbe + "/policies", Map.of("name", "Bad", "grants",
            List.of(Map.of("entitlement", "cn=UserAccount,cn=AD,cn=Driver Set,o=system", "values", List.of("a")))), h).status());
        assertEquals("a valued entitlement needs a value", 400, call("POST", rbe + "/policies", Map.of("name", "Bad", "grants",
            List.of(Map.of("entitlement", "cn=Group,cn=AD,cn=Driver Set,o=system"))), h).status());
        assertEquals("not an entitlement here", 400, call("POST", rbe + "/policies", Map.of("name", "Bad", "grants",
            List.of(Map.of("entitlement", "cn=AD,cn=Driver Set,o=system"))), h).status());
        assertEquals("no such member", 400, call("POST", rbe + "/policies", Map.of("name", "Bad", "members", List.of("cn=nobody,o=system")), h).status());

        // change: from the version read; what is left out is cleared
        String guid = (String) made.body().get("guid");
        Reply read = call("GET", "/api/v2/trees/acme/idm/rbe/policies/" + guid, null, h);
        assertEquals(List.of("cn=p2,ou=People,o=system"), read.body().get("staticMembers"));
        assertEquals(List.of("g1", "g2"), Json.asMap(((List<?>) read.body().get("grantValues")).get(1)).get("values"));
        Map<String, Object> change = new java.util.HashMap<>(Map.of("version", "stale", "membership", membership, "identity", "",
            "grants", List.of(Map.of("entitlement", "cn=Mail,cn=AD,cn=Driver Set,o=system", "values", List.of("x@acme.example")))));
        assertEquals(409, call("PUT", "/api/v2/trees/acme/idm/rbe/policies/" + guid, change, h).status());
        change.put("version", read.body().get("version"));
        Reply changed = call("PUT", "/api/v2/trees/acme/idm/rbe/policies/" + guid, change, h);
        assertEquals(String.valueOf(changed.body()), 200, changed.status());
        p = edir.entry("cn=Staff," + c);
        assertNull("identity cleared", p.getAttributeValue("dgIdentity"));
        assertNull("no criteria sent: cleared", p.getAttributeValue("DirXML-SPFilterXML"));
        assertNull("description left out: cleared", p.getAttributeValue("description"));
        assertNull("static members left out: cleared", p.getAttributeValue("member"));
        assertEquals(List.of("cn=Mail,cn=AD,cn=Driver Set,o=system#0#<ref><param>x@acme.example</param></ref>"), List.of(p.getAttributeValues("DirXML-EntitlementRef")));
        String audit;
        try (var files = Files.list(dataPath.resolve("audit"))) {
            StringBuilder all = new StringBuilder();
            for (Path f : files.toList()) {
                all.append(Files.readString(f));
            }
            audit = all.toString();
        }
        assertTrue(audit.contains("idm.rbe.create"));
        assertTrue(audit.contains("idm.rbe.change"));
        assertEquals("forced: deleted though it has a query", 200, call("DELETE", "/api/v2/trees/acme/idm/rbe/policies/" + guid, Map.of("name", "Staff", "force", true), h).status());
    }
}
