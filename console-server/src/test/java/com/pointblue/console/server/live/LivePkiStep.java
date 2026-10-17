package com.pointblue.console.server.live;

import static com.pointblue.console.server.live.LiveSetupCheck.call;

import com.pointblue.console.server.data.DataDir;
import com.pointblue.console.server.http.Server;
import com.pointblue.console.server.http.ServerClient;
import com.pointblue.dirxml.dev.LegacyTls;
import com.pointblue.dirxml.dev.deploy.Environments;
import com.pointblue.dirxml.dev.json.Json;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * ONE PKI operation through the console's API against a lab tree, per run, so that a run that upsets
 * eDirectory is known exactly (a lab ndsd crashed after a batch of PKI calls). Writes run
 * only on environments listed in -Dlive.writable. Not a JUnit test.
 *
 *   java -cp … LivePkiStep <environments.properties> <env> server-create <name>
 *   java -cp … LivePkiStep <environments.properties> <env> server-delete <name>
 *   java -cp … LivePkiStep <environments.properties> <env> user-create <user DN> <name>
 *   java -cp … LivePkiStep <environments.properties> <env> user-list <user DN>
 *   java -cp … LivePkiStep <environments.properties> <env> defaults-read <server name>
 *   java -cp … LivePkiStep <environments.properties> <env> defaults-repair <server name> <invalid|all> <dns,ec,ip>
 */
public final class LivePkiStep {

    public static void main(String[] args) throws Exception {
        LegacyTls.enable();
        // writes go only to environments named in -Dlive.writable (comma-separated): pure test trees
        if (!List.of(System.getProperty("live.writable", "").split(",")).contains(args[1])) {
            throw new IllegalStateException("PKI steps run only on environments listed in -Dlive.writable");
        }
        Environments.Environment env = Environments.load(Path.of(args[0])).get(args[1]);
        URI u = URI.create(env.url);
        Path dataPath = Files.createTempDirectory("dc-live-pki-");
        Server server = new Server(new DataDir(dataPath), ServerClient.loopback(), "https://localhost:8443", new PrintStream(new ByteArrayOutputStream()));
        try {
            server.start();
            LiveSetupCheck.base = "https://127.0.0.1:" + server.port();
            LiveSetupCheck.http = ServerClient.trusting(server);
            String pw = env.vaultConfig().password;
            Map<String, String> h = setUp(dataPath, u.getHost(), u.getPort() > 0 ? u.getPort() : 636, env.bindDn, pw);
            String t = "/api/v2/trees/lab";
            String op = args[2];
            System.out.println("# " + op + " " + String.join(" ", List.of(args).subList(3, args.length)));
            switch (op) {
                case "server-create" -> {
                    String server0 = serverGuid(call("GET", t + "/edir/servers", null, h));
                    show(call("POST", t + "/security/pki/servers/" + server0 + "/certificates",
                        Map.of("name", args[3], "algorithm", "rsa", "rsaBits", 2048, "signature", "sha256", "validityYears", 1,
                            "names", List.of("dns:" + args[3] + ".example.test"), "exportable", !List.of(args).contains("locked")), h));
                }
                case "server-revoke" -> {
                    String guid = null;
                    for (Object o : (List<?>) call("GET", t + "/security/pki", null, h).body().get("serverCertificates")) {
                        Map<String, Object> k = Json.asMap(o);
                        if (String.valueOf(k.get("name")).startsWith(args[3] + " - ")) {
                            guid = (String) k.get("guid");
                        }
                    }
                    show(call("POST", t + "/security/pki/server-certificates/" + guid + "/revoke", Map.of("reason", 5, "comment", "directory console test"), h));
                }
                case "server-delete" -> {
                    LiveSetupCheck.Reply pki = call("GET", t + "/security/pki", null, h);
                    String guid = null;
                    for (Object o : (List<?>) pki.body().get("serverCertificates")) {
                        Map<String, Object> k = Json.asMap(o);
                        if (String.valueOf(k.get("name")).startsWith(args[3] + " - ")) {
                            guid = (String) k.get("guid");
                        }
                    }
                    if (guid == null) {
                        System.out.println("[skip] no server certificate " + args[3]);
                        return;
                    }
                    show(call("DELETE", t + "/security/pki/server-certificates/" + guid, null, h));
                }
                // READ-ONLY (in eDirectory): a certificate with its private key, as PKCS#12. The file's password is made
                // here and never printed; only what the file holds is shown.
                case "server-export", "user-export" -> {
                    String path;
                    if (op.equals("server-export")) {
                        String guid = null;
                        for (Object o : (List<?>) call("GET", t + "/security/pki", null, h).body().get("serverCertificates")) {
                            Map<String, Object> k = Json.asMap(o);
                            if (String.valueOf(k.get("name")).equals(args[3])) {
                                guid = (String) k.get("guid");
                            }
                        }
                        if (guid == null) {
                            System.out.println("[skip] no server certificate " + args[3]);
                            return;
                        }
                        path = t + "/security/pki/server-certificates/" + guid + "/export";
                    } else {
                        path = t + "/security/objects/" + guid(t, h, args[3]) + "/certificates/" + URLEncoder.encode(args[4], "UTF-8").replace("+", "%20") + "/export";
                    }
                    String scheme = List.of(args).contains("pbes1") ? "pbes1" : "pbes2";
                    byte[] r = new byte[18];
                    new java.security.SecureRandom().nextBytes(r);
                    String filePw = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(r);
                    LiveSetupCheck.Reply x = call("POST", path, Map.of("password", filePw, "scheme", scheme), h);
                    if (x.status() != 200) {
                        show(x);
                        return;
                    }
                    byte[] file = java.util.Base64.getDecoder().decode((String) x.body().get("pkcs12"));
                    java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
                    ks.load(new java.io.ByteArrayInputStream(file), filePw.toCharArray());
                    System.out.println("[ok 200] " + x.body().get("fileName") + ", " + file.length + " bytes, scheme " + scheme);
                    System.out.println("  protection: " + protections(file));
                    if (System.getenv("CHECK_OPENSSL") != null) {
                        Path tmp = Files.createTempFile(Path.of(System.getenv("CHECK_OPENSSL")), "export", ".pfx");
                        try {
                            Files.write(tmp, file);
                            ProcessBuilder pb = new ProcessBuilder("openssl", "pkcs12", "-in", tmp.toString(), "-noout", "-passin", "env:P12PW").redirectErrorStream(true);
                            pb.environment().put("P12PW", filePw);
                            Process proc = pb.start();
                            String said = new String(proc.getInputStream().readAllBytes()).lines().findFirst().orElse("");
                            System.out.println("  openssl without -legacy: exit " + proc.waitFor() + (said.isBlank() ? "" : " (" + said + ")"));
                        } finally {
                            Files.delete(tmp);
                        }
                    }
                    for (String alias : java.util.Collections.list(ks.aliases())) {
                        java.security.cert.Certificate[] chain = ks.getCertificateChain(alias);
                        java.security.Key key = ks.isKeyEntry(alias) ? ks.getKey(alias, filePw.toCharArray()) : null;
                        System.out.println("  entry: key " + (key == null ? "none" : key.getAlgorithm()) + ", chain of " + (chain == null ? 0 : chain.length)
                            + (chain == null ? "" : ", leaf " + ((java.security.cert.X509Certificate) chain[0]).getSubjectX500Principal()));
                        if (key == null && ks.isCertificateEntry(alias)) {
                            System.out.println("  certificate only: " + ((java.security.cert.X509Certificate) ks.getCertificate(alias)).getSubjectX500Principal());
                        }
                    }
                }
                // a throwaway OU holding one user (cn=pkiexport), and its removal with everything in it
                case "test-ou-create" -> {
                    LiveSetupCheck.Reply c = call("POST", t + "/objects/" + guid(t, h, args[3]) + "/children",
                        Map.of("objectClass", "organizationalUnit", "name", Map.of("type", "ou", "value", args[4])), h);
                    show(c);
                    show(call("POST", t + "/objects/" + c.body().get("guid") + "/children", Map.of("objectClass", "inetOrgPerson",
                        "name", Map.of("type", "cn", "value", "pkiexport"), "attributes", Map.of("sn", List.of("Export"))), h));
                }
                case "test-ou-delete" -> {
                    String ou = guid(t, h, args[3]);
                    Map<String, String> d = new java.util.HashMap<>(h);
                    d.put("X-Confirm-Count", String.valueOf(call("GET", t + "/objects/" + ou + "/subtree", null, h).body().get("count")));
                    d.put("If-Match", "*");
                    show(call("DELETE", t + "/objects/" + ou + "?subtree=true", null, d));
                }
                // READ-ONLY: any GET under the tree's API, such as schema/attributes/cefConfiguration
                case "get" -> show(call("GET", t + "/" + args[3], null, h));
                // WRITE then RESTORE: a CEF configuration on one server, read back, then removed (eDirectory's defaults again)
                case "audit-try" -> {
                    String a = t + "/edir/servers/" + args[3] + "/audit";
                    Map<String, Object> settings = new HashMap<>(Json.asMap(call("GET", a, null, h).body().get("settings")));
                    List<Object> events = new ArrayList<>((List<?>) settings.get("events"));
                    events.add("LDAP_PASSWORD_MODIFY");
                    settings.put("events", events);
                    settings.put("exclude", Map.of("classes", List.of(), "attributes", List.of("Last Login Time", "Login Time")));
                    LiveSetupCheck.Reply put = call("PUT", a, settings, h);
                    System.out.println("[" + put.status() + "] raw after write: " + put.body().get("raw"));
                    LiveSetupCheck.Reply back = call("GET", a, null, h);
                    System.out.println("read back: events " + ((List<?>) Json.asMap(back.body().get("settings")).get("events")).size()
                        + ", exclude " + Json.asMap(back.body().get("settings")).get("exclude") + ", unknown " + Json.asMap(back.body().get("settings")).get("unknown"));
                    LiveSetupCheck.Reply reset = call("DELETE", a, null, h);
                    System.out.println("[" + reset.status() + "] after reset: configured=" + reset.body().get("configured") + " raw=" + reset.body().get("raw"));
                }
                // WRITE then RESTORE: one trap's interval in an SNMP group, then back; the stored bytes must match the original
                case "snmp-try" -> {
                    Map<String, Object> g = null;
                    for (Object o : (List<?>) call("GET", t + "/edir/snmp", null, h).body().get("groups")) {
                        if (String.valueOf(Json.asMap(o).get("name")).equals(args[3])) {
                            g = Json.asMap(o);
                        }
                    }
                    Map<String, Object> first = Json.asMap(((List<?>) g.get("traps")).get(0));
                    long was = ((Number) first.get("interval")).longValue();
                    String n = String.valueOf(first.get("number"));
                    String path = t + "/edir/snmp/" + g.get("guid");
                    LiveSetupCheck.Reply changed = call("PATCH", path, Map.of("traps", Map.of(n, Map.of("interval", was + 2))), h);
                    Map<String, Object> now = Json.asMap(((List<?>) changed.body().get("traps")).get(0));
                    System.out.println("[" + changed.status() + "] trap " + n + " interval " + was + " -> " + now.get("interval"));
                    LiveSetupCheck.Reply back = call("PATCH", path, Map.of("traps", Map.of(n, Map.of("interval", was))), h);
                    System.out.println("[" + back.status() + "] restored; traps identical to before: " + String.valueOf(back.body().get("traps")).equals(String.valueOf(g.get("traps"))));
                }
                // WRITE: a throwaway public-read attribute on a test user, a policy encrypting it on one server, and anonymous
                // clear-text reads on that server before and after (args: server name, server address)
                case "eap-try" -> {
                    String srv = serverNamed(call("GET", t + "/edir/servers", null, h), args[3]);
                    show(call("POST", t + "/edir/schema/attributes", Map.of("name", "dcTestSecret", "syntax", "1.3.6.1.4.1.1466.115.121.1.15", "singleValue", true,
                        "flags", List.of("publicRead")), h));
                    show(call("POST", t + "/edir/schema/classes", Map.of("name", "dcTestAux", "kind", "auxiliary", "may", List.of("dcTestSecret")), h));
                    LiveSetupCheck.Reply ou = call("POST", t + "/objects/" + guid(t, h, "o=data") + "/children",
                        Map.of("objectClass", "organizationalUnit", "name", Map.of("type", "ou", "value", "dc-eap-test")), h);
                    show(ou);
                    LiveSetupCheck.Reply user = call("POST", t + "/objects/" + ou.body().get("guid") + "/children", Map.of("objectClass", List.of("inetOrgPerson", "dcTestAux"), "name", Map.of("type", "cn", "value", "eapuser"),
                        "attributes", Map.of("sn", List.of("Eap"), "dcTestSecret", List.of("plain-before"))), h);
                    show(user);
                    System.out.println("anonymous clear read before: " + anonymousRead(args[4], "cn=eapuser,ou=dc-eap-test,o=data", "dcTestSecret"));
                    LiveSetupCheck.Reply made = call("POST", t + "/edir/encryption/policies", Map.of("parent", "ou=dc-eap-test,o=data", "name", "dcTestPolicy",
                        "attributes", List.of(Map.of("attribute", "dcTestSecret"))), h);
                    show(made);
                    String pg = null;
                    for (Object o : (List<?>) made.body().get("policies")) {
                        if ("dcTestPolicy".equals(Json.asMap(o).get("name"))) {
                            pg = (String) Json.asMap(o).get("guid");
                        }
                    }
                    LiveSetupCheck.Reply as = call("PUT", t + "/edir/servers/" + srv + "/encryption-policy", Map.of("policy", pg), h);
                    if (as.status() == 409 && "server-sign-in-required".equals(as.body().get("title"))) {
                        show(call("POST", "/api/v2/session/servers", Map.of("server", srv, "password", pw), h));
                        as = call("PUT", t + "/edir/servers/" + srv + "/encryption-policy", Map.of("policy", pg), h);
                    }
                    show(as);
                    Thread.sleep(20_000);
                    System.out.println("anonymous clear read after: " + anonymousRead(args[4], "cn=eapuser,ou=dc-eap-test,o=data", "dcTestSecret"));
                }
                // WRITE: [Public] may browse the test OU and below (removed with the OU); then an anonymous clear read (args: server address)
                case "eap-read" -> {
                    Map<String, String> m = new HashMap<>(h);
                    m.put("If-Match", "*");
                    show(call("PATCH", t + "/objects/" + guid(t, h, "ou=dc-eap-test,o=data"), Map.of("changes", List.of(Map.of("op", "add", "attribute", "ACL",
                        "values", List.of(Map.of("privileges", 1, "scope", "subtree", "trustee", Map.of("special", "[Public]"), "attribute", "[Entry Rights]"))))), m));
                    Thread.sleep(15_000);
                    System.out.println("anonymous clear read: " + anonymousRead(args[3], "cn=eapuser,ou=dc-eap-test,o=data", "dcTestSecret"));
                }
                // WRITE: give the server the test policy again (limber runs there), wait, then an anonymous clear read (args: server name, address)
                case "eap-again" -> {
                    String srv = serverNamed(call("GET", t + "/edir/servers", null, h), args[3]);
                    String pg = null;
                    for (Object o : (List<?>) call("GET", t + "/edir/encryption", null, h).body().get("policies")) {
                        if ("dcTestPolicy".equals(Json.asMap(o).get("name"))) {
                            pg = (String) Json.asMap(o).get("guid");
                        }
                    }
                    LiveSetupCheck.Reply as = call("PUT", t + "/edir/servers/" + srv + "/encryption-policy", Map.of("policy", pg), h);
                    if (as.status() == 409 && "server-sign-in-required".equals(as.body().get("title"))) {
                        show(call("POST", "/api/v2/session/servers", Map.of("server", srv, "password", pw), h));
                        as = call("PUT", t + "/edir/servers/" + srv + "/encryption-policy", Map.of("policy", pg), h);
                    }
                    System.out.println("[" + as.status() + "] assigned again");
                    Thread.sleep(30_000);
                    System.out.println("anonymous clear read: " + anonymousRead(args[4], "cn=eapuser,ou=dc-eap-test,o=data", "dcTestSecret"));
                }
                case "eap-clean" -> {
                    String srv = serverNamed(call("GET", t + "/edir/servers", null, h), args[3]);
                    LiveSetupCheck.Reply un = call("PUT", t + "/edir/servers/" + srv + "/encryption-policy", java.util.Collections.singletonMap("policy", null), h);
                    if (un.status() == 409 && "server-sign-in-required".equals(un.body().get("title"))) {
                        show(call("POST", "/api/v2/session/servers", Map.of("server", srv, "password", pw), h));
                        un = call("PUT", t + "/edir/servers/" + srv + "/encryption-policy", java.util.Collections.singletonMap("policy", null), h);
                    }
                    show(un);
                    for (Object o : (List<?>) un.body().get("policies")) {
                        if ("dcTestPolicy".equals(Json.asMap(o).get("name"))) {
                            show(call("DELETE", t + "/edir/encryption/policies/" + Json.asMap(o).get("guid"), null, h));
                        }
                    }
                    String ou = guid(t, h, "ou=dc-eap-test,o=data");
                    if (ou != null) {
                        Map<String, String> d = new HashMap<>(h);
                        d.put("X-Confirm-Count", String.valueOf(call("GET", t + "/objects/" + ou + "/subtree", null, h).body().get("count")));
                        d.put("If-Match", "*");
                        show(call("DELETE", t + "/objects/" + ou + "?subtree=true", null, d));
                    }
                    show(call("DELETE", t + "/edir/schema/classes/dcTestAux", null, h));
                    show(call("DELETE", t + "/edir/schema/attributes/dcTestSecret", null, h));
                }
                // WRITE then CLEAR: one filter given as JSON (args: server name, JSON list of {class, attributes})
                case "filter-one" -> {
                    String srv = serverNamed(call("GET", t + "/edir/servers", null, h), args[3]);
                    show(call("PUT", t + "/edir/servers/" + srv + "/replica-filter", Map.of("classes", Json.parse(args[4])), h));
                    show(call("GET", t + "/edir/servers/" + srv + "/replica-filter", null, h));
                    show(call("PUT", t + "/edir/servers/" + srv + "/replica-filter", Map.of("classes", List.of()), h));
                }
                // WRITE then CLEAR: a replica filter on a server with no filtered replicas (args: server name)
                case "filter-try" -> {
                    String srv = serverNamed(call("GET", t + "/edir/servers", null, h), args[3]);
                    show(call("GET", t + "/edir/servers/" + srv + "/replica-filter", null, h));
                    show(call("PUT", t + "/edir/servers/" + srv + "/replica-filter", Map.of("classes", List.of(
                        Map.of("class", "inetOrgPerson", "attributes", List.of("cn", "sn", "mail")), Map.of("class", "organizationalUnit", "attributes", List.of()))), h));
                    show(call("GET", t + "/edir/servers/" + srv + "/replica-filter", null, h));
                    show(call("PUT", t + "/edir/servers/" + srv + "/replica-filter", Map.of("classes", List.of()), h));
                    show(call("GET", t + "/edir/servers/" + srv + "/replica-filter", null, h));
                }
                // READ-ONLY: encryption policies and encrypted replication; a server's replica filter
                case "encryption" -> show(call("GET", t + "/edir/encryption", null, h));
                case "replica-filter" -> show(call("GET", t + "/edir/servers/" + serverNamed(call("GET", t + "/edir/servers", null, h), args[3]) + "/replica-filter", null, h));
                // READ-ONLY: the LDAP Server and Group objects
                case "ldap" -> show(call("GET", t + "/edir/ldap", null, h));
                // READ-ONLY: one LDAP Server or Group object's settings, by name
                case "ldap-read" -> {
                    Map<String, Object> all = call("GET", t + "/edir/ldap", null, h).body();
                    for (String kind : List.of("servers", "groups")) {
                        for (Object o : (List<?>) all.get(kind)) {
                            Map<String, Object> m = Json.asMap(o);
                            if (String.valueOf(m.get("name")).equals(args[3])) {
                                show(call("GET", t + "/edir/ldap/" + kind + "/" + m.get("guid"), null, h));
                            }
                        }
                    }
                }
                // the LDAP server re-reads its configuration, on its own host (signing in there first if asked)
                case "ldap-refresh", "ldap-reload" -> {
                    String verb = op.equals("ldap-reload") ? "reload" : "refresh";
                    String guid = null;
                    for (Object o : (List<?>) call("GET", t + "/edir/ldap", null, h).body().get("servers")) {
                        Map<String, Object> m = Json.asMap(o);
                        if (String.valueOf(m.get("name")).equals(args[3])) {
                            guid = (String) m.get("guid");
                        }
                    }
                    LiveSetupCheck.Reply r = call("POST", t + "/edir/ldap/servers/" + guid + "/" + verb, Map.of(), h);
                    if (r.status() == 409 && "server-sign-in-required".equals(r.body().get("title"))) {
                        System.out.println("(signing in to " + Json.asMap(r.body().get("server")).get("name") + ")");
                        show(call("POST", "/api/v2/session/servers", Map.of("server", Json.asMap(r.body().get("server")).get("guid"), "password", pw), h));
                        r = call("POST", t + "/edir/ldap/servers/" + guid + "/" + verb, Map.of(), h);
                    }
                    show(r);
                }
                case "user-create" -> show(call("POST", t + "/security/objects/" + guid(t, h, args[3]) + "/certificates",
                    Map.of("name", args[4], "algorithm", "rsa", "rsaBits", 2048, "validityYears", 1, "exportable", List.of(args).contains("exportable")), h));
                // READ-ONLY: the object inspector's view of an object
                case "assoc-read" -> show(call("GET", t + "/idm/objects/" + guid(t, h, args[3]) + "/associations", null, h));
                // one association of an object: the one with the named driver gets this state (and value, when given)
                case "assoc-change" -> {
                    String o = guid(t, h, args[3]);
                    String raw = null;
                    for (Object a : (List<?>) call("GET", t + "/idm/objects/" + o + "/associations", null, h).body().get("associations")) {
                        Map<String, Object> m = Json.asMap(a);
                        if (m.get("driver") != null && args[4].equalsIgnoreCase(String.valueOf(Json.asMap(m.get("driver")).get("name")))) {
                            raw = (String) m.get("raw");
                        }
                    }
                    if (raw == null) {
                        throw new IllegalStateException("no association with " + args[4]);
                    }
                    Map<String, Object> body = new HashMap<>(Map.of("raw", raw, "state", args[5]));
                    if (args.length > 6) {
                        body.put("value", args[6]);
                    }
                    show(call("PATCH", t + "/idm/objects/" + o + "/associations", body, h));
                }
                // READ-ONLY: an object's attributes whose names contain the given text
                case "obj-read" -> {
                    Map<String, Object> attrs = Json.asMap(call("GET", t + "/objects/" + guid(t, h, args[3]), null, h).body().get("attributes"));
                    attrs.forEach((k, v) -> {
                        if (args.length < 5 || k.toLowerCase().contains(args[4].toLowerCase())) {
                            System.out.println(k + ": " + Json.compact(v));
                        }
                    });
                }
                // READ-ONLY: a driver's (or driver set's) trace settings
                case "trace-read" -> show(call("GET", t + "/idm/" + (args.length > 4 ? args[4] : "drivers") + "/" + guid(t, h, args[3]) + "/trace", null, h));
                // READ-ONLY: a driver set's jobs, as the engine lists them
                case "jobs" -> show(call("GET", t + "/idm/driversets/" + guid(t, h, args[3]) + "/jobs", null, h));
                // READ-ONLY: the job types the engine offers for a driver or driver set (args[4]: drivers|driversets)
                case "job-types" -> show(call("GET", t + "/idm/" + (args.length > 4 ? args[4] : "driversets") + "/" + guid(t, h, args[3]) + "/job-types", null, h));
                // a disabled, unscheduled Subscriber channel trigger job under a driver, on the connected server, with one changed value
                case "job-create" -> show(call("POST", t + "/idm/drivers/" + guid(t, h, args[3]) + "/jobs", Map.of("type", "com.novell.nds.dirxml.job.trigger.Trigger",
                    "name", args[4], "disabled", true, "schedule", "", "servers", List.of(args[5]), "scope", List.of(),
                    "parameters", Map.of("process-unassociated", "true")), h));
                // a job, its name typed
                case "job-delete" -> show(call("DELETE", t + "/idm/jobs/" + guid(t, h, args[3]), Map.of("name", args[4]), h));
                // READ-ONLY: a container's first rows, as the browser lists them: class, classes and whether each opens
                case "children" -> {
                    Map<String, Object> page = call("GET", t + "/objects/" + guid(t, h, args[3]) + "/children?count=" + (args.length > 4 ? args[4] : "8"), null, h).body();
                    System.out.println("total " + page.get("total"));
                    for (Object o : (List<?>) page.get("items")) {
                        Map<String, Object> r = Json.asMap(o);
                        System.out.println(r.get("name") + " | " + r.get("objectClass") + " | container=" + r.get("container") + " children=" + r.get("children")
                            + (r.get("childCount") == null ? "" : " count=" + r.get("childCount")) + " | " + r.get("objectClasses"));
                    }
                }
                // READ-ONLY: a job's definition, as the console reads it
                case "job-read" -> show(call("GET", t + "/idm/jobs/" + guid(t, h, args[3]) + "/definition", null, h));
                // READ-ONLY: the DNs an LDAP filter finds, with the named attributes
                case "find" -> {
                    Map<String, Object> req = new HashMap<>(Map.of("ldapFilter", args[3], "scope", "subtree", "page", Map.of("count", 200)));
                    if (args.length > 4) {
                        req.put("attributes", List.of(args).subList(4, args.length));
                    }
                    for (Object o : (List<?>) call("POST", t + "/search", req, h).body().get("items")) {
                        Map<String, Object> m = Json.asMap(o);
                        System.out.println(m.get("dn") + (m.get("attributes") == null ? "" : "  " + Json.compact(m.get("attributes"))));
                    }
                }
                // READ-ONLY: a mapping table as the console reads it
                case "mt-read" -> show(call("GET", t + "/idm/mapping-tables/" + guid(t, h, args[3]), null, h));
                // READ-ONLY: a driver's properties
                case "props" -> show(call("GET", t + "/idm/drivers/" + guid(t, h, args[3]) + "/properties", null, h));
                // READ-ONLY: version discovery for a driver set, on the named server (or the connected one)
                case "versions" -> show(call("GET", t + "/idm/driversets/" + guid(t, h, args[3]) + "/versions"
                    + (args.length > 4 ? "?server=" + serverNamed(call("GET", t + "/edir/servers", null, h), args[4]) : ""), null, h));
                // READ-ONLY: a driver set's drivers with state and cache sizes
                case "set-status" -> show(call("GET", t + "/idm/driversets/" + guid(t, h, args[3]), null, h));
                // READ-ONLY: a stopped driver's cache, as the console reads it
                case "cache-read" -> show(call("GET", t + "/idm/drivers/" + guid(t, h, args[3]) + "/cache?count=" + (args.length > 4 ? args[4] : "5"), null, h));
                // READ-ONLY: the cache summary and events with their positions
                case "cache-events" -> {
                    String g = guid(t, h, args[3]);
                    show(call("GET", t + "/idm/drivers/" + g + "/cache/summary", null, h));
                    show(call("GET", t + "/idm/drivers/" + g + "/cache/events?count=" + (args.length > 4 ? args[4] : "10"), null, h));
                }
                // one cached event, named by position and event-id (a stopped driver)
                case "cache-delete" -> show(call("POST", t + "/idm/drivers/" + guid(t, h, args[3]) + "/cache/delete",
                    Map.of("events", List.of(Map.of("position", Integer.parseInt(args[4]), "eventId", args[5]))), h));
                // READ-ONLY: a driver set's statistics on the connected server
                case "stats" -> show(call("GET", t + "/idm/driversets/" + guid(t, h, args[3]) + "/statistics", null, h));
                // READ-ONLY: a driver set's properties
                case "set-props" -> show(call("GET", t + "/idm/driversets/" + guid(t, h, args[3]) + "/properties", null, h));
                case "ca-config" -> show(new LiveSetupCheck.Reply(200, Json.asMap(Json.asMap(call("GET", t + "/security/pki", null, h).body().get("ca")).get("configuration")), null));
                case "crl-times" -> {
                    // READ-ONLY: the CRL configuration's own times beside the issued CRL's
                    for (Object o : (List<?>) call("GET", t + "/security/pki", null, h).body().get("crls")) {
                        Map<String, Object> c = Json.asMap(o);
                        System.out.println(c.get("name") + ": issued " + c.get("issued") + " / thisUpdate " + c.get("thisUpdate")
                            + "; nextIssue " + c.get("nextIssue") + " / nextUpdate " + c.get("nextUpdate"));
                    }
                }
                // only the sequence named here (a test one) is created or deleted; the others are left alone
                case "seq-create" -> show(call("POST", t + "/security/login-policy/sequences",
                    Map.of("name", args[3], "methods", List.of("NDS", "Challenge Response")), h));
                case "seq-delete" -> show(call("DELETE", t + "/security/login-policy/sequences/" + URLEncoder.encode(args[3], "UTF-8").replace("+", "%20"), null, h));
                case "defaults-read" -> show(call("GET", t + "/security/pki/servers/" + serverNamed(call("GET", t + "/edir/servers", null, h), args[3]) + "/default-certificates", null, h));
                // one server's default certificates: each named one is deleted and made again
                case "defaults-repair" -> show(call("POST", t + "/security/pki/servers/" + serverNamed(call("GET", t + "/edir/servers", null, h), args[3]) + "/default-certificates",
                    Map.of("replace", args[4], "kinds", List.of(args[5].split(","))), h));
                case "user-list" -> show(call("GET", t + "/security/objects/" + guid(t, h, args[3]) + "/certificates", null, h));
                default -> throw new IllegalArgumentException("unknown step " + op);
            }
        } finally {
            server.stop();
            try (var st = Files.walk(dataPath)) {
                st.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    /** The encryption algorithms a PKCS#12 file names (readable without its password). */
    private static String protections(byte[] file) {
        Map<String, String> known = new java.util.LinkedHashMap<>();
        known.put("2a864886f70d01050d", "PBES2");
        known.put("608648016503040102", "AES-128-CBC");
        known.put("60864801650304012a", "AES-256-CBC");
        known.put("2a864886f70d010c0103", "PBE-SHA1-3DES");
        known.put("2a864886f70d010c0106", "PBE-SHA1-RC2-40");
        known.put("2a864886f70d010c0105", "PBE-SHA1-RC2-128");
        known.put("2a864886f70d010c0101", "PBE-SHA1-RC4-128");
        String hex = java.util.HexFormat.of().formatHex(file);
        List<String> found = new java.util.ArrayList<>();
        known.forEach((oid, name) -> {
            int n = hex.split("06" + String.format("%02x", oid.length() / 2) + oid, -1).length - 1;
            if (n > 0) {
                found.add(name + (n > 1 ? " x" + n : ""));
            }
        });
        return found.isEmpty() ? "unrecognised" : String.join(", ", found);
    }

    /** An anonymous read of one attribute over clear LDAP (port 389): its value, or the error eDirectory gives. */
    private static String anonymousRead(String host, String dn, String attribute) {
        java.util.Hashtable<String, String> env = new java.util.Hashtable<>();
        env.put(javax.naming.Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(javax.naming.Context.PROVIDER_URL, "ldap://" + host + ":389");
        env.put("com.sun.jndi.ldap.connect.timeout", "5000");
        try {
            javax.naming.directory.InitialDirContext c = new javax.naming.directory.InitialDirContext(env);
            try {
                javax.naming.directory.Attribute a = c.getAttributes(dn, new String[] {attribute}).get(attribute);
                return a == null ? "(not returned)" : "value " + a.get();
            } finally {
                c.close();
            }
        } catch (javax.naming.NamingException e) {
            return "refused: " + e.getMessage();
        }
    }

    private static String guid(String t, Map<String, String> h, String dn) throws Exception {
        return (String) call("GET", t + "/objects?dn=" + URLEncoder.encode(dn, "UTF-8"), null, h).body().get("guid");
    }

    private static String serverNamed(LiveSetupCheck.Reply servers, String name) {
        for (Object o : (List<?>) servers.body().get("list")) {
            Map<String, Object> m = Json.asMap(o);
            if (name.equalsIgnoreCase(String.valueOf(m.get("name")))) {
                return (String) m.get("guid");
            }
        }
        throw new IllegalStateException("no server named " + name);
    }

    /** The server this console connection is on. */
    private static String serverGuid(LiveSetupCheck.Reply servers) {
        for (Object o : (List<?>) servers.body().get("list")) {
            Map<String, Object> m = Json.asMap(o);
            if (Boolean.TRUE.equals(m.get("connected"))) {
                System.out.println("server: " + m.get("dn"));
                return (String) m.get("guid");
            }
        }
        throw new IllegalStateException("no connected server");
    }

    private static void show(LiveSetupCheck.Reply r) {
        if (System.getenv("PKI_RAW") != null) {
            System.out.println(Json.compact(r.body()));
        }
        String body = Json.compact(r.body()).replaceAll("\"der\":\"[^\"]{40}[^\"]*\"", "\"der\":\"…\"").replaceAll("\"certificate\":\"[^\"]{40}[^\"]*\"", "\"certificate\":\"…\"");
        System.out.println("[" + (r.status() / 100 == 2 ? "ok" : "FAIL") + " " + r.status() + "] " + (body.length() > 1500 ? body.substring(0, 1500) + "…" : body));
    }

    private static Map<String, String> setUp(Path dataPath, String host, int port, String dn, String pw) throws Exception {
        Matcher m = Pattern.compile("Setup token: ([0-9a-f]{32})").matcher(Files.readString(dataPath.resolve("bootstrap.txt")));
        m.find();
        Map<String, String> t = Map.of("X-Setup-Token", m.group(1));
        call("PUT", "/api/v2/setup/directory", Map.of("id", "lab", "name", "lab", "host", host, "port", port, "tier", "lab"), t);
        LiveSetupCheck.Reply probe = call("POST", "/api/v2/setup/probe", Map.of(), t);
        int rec = Json.asInt(probe.body().get("recommended"), 0);
        String sha = (String) Json.asMap(((List<?>) probe.body().get("chain")).get(rec)).get("sha256");
        String tail = sha.replace(":", "").toLowerCase();
        call("POST", "/api/v2/setup/trust", Map.of("probeId", probe.body().get("probeId"), "index", rec, "confirm", tail.substring(tail.length() - 8), "hostException", true), t);
        call("POST", "/api/v2/setup/authority", Map.of("dn", dn, "password", pw), t);
        call("PUT", "/api/v2/setup/service-account", Map.of("dn", dn, "password", pw), t);
        call("POST", "/api/v2/setup/finish", Map.of(), t);
        LiveSetupCheck.Reply in = call("POST", "/api/v2/session", Map.of("directory", "lab", "name", dn, "password", pw), Map.of());
        String cookie = in.raw().headers().firstValue("Set-Cookie").orElse("");
        Map<String, String> h = new HashMap<>(Map.of("Cookie", cookie.substring(0, cookie.indexOf(';'))));
        h.put("X-CSRF-Token", String.valueOf(in.body().get("csrf")));
        return h;
    }
}
