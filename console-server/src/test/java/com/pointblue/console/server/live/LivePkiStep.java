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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * ONE PKI operation through the console's API against a lab tree, per run, so that a run that upsets
 * eDirectory is known exactly (ig4's ndsd crashed after a batch of PKI calls, 2026-10-13). Writes run
 * on ig4 only. Not a JUnit test.
 *
 *   java -cp … LivePkiStep <environments.properties> ig4 server-create <name>
 *   java -cp … LivePkiStep <environments.properties> ig4 server-delete <name>
 *   java -cp … LivePkiStep <environments.properties> ig4 user-create <user DN> <name>
 *   java -cp … LivePkiStep <environments.properties> ig4 user-list <user DN>
 *   java -cp … LivePkiStep <environments.properties> ig4 defaults-read <server name>
 *   java -cp … LivePkiStep <environments.properties> ig4 defaults-repair <server name> <invalid|all> <dns,ec,ip>
 */
public final class LivePkiStep {

    public static void main(String[] args) throws Exception {
        LegacyTls.enable();
        if (!args[1].equals("ig4")) {
            throw new IllegalStateException("PKI steps run on ig4 only");
        }
        Environments.Environment env = Environments.load(Path.of(args[0])).get(args[1]);
        URI u = URI.create(env.url);
        Path dataPath = Files.createTempDirectory("dc-live-pki-");
        Server server = new Server(new DataDir(dataPath), 0, "https://localhost:8443", new PrintStream(new ByteArrayOutputStream()));
        try {
            server.start();
            LiveSetupCheck.base = "https://localhost:" + server.port();
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
                            "names", List.of("dns:" + args[3] + ".example.test")), h));
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
                case "user-create" -> show(call("POST", t + "/security/objects/" + guid(t, h, args[3]) + "/certificates",
                    Map.of("name", args[4], "algorithm", "rsa", "rsaBits", 2048, "validityYears", 1), h));
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
