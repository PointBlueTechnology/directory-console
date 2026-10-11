package com.pointblue.console.server.live;

import com.pointblue.console.server.data.DataDir;
import com.pointblue.console.server.http.Server;
import com.pointblue.console.server.http.ServerClient;
import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.console.server.tls.TrustStore;
import com.pointblue.dirxml.dev.LegacyTls;
import com.pointblue.dirxml.dev.deploy.Environments;
import com.pointblue.dirxml.dev.json.Json;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.LdapName;

/**
 * Live check of Phase 1 against a lab vault: the real server, in-process, driven through its setup and
 * sign-in API exactly as a person would, against the environment named on the command line. Not a JUnit
 * test (CI never runs it). Read-only towards eDirectory: binds, searches, GetEffectivePrivileges. It never
 * tries a wrong password against a real account (no intruder-lockout risk) and prints outcomes only, never
 * a password.
 *
 *   java -cp … LiveSetupCheck <environments.properties> <env>
 */
public final class LiveSetupCheck {

    static HttpClient http;
    static String base;

    public static void main(String[] args) throws Exception {
        LegacyTls.enable();
        Environments.Environment env = Environments.load(Path.of(args[0])).get(args[1]);
        if (env.tier != null && env.tier.name().equalsIgnoreCase("prd")) {
            throw new IllegalStateException("refusing a prd-tier environment");
        }
        URI u = URI.create(env.url);
        String host = u.getHost();
        int port = u.getPort() > 0 ? u.getPort() : 636;
        String adminDn = env.bindDn;
        String adminPw = env.password;
        Path dataPath = Files.createTempDirectory("dc-live-");
        System.out.println("# Directory Console Phase 1 live check: " + args[1] + " (" + host + ":" + port + ")");
        Server server = new Server(new DataDir(dataPath), 0, "https://localhost:8443", new PrintStream(new ByteArrayOutputStream()));
        try {
            server.start();
            base = "https://localhost:" + server.port();
            http = ServerClient.trusting(server);
            Matcher m = Pattern.compile("Setup token: ([0-9a-f]{32})").matcher(Files.readString(dataPath.resolve("bootstrap.txt")));
            m.find();
            Map<String, String> t = Map.of("X-Setup-Token", m.group(1));

            step("directory", call("PUT", "/api/v2/setup/directory", Map.of("id", "lab", "name", args[1], "host", host, "port", port, "tier", "lab"), t));
            Reply probe = call("POST", "/api/v2/setup/probe", Map.of(), t);
            step("probe", probe);
            Map<String, Object> pb = probe.body;
            System.out.println("  status=" + pb.get("status") + " hostnameMatches=" + pb.get("hostnameMatches") + " recommended=" + pb.get("recommended"));
            for (Object c : (List<?>) pb.get("chain")) {
                Map<String, Object> cm = Json.asMap(c);
                System.out.println("  [" + cm.get("index") + "] " + cm.get("subject") + "  selfSigned=" + cm.get("selfSigned") + "  names=" + cm.get("names"));
            }
            int rec = Json.asInt(pb.get("recommended"), 0);
            String sha = (String) Json.asMap(((List<?>) pb.get("chain")).get(rec)).get("sha256");
            String tail = sha.replace(":", "").toLowerCase();
            tail = tail.substring(tail.length() - 8);
            Reply trust = call("POST", "/api/v2/setup/trust", Map.of("probeId", pb.get("probeId"), "index", rec, "confirm", tail), t);
            step("trust", trust);
            System.out.println("  connection: " + trust.body.get("connection"));

            Reply auth = call("POST", "/api/v2/setup/authority", Map.of("dn", adminDn, "password", adminPw), t);
            step("authority (bind + supervisor rights on the tree)", auth);
            step("service account", call("PUT", "/api/v2/setup/service-account", Map.of("dn", adminDn, "password", adminPw), t));
            step("login policy", call("PUT", "/api/v2/setup/login", Map.of("duplicates", "choose"), t));
            step("finish", call("POST", "/api/v2/setup/finish", Map.of(), t));

            Reply in = call("POST", "/api/v2/session", Map.of("directory", "lab", "name", adminDn, "password", adminPw), Map.of());
            step("sign-in by full DN", in);
            System.out.println("  roles=" + in.body.get("roles") + " via=" + in.body.get("via"));

            String cn = (String) new LdapName(adminDn).getRdn(new LdapName(adminDn).size() - 1).getValue();
            Reply ctxless = call("POST", "/api/v2/session", Map.of("directory", "lab", "name", cn, "password", adminPw), Map.of());
            step("contextless sign-in by CN '" + cn + "'", ctxless);
            if (ctxless.status == 409) {
                System.out.println("  candidates=" + ((List<?>) ctxless.body.get("candidates")).size());
            }

            String dup = duplicateCn(server, host, port, adminDn, adminPw);
            if (dup != null) {
                // the choose step answers before any bind: the placeholder password is never tried
                Reply choose = call("POST", "/api/v2/session", Map.of("directory", "lab", "name", dup, "password", "not-used"), Map.of());
                System.out.println("[" + (choose.status == 409 && "choose-account".equals(choose.body.get("title")) ? "ok" : "FAIL") + "] duplicate CN -> "
                    + choose.status + " " + choose.body.get("title") + ", candidates=" + (choose.body.get("candidates") instanceof List<?> l ? l.size() : 0));
            }
            Reply unknown = call("POST", "/api/v2/session", Map.of("directory", "lab", "name", "dc-no-such-user-" + System.nanoTime(), "password", "x"), Map.of());
            System.out.println("[" + (unknown.status == 401 ? "ok" : "FAIL") + "] unknown name -> " + unknown.status + " " + unknown.body.get("title"));

            String cookie = in.raw.headers().firstValue("Set-Cookie").orElse("");
            Map<String, String> session = Map.of("Cookie", cookie.isEmpty() ? "" : cookie.substring(0, cookie.indexOf(';')));
            Reply cfg = call("GET", "/api/v2/config", null, session);
            System.out.println("[" + (cfg.status == 200 && !Json.compact(cfg.body).contains(adminPw) ? "ok" : "FAIL") + "] config is redacted");
            System.out.println("[" + (Boolean.TRUE.equals(call("GET", "/api/v2/audit/verify", null, session).body.get("intact")) ? "ok" : "FAIL") + "] audit chain intact");
        } finally {
            server.stop();
            try (var s = Files.walk(dataPath)) {
                s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    /** A cn shared by several active users, found as the admin through the console's own trust store. */
    private static String duplicateCn(Server server, String host, int port, String dn, String pw) throws Exception {
        try (Ldap l = Ldap.connect(new TrustStore(new DataDir(ServerClient.dataDir(server))), new Ldap.Target("lab", host, port), null, dn, pw.toCharArray(), Duration.ofSeconds(10))) {
            Map<String, Integer> seen = new HashMap<>();
            for (Ldap.Entry e : l.search("", "(&(objectClass=inetOrgPerson)(!(loginDisabled=TRUE)))", null, SearchControls.SUBTREE_SCOPE, new String[] {"cn"}, 0)) {
                for (Object v : e.attributes().getOrDefault("cn", List.of())) {
                    String k = String.valueOf(v);
                    if (seen.merge(k.toLowerCase(), 1, Integer::sum) == 2) {
                        return k;
                    }
                }
            }
        }
        System.out.println("[skip] no duplicate cn among active users");
        return null;
    }

    record Reply(int status, Map<String, Object> body, HttpResponse<String> raw) {
    }

    static Reply call(String method, String path, Object body, Map<String, String> headers) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path)).timeout(Duration.ofSeconds(60))
            .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(Json.compact(body)));
        if (body != null) {
            b.header("Content-Type", "application/json");
        }
        headers.forEach((k, v) -> {
            if (!v.isEmpty()) {
                b.header(k, v);
            }
        });
        HttpResponse<String> r = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
        Object o = r.body().isBlank() ? Map.of() : Json.parse(r.body());
        return new Reply(r.statusCode(), o instanceof Map ? Json.asMap(o) : Map.of("list", o), r);
    }

    static void step(String what, Reply r) {
        boolean ok = r.status / 100 == 2;
        System.out.println("[" + (ok ? "ok" : "FAIL") + "] " + what + " -> " + r.status + (ok ? "" : " " + r.body.get("title") + ": " + r.body.get("detail")));
    }
}
