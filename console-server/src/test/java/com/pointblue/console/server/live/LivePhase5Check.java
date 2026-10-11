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
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Live check of the Phase 5 API against a lab tree with two servers: reads (servers, a server's
 * replicas and indexes, partitions); a test attribute and class (with an optional attribute added)
 * created and deleted; an index on the second server added and removed; and a test OU under
 * {@code parent} split into a partition, its replica on the second server removed, added back, made
 * read-only and read/write again, then merged and deleted. Everything is made for the run and undone.
 * Not a JUnit test.
 *
 *   java -cp … LivePhase5Check <environments.properties> <env> <parent DN> <second server DN>
 */
public final class LivePhase5Check {

    private static final String T = "/api/v2/trees/lab/edir";
    private static Map<String, String> admin;

    public static void main(String[] args) throws Exception {
        LegacyTls.enable();
        Environments.Environment env = Environments.load(Path.of(args[0])).get(args[1]);
        if (env.tier != null && env.tier.name().equalsIgnoreCase("prd")) {
            throw new IllegalStateException("refusing a prd-tier environment");
        }
        URI u = URI.create(env.url);
        Path dataPath = Files.createTempDirectory("dc-live-p5-");
        Server server = new Server(new DataDir(dataPath), 0, "https://localhost:8443", new PrintStream(new ByteArrayOutputStream()));
        String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
        String ouGuid = null;
        boolean split = false;
        try {
            server.start();
            LiveSetupCheck.base = "https://localhost:" + server.port();
            LiveSetupCheck.http = ServerClient.trusting(server);
            setUp(dataPath, u.getHost(), u.getPort() > 0 ? u.getPort() : 636, env.bindDn, env.password);
            System.out.println("# Phase 5 live check: " + args[1]);

            // ---- reads ----
            LiveSetupCheck.Reply servers = call("GET", T + "/servers", null, admin);
            List<?> list = (List<?>) servers.body().get("list");
            ok("servers", servers.status() == 200 && list != null && list.size() >= 2, list == null ? servers.body() : list.stream().map(x -> {
                Map<String, Object> m = Json.asMap(x);
                return m.get("name") + " " + m.get("version") + " " + m.get("status") + " connected=" + m.get("connected") + " " + m.get("addresses");
            }).toList());
            String secondGuid = null;
            for (Object o : list) {
                Map<String, Object> m = Json.asMap(o);
                if (String.valueOf(m.get("dn")).equalsIgnoreCase(args[3])) {
                    secondGuid = (String) m.get("guid");
                }
            }
            LiveSetupCheck.Reply detail = call("GET", T + "/servers/" + secondGuid, null, admin);
            List<?> replicas = (List<?>) detail.body().get("replicas");
            List<?> indexes = (List<?>) detail.body().get("indexes");
            ok("second server: replicas and indexes", detail.status() == 200 && replicas != null && !replicas.isEmpty() && indexes != null && !indexes.isEmpty(),
                replicas + " / " + (indexes == null ? null : indexes.size() + " indexes, first " + indexes.get(0)));
            LiveSetupCheck.Reply parts = call("GET", T + "/partitions", null, admin);
            ok("partitions", parts.status() == 200, ((List<?>) parts.body().get("list")).stream().map(x -> {
                Map<String, Object> m = Json.asMap(x);
                return m.get("name") + " entries=" + m.get("entries") + " busy=" + m.get("busy") + " " + ((List<?>) m.get("replicas")).stream()
                    .map(r -> Json.asMap(Json.asMap(r).get("server")).get("name") + ":" + Json.asMap(r).get("type") + "/" + Json.asMap(r).get("state")).toList();
            }).toList());

            // ---- schema ----
            String attr = "dcp5a" + ts;
            String extra = "dcp5b" + ts;
            String cls = "dcp5c" + ts;
            ok("schema: add attribute", call("POST", T + "/schema/attributes", Map.of("name", attr, "syntax", "1.3.6.1.4.1.1466.115.121.1.15", "upperBound", 64, "singleValue", true), admin).status() == 201, attr);
            ok("schema: add attribute 2", call("POST", T + "/schema/attributes", Map.of("name", extra, "syntax", "1.3.6.1.4.1.1466.115.121.1.15"), admin).status() == 201, extra);
            ok("schema: add class", call("POST", T + "/schema/classes", Map.of("name", cls, "kind", "auxiliary", "may", List.of(attr)), admin).status() == 201, cls);
            LiveSetupCheck.Reply may = call("POST", T + "/schema/classes/" + cls + "/may", Map.of("attributes", List.of(extra)), admin);
            LiveSetupCheck.Reply readBack = call("GET", "/api/v2/trees/lab/schema/classes/" + cls, null, admin);
            ok("schema: add an optional attribute", may.status() == 201 && String.valueOf(readBack.body().get("may")).contains(extra), readBack.body().get("may"));

            // ---- index ----
            LiveSetupCheck.Reply ix = call("POST", T + "/servers/" + secondGuid + "/indexes", Map.of("name", "dcp5ix" + ts, "attributes", List.of(attr), "rule", "value"), admin);
            ok("index: add", ix.status() == 201, ((List<?>) ix.body().getOrDefault("indexes", List.of())).stream().filter(x -> String.valueOf(x).contains("dcp5ix")).toList() + detail(ix));
            LiveSetupCheck.Reply system = call("DELETE", T + "/servers/" + secondGuid + "/indexes/CN", null, admin);
            ok("index: a system index cannot be removed", system.status() == 409, system.body().get("detail"));
            ok("index: remove", call("DELETE", T + "/servers/" + secondGuid + "/indexes/dcp5ix" + ts, null, admin).status() == 200, "");
            ok("schema: remove class", call("DELETE", T + "/schema/classes/" + cls, null, admin).status() == 200, "");
            ok("schema: remove attribute 2", call("DELETE", T + "/schema/attributes/" + extra, null, admin).status() == 200, "");
            ok("schema: remove attribute", call("DELETE", T + "/schema/attributes/" + attr, null, admin).status() == 200, "");

            // ---- partitions ----
            String parent = (String) call("GET", "/api/v2/trees/lab/objects?dn=" + java.net.URLEncoder.encode(args[2], "UTF-8"), null, admin).body().get("guid");
            LiveSetupCheck.Reply ou = call("POST", "/api/v2/trees/lab/objects/" + parent + "/children",
                Map.of("objectClass", "organizationalUnit", "name", Map.of("type", "ou", "value", "dcp5api-" + ts)), admin);
            ouGuid = (String) ou.body().get("guid");
            ok("create test OU", ou.status() == 201, ou.body().get("dn"));
            LiveSetupCheck.Reply s = call("POST", T + "/partitions", Map.of("container", ouGuid), admin);
            split = s.status() == 202;
            ok("split", split, s.status() + detail(s));
            settle(ouGuid, secondGuid, "read-write");
            ok("remove the second server's replica", call("DELETE", T + "/partitions/" + ouGuid + "/replicas/" + secondGuid, null, admin).status() == 202, "");
            settle(ouGuid, secondGuid, "subordinate-reference");
            ok("add it back read/write", call("POST", T + "/partitions/" + ouGuid + "/replicas", Map.of("server", secondGuid, "type", "read-write"), admin).status() == 202, "");
            settle(ouGuid, secondGuid, "read-write");
            ok("make it read-only", call("PUT", T + "/partitions/" + ouGuid + "/replicas/" + secondGuid, Map.of("type", "read-only"), admin).status() == 202, "");
            settle(ouGuid, secondGuid, "read-only");
            ok("make it read/write", call("PUT", T + "/partitions/" + ouGuid + "/replicas/" + secondGuid, Map.of("type", "read-write"), admin).status() == 202, "");
            settle(ouGuid, secondGuid, "read-write");
            LiveSetupCheck.Reply bg = call("POST", T + "/servers/" + secondGuid + "/background", Map.of("process", "limber"), admin);
            ok("background: limber", bg.status() == 204, bg.status() + detail(bg));
            ok("LDAP server refresh", call("POST", T + "/ldap-refresh", Map.of(), admin).status() == 204, "");
        } finally {
            if (split) {
                for (int i = 0; i < 60; i++) {
                    LiveSetupCheck.Reply m = call("POST", T + "/partitions/" + ouGuid + "/merge", Map.of(), admin);
                    if (m.status() == 202) {
                        ok("merge", true, "try " + (i + 1));
                        break;
                    }
                    Thread.sleep(10_000);
                }
                for (int i = 0; i < 60; i++) {
                    LiveSetupCheck.Reply p = call("GET", T + "/partitions", null, admin);
                    final String g = ouGuid;
                    if (((List<?>) p.body().get("list")).stream().noneMatch(x -> g.equals(Json.asMap(x).get("id")))) {
                        ok("merged", true, (5 * i) + " s");
                        break;
                    }
                    Thread.sleep(5000);
                }
            }
            if (ouGuid != null) {
                for (int i = 0; i < 24; i++) {
                    Map<String, String> h = new HashMap<>(admin);
                    h.put("If-Match", "*");
                    LiveSetupCheck.Reply d = call("DELETE", "/api/v2/trees/lab/objects/" + ouGuid, null, h);
                    if (d.status() == 204 || d.status() == 200) {
                        ok("cleanup: delete the test OU", true, "");
                        break;
                    }
                    Thread.sleep(5000);
                }
            }
            server.stop();
            try (var st = Files.walk(dataPath)) {
                st.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    /** Poll the partition list until the second server's replica of {@code partition} has {@code type} and nothing is busy. */
    private static void settle(String partition, String server, String type) throws Exception {
        long start = System.currentTimeMillis();
        String last = "";
        while (System.currentTimeMillis() - start < 900_000) {
            LiveSetupCheck.Reply p = call("GET", T + "/partitions", null, admin);
            for (Object o : (List<?>) p.body().get("list")) {
                Map<String, Object> m = Json.asMap(o);
                if (!partition.equals(m.get("id"))) {
                    continue;
                }
                String now = ((List<?>) m.get("replicas")).stream().map(r -> Json.asMap(Json.asMap(r).get("server")).get("name") + ":" + Json.asMap(r).get("type")
                    + "/" + Json.asMap(r).get("state") + (Boolean.TRUE.equals(Json.asMap(r).get("busy")) ? "/busy" : "")).toList() + " busy=" + m.get("busy");
                if (!now.equals(last)) {
                    System.out.println("    " + (System.currentTimeMillis() - start) / 1000 + " s: " + now);
                    last = now;
                }
                boolean done = !Boolean.TRUE.equals(m.get("busy")) && ((List<?>) m.get("replicas")).stream()
                    .anyMatch(r -> server.equals(Json.asMap(Json.asMap(r).get("server")).get("guid")) && type.equals(Json.asMap(r).get("type")));
                if (done) {
                    return;
                }
            }
            Thread.sleep(3000);
        }
        System.out.println("[FAIL] not settled to " + type);
    }

    private static void setUp(Path dataPath, String host, int port, String dn, String pw) throws Exception {
        Matcher m = Pattern.compile("Setup token: ([0-9a-f]{32})").matcher(Files.readString(dataPath.resolve("bootstrap.txt")));
        m.find();
        Map<String, String> t = Map.of("X-Setup-Token", m.group(1));
        call("PUT", "/api/v2/setup/directory", Map.of("id", "lab", "name", "lab", "host", host, "port", port, "tier", "lab"), t);
        LiveSetupCheck.Reply probe = call("POST", "/api/v2/setup/probe", Map.of(), t);
        int rec = Json.asInt(probe.body().get("recommended"), 0);
        String sha = (String) Json.asMap(((List<?>) probe.body().get("chain")).get(rec)).get("sha256");
        String tail = sha.replace(":", "").toLowerCase();
        call("POST", "/api/v2/setup/trust", Map.of("probeId", probe.body().get("probeId"), "index", rec, "confirm", tail.substring(tail.length() - 8)), t);
        call("POST", "/api/v2/setup/authority", Map.of("dn", dn, "password", pw), t);
        call("PUT", "/api/v2/setup/service-account", Map.of("dn", dn, "password", pw), t);
        call("POST", "/api/v2/setup/finish", Map.of(), t);
        LiveSetupCheck.Reply in = call("POST", "/api/v2/session", Map.of("directory", "lab", "name", dn, "password", pw), Map.of());
        String cookie = in.raw().headers().firstValue("Set-Cookie").orElse("");
        admin = new HashMap<>(Map.of("Cookie", cookie.substring(0, cookie.indexOf(';'))));
        admin.put("X-CSRF-Token", String.valueOf(in.body().get("csrf")));
    }

    private static String detail(LiveSetupCheck.Reply r) {
        return r.status() / 100 == 2 ? "" : " " + r.body().get("title") + ": " + r.body().get("detail");
    }

    private static void ok(String what, boolean ok, Object detail) {
        System.out.println("[" + (ok ? "ok" : "FAIL") + "] " + what + ": " + detail);
    }
}
