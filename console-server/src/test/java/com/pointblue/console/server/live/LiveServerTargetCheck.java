package com.pointblue.console.server.live;

import static com.pointblue.console.server.live.LiveSetupCheck.call;

import com.pointblue.console.server.auth.FakeIdp;
import com.pointblue.console.server.data.DataDir;
import com.pointblue.console.server.http.Phase3Access;
import com.pointblue.console.server.http.Server;
import com.pointblue.console.server.http.ServerClient;
import com.pointblue.dirxml.dev.LegacyTls;
import com.pointblue.dirxml.dev.deploy.Environments;
import com.pointblue.dirxml.dev.json.Json;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
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
 * Live check of server-targeted operations (?server=) against a lab tree with two servers. A test
 * container and user are made under {@code parent} (no password, no rights); a direct sign-in lists
 * the servers holding the user's replica, signs in to the second, reads from it and compares both; a
 * running driver's status and named passwords are compared, and its start option on the second server
 * is set to the value that server already has; a single sign-on session reaches the second server by
 * itself. Everything made for the run is deleted. Not a JUnit test.
 *
 *   java -cp … LiveServerTargetCheck <environments.properties> <env> <parent DN> <second server DN>
 */
public final class LiveServerTargetCheck {

    private static final String T = "/api/v2/trees/lab";
    private static Map<String, String> admin;

    public static void main(String[] args) throws Exception {
        LegacyTls.enable();
        Environments.Environment env = Environments.load(Path.of(args[0])).get(args[1]);
        if (env.tier != null && env.tier.name().equalsIgnoreCase("prd")) {
            throw new IllegalStateException("refusing a prd-tier environment");
        }
        URI u = URI.create(env.url);
        Path dataPath = Files.createTempDirectory("dc-live-srv-");
        Server server = new Server(new DataDir(dataPath), ServerClient.loopback(), "https://localhost:8443", new PrintStream(new ByteArrayOutputStream()));
        String container = null;
        try (FakeIdp idp = new FakeIdp()) {
            server.start();
            LiveSetupCheck.base = "https://127.0.0.1:" + server.port();
            LiveSetupCheck.http = ServerClient.trusting(server);
            setUp(dataPath, u.getHost(), u.getPort() > 0 ? u.getPort() : 636, env.bindDn, env.password);
            System.out.println("# server-targeted operations: " + args[1]);

            String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
            String uid = "dcsrv-" + ts;
            String parent = (String) call("GET", T + "/objects?dn=" + java.net.URLEncoder.encode(args[2], "UTF-8"), null, admin).body().get("guid");
            LiveSetupCheck.Reply c = call("POST", T + "/objects/" + parent + "/children", Map.of("objectClass", "organizationalUnit", "name", Map.of("type", "ou", "value", uid)), admin);
            container = (String) c.body().get("guid");
            LiveSetupCheck.Reply user = call("POST", T + "/objects/" + container + "/children", Map.of("objectClass", "inetOrgPerson",
                "name", Map.of("type", "cn", "value", "srv-tester"), "attributes", Map.of("sn", List.of("Tester"), "uid", List.of(uid))), admin);
            String userGuid = (String) user.body().get("guid");
            ok("test container and user", c.status() == 201 && user.status() == 201, user.body().get("dn"));

            List<?> holders = (List<?>) call("GET", T + "/objects/" + userGuid + "/servers", null, admin).body().get("list");
            ok("servers holding the user's replica", holders != null && holders.size() >= 2, holders);
            String second = null;
            for (Object o : holders) {
                if (String.valueOf(Json.asMap(o).get("dn")).equalsIgnoreCase(args[3])) {
                    second = (String) Json.asMap(o).get("guid");
                }
            }
            LiveSetupCheck.Reply needs = call("GET", T + "/objects/" + userGuid + "?server=" + second, null, admin);
            ok("a direct sign-in is asked to sign in to the second server", needs.status() == 409 && "server-sign-in-required".equals(needs.body().get("title")), needs.body().get("detail"));
            LiveSetupCheck.Reply in = call("POST", "/api/v2/session/servers", Map.of("server", second, "password", env.password), admin);
            ok("sign in to the second server", in.status() == 200, in.body());
            // a new object reaches the other replica after replication: wait for it
            LiveSetupCheck.Reply there = null;
            long waited = System.currentTimeMillis();
            for (int i = 0; i < 60; i++) {
                there = call("GET", T + "/objects/" + userGuid + "?server=" + second, null, admin);
                if (there.status() == 200) {
                    break;
                }
                Thread.sleep(2000);
            }
            System.out.println("    replicated to the second server after " + (System.currentTimeMillis() - waited) / 1000 + " s");
            ok("read from the second server", there.status() == 200 && String.valueOf(Json.asMap(there.body().get("servedBy")).get("dn")).equalsIgnoreCase(args[3]),
                there.body().get("servedBy") + detail(there));
            LiveSetupCheck.Reply all = call("GET", T + "/objects/" + userGuid + "?server=all", null, admin);
            ok("compare the user across replicas", all.status() == 200, ((List<?>) all.body().get("servers")).stream()
                .map(x -> Json.asMap(Json.asMap(x).get("server")).get("name") + ":" + Json.asMap(x).get("status")).toList() + " attributes=" + all.body().get("attributes"));
            Map<String, String> h = new HashMap<>(admin);
            h.put("If-Match", there.raw().headers().firstValue("ETag").orElse("*"));
            LiveSetupCheck.Reply w = call("PATCH", T + "/objects/" + userGuid + "?server=" + second,
                Map.of("changes", List.of(Map.of("op", "replace", "attribute", "description", "values", List.of("written on the second server")))), h);
            ok("write through the second server", w.status() == 200 && String.valueOf(Json.asMap(w.body().get("attributes")).get("description")).contains("second server"), w.status() + detail(w));

            // ---- Identity Manager ----
            LiveSetupCheck.Reply status = call("GET", T + "/idm", null, admin);
            if (Boolean.TRUE.equals(status.body().get("available"))) {
                List<?> sets = (List<?>) call("GET", T + "/idm/driversets", null, admin).body().get("items");
                String set = (String) Json.asMap(sets.get(0)).get("guid");
                Map<String, Object> running = null;
                for (Object o : (List<?>) call("GET", T + "/idm/driversets/" + set, null, admin).body().get("drivers")) {
                    if ("running".equalsIgnoreCase(String.valueOf(Json.asMap(o).get("state")))) {
                        running = Json.asMap(o);
                        break;
                    }
                }
                String drv = (String) running.get("guid");
                LiveSetupCheck.Reply cmp = call("GET", T + "/idm/drivers/" + drv + "?server=all", null, admin);
                ok("compare " + running.get("name") + " across servers", cmp.status() == 200, cmp.body().get("servers"));
                LiveSetupCheck.Reply pw = call("GET", T + "/idm/drivers/" + drv + "/passwords?server=all", null, admin);
                ok("compare its named passwords (names only)", pw.status() == 200, pw.body().get("servers"));
                List<?> runs = (List<?>) call("GET", T + "/idm/drivers/" + drv + "/servers", null, admin).body().get("list");
                ok("servers that run its driver set", runs != null && !runs.isEmpty(), runs);
                String onSecond = null;
                for (Object o : (List<?>) cmp.body().get("servers")) {
                    Map<String, Object> m = Json.asMap(o);
                    if (second.equals(Json.asMap(m.get("server")).get("guid"))) {
                        onSecond = String.valueOf(m.get("startOption")).toLowerCase();
                    }
                }
                if (onSecond != null && !onSecond.equals("null")) {
                    String option = onSecond.contains("auto") ? "auto" : onSecond.contains("manual") ? "manual" : "disabled";
                    LiveSetupCheck.Reply set2 = call("PUT", T + "/idm/drivers/" + drv + "/start-option?server=" + second, Map.of("option", option), admin);
                    ok("set the start option on the second server to its own value (" + option + ")", set2.status() == 200, set2.body());
                }
            } else {
                System.out.println("[skip] Identity Manager: " + status.body().get("problem"));
            }

            // ---- single sign-on reaches the second server by itself ----
            Phase3Access.singleSignOn(server, idp.issuer, List.of(args[2]));
            idp.person("tester", Map.of("name", "Server Tester", "preferred_username", uid, "groups", List.of("testers")));
            idp.signInAs = "tester";
            LiveSetupCheck.Reply start = call("GET", "/api/v2/oidc/start?directory=lab&next=/", null, Map.of());
            String state = start.raw().headers().allValues("Set-Cookie").stream().filter(x -> x.startsWith("__Host-console-oidc=")).findFirst().orElseThrow();
            HttpResponse<String> atIdp = LiveSetupCheck.http.send(HttpRequest.newBuilder(URI.create(start.raw().headers().firstValue("Location").orElseThrow())).GET().build(),
                HttpResponse.BodyHandlers.ofString());
            LiveSetupCheck.Reply cb = call("GET", atIdp.headers().firstValue("Location").orElseThrow().substring("https://localhost:8443".length()), null,
                Map.of("Cookie", state.substring(0, state.indexOf(';'))));
            String cookie = cb.raw().headers().allValues("Set-Cookie").stream().filter(x -> x.startsWith("__Host-console=")).findFirst().orElse("x=;");
            Map<String, String> sso = Map.of("Cookie", cookie.substring(0, cookie.indexOf(';')));
            LiveSetupCheck.Reply viaSso = call("GET", T + "/objects/" + userGuid + "?server=" + second, null, sso);
            ok("single sign-on reads from the second server without signing in again", viaSso.status() == 200
                && String.valueOf(Json.asMap(viaSso.body().get("servedBy")).get("dn")).equalsIgnoreCase(args[3]), viaSso.status() + detail(viaSso));
        } finally {
            if (container != null) {
                LiveSetupCheck.Reply count = call("GET", T + "/objects/" + container + "/subtree", null, admin);
                Map<String, String> h = new HashMap<>(admin);
                h.put("If-Match", "*");
                h.put("X-Confirm-Count", String.valueOf(count.body().get("count")));
                LiveSetupCheck.Reply d = call("DELETE", T + "/objects/" + container + "?subtree=true", null, h);
                ok("cleanup: subtree delete", d.status() == 200, "deleted=" + d.body().get("deleted") + detail(d));
            }
            server.stop();
            try (var st = Files.walk(dataPath)) {
                st.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
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
