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
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Live check of the Identity Manager API against a lab vault: reads everything for the first driver set and one running driver, then restarts that
 * driver and sets its start option to the value it already has. Prints the JSON (shortened), never a
 * password. Not a JUnit test.
 *
 *   java -cp … LiveIdmCheck <environments.properties> <env>
 */
public final class LiveIdmCheck {

    private static Map<String, String> session;

    public static void main(String[] args) throws Exception {
        LegacyTls.enable();
        Environments.Environment env = Environments.load(Path.of(args[0])).get(args[1]);
        if (env.tier != null && env.tier.name().equalsIgnoreCase("prd")) {
            throw new IllegalStateException("refusing a prd-tier environment");
        }
        URI u = URI.create(env.url);
        Path dataPath = Files.createTempDirectory("dc-live-idm-");
        Server server = new Server(new DataDir(dataPath), ServerClient.loopback(), "https://localhost:8443", new PrintStream(new ByteArrayOutputStream()));
        try {
            server.start();
            LiveSetupCheck.base = "https://127.0.0.1:" + server.port();
            LiveSetupCheck.http = ServerClient.trusting(server);
            setUp(dataPath, u.getHost(), u.getPort() > 0 ? u.getPort() : 636, env.bindDn, env.password);
            String t = "/api/v2/trees/lab/idm";
            show("engine", call("GET", t, null, session));
            LiveSetupCheck.Reply sets = call("GET", t + "/driversets", null, session);
            show("driver sets", sets);
            List<?> items = (List<?>) sets.body().get("items");
            if (items == null || items.isEmpty()) {
                return;
            }
            String set = (String) Json.asMap(items.get(0)).get("guid");
            LiveSetupCheck.Reply status = call("GET", t + "/driversets/" + set, null, session);
            show("driver set status", status);
            for (String part : new String[] {"activation", "servers", "jobs", "log-level", "passwords"}) {
                show("driver set " + part, call("GET", t + "/driversets/" + set + "/" + part, null, session));
            }
            Map<String, Object> running = null;
            for (Object o : (List<?>) status.body().get("drivers")) {
                Map<String, Object> d = Json.asMap(o);
                if ("running".equalsIgnoreCase(String.valueOf(d.get("state")))) {
                    running = d;
                    break;
                }
            }
            if (running == null) {
                System.out.println("[skip] no running driver");
                return;
            }
            String drv = (String) running.get("guid");
            System.out.println("# driver " + running.get("name"));
            show("driver status", call("GET", t + "/drivers/" + drv, null, session));
            for (String part : new String[] {"jobs", "health", "log-level", "password-sync", "passwords", "cache?count=3", "associations?limit=3"}) {
                show("driver " + part, call("GET", t + "/drivers/" + drv + "/" + part, null, session));
            }
            Map<String, String> w = new HashMap<>(session);
            show("restart", call("POST", t + "/drivers/" + drv + "/restart", Map.of(), w));
            String option = String.valueOf(running.get("startOption")).toLowerCase().contains("auto") ? "auto"
                : String.valueOf(running.get("startOption")).toLowerCase().contains("manual") ? "manual" : "disabled";
            show("start option (unchanged: " + option + ")", call("PUT", t + "/drivers/" + drv + "/start-option", Map.of("option", option), w));
            show("after", call("GET", t + "/driversets/" + set, null, session));
        } finally {
            server.stop();
            try (var s = Files.walk(dataPath)) {
                s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    private static void show(String what, LiveSetupCheck.Reply r) {
        String body = Json.compact(r.body());
        System.out.println("[" + (r.status() / 100 == 2 ? "ok" : "FAIL") + "] " + what + " -> " + r.status() + "  "
            + (body.length() > 700 ? body.substring(0, 700) + "…" : body));
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
        session = new HashMap<>(Map.of("Cookie", cookie.substring(0, cookie.indexOf(';'))));
        session.put("X-CSRF-Token", String.valueOf(in.body().get("csrf")));
    }
}
