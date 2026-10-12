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
 * READ-ONLY live check through the console's API: servers, partitions, the servers holding the driver
 * set's replica and those running it. Writes nothing to the directory. Not a JUnit test.
 *
 *   java -cp … LiveReadCheck <environments.properties> <env> [driver set DN]
 */
public final class LiveReadCheck {

    public static void main(String[] args) throws Exception {
        LegacyTls.enable();
        Environments.Environment env = Environments.load(Path.of(args[0])).get(args[1]);
        URI u = URI.create(env.url);
        Path dataPath = Files.createTempDirectory("dc-live-read-");
        Server server = new Server(new DataDir(dataPath), 0, "https://localhost:8443", new PrintStream(new ByteArrayOutputStream()));
        try {
            server.start();
            LiveSetupCheck.base = "https://localhost:" + server.port();
            LiveSetupCheck.http = ServerClient.trusting(server);
            // the password may live in the keychain: vaultConfig() resolves it, in this process only
            Map<String, String> h = setUp(dataPath, u.getHost(), u.getPort() > 0 ? u.getPort() : 636, env.bindDn, env.vaultConfig().password);
            String t = "/api/v2/trees/lab";
            show("servers", call("GET", t + "/edir/servers", null, h));
            show("partitions", call("GET", t + "/edir/partitions", null, h));
            String driverSet = args.length > 2 ? args[2] : null;
            if (driverSet != null) {
                LiveSetupCheck.Reply ds = call("GET", t + "/objects?dn=" + java.net.URLEncoder.encode(driverSet, "UTF-8"), null, h);
                show("servers holding the driver set's replica", call("GET", t + "/objects/" + ds.body().get("guid") + "/servers", null, h));
                show("Identity Manager", call("GET", t + "/idm", null, h));
                show("driver set servers", call("GET", t + "/idm/driversets/" + ds.body().get("guid") + "/servers", null, h));
                LiveSetupCheck.Reply set = call("GET", t + "/idm/driversets/" + ds.body().get("guid"), null, h);
                List<?> drivers = (List<?>) set.body().get("drivers");
                show("drivers", set);
                if (drivers != null && !drivers.isEmpty()) {
                    String drv = (String) Json.asMap(drivers.get(0)).get("guid");
                    show("servers running the first driver's set", call("GET", t + "/idm/drivers/" + drv + "/servers", null, h));
                }
            }
        } finally {
            server.stop();
            try (var st = Files.walk(dataPath)) {
                st.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    private static void show(String what, LiveSetupCheck.Reply r) {
        String body = Json.compact(r.body());
        System.out.println("[" + (r.status() / 100 == 2 ? "ok" : "FAIL " + r.status()) + "] " + what + ": " + (body.length() > 1200 ? body.substring(0, 1200) + "…" : body));
    }

    private static void step(String what, LiveSetupCheck.Reply r) {
        if (r.status() / 100 != 2) {
            System.out.println("[setup] " + what + " -> " + r.status() + " " + r.body().get("title") + ": " + r.body().get("detail"));
        }
    }

    private static Map<String, String> setUp(Path dataPath, String host, int port, String dn, String pw) throws Exception {
        Matcher m = Pattern.compile("Setup token: ([0-9a-f]{32})").matcher(Files.readString(dataPath.resolve("bootstrap.txt")));
        m.find();
        Map<String, String> t = Map.of("X-Setup-Token", m.group(1));
        step("/api/v2/setup/directory", call("PUT", "/api/v2/setup/directory", Map.of("id", "lab", "name", "lab", "host", host, "port", port, "tier", "lab"), t));
        LiveSetupCheck.Reply probe = call("POST", "/api/v2/setup/probe", Map.of(), t);
        int rec = Json.asInt(probe.body().get("recommended"), 0);
        String sha = (String) Json.asMap(((List<?>) probe.body().get("chain")).get(rec)).get("sha256");
        String tail = sha.replace(":", "").toLowerCase();
        step("/api/v2/setup/trust", call("POST", "/api/v2/setup/trust", Map.of("probeId", probe.body().get("probeId"), "index", rec, "confirm", tail.substring(tail.length() - 8), "hostException", true), t));
        step("/api/v2/setup/authority", call("POST", "/api/v2/setup/authority", Map.of("dn", dn, "password", pw), t));
        step("/api/v2/setup/service-account", call("PUT", "/api/v2/setup/service-account", Map.of("dn", dn, "password", pw), t));
        step("/api/v2/setup/finish", call("POST", "/api/v2/setup/finish", Map.of(), t));
        LiveSetupCheck.Reply in = call("POST", "/api/v2/session", Map.of("directory", "lab", "name", dn, "password", pw), Map.of());
        step("/api/v2/session", in);
        String cookie = in.raw().headers().firstValue("Set-Cookie").orElse("");
        Map<String, String> h = new HashMap<>(Map.of("Cookie", cookie.substring(0, cookie.indexOf(';'))));
        h.put("X-CSRF-Token", String.valueOf(in.body().get("csrf")));
        return h;
    }
}
