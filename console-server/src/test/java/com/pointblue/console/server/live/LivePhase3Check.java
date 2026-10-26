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
 * Live check of single sign-on against a lab tree: the environment's account is the console's
 * service account, a fake identity provider on loopback vouches for a test user made for the run, and
 * the console must act with that user's own eDirectory rights (RFC 4370). In a new container under
 * {@code parent}: a user with a uid, then sign-in through the provider, reads, a write the admin can
 * make and the user cannot, Identity Manager under the user's rights, and a disabled account. No password is set or used for the test user; no
 * rights or IRFs are written. The container is deleted at the end. Not a JUnit test.
 *
 *   java -cp … LivePhase3Check <environments.properties> <env> <parent DN>
 */
public final class LivePhase3Check {

    private static Map<String, String> admin;
    private static final String TREE = "lab";

    public static void main(String[] args) throws Exception {
        LegacyTls.enable();
        Environments.Environment env = Environments.load(Path.of(args[0])).get(args[1]);
        if (env.tier != null && env.tier.name().equalsIgnoreCase("prd")) {
            throw new IllegalStateException("refusing a prd-tier environment");
        }
        URI u = URI.create(env.url);
        Path dataPath = Files.createTempDirectory("dc-live-p3-");
        Server server = new Server(new DataDir(dataPath), ServerClient.loopback(), "https://localhost:8443", new PrintStream(new ByteArrayOutputStream()));
        String container = null;
        try (FakeIdp idp = new FakeIdp()) {
            server.start();
            LiveSetupCheck.base = "https://127.0.0.1:" + server.port();
            LiveSetupCheck.http = ServerClient.trusting(server);
            setUp(dataPath, u.getHost(), u.getPort() > 0 ? u.getPort() : 636, env.bindDn, env.password);
            System.out.println("# Single sign-on live check: " + args[1] + " (service account and admin: the environment's account)");

            String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
            String uid = "dcp3-" + ts;
            String parent = (String) call("GET", "/api/v2/trees/" + TREE + "/objects?dn=" + enc(args[2]), null, admin).body().get("guid");
            LiveSetupCheck.Reply c = call("POST", "/api/v2/trees/" + TREE + "/objects/" + parent + "/children",
                Map.of("objectClass", "organizationalUnit", "name", Map.of("type", "ou", "value", uid)), admin);
            container = (String) c.body().get("guid");
            ok("create container", c.status() == 201, c.body().get("dn"));
            LiveSetupCheck.Reply user = call("POST", "/api/v2/trees/" + TREE + "/objects/" + container + "/children",
                Map.of("objectClass", "inetOrgPerson", "name", Map.of("type", "cn", "value", "sso-tester"),
                    "attributes", Map.of("sn", List.of("Tester"), "uid", List.of(uid))), admin);
            String userDn = String.valueOf(user.body().get("dn"));
            String userGuid = (String) user.body().get("guid");
            ok("create the test user (no password)", user.status() == 201, userDn);

            Phase3Access.singleSignOn(server, idp.issuer, List.of(args[2]));
            idp.person("tester", Map.of("name", "SSO Tester", "preferred_username", uid, "groups", List.of("testers")));

            LiveSetupCheck.Reply cb = sso(idp, "tester");
            String location = cb.raw().headers().firstValue("Location").orElse("");
            ok("single sign-on", cb.status() == 302 && location.equals("/"), "-> " + location);
            Map<String, String> me = cookie(cb);
            Map<String, Object> who = call("GET", "/api/v2/session", null, me).body();
            ok("session acts as the test user", userDn.equalsIgnoreCase(String.valueOf(who.get("dn"))) && "oidc".equals(who.get("via")),
                who.get("dn") + " via " + who.get("via") + " roles " + who.get("roles"));
            me.put("X-CSRF-Token", String.valueOf(who.get("csrf")));

            LiveSetupCheck.Reply self = call("GET", "/api/v2/trees/" + TREE + "/objects/" + userGuid, null, me);
            ok("read own entry under the control", self.status() == 200, "attributes=" + Json.asMap(self.body().get("attributes")).keySet());
            LiveSetupCheck.Reply box = call("GET", "/api/v2/trees/" + TREE + "/objects/" + container, null, me);
            ok("read the container", box.status() == 200 || box.status() == 404, box.status() + detail(box));

            Map<String, Object> change = Map.of("changes", List.of(Map.of("op", "replace", "attribute", "description", "values", List.of("set by " + uid))));
            LiveSetupCheck.Reply asUser = call("PATCH", "/api/v2/trees/" + TREE + "/objects/" + container, change, withEtag(me, container));
            ok("the user's write is refused by eDirectory (the person's rights, not the service account's)",
                asUser.status() == 403 && "insufficient-rights".equals(asUser.body().get("title")), asUser.status() + detail(asUser));
            LiveSetupCheck.Reply asAdmin = call("PATCH", "/api/v2/trees/" + TREE + "/objects/" + container, change, withEtag(admin, container));
            ok("the same write as the admin succeeds", asAdmin.status() == 200, asAdmin.status() + detail(asAdmin));

            // the service account's rights, read as itself (here the environment's account: expect "more than needed")
            LiveSetupCheck.Reply rights = call("GET", "/api/v2/directories/" + TREE + "/service-account/check", null, admin);
            ok("service account check answers", rights.status() == 200, rights.body().get("result"));
            for (Object o : (List<?>) rights.body().getOrDefault("checks", List.of())) {
                Map<String, Object> f = Json.asMap(o);
                System.out.println("    " + f.get("purpose") + " | " + f.get("where") + " | " + f.get("check") + " | " + f.get("result") + " | " + f.get("detail"));
            }

            // Identity Manager: the session's own engine connection, as the service account acting as the user
            LiveSetupCheck.Reply idm = call("GET", "/api/v2/trees/" + TREE + "/idm", null, me);
            ok("Identity Manager is available to the single sign-on session", Boolean.TRUE.equals(idm.body().get("available")),
                "engine " + idm.body().get("engineVersion") + (idm.body().get("problem") == null ? "" : " problem: " + idm.body().get("problem")));
            List<?> sets = (List<?>) call("GET", "/api/v2/trees/" + TREE + "/idm/driversets", null, admin).body().get("items");
            if (sets != null && !sets.isEmpty()) {
                String set = String.valueOf(Json.asMap(sets.get(0)).get("guid"));
                Map<String, Object> asAdminSet = call("GET", "/api/v2/trees/" + TREE + "/idm/driversets/" + set, null, admin).body();
                List<?> drivers = (List<?>) asAdminSet.get("drivers");
                String drv = String.valueOf(Json.asMap(drivers.get(0)).get("guid"));
                LiveSetupCheck.Reply asAdminDrv = call("GET", "/api/v2/trees/" + TREE + "/idm/drivers/" + drv, null, admin);
                ok("the admin reads a driver's state", asAdminDrv.status() == 200, asAdminDrv.body().get("state"));
                LiveSetupCheck.Reply asUserDrv = call("GET", "/api/v2/trees/" + TREE + "/idm/drivers/" + drv, null, me);
                ok("the user's engine requests are decided with the user's rights (refused, or no state)",
                    asUserDrv.status() != 200 || asUserDrv.body().get("state") == null || "unknown".equals(asUserDrv.body().get("state")),
                    asUserDrv.status() + " state=" + asUserDrv.body().get("state") + detail(asUserDrv));
            }

            LiveSetupCheck.Reply account = call("GET", "/api/v2/trees/" + TREE + "/objects/" + userGuid + "/account", null, admin);
            Map<String, String> h = new HashMap<>(admin);
            h.put("If-Match", account.raw().headers().firstValue("ETag").orElse("*"));
            ok("disable the test user", call("PATCH", "/api/v2/trees/" + TREE + "/objects/" + userGuid + "/account", Map.of("disabled", true), h).status() == 200, "");
            String refused = sso(idp, "tester").raw().headers().firstValue("Location").orElse("");
            ok("a disabled account cannot sign in", refused.equals("/?sso-error=no-account"), refused);
        } finally {
            if (container != null) {
                LiveSetupCheck.Reply count = call("GET", "/api/v2/trees/" + TREE + "/objects/" + container + "/subtree", null, admin);
                Map<String, String> h = new HashMap<>(admin);
                h.put("If-Match", "*");
                h.put("X-Confirm-Count", String.valueOf(count.body().get("count")));
                LiveSetupCheck.Reply d = call("DELETE", "/api/v2/trees/" + TREE + "/objects/" + container + "?subtree=true", null, h);
                ok("cleanup: subtree delete", d.status() == 200, "deleted=" + d.body().get("deleted") + detail(d));
            }
            server.stop();
            try (var s = Files.walk(dataPath)) {
                s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    private static Map<String, String> withEtag(Map<String, String> h, String guid) throws Exception {
        Map<String, String> out = new HashMap<>(h);
        out.put("If-Match", call("GET", "/api/v2/trees/" + TREE + "/objects/" + guid, null, h).raw().headers().firstValue("ETag").orElse("*"));
        return out;
    }

    /** The browser's part of a sign-in: start, the provider's redirect back, the callback with the state cookie. */
    private static LiveSetupCheck.Reply sso(FakeIdp idp, String person) throws Exception {
        idp.signInAs = person;
        LiveSetupCheck.Reply start = call("GET", "/api/v2/oidc/start?directory=" + TREE + "&next=/", null, Map.of());
        String state = start.raw().headers().allValues("Set-Cookie").stream().filter(c -> c.startsWith("__Host-console-oidc=")).findFirst().orElseThrow();
        HttpResponse<String> atIdp = LiveSetupCheck.http.send(HttpRequest.newBuilder(URI.create(start.raw().headers().firstValue("Location").orElseThrow())).GET().build(),
            HttpResponse.BodyHandlers.ofString());
        String back = atIdp.headers().firstValue("Location").orElseThrow();
        return call("GET", back.substring("https://localhost:8443".length()), null, Map.of("Cookie", state.substring(0, state.indexOf(';'))));
    }

    private static Map<String, String> cookie(LiveSetupCheck.Reply r) {
        String c = r.raw().headers().allValues("Set-Cookie").stream().filter(x -> x.startsWith("__Host-console=")).findFirst().orElse("x=;");
        return new HashMap<>(Map.of("Cookie", c.substring(0, c.indexOf(';'))));
    }

    private static void setUp(Path dataPath, String host, int port, String dn, String pw) throws Exception {
        Matcher m = Pattern.compile("Setup token: ([0-9a-f]{32})").matcher(Files.readString(dataPath.resolve("bootstrap.txt")));
        m.find();
        Map<String, String> t = Map.of("X-Setup-Token", m.group(1));
        call("PUT", "/api/v2/setup/directory", Map.of("id", TREE, "name", TREE, "host", host, "port", port, "tier", "lab"), t);
        LiveSetupCheck.Reply probe = call("POST", "/api/v2/setup/probe", Map.of(), t);
        int rec = Json.asInt(probe.body().get("recommended"), 0);
        String sha = (String) Json.asMap(((List<?>) probe.body().get("chain")).get(rec)).get("sha256");
        String tail = sha.replace(":", "").toLowerCase();
        call("POST", "/api/v2/setup/trust", Map.of("probeId", probe.body().get("probeId"), "index", rec, "confirm", tail.substring(tail.length() - 8)), t);
        call("POST", "/api/v2/setup/authority", Map.of("dn", dn, "password", pw), t);
        call("PUT", "/api/v2/setup/service-account", Map.of("dn", dn, "password", pw), t);
        call("POST", "/api/v2/setup/finish", Map.of(), t);
        LiveSetupCheck.Reply in = call("POST", "/api/v2/session", Map.of("directory", TREE, "name", dn, "password", pw), Map.of());
        String cookie = in.raw().headers().firstValue("Set-Cookie").orElse("");
        admin = new HashMap<>(Map.of("Cookie", cookie.substring(0, cookie.indexOf(';'))));
        admin.put("X-CSRF-Token", String.valueOf(in.body().get("csrf")));
    }

    private static String enc(String s) {
        return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8);
    }

    private static String detail(LiveSetupCheck.Reply r) {
        return r.status() / 100 == 2 ? "" : " " + r.body().get("title") + ": " + r.body().get("detail");
    }

    private static void ok(String what, boolean ok, Object detail) {
        System.out.println("[" + (ok ? "ok" : "FAIL") + "] " + what + ": " + detail);
    }
}
