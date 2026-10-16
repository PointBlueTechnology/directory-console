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
 * Live check of the security services against a lab tree: the PKI read (CA, server certificates, trusted roots,
 * CRLs) with private keys withheld; a test password policy and challenge set created, linked,
 * assigned to a test OU (both sides checked), seen from a user in it, changed, and deleted (the
 * deletion of an assigned policy asks for the count first); the Login Policy read. Everything made for
 * the run is deleted. Not a JUnit test.
 *
 *   java -cp … LivePhase6Check <environments.properties> <env> <parent DN>
 */
public final class LivePhase6Check {

    private static final String T = "/api/v2/trees/lab";
    private static Map<String, String> admin;

    public static void main(String[] args) throws Exception {
        LegacyTls.enable();
        Environments.Environment env = Environments.load(Path.of(args[0])).get(args[1]);
        if (env.tier != null && env.tier.name().equalsIgnoreCase("prd")) {
            throw new IllegalStateException("refusing a prd-tier environment");
        }
        URI u = URI.create(env.url);
        Path dataPath = Files.createTempDirectory("dc-live-p6-");
        Server server = new Server(new DataDir(dataPath), ServerClient.loopback(), "https://localhost:8443", new PrintStream(new ByteArrayOutputStream()));
        String ou = null;
        String policy = null;
        String set = null;
        try {
            server.start();
            LiveSetupCheck.base = "https://127.0.0.1:" + server.port();
            LiveSetupCheck.http = ServerClient.trusting(server);
            setUp(dataPath, u.getHost(), u.getPort() > 0 ? u.getPort() : 636, env.bindDn, env.password);
            System.out.println("# Security services live check: " + args[1]);

            LiveSetupCheck.Reply pki = call("GET", T + "/security/pki", null, admin);
            Map<String, Object> ca = Json.asMap(pki.body().get("ca"));
            List<?> certs = (List<?>) ca.get("certificates");
            ok("Organizational CA", pki.status() == 200 && certs.size() >= 1, ca.get("name") + " " + certs.stream().map(c -> Json.asMap(c).get("key") + " until " + Json.asMap(c).get("notAfter")).toList());
            List<?> kmos = (List<?>) pki.body().get("serverCertificates");
            ok("server certificates", !kmos.isEmpty(), kmos.stream().map(k -> {
                Map<String, Object> m = Json.asMap(k);
                Map<String, Object> c = m.get("certificate") == null ? Map.of() : Json.asMap(m.get("certificate"));
                return m.get("name") + " [" + c.get("key") + ", until " + c.get("notAfter") + ", SAN " + c.get("subjectAltNames") + "] used by " + m.get("usedBy");
            }).toList());
            ok("trusted roots", pki.body().get("trustedRoots") instanceof List<?>, pki.body().get("trustedRoots") == null ? null
                : ((List<?>) pki.body().get("trustedRoots")).stream().map(x -> Json.asMap(x).get("name") + " until " + Json.asMap(Json.asMap(x).get("certificate")).get("notAfter")).toList());
            ok("CRLs", pki.body().get("crls") instanceof List<?>, ((List<?>) pki.body().get("crls")).stream().map(x -> {
                Map<String, Object> m = Json.asMap(x);
                return m.get("name") + " (" + m.get("type") + ") #" + m.get("number") + " next " + m.get("nextIssue") + " revoked=" + m.get("revoked");
            }).toList());
            LiveSetupCheck.Reply caObject = call("GET", T + "/objects/" + ca.get("guid"), null, admin);
            Object key = Json.asMap(caObject.body().get("attributes")).get("nDSPKIPrivateKey");
            ok("the CA's private key is withheld from an object read", String.valueOf(key).equals("[{withheld=1}]"),
                "nDSPKIPrivateKey=" + key);

            List<?> policies = (List<?>) call("GET", T + "/security/password-policies", null, admin).body().get("list");
            ok("password policies", policies != null && !policies.isEmpty(), policies);
            String sample = null;
            for (Object o : policies) {
                if ("Sample Password Policy".equals(Json.asMap(o).get("name"))) {
                    sample = (String) Json.asMap(o).get("guid");
                }
            }
            if (sample != null) {
                LiveSetupCheck.Reply sp = call("GET", T + "/security/password-policies/" + sample, null, admin);
                ok("the sample policy decoded", sp.status() == 200, "options=" + sp.body().get("options") + " forgotten=" + sp.body().get("forgotten")
                    + " assignments=" + ((List<?>) sp.body().get("assignments")).size());
            }

            String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
            LiveSetupCheck.Reply cs = call("POST", T + "/security/challenge-sets", Map.of("name", "dcp6cs-" + ts, "description", "Directory Console live check",
                "required", List.of(Map.of("kind", "admin", "text", "What is your favourite colour?", "min", 2, "max", 40), Map.of("kind", "user", "min", 4, "max", 64)),
                "random", List.of(Map.of("kind", "admin", "text", "Name of your first pet?", "min", 2, "max", 40), Map.of("kind", "admin", "text", "City of birth?", "min", 2, "max", 40)),
                "randomCount", 1), admin);
            set = (String) cs.body().get("guid");
            ok("create a challenge set", cs.status() == 201 && ((List<?>) cs.body().get("required")).size() == 2, cs.body().get("required") + detail(cs));

            LiveSetupCheck.Reply np = call("POST", T + "/security/password-policies", Map.of("name", "dcp6-" + ts, "description", "Directory Console live check",
                "rules", Map.of("minLength", 10, "maxLength", 64, "minUpper", 1, "minNumeric", 1, "expirationDays", 90, "historyLimit", 8, "uniqueRequired", true),
                "challengeSet", set), admin);
            policy = (String) np.body().get("guid");
            ok("create a password policy", np.status() == 201 && Boolean.TRUE.equals(Json.asMap(np.body().get("options")).get("universalPassword")),
                "rules=" + np.body().get("rules") + " options=" + np.body().get("options") + " challengeSet=" + np.body().get("challengeSet") + detail(np));

            String parent = (String) call("GET", T + "/objects?dn=" + java.net.URLEncoder.encode(args[2], "UTF-8"), null, admin).body().get("guid");
            LiveSetupCheck.Reply c = call("POST", T + "/objects/" + parent + "/children", Map.of("objectClass", "organizationalUnit", "name", Map.of("type", "ou", "value", "dcp6-" + ts)), admin);
            ou = (String) c.body().get("guid");
            LiveSetupCheck.Reply user = call("POST", T + "/objects/" + ou + "/children", Map.of("objectClass", "inetOrgPerson",
                "name", Map.of("type", "cn", "value", "p6user"), "attributes", Map.of("sn", List.of("Six"))), admin);
            ok("test OU and user", c.status() == 201 && user.status() == 201, user.body().get("dn"));

            LiveSetupCheck.Reply as = call("POST", T + "/security/password-policies/" + policy + "/assignments", Map.of("target", ou), admin);
            Object ouPolicy = Json.asMap(call("GET", T + "/objects/" + ou, null, admin).body().get("attributes")).get("nspmPasswordPolicyDN");
            ok("assign it to the OU: both sides written", as.status() == 200 && ((List<?>) as.body().get("assignments")).size() == 1 && String.valueOf(ouPolicy).contains("dcp6-"),
                "policy.assignments=" + as.body().get("assignments") + " ou.nspmPasswordPolicyDN=" + ouPolicy);
            LiveSetupCheck.Reply seen = call("GET", T + "/security/objects/" + user.body().get("guid") + "/password-policy", null, admin);
            ok("seen from a user in the OU", seen.status() == 200 && String.valueOf(seen.body().get("containers")).contains("dcp6-"), seen.body());

            LiveSetupCheck.Reply ch = call("PATCH", T + "/security/password-policies/" + policy, Map.of("rules", Map.of("minLength", 12, "minSpecial", 1),
                "options", Map.of("userRetrieve", false, "adminRetrieve", false)), admin);
            ok("change rules and options", ch.status() == 200 && Integer.valueOf(12).equals(Json.asInt(Json.asMap(ch.body().get("rules")).get("minLength"), 0))
                && Boolean.FALSE.equals(Json.asMap(ch.body().get("options")).get("adminRetrieve")), ch.body().get("rules") + " " + ch.body().get("options"));

            LiveSetupCheck.Reply refused = call("DELETE", T + "/security/password-policies/" + policy, null, admin);
            ok("deleting an assigned policy asks for the count", refused.status() == 409 && "confirm-count".equals(refused.body().get("title")), refused.body().get("detail"));
            LiveSetupCheck.Reply inUse = call("DELETE", T + "/security/challenge-sets/" + set, null, admin);
            ok("a challenge set in use is not deleted", inUse.status() == 409, inUse.body().get("detail"));

            LiveSetupCheck.Reply un = call("DELETE", T + "/security/password-policies/" + policy + "/assignments/" + ou, null, admin);
            Object after = Json.asMap(call("GET", T + "/objects/" + ou, null, admin).body().get("attributes")).get("nspmPasswordPolicyDN");
            ok("unassign: both sides cleared", un.status() == 200 && ((List<?>) un.body().get("assignments")).isEmpty() && after == null, "ou.nspmPasswordPolicyDN=" + after);

            LiveSetupCheck.Reply lp = call("GET", T + "/security/login-policy", null, admin);
            ok("Login Policy", lp.status() == 200, lp.body());
        } finally {
            if (policy != null) {
                LiveSetupCheck.Reply d = call("DELETE", T + "/security/password-policies/" + policy, null, withCount(admin, "1"));
                if (d.status() != 204) {
                    d = call("DELETE", T + "/security/password-policies/" + policy, null, admin);
                }
                ok("cleanup: delete the policy", d.status() == 204, d.status() + detail(d));
            }
            if (set != null) {
                LiveSetupCheck.Reply d = call("DELETE", T + "/security/challenge-sets/" + set, null, admin);
                ok("cleanup: delete the challenge set", d.status() == 204, d.status() + detail(d));
            }
            if (ou != null) {
                LiveSetupCheck.Reply count = call("GET", T + "/objects/" + ou + "/subtree", null, admin);
                Map<String, String> h = withCount(admin, String.valueOf(count.body().get("count")));
                h.put("If-Match", "*");
                LiveSetupCheck.Reply d = call("DELETE", T + "/objects/" + ou + "?subtree=true", null, h);
                ok("cleanup: subtree delete", d.status() == 200, "deleted=" + d.body().get("deleted") + detail(d));
            }
            server.stop();
            try (var st = Files.walk(dataPath)) {
                st.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    private static Map<String, String> withCount(Map<String, String> h, String n) {
        Map<String, String> out = new HashMap<>(h);
        out.put("X-Confirm-Count", n);
        return out;
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
        String d = String.valueOf(detail);
        System.out.println("[" + (ok ? "ok" : "FAIL") + "] " + what + ": " + (d.length() > 900 ? d.substring(0, 900) + "…" : d));
    }
}
