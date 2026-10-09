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
 * Live check of Phase 2's object API against a lab vault, through the real server: set up and sign in as
 * the environment's admin, then browse, search, read the schema, and (inside one new container under
 * {@code parentDN}, removed at the end) create, modify, rename, move and delete. Not a JUnit test. Prints
 * outcomes, never a password.
 *
 *   java -cp … LiveObjectsCheck <environments.properties> <env> <parentDN>
 */
public final class LiveObjectsCheck {

    private static Map<String, String> session;
    private static String tree = "lab";

    public static void main(String[] args) throws Exception {
        LegacyTls.enable();
        Environments.Environment env = Environments.load(Path.of(args[0])).get(args[1]);
        if (env.tier != null && env.tier.name().equalsIgnoreCase("prd")) {
            throw new IllegalStateException("refusing a prd-tier environment");
        }
        URI u = URI.create(env.url);
        String host = u.getHost();
        int port = u.getPort() > 0 ? u.getPort() : 636;
        Path dataPath = Files.createTempDirectory("dc-live-");
        System.out.println("# Directory Console Phase 2 live check: " + args[1] + " (" + host + ":" + port + ")");
        Server server = new Server(new DataDir(dataPath), 0, "https://localhost:8443", new PrintStream(new ByteArrayOutputStream()));
        String container = null;
        try {
            server.start();
            LiveSetupCheck.base = "https://localhost:" + server.port();
            LiveSetupCheck.http = ServerClient.trusting(server);
            setUp(dataPath, host, port, env.bindDn, env.password);

            // ---- reads ----
            LiveSetupCheck.Reply roots = get("/roots");
            List<Map<String, Object>> top = items(roots);
            ok("roots", roots.status() == 200 && !top.isEmpty(), top.stream().map(r -> r.get("dn") + " children=" + r.get("children") + "/" + r.get("childCount")).toList());

            LiveSetupCheck.Reply parent = get("/objects?dn=" + java.net.URLEncoder.encode(args[2], java.nio.charset.StandardCharsets.UTF_8));
            String parentGuid = (String) parent.body().get("guid");
            ok("resolve " + args[2], parent.status() == 200 && parentGuid != null, parentGuid + " objectClass=" + parent.body().get("objectClass")
                + " children=" + parent.body().get("children") + " etag=" + parent.raw().headers().firstValue("ETag").orElse("-"));
            LiveSetupCheck.Reply byGuid = get("/objects/" + parentGuid);
            ok("read by GUID", byGuid.status() == 200 && args[2].equalsIgnoreCase(String.valueOf(byGuid.body().get("dn"))),
                "attributes=" + Json.asMap(byGuid.body().get("attributes")).size() + " operational=" + byGuid.body().get("operational"));

            for (Map<String, Object> r : top) {
                if ("yes".equals(r.get("children"))) {
                    LiveSetupCheck.Reply ch = get("/objects/" + r.get("guid") + "/children?count=5");
                    ok("children of " + r.get("dn") + " (window 1-5)", ch.status() == 200 && Json.asInt(ch.body().get("total"), -2) == Json.asInt(r.get("childCount"), -3),
                        "total=" + ch.body().get("total") + " (subordinateCount " + r.get("childCount") + ") " + names(ch) + detail(ch));
                    LiveSetupCheck.Reply tail = get("/objects/" + r.get("guid") + "/children?count=500");
                    ok("  all children in one window", tail.status() == 200 && items(tail).size() == Json.asInt(r.get("childCount"), -3), names(tail));
                    LiveSetupCheck.Reply cont = get("/objects/" + r.get("guid") + "/children?kind=containers&count=5");
                    ok("  containers only", cont.status() == 200, "total=" + cont.body().get("total") + " " + names(cont) + detail(cont));
                    LiveSetupCheck.Reply leaves = get("/objects/" + r.get("guid") + "/children?kind=leaves&count=5&offset=3");
                    ok("  leaves, from 3", leaves.status() == 200, "offset=" + leaves.body().get("offset") + " total=" + leaves.body().get("total") + " " + names(leaves) + detail(leaves));
                }
            }

            LiveSetupCheck.Reply search = call("POST", "/api/v2/trees/" + tree + "/search", Map.of(
                "filter", Map.of("and", List.of(Map.of("eq", Map.of("objectClass", "inetOrgPerson")), Map.of("prefix", Map.of("cn", "t")))),
                "attributes", List.of("cn", "mail"), "page", Map.of("count", 5)), session);
            ok("search inetOrgPerson cn=t*", search.status() == 200, "total=" + search.body().get("total") + " " + names(search) + detail(search));
            LiveSetupCheck.Reply jump = call("POST", "/api/v2/trees/" + tree + "/search", Map.of(
                "filter", Map.of("eq", Map.of("objectClass", "inetOrgPerson")), "page", Map.of("count", 3, "startAt", "m")), session);
            ok("search jump to 'm'", jump.status() == 200, "offset=" + jump.body().get("offset") + " " + names(jump) + detail(jump));
            LiveSetupCheck.Reply weird = call("POST", "/api/v2/trees/" + tree + "/search", Map.of(
                "filter", Map.of("eq", Map.of("cn", "x)(objectClass=*")), "page", Map.of("count", 3)), session);
            ok("filter value with ')(' is literal", weird.status() == 200 && Json.asInt(weird.body().get("count"), -1) == 0, "count=" + weird.body().get("count") + detail(weird));
            LiveSetupCheck.Reply adv = call("POST", "/api/v2/trees/" + tree + "/search", Map.of("ldapFilter", "(&(objectClass=organizationalUnit)(ou=*))", "page", Map.of("count", 3)), session);
            ok("advanced ldapFilter", adv.status() == 200, "total=" + adv.body().get("total") + detail(adv));

            LiveSetupCheck.Reply classes = get("/schema/classes");
            LiveSetupCheck.Reply ou = get("/schema/classes/organizationalUnit");
            LiveSetupCheck.Reply top2 = get("/schema/classes/Top");
            LiveSetupCheck.Reply group = get("/schema/classes/groupOfNames");
            ok("schema classes", classes.status() == 200, "ou.container=" + ou.body().get("container") + " Top.container=" + top2.body().get("container")
                + " group.container=" + group.body().get("container") + " ou.allMust=" + ou.body().get("allMust"));
            LiveSetupCheck.Reply member = get("/schema/attributes/member");
            ok("schema attribute member", member.status() == 200, String.valueOf(member.body()));

            // ---- writes, inside one container ----
            String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
            LiveSetupCheck.Reply c = call("POST", "/api/v2/trees/" + tree + "/objects/" + parentGuid + "/children",
                Map.of("objectClass", "organizationalUnit", "name", Map.of("type", "ou", "value", "dcp2api-" + ts)), csrf());
            container = (String) c.body().get("guid");
            ok("create container", c.status() == 201, c.body().get("dn") + " " + container);
            LiveSetupCheck.Reply a = create(container, "organizationalUnit", "ou", "a, b+c");
            LiveSetupCheck.Reply b = create(container, "organizationalUnit", "ou", "b");
            LiveSetupCheck.Reply g = call("POST", "/api/v2/trees/" + tree + "/objects/" + a.body().get("guid") + "/children",
                Map.of("objectClass", "groupOfNames", "name", Map.of("type", "cn", "value", "Team #1 (dc)"),
                    "attributes", Map.of("description", List.of("made by the live check"), "member", List.of(Map.of("guid", parentGuid)))), csrf());
            String gGuid = (String) g.body().get("guid");
            ok("create OU with special characters", a.status() == 201, a.body().get("dn") + " name=" + a.body().get("name") + " dot=" + Json.asMap(a.body().get("display")).get("dot"));
            ok("create group with a member by GUID", g.status() == 201, g.body().get("dn") + " member=" + Json.asMap(g.body().get("attributes")).get("member") + detail(g));
            String etag = g.raw().headers().firstValue("ETag").orElse("");

            LiveSetupCheck.Reply noMatch = patch(gGuid, null, List.of(Map.of("op", "replace", "attribute", "description", "values", List.of("x"))));
            ok("modify without If-Match refused", noMatch.status() == 428, noMatch.status() + " " + noMatch.body().get("title"));
            LiveSetupCheck.Reply m1 = patch(gGuid, etag, List.of(Map.of("op", "replace", "attribute", "description", "values", List.of("changed"))));
            ok("modify with If-Match", m1.status() == 200, "description=" + Json.asMap(m1.body().get("attributes")).get("description"));
            LiveSetupCheck.Reply stale = patch(gGuid, etag, List.of(Map.of("op", "replace", "attribute", "description", "values", List.of("stale"))));
            ok("modify with a stale ETag refused", stale.status() == 412, stale.status() + " " + stale.body().get("title"));
            String e2 = m1.raw().headers().firstValue("ETag").orElse("");
            LiveSetupCheck.Reply bad = patch(gGuid, e2, List.of(Map.of("op", "add", "attribute", "noSuchAttrXyz", "values", List.of("x"))));
            ok("undefined attribute -> problem", bad.status() == 400, bad.status() + " " + bad.body().get("title") + " ldap=" + bad.body().get("ldapResultCode"));

            LiveSetupCheck.Reply rn = call("POST", "/api/v2/trees/" + tree + "/objects/" + gGuid + "/rename", Map.of("name", "Team, renamed"), csrf(e2));
            ok("rename", rn.status() == 200 && gGuid.equals(rn.body().get("guid")), String.valueOf(rn.body().get("dn")));
            String e3 = rn.raw().headers().firstValue("ETag").orElse("");
            LiveSetupCheck.Reply mv = call("POST", "/api/v2/trees/" + tree + "/objects/" + gGuid + "/move", Map.of("newParent", b.body().get("guid")), csrf(e3));
            ok("move", mv.status() == 200 && gGuid.equals(mv.body().get("guid")), mv.body().get("dn") + " etag changed=" + !e3.equals(mv.raw().headers().firstValue("ETag").orElse("")));
            LiveSetupCheck.Reply into = call("POST", "/api/v2/trees/" + tree + "/objects/" + container + "/move", Map.of("newParent", b.body().get("guid")), csrf("*"));
            ok("move into itself refused", into.status() == 409, into.status() + " " + into.body().get("title"));
            LiveSetupCheck.Reply nonLeaf = call("DELETE", "/api/v2/trees/" + tree + "/objects/" + b.body().get("guid"), null, csrf("*"));
            ok("delete non-leaf refused", nonLeaf.status() == 409, nonLeaf.status() + " " + nonLeaf.body().get("title") + " nds=" + nonLeaf.body().get("ndsError"));
            LiveSetupCheck.Reply rights = get("/objects/" + container + "/rights");
            ok("effective rights", rights.status() == 200, String.valueOf(rights.body()));
            LiveSetupCheck.Reply audit = call("GET", "/api/v2/audit/verify", null, session);
            ok("audit chain intact", Boolean.TRUE.equals(audit.body().get("intact")), "lines=" + audit.body().get("lines"));
        } finally {
            if (container != null) {
                cleanUp(container);
            }
            server.stop();
            try (var s = Files.walk(dataPath)) {
                s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    private static void setUp(Path dataPath, String host, int port, String dn, String pw) throws Exception {
        Matcher m = Pattern.compile("Setup token: ([0-9a-f]{32})").matcher(Files.readString(dataPath.resolve("bootstrap.txt")));
        m.find();
        Map<String, String> t = Map.of("X-Setup-Token", m.group(1));
        call("PUT", "/api/v2/setup/directory", Map.of("id", tree, "name", "lab", "host", host, "port", port, "tier", "lab"), t);
        LiveSetupCheck.Reply probe = call("POST", "/api/v2/setup/probe", Map.of(), t);
        int rec = Json.asInt(probe.body().get("recommended"), 0);
        String sha = (String) Json.asMap(((List<?>) probe.body().get("chain")).get(rec)).get("sha256");
        String tail = sha.replace(":", "").toLowerCase();
        call("POST", "/api/v2/setup/trust", Map.of("probeId", probe.body().get("probeId"), "index", rec, "confirm", tail.substring(tail.length() - 8)), t);
        call("POST", "/api/v2/setup/authority", Map.of("dn", dn, "password", pw), t);
        call("PUT", "/api/v2/setup/service-account", Map.of("dn", dn, "password", pw), t);
        LiveSetupCheck.step("finish setup", call("POST", "/api/v2/setup/finish", Map.of(), t));
        LiveSetupCheck.Reply in = call("POST", "/api/v2/session", Map.of("directory", tree, "name", dn, "password", pw), Map.of());
        LiveSetupCheck.step("sign in", in);
        String cookie = in.raw().headers().firstValue("Set-Cookie").orElse("");
        session = new HashMap<>(Map.of("Cookie", cookie.substring(0, cookie.indexOf(';'))));
        session.put("X-CSRF-Token", String.valueOf(in.body().get("csrf")));
    }

    private static Map<String, String> csrf() {
        return session;
    }

    private static Map<String, String> csrf(String ifMatch) {
        Map<String, String> h = new HashMap<>(session);
        h.put("If-Match", ifMatch);
        return h;
    }

    private static LiveSetupCheck.Reply get(String path) throws Exception {
        return call("GET", "/api/v2/trees/" + tree + path, null, session);
    }

    private static LiveSetupCheck.Reply create(String parent, String oc, String type, String value) throws Exception {
        return call("POST", "/api/v2/trees/" + tree + "/objects/" + parent + "/children", Map.of("objectClass", oc, "name", Map.of("type", type, "value", value)), csrf());
    }

    private static LiveSetupCheck.Reply patch(String guid, String etag, List<Map<String, Object>> changes) throws Exception {
        return call("PATCH", "/api/v2/trees/" + tree + "/objects/" + guid, Map.of("changes", changes), etag == null ? csrf() : csrf(etag));
    }

    /** Delete everything under the container, deepest first, then the container. */
    private static void cleanUp(String container) throws Exception {
        LiveSetupCheck.Reply all = call("POST", "/api/v2/trees/" + tree + "/search", Map.of("base", Map.of("guid", container), "scope", "subtree", "page", Map.of("count", 100)), session);
        List<Map<String, Object>> items = items(all);
        items.sort(Comparator.comparingInt((Map<String, Object> r) -> ((List<?>) r.get("rdns")).size()).reversed());
        int failed = 0;
        for (Map<String, Object> r : items) {
            LiveSetupCheck.Reply d = call("DELETE", "/api/v2/trees/" + tree + "/objects/" + r.get("guid"), null, csrf("*"));
            for (int retry = 0; retry < 20 && (d.status() == 503 || d.status() == 409); retry++) {
                // eDirectory finishes a move in the background ("previous move in progress", -637)
                Thread.sleep(3000);
                d = call("DELETE", "/api/v2/trees/" + tree + "/objects/" + r.get("guid"), null, csrf("*"));
            }
            if (d.status() != 204) {
                failed++;
                System.out.println("  cleanup " + r.get("dn") + ": " + d.status() + " " + d.body().get("detail"));
            }
        }
        System.out.println("[" + (failed == 0 && !items.isEmpty() ? "ok" : "FAIL") + "] cleanup: " + items.size() + " objects deleted through the API");
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> items(LiveSetupCheck.Reply r) {
        Object i = r.body().get("items");
        return i instanceof List<?> l ? new java.util.ArrayList<>((List<Map<String, Object>>) l) : new java.util.ArrayList<>();
    }

    private static String names(LiveSetupCheck.Reply r) {
        return items(r).stream().map(x -> String.valueOf(x.get("name"))).toList().toString();
    }

    private static String detail(LiveSetupCheck.Reply r) {
        return r.status() / 100 == 2 ? "" : " -> " + r.status() + " " + r.body().get("title") + ": " + r.body().get("detail");
    }

    private static void ok(String what, boolean ok, Object detail) {
        System.out.println("[" + (ok ? "ok" : "FAIL") + "] " + what + ": " + detail);
    }
}
