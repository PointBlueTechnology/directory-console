package com.pointblue.console.server.http;

import com.pointblue.console.server.audit.AuditLog;
import com.pointblue.console.server.auth.DirectoryConfig;
import com.pointblue.console.server.auth.Role;
import com.pointblue.console.server.auth.Sessions;
import com.pointblue.console.server.auth.TaskPreset;
import com.pointblue.console.server.data.ConfigStore;
import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.console.server.ldap.Names;
import com.pointblue.dirxml.dev.json.Json;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import javax.naming.NamingException;

/**
 * A directory's sign-in and authorization settings, for console admins. Every change needs a sign-in within the last 10 minutes, is validated as a
 * whole before it is saved, becomes a new configuration version and is audited. The OIDC client
 * secret is write-only.
 *
 * <pre>
 * GET  /api/v2/directories/{id}/settings        roles, presets, single sign-on, break-glass; ETag is the configuration version
 * PUT  /api/v2/directories/{id}/roles           [ {"group", "role", "scopes", "presets"} ]
 * PUT  /api/v2/directories/{id}/presets         { id: preset }  (the export format of GET …/presets)
 * GET  /api/v2/directories/{id}/presets         the presets, for export
 * PUT  /api/v2/directories/{id}/oidc            {"issuer", "clientId", "clientSecret"?, …} or null to turn single sign-on off
 * POST /api/v2/directories/{id}/oidc/test       {"value"}: which account that claim value maps to
 * PUT  /api/v2/directories/{id}/tier            {"tier": production|lab}
 * PUT  /api/v2/directories/{id}/login           {"searchBases": [DN…], "duplicates": choose|error, "direct": bool, "allowed": [DN…]}
 *                                               (direct false needs single sign-on; then only break-glass and allowed
 *                                               accounts sign in with a password)
 * PUT  /api/v2/directories/{id}/service-account {"dn", "password"} (checked by signing in as it), or null for none
 * PUT  /api/v2/directories/{id}/session         {"idleMinutes": 5-240, "maxHours": 1-24}: applies at once, to sessions already open too
 * </pre>
 *
 * The tier, sign-in options and service account are what the console's first sign-in leaves for later
 * (see Setup): it configures a tree with the production tier, no service account and no search bases.
 */
final class Settings {

    private final Server server;

    Settings(Server server) {
        this.server = server;
    }

    void handle(HttpExchange ex, String path, String method) throws IOException {
        String[] p = path.substring("/api/v2/directories/".length()).split("/", -1);
        Sessions.Session s = server.session(ex, Role.ADMIN);
        String id = p[0];
        DirectoryConfig d = DirectoryConfig.find(server.config.read(), id);
        if (d == null) {
            throw new Http.Problem(404, "unknown-directory", "no directory " + id);
        }
        String route = method + " " + String.join("/", java.util.Arrays.copyOfRange(p, 1, p.length));
        if (!method.equals("GET")) {
            server.stepUp(s);
        }
        switch (route) {
            case "GET settings" -> settings(ex, d);
            case "GET presets" -> Http.json(ex, 200, rawSection(id, "presets", Map.of()));
            case "PUT roles" -> save(ex, s, d, "roles", body(ex), v -> validateRoles(d, v, false));
            case "PUT presets" -> save(ex, s, d, "presets", body(ex), v -> validatePresets(d, v));
            case "PUT oidc" -> oidc(ex, s, d);
            case "POST oidc/test" -> test(ex, d);
            case "PUT tier" -> {
                String tier = Http.string(Json.asMap(body(ex)), "tier", true);
                save(ex, s, d, "tier", tier, v -> {
                    if (!v.equals("production") && !v.equals("lab")) {
                        throw new IllegalArgumentException("tier is production or lab");
                    }
                });
            }
            case "PUT login" -> login(ex, s, d);
            case "PUT session" -> {
                Map<String, Object> b = Json.asMap(body(ex));
                int idle = Http.integer(b, "idleMinutes", 30);
                int hours = Http.integer(b, "maxHours", 12);
                save(ex, s, d, "session", Map.of("idleMinutes", idle, "maxHours", hours), v -> {
                    if (idle < Server.MIN_IDLE_MINUTES || idle > Server.MAX_IDLE_MINUTES) {
                        throw new IllegalArgumentException("the idle timeout is " + Server.MIN_IDLE_MINUTES + " to " + Server.MAX_IDLE_MINUTES + " minutes");
                    }
                    if (hours < Server.MIN_HOURS || hours > Server.MAX_HOURS) {
                        throw new IllegalArgumentException("the longest session is " + Server.MIN_HOURS + " to " + Server.MAX_HOURS + " hours");
                    }
                });
            }
            case "PUT service-account" -> serviceAccount(ex, s, d);
            default -> throw new Http.Problem(404, "not-found", method + " " + path);
        }
    }

    private static Object body(HttpExchange ex) throws IOException {
        String text = new String(ex.getRequestBody().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        try {
            return text.isBlank() ? null : Json.parse(text);
        } catch (RuntimeException e) {
            throw new Http.Problem(400, "bad-json", "the body is not JSON");
        }
    }

    private Object rawSection(String id, String key, Object dflt) {
        Map<String, Object> dir = Json.asMap(Json.asMap(server.config.read().get("directories")).get(id));
        Object v = dir.get(key);
        return v == null ? dflt : v;
    }

    private void settings(HttpExchange ex, DirectoryConfig d) throws IOException {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", d.id());
        m.put("name", d.name());
        m.put("tier", d.tier());
        m.put("directLogin", d.directLogin());
        m.put("serviceAccount", d.serviceAccountDn());
        Sessions.Limits limits = server.sessionLimits(d.id());
        m.put("session", Map.of("idleMinutes", limits == null ? 30 : limits.idle().toMinutes(), "maxHours", limits == null ? 12 : limits.absolute().toHours()));
        m.put("login", Map.of("searchBases", d.searchBases(), "duplicates", d.duplicates() == DirectoryConfig.Duplicates.ERROR ? "error" : "choose",
            "allowed", d.directAllowed()));
        m.put("breakGlass", d.breakGlass());
        m.put("roles", d.roles().stream().map(DirectoryConfig.RoleMapping::json).toList());
        m.put("presets", d.presets().values().stream().map(TaskPreset::json).toList());
        Map<String, Object> o = null;
        if (rawSection(d.id(), "oidc", null) instanceof Map<?, ?> raw) {
            o = new LinkedHashMap<>(Json.asMap(raw));
            o.remove("clientSecret");
            o.put("clientSecretSet", server.config.secret(d.oidcSecretPath()) != null);
            if (d.oidc() != null) {
                // as parsed: every mapping with its scopes and presets, every list present
                o.put("roles", d.oidc().roles().stream().map(DirectoryConfig.RoleMapping::json).toList());
                o.put("searchBases", d.oidc().searchBases());
                o.put("objectClasses", d.oidc().objectClasses());
                o.put("neverProxy", d.oidc().neverProxy());
                o.put("claim", d.oidc().claim());
                o.put("attribute", d.oidc().attribute());
                o.put("label", d.oidc().label());
            }
        }
        m.put("oidc", o);
        m.put("redirectUri", server.oidc.redirectUri());
        ex.getResponseHeaders().set("ETag", "\"" + server.config.version() + "\"");
        Http.json(ex, 200, m);
    }

    /** Replace {@code key} of this directory with {@code value} (null removes it), after {@code validate}. */
    private void save(HttpExchange ex, Sessions.Session s, DirectoryConfig d, String key, Object value, Consumer<Object> validate) throws IOException {
        try {
            validate.accept(value);
        } catch (IllegalArgumentException e) {
            throw new Http.Problem(400, "invalid-settings", e.getMessage());
        }
        int expected = expectedVersion(ex);
        try {
            server.config.update(expected, s.principal.dn(), d.id() + " " + key, doc -> {
                Map<String, Object> dir = Json.asMap(Json.asMap(doc.get("directories")).get(d.id()));
                if (value == null) {
                    dir.remove(key);
                } else {
                    dir.put(key, value);
                }
            });
        } catch (ConfigStore.Conflict c) {
            throw new Http.Problem(409, "version-conflict", c.getMessage());
        }
        server.audit.log(new AuditLog.Actor(s.principal.subject(), s.principal.dn(), s.principal.via()), "settings." + key, d.id(),
            Map.of("summary", summary(key, value)), "ok");
        settings(ex, DirectoryConfig.find(server.config.read(), d.id()));
    }

    private int expectedVersion(HttpExchange ex) {
        String m = ex.getRequestHeaders().getFirst("If-Match");
        if (m == null) {
            return server.config.version();
        }
        try {
            return Integer.parseInt(m.replace("\"", "").trim());
        } catch (NumberFormatException e) {
            throw new Http.Problem(400, "bad-if-match", "If-Match is the settings' ETag");
        }
    }

    private static Object summary(String key, Object value) {
        if (value == null) {
            return "removed";
        }
        if (value instanceof List<?> l) {
            return l.size() + " entries";
        }
        if (value instanceof Map<?, ?> m) {
            Map<String, Object> out = new LinkedHashMap<>();
            if (key.equals("oidc")) {
                // never the secret; the provider and mapping
                for (String k : new String[] {"issuer", "clientId", "claim", "attribute"}) {
                    if (m.get(k) != null) {
                        out.put(k, m.get(k));
                    }
                }
                return out;
            }
            if (key.equals("login")) {
                // who may still use a password is the part worth seeing in the audit log
                out.put("direct", !Boolean.FALSE.equals(m.get("direct")));
                out.put("allowed", m.get("allowed") instanceof List<?> a ? a : List.of());
                return out;
            }
            return new ArrayList<>(Json.asMap(m).keySet());
        }
        return String.valueOf(value);
    }

    // ---- validation -------------------------------------------------------------------------------

    /** Role mappings: eDirectory group DNs (or, for {@code idp}, provider group names), valid scopes, known presets. */
    private static void validateRoles(DirectoryConfig d, Object v, boolean idp) {
        if (!(v instanceof List<?> l)) {
            throw new IllegalArgumentException("role mappings are a list");
        }
        for (Object o : l) {
            if (!(o instanceof Map<?, ?>)) {
                throw new IllegalArgumentException("each role mapping is an object");
            }
            DirectoryConfig.RoleMapping m = roleMapping(Json.asMap(o));
            if (m.group() == null || m.group().isBlank()) {
                throw new IllegalArgumentException("a role mapping needs a group");
            }
            if (!idp) {
                dn(m.group(), "group");
            }
            m.scopes().forEach(sc -> dn(sc, "scope"));
            if (m.role() == Role.ADMIN && !m.scopes().isEmpty()) {
                throw new IllegalArgumentException("admin is console-wide; it cannot be limited to containers");
            }
            for (String p : m.presets()) {
                if (!d.presets().containsKey(p)) {
                    throw new IllegalArgumentException("there is no task preset " + p);
                }
            }
        }
    }

    private static DirectoryConfig.RoleMapping roleMapping(Map<String, Object> m) {
        return DirectoryConfig.RoleMapping.of(m);
    }

    private static void dn(String dn, String what) {
        try {
            Names.parse(dn);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("the " + what + " " + dn + " is not a DN");
        }
    }

    private static void validatePresets(DirectoryConfig d, Object v) {
        if (!(v instanceof Map<?, ?> m)) {
            throw new IllegalArgumentException("presets are an object of id → preset");
        }
        m.forEach((k, p) -> {
            if (!(p instanceof Map<?, ?>)) {
                throw new IllegalArgumentException("preset " + k + " is not an object");
            }
            TaskPreset.of(String.valueOf(k), Json.asMap(p));
        });
        // a preset still granted by a role mapping cannot disappear
        for (DirectoryConfig.RoleMapping r : d.roles()) {
            for (String p : r.presets()) {
                if (!m.containsKey(p)) {
                    throw new IllegalArgumentException("preset " + p + " is granted to " + r.group() + "; remove that grant first");
                }
            }
        }
        if (d.oidc() != null) {
            for (DirectoryConfig.RoleMapping r : d.oidc().roles()) {
                for (String p : r.presets()) {
                    if (!m.containsKey(p)) {
                        throw new IllegalArgumentException("preset " + p + " is granted to the provider group " + r.group() + "; remove that grant first");
                    }
                }
            }
        }
    }

    private void oidc(HttpExchange ex, Sessions.Session s, DirectoryConfig d) throws IOException {
        Object b = body(ex);
        if (b == null) {
            save(ex, s, d, "oidc", null, v -> ssoStillNeeded(d, "turning single sign-on off"));
            return;
        }
        if (!(b instanceof Map<?, ?>)) {
            throw new Http.Problem(400, "invalid-settings", "single sign-on settings are an object, or null to turn it off");
        }
        Map<String, Object> o = new LinkedHashMap<>(Json.asMap(b));
        for (String k : new String[] {"issuer", "clientId"}) {
            if (Json.asString(o.get(k)) == null || Json.asString(o.get(k)).isBlank()) {
                throw new Http.Problem(400, "invalid-settings", "single sign-on needs " + k);
            }
        }
        String issuer = Json.asString(o.get("issuer")).trim();
        if (!issuer.startsWith("https://") && !(issuer.startsWith("http://127.0.0.1") || issuer.startsWith("http://localhost"))) {
            throw new Http.Problem(400, "invalid-settings", "the issuer must be an https URL");
        }
        if (d.serviceAccountDn() == null) {
            throw new Http.Problem(409, "no-service-account", "single sign-on acts through the console's service account; configure one first");
        }
        Object secret = o.remove("clientSecret");
        if (secret instanceof String str && !str.isEmpty()) {
            o.put("clientSecret", server.config.seal(str, d.oidcSecretPath()));
        } else if (rawSection(d.id(), "oidc", null) instanceof Map<?, ?> old && old.get("clientSecret") != null && !Boolean.FALSE.equals(secret)) {
            // absent: keep the stored secret; false: remove it (a public client)
            o.put("clientSecret", old.get("clientSecret"));
        }
        o.remove("clientSecretSet");
        save(ex, s, d, "oidc", o, v -> {
            validateRoles(d, o.getOrDefault("roles", List.of()), true);
            Object nv = o.get("neverProxy");
            if (nv instanceof List<?> l) {
                l.forEach(x -> dn(String.valueOf(x), "never-proxy entry"));
            }
            String attr = Json.asString(o.get("attribute"));
            if (attr != null && !attr.matches("[A-Za-z][A-Za-z0-9-]*")) {
                throw new IllegalArgumentException("the mapping attribute " + attr + " is not an attribute name");
            }
        });
    }

    /** The mapping, tried: which active account a claim value finds (as the service account). */
    private void test(HttpExchange ex, DirectoryConfig d) throws IOException {
        if (d.oidc() == null) {
            throw new Http.Problem(409, "no-sso", "single sign-on is not configured");
        }
        String value = Http.string(Http.body(ex), "value", true);
        String pw = server.config.secret(d.serviceAccountPasswordPath());
        if (d.serviceAccountDn() == null || pw == null) {
            throw new Http.Problem(409, "no-service-account", "the console's service account is not configured");
        }
        try (Ldap svc = Ldap.connect(server.trust, d.target(), null, d.serviceAccountDn(), pw.toCharArray(), Duration.ofSeconds(10))) {
            List<String> dns = server.oidc.mapped(svc, d, value);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("matches", dns);
            m.put("neverProxy", dns.size() == 1 && server.oidc.isNeverProxy(d, dns.get(0)));
            Http.json(ex, 200, m);
        } catch (Ldap.Untrusted | Ldap.BadCredentials | NamingException e) {
            throw new Http.Problem(502, "directory-error", "the service account could not search: " + e.getMessage());
        }
    }

    /** The sign-in options: search bases (checked to exist) and what several matches for a name do; the rest of "login" is kept. */
    private void login(HttpExchange ex, Sessions.Session s, DirectoryConfig d) throws IOException {
        Map<String, Object> b = Json.asMap(body(ex));
        Map<String, Object> login = new LinkedHashMap<>();
        if (rawSection(d.id(), "login", null) instanceof Map<?, ?> was) {
            login.putAll(Json.asMap(was));
        }
        if (b.containsKey("duplicates")) {
            login.put("duplicates", Http.string(b, "duplicates", true));
        }
        if (b.get("searchBases") instanceof List<?> l) {
            login.put("searchBases", dns(l));
        }
        if (b.containsKey("direct")) {
            login.put("direct", Json.asBool(b.get("direct")));
        }
        if (b.get("allowed") instanceof List<?> l) {
            login.put("allowed", dns(l));
        }
        save(ex, s, d, "login", login, v -> {
            if (Boolean.FALSE.equals(login.get("direct"))) {
                if (d.oidc() == null || d.serviceAccountDn() == null) {
                    throw new IllegalArgumentException("set up single sign-on before turning direct sign-in off");
                }
                if (d.breakGlass().isEmpty() && !(login.get("allowed") instanceof List<?> a && !a.isEmpty())) {
                    throw new IllegalArgumentException("list at least one account that may still sign in with a password");
                }
            }
            for (Object dn : login.get("allowed") instanceof List<?> a ? a : List.of()) {
                try {
                    Names.parse(String.valueOf(dn));
                } catch (RuntimeException e) {
                    throw new IllegalArgumentException("not a DN: " + dn);
                }
            }
            Object dup = login.get("duplicates");
            if (dup != null && !"choose".equals(dup) && !"error".equals(dup)) {
                throw new IllegalArgumentException("duplicates is choose or error");
            }
            for (Object base : login.get("searchBases") instanceof List<?> l ? l : List.of()) {
                try {
                    Names.parse(String.valueOf(base));
                } catch (RuntimeException e) {
                    throw new IllegalArgumentException("not a DN: " + base);
                }
            }
        });
    }

    /** Single sign-on is the only way in for most people while direct sign-in is off. */
    private static void ssoStillNeeded(DirectoryConfig d, String what) {
        if (!d.directLogin()) {
            throw new IllegalArgumentException("direct sign-in is off, so only single sign-on lets most people in: turn direct sign-in on before " + what);
        }
    }

    private static List<String> dns(List<?> l) {
        List<String> out = new ArrayList<>();
        for (Object o : l) {
            String dn = String.valueOf(o).trim();
            if (!dn.isEmpty()) {
                out.add(dn);
            }
        }
        return out;
    }

    /** The console's service account, proven by signing in as it; its password is sealed. Null removes it. */
    private void serviceAccount(HttpExchange ex, Sessions.Session s, DirectoryConfig d) throws IOException {
        Object raw = body(ex);
        if (raw == null) {
            save(ex, s, d, "serviceAccount", null, v -> ssoStillNeeded(d, "removing the service account"));
            return;
        }
        Map<String, Object> b = Json.asMap(raw);
        String dn = Http.string(b, "dn", true).trim();
        String pw = Http.string(b, "password", true);
        String bound;
        try (Ldap l = Ldap.connect(server.trust, d.target(), null, dn, pw.toCharArray(), Duration.ofSeconds(10))) {
            bound = l.boundDn() == null ? dn : l.boundDn();
        } catch (Ldap.BadCredentials e) {
            throw new Http.Problem(401, "bad-credentials", "the service account's name or password is incorrect");
        } catch (Ldap.Untrusted u) {
            throw new Http.Problem(409, "untrusted-certificate", u.getMessage());
        } catch (NamingException e) {
            throw new Http.Problem(502, "directory-error", e.getMessage());
        }
        Map<String, Object> account = Map.of("dn", bound, "password", server.config.seal(pw, d.serviceAccountPasswordPath()));
        save(ex, s, d, "serviceAccount", account, v -> { });
    }
}
