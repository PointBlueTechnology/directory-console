package com.pointblue.console.server.auth;

import com.pointblue.console.server.data.ConfigStore;
import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.dirxml.dev.json.Json;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * One configured directory, read from {@code directories/<id>} in the configuration:
 *
 * <pre>
 * { "name": "Production tree", "host": "edir1.acme.local", "port": 636, "tier": "production",
 *   "login": { "direct": true, "searchBases": ["o=acme"], "objectClasses": ["inetOrgPerson"],
 *              "matchAttributes": ["cn"], "excludeInactive": true, "maxCandidates": 10,
 *              "duplicates": "choose", "labelAttribute": "title" },
 *   "serviceAccount": { "dn": "cn=console,ou=sa,o=system", "password": {"sealed": "v1:…"} },
 *   "roles": [ { "group": "cn=Console Admins,ou=groups,o=acme", "role": "admin" } ],
 *   "breakGlass": [ "cn=admin,o=system" ] }
 * </pre>
 */
public record DirectoryConfig(String id, String name, String host, int port, String tier,
                              boolean directLogin, List<String> searchBases, List<String> objectClasses,
                              List<String> matchAttributes, boolean excludeInactive, int maxCandidates,
                              Duplicates duplicates, String labelAttribute,
                              String serviceAccountDn, List<RoleMapping> roles, List<String> breakGlass) {

    /** What contextless login does when a name matches more than one account. */
    public enum Duplicates { CHOOSE, ERROR }

    public record RoleMapping(String group, Role role) {
    }

    public Ldap.Target target() {
        return new Ldap.Target(id, host, port);
    }

    public boolean production() {
        return "production".equals(tier);
    }

    /** The service account's password path in the configuration (for {@link ConfigStore#secret}). */
    public String serviceAccountPasswordPath() {
        return "directories/" + id + "/serviceAccount/password";
    }

    public static List<DirectoryConfig> all(Map<String, Object> config) {
        List<DirectoryConfig> out = new ArrayList<>();
        Object dirs = config.get("directories");
        if (dirs instanceof Map<?, ?> m) {
            for (Object id : m.keySet()) {
                out.add(of(String.valueOf(id), Json.asMap(m.get(id))));
            }
        }
        return out;
    }

    public static DirectoryConfig find(Map<String, Object> config, String id) {
        return all(config).stream().filter(d -> d.id.equals(id)).findFirst().orElse(null);
    }

    static DirectoryConfig of(String id, Map<String, Object> d) {
        Map<String, Object> login = d.get("login") instanceof Map<?, ?> ? Json.asMap(d.get("login")) : Map.of();
        Map<String, Object> sa = d.get("serviceAccount") instanceof Map<?, ?> ? Json.asMap(d.get("serviceAccount")) : Map.of();
        List<RoleMapping> roles = new ArrayList<>();
        if (d.get("roles") instanceof List<?> l) {
            for (Object o : l) {
                Map<String, Object> r = Json.asMap(o);
                roles.add(new RoleMapping(Json.asString(r.get("group")), Role.parse(Json.asString(r.get("role")))));
            }
        }
        return new DirectoryConfig(id, str(d, "name", id), Json.asString(d.get("host")), Json.asInt(d.get("port"), 636),
            str(d, "tier", "production"), bool(login, "direct", true), strings(login.get("searchBases")),
            strings(login.get("objectClasses"), "inetOrgPerson"), strings(login.get("matchAttributes"), "cn"),
            bool(login, "excludeInactive", true), Json.asInt(login.get("maxCandidates"), 10),
            "error".equals(login.get("duplicates")) ? Duplicates.ERROR : Duplicates.CHOOSE,
            Json.asString(login.get("labelAttribute")), Json.asString(sa.get("dn")), roles, strings(d.get("breakGlass")));
    }

    private static String str(Map<String, Object> m, String k, String dflt) {
        String v = Json.asString(m.get(k));
        return v == null || v.isBlank() ? dflt : v;
    }

    private static boolean bool(Map<String, Object> m, String k, boolean dflt) {
        return m.get(k) == null ? dflt : Json.asBool(m.get(k));
    }

    private static List<String> strings(Object o, String... dflt) {
        List<String> out = new ArrayList<>();
        if (o instanceof List<?> l) {
            l.forEach(v -> out.add(String.valueOf(v)));
        }
        return out.isEmpty() ? List.of(dflt) : out;
    }
}
