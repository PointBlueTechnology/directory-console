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
 *   "login": { "direct": true, "allowed": [], "searchBases": ["o=acme"], "objectClasses": ["inetOrgPerson"],
 *              "matchAttributes": ["cn"], "excludeInactive": true, "maxCandidates": 10,
 *              "duplicates": "choose", "labelAttribute": "title" },
 *   "serviceAccount": { "dn": "cn=console,ou=sa,o=system", "password": {"sealed": "v1:…"} },
 *   "roles": [ { "group": "cn=Console Admins,ou=groups,o=acme", "role": "admin" },
 *              { "group": "cn=Help Desk,ou=groups,o=acme", "presets": ["reset"], "scopes": ["ou=staff,o=acme"] } ],
 *   "breakGlass": [ "cn=admin,o=system" ],
 *   "presets": { "reset": { "name": "Reset password and unlock", "objectClass": "inetOrgPerson",
 *                           "actions": ["password", "unlock"], "attributes": [] } },
 *   "oidc": { "issuer": "https://idp.acme.example/realms/acme", "clientId": "directory-console",
 *             "clientSecret": {"sealed": "v1:…"}, "label": "Acme SSO", "groupsClaim": "groups",
 *             "claim": "preferred_username", "attribute": "uid", "searchBases": ["ou=staff,o=acme"],
 *             "roles": [ { "group": "console-admins", "role": "admin" } ], "neverProxy": [] } }
 * </pre>
 *
 * With {@code login.direct} false, only the break-glass accounts and those in {@code login.allowed} sign in with
 * a password (the allowed ones with their mapped roles); everyone else uses single sign-on.
 *
 * <p>A role mapping's {@code role} is optional when it grants {@code presets}; {@code scopes} limit both
 * to objects under those containers (section 7.4). OIDC role mappings name the provider's groups.
 */
public record DirectoryConfig(String id, String name, String host, int port, String tier,
                              boolean directLogin, List<String> directAllowed, List<String> searchBases, List<String> objectClasses,
                              List<String> matchAttributes, boolean excludeInactive, int maxCandidates,
                              Duplicates duplicates, String labelAttribute,
                              String serviceAccountDn, List<RoleMapping> roles, List<String> breakGlass,
                              Map<String, TaskPreset> presets, Oidc oidc) {

    /** What contextless login does when a name matches more than one account. */
    public enum Duplicates { CHOOSE, ERROR }

    /** A group (an eDirectory group DN, or for OIDC the provider's group name) and what it grants. */
    public record RoleMapping(String group, Role role, List<String> scopes, List<String> presets) {

        public RoleMapping(String group, Role role) {
            this(group, role, List.of(), List.of());
        }

        public Grant grant() {
            return new Grant(role, scopes, presets);
        }

        public static RoleMapping of(Map<String, Object> r) {
            String role = Json.asString(r.get("role"));
            List<String> presets = strings(r.get("presets"));
            if ((role == null || role.isBlank()) && presets.isEmpty()) {
                throw new IllegalArgumentException("a role mapping needs a role or presets");
            }
            return new RoleMapping(Json.asString(r.get("group")), role == null || role.isBlank() ? null : Role.parse(role),
                strings(r.get("scopes")), presets);
        }

        public Map<String, Object> json() {
            Map<String, Object> m = new java.util.LinkedHashMap<>();
            m.put("group", group);
            if (role != null) {
                m.put("role", role.id());
            }
            m.put("scopes", scopes);
            m.put("presets", presets);
            return m;
        }
    }

    /**
     * OpenID Connect sign-in for this directory (section 7.3): the provider, how its claim finds the
     * person's eDirectory object (as the service account), and provider group → grant mappings.
     */
    public record Oidc(String issuer, String clientId, String scopes, String groupsClaim, String label,
                       String claim, String attribute, List<String> searchBases, List<String> objectClasses,
                       List<RoleMapping> roles, List<String> neverProxy) {

        static Oidc of(Map<String, Object> o) {
            List<RoleMapping> roles = new ArrayList<>();
            if (o.get("roles") instanceof List<?> l) {
                l.forEach(r -> roles.add(RoleMapping.of(Json.asMap(r))));
            }
            return new Oidc(Json.asString(o.get("issuer")), Json.asString(o.get("clientId")), Json.asString(o.get("scopes")),
                Json.asString(o.get("groupsClaim")), str(o, "label", "single sign-on"), str(o, "claim", "preferred_username"),
                str(o, "attribute", "uid"), strings(o.get("searchBases")), strings(o.get("objectClasses"), "inetOrgPerson"),
                roles, strings(o.get("neverProxy")));
        }
    }

    /** The client secret's path in the configuration (for {@link ConfigStore#secret}). */
    public String oidcSecretPath() {
        return "directories/" + id + "/oidc/clientSecret";
    }

    public Ldap.Target target() {
        return new Ldap.Target(id, host, port);
    }

    /** Whether {@code dn} may sign in with a password: anyone while direct sign-in is on, else the listed accounts. */
    public boolean passwordAllowed(String dn) {
        return directLogin || breakGlass.stream().anyMatch(b -> DirectLogin.sameDn(b, dn))
            || directAllowed.stream().anyMatch(b -> DirectLogin.sameDn(b, dn));
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
                roles.add(RoleMapping.of(Json.asMap(o)));
            }
        }
        Map<String, TaskPreset> presets = new java.util.LinkedHashMap<>();
        if (d.get("presets") instanceof Map<?, ?> pm) {
            pm.forEach((k, v) -> presets.put(String.valueOf(k), TaskPreset.of(String.valueOf(k), Json.asMap(v))));
        }
        Oidc oidc = d.get("oidc") instanceof Map<?, ?> om && om.get("issuer") != null ? Oidc.of(Json.asMap(om)) : null;
        return new DirectoryConfig(id, str(d, "name", id), Json.asString(d.get("host")), Json.asInt(d.get("port"), 636),
            str(d, "tier", "production"), bool(login, "direct", true), strings(login.get("allowed")), strings(login.get("searchBases")),
            strings(login.get("objectClasses"), "inetOrgPerson"), strings(login.get("matchAttributes"), "cn"),
            bool(login, "excludeInactive", true), Json.asInt(login.get("maxCandidates"), 10),
            "error".equals(login.get("duplicates")) ? Duplicates.ERROR : Duplicates.CHOOSE,
            Json.asString(login.get("labelAttribute")), Json.asString(sa.get("dn")), roles, strings(d.get("breakGlass")),
            presets, oidc);
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
