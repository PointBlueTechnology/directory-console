package com.pointblue.console.server.http;

import com.pointblue.dirxml.dev.json.Json;
import java.util.List;
import java.util.Map;

/** Test access to configuration the UI cannot change yet (role mappings arrive with the admin pages). */
public final class DemoAccess {

    private DemoAccess() {
    }

    public static void mapViewers(Server server) throws Exception {
        server.config.update(server.config.version(), "demo", "role mapping", doc -> {
            Map<String, Object> dirs = Json.asMap(doc.get("directories"));
            dirs.keySet().forEach(id -> Json.asMap(dirs.get(id)).put("roles", List.of(Map.of("group", "cn=Viewers,ou=Groups,o=acme", "role", "viewer"))));
        });
    }

    public static void engines(Server server, com.pointblue.console.server.idm.Engines engines) {
        server.login.engines(engines);
    }

    /**
     * Phase 3 for the demo: a scoped editor group (Sales only), a help desk with task presets only,
     * two presets, and single sign-on through the demo identity provider at {@code issuer}.
     */
    public static void phase3(Server server, String issuer) throws Exception {
        server.config.update(server.config.version(), "demo", "phase 3", doc -> {
            Map<String, Object> d = Json.asMap(Json.asMap(doc.get("directories")).get("acme"));
            d.put("roles", List.of(
                Map.of("group", "cn=Viewers,ou=Groups,o=acme", "role", "viewer"),
                Map.of("group", "cn=Sales Editors,ou=Groups,o=acme", "role", "editor", "scopes", List.of("ou=Sales,ou=Users,o=acme")),
                Map.of("group", "cn=Help Desk,ou=Groups,o=acme", "presets", List.of("reset", "phone"), "scopes", List.of("ou=Users,o=acme"))));
            d.put("presets", Map.of(
                "reset", Map.of("name", "Reset password and unlock", "description", "For the help desk", "objectClass", "inetOrgPerson",
                    "actions", List.of("password", "unlock", "enable")),
                "phone", Map.of("name", "Edit phone and title", "objectClass", "inetOrgPerson", "actions", List.of("attributes"),
                    "attributes", List.of(
                        Map.of("name", "telephoneNumber", "label", "Phone", "pattern", "\\+?[0-9 ()-]{4,20}"),
                        Map.of("name", "title", "label", "Title", "required", true),
                        Map.of("name", "sn", "label", "Surname", "readOnly", true),
                        Map.of("name", "description", "value", "Updated by the help desk")))));
            d.put("oidc", Map.of("issuer", issuer, "clientId", "directory-console", "label", "Acme SSO", "claim", "preferred_username",
                "attribute", "uid", "searchBases", List.of("o=acme"),
                "roles", List.of(
                    Map.of("group", "sales-editors", "role", "editor", "scopes", List.of("ou=Sales,ou=Users,o=acme")),
                    Map.of("group", "help-desk", "presets", List.of("reset", "phone"), "scopes", List.of("ou=Users,o=acme")),
                    Map.of("group", "console-admins", "role", "admin"))));
        });
    }

    /** Where the console reaches a server (DN → "host:port"): the demo's second server is the same fake directory. */
    public static void serverAddresses(Server server, Map<String, String> addresses) throws Exception {
        server.config.update(server.config.version(), "demo", "server addresses", doc ->
            Json.asMap(Json.asMap(doc.get("directories")).get("acme")).put("serverAddresses", addresses));
    }
}
