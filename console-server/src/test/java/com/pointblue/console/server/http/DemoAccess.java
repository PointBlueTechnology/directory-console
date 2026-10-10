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
}
