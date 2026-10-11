package com.pointblue.console.server.http;

import com.pointblue.dirxml.dev.json.Json;
import java.util.List;
import java.util.Map;

/** Test access: single sign-on for a live check, through a fake provider, mapping uid under {@code bases}. */
public final class Phase3Access {

    private Phase3Access() {
    }

    public static void singleSignOn(Server server, String issuer, List<String> bases) throws Exception {
        server.config.update(server.config.version(), "live check", "single sign-on", doc -> {
            Map<String, Object> d = Json.asMap(Json.asMap(doc.get("directories")).values().iterator().next());
            d.put("oidc", Map.of("issuer", issuer, "clientId", "directory-console", "claim", "preferred_username", "attribute", "uid",
                "searchBases", bases, "roles", List.of(Map.of("group", "testers", "role", "editor"))));
        });
    }
}
