package com.pointblue.console.server.http;

import com.pointblue.console.server.auth.AgentKeys;
import com.pointblue.console.server.auth.DirectoryConfig;
import com.pointblue.dirxml.dev.apps.IdApps;
import com.pointblue.dirxml.dev.json.Json;
import java.io.IOException;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Identity Applications for agent keys (docs/MCP.md, "Identity Applications"). A directory with an Identity
 * Applications address ({@code directories.<id>.apps = {"url", "clientId"}}, the client's secret sealed at
 * {@code directories/<id>/apps/clientSecret}) offers its keys the Identity Applications tools. When a person makes a key
 * with their password, the console makes one OSP password grant with it and keeps only the refresh token, sealed with
 * the console's key, beside the key; access tokens are kept in memory and renewed with the refresh token (DirXMLDev's
 * {@link IdApps}). When the refresh token stops working the key's Identity Applications tools answer
 * {@code authorize-again} until the person types their password again in the console.
 */
final class AgentApps {

    /** A directory's Identity Applications settings; null {@code url} when it has none. */
    record Settings(String url, String clientId, boolean secretSet) {
        boolean on() {
            return url != null && !url.isBlank();
        }

        Map<String, Object> json() {
            return on() ? Map.of("url", url, "clientId", clientId, "clientSecretSet", secretSet) : Map.of();
        }
    }

    private record Client(Settings settings, String secret, IdApps apps) {
    }

    private final Server server;
    private final Map<String, Client> clients = new ConcurrentHashMap<>();
    /** By key id. */
    private final Map<String, IdApps.Session> sessions = new ConcurrentHashMap<>();

    AgentApps(Server server) {
        this.server = server;
    }

    static String secretPath(String directoryId) {
        return "directories/" + directoryId + "/apps/clientSecret";
    }

    static String tokenPath(String keyId) {
        return "agent-keys/" + keyId + "/apps";
    }

    Settings settings(String directoryId) {
        Object dirs = server.config.read().get("directories");
        Object d = dirs instanceof Map<?, ?> m ? m.get(directoryId) : null;
        Object a = d instanceof Map<?, ?> dm ? dm.get("apps") : null;
        if (!(a instanceof Map<?, ?> am) || am.get("url") == null) {
            return new Settings(null, null, false);
        }
        String client = Json.asString(am.get("clientId"));
        return new Settings(Json.asString(am.get("url")), client == null || client.isBlank() ? IdApps.DEFAULT_CLIENT : client,
            server.config.secret(secretPath(directoryId)) != null);
    }

    /** The client for {@code d}'s Identity Applications, trusting Java's public roots and the console's trusted certificates. */
    private IdApps client(DirectoryConfig d) {
        Settings s = settings(d.id());
        if (!s.on()) {
            throw new Http.Problem(409, "no-identity-applications", d.name() + " has no Identity Applications address");
        }
        String secret = server.config.secret(secretPath(d.id()));
        Client c = clients.get(d.id());
        if (c == null || !c.settings().equals(s) || !Objects.equals(c.secret(), secret)) {
            javax.net.ssl.SSLContext tls;
            try {
                tls = server.trust.withPublicRoots(d.id());
            } catch (java.security.GeneralSecurityException e) {
                throw new Http.Problem(503, "unavailable", "TLS for Identity Applications could not be set up: " + e.getMessage());
            }
            c = new Client(s, secret, new IdApps(s.url(), s.clientId(), secret == null ? "" : secret, tls));
            clients.put(d.id(), c);
            sessions.clear();
        }
        return c.apps();
    }

    /**
     * Authorize key {@code k} for Identity Applications with the person's password: one password grant, the refresh
     * token sealed and kept. The key as it is now; a refusal says why (a wrong password, the provider refusing).
     */
    AgentKeys.Key authorize(AgentKeys.Key k, DirectoryConfig d, char[] password) throws IOException {
        IdApps apps = client(d);
        IdApps.Tokens t;
        try {
            t = apps.password(k.dn(), password);
        } catch (IdApps.Refused r) {
            throw new Http.Problem(r.status == 400 || r.status == 401 ? 401 : 502, "identity-applications-refused",
                "Identity Applications refused the sign-in: " + r.getMessage());
        } catch (IOException e) {
            throw new Http.Problem(503, "unavailable", "Identity Applications did not answer: " + e.getMessage());
        }
        if (t.refresh() == null) {
            throw new Http.Problem(502, "no-refresh-token", "Identity Applications gave no refresh token: the client " + settings(d.id()).clientId()
                + " needs a secret (a confidential client) for keys to keep working");
        }
        sessions.put(k.id(), apps.session(t));
        return server.agents.keys.apps(k.id(), server.config.seal(t.refresh(), tokenPath(k.id())), "authorized");
    }

    /** The key's Identity Applications session; {@code authorize-again} (409) when it has no working token. */
    IdApps.Session session(AgentKeys.Key k, DirectoryConfig d) throws IOException {
        IdApps.Session s = sessions.get(k.id());
        IdApps apps = client(d);
        if (s != null && sessions.get(k.id()) == s) {
            return s;
        }
        String refresh = server.config.unseal(k.apps(), tokenPath(k.id()));
        if (refresh == null) {
            throw authorizeAgain(k);
        }
        s = apps.session(refresh);
        sessions.put(k.id(), s);
        return s;
    }

    /** A call with the key's session; a refused refresh token marks the key {@code authorize-again}. */
    Map<String, Object> call(AgentKeys.Key k, DirectoryConfig d, Op op) throws IOException {
        IdApps.Session s = session(k, d);
        try {
            return op.run(s);
        } catch (IdApps.Refused r) {
            sessions.remove(k.id());
            if (r.status != 400 && r.status != 401) {
                throw new Http.Problem(503, "unavailable", "Identity Applications' sign-in service did not answer: " + r.getMessage());
            }
            // the refresh token expired or was revoked (or the client's secret changed)
            server.agents.keys.apps(k.id(), null, "authorize-again");
            throw authorizeAgain(k);
        } catch (IdApps.Fault f) {
            throw new Http.Problem(f.status == 401 ? 401 : f.status >= 500 ? 502 : 409, f.code == null ? "identity-applications" : f.code, f.getMessage());
        } catch (IOException e) {
            throw new Http.Problem(503, "unavailable", "Identity Applications did not answer: " + e.getMessage());
        }
    }

    interface Op {
        Map<String, Object> run(IdApps.Session s) throws IOException;
    }

    private Http.Problem authorizeAgain(AgentKeys.Key k) {
        return new Http.Problem(409, "authorize-again", "this key's Identity Applications sign-in stopped working; " + k.name()
            + " authorizes it again in the console (Agent keys > " + k.label() + " > Authorize), with their password");
    }

    /** A key revoked or removed: forget its session. */
    void forget(String keyId) {
        sessions.remove(keyId);
    }
}
