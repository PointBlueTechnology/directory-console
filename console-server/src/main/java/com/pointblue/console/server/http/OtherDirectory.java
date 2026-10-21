package com.pointblue.console.server.http;

import com.pointblue.console.server.audit.AuditLog;
import com.pointblue.console.server.auth.DirectoryConfig;
import com.pointblue.console.server.auth.Role;
import com.pointblue.console.server.auth.Sessions;
import com.pointblue.console.server.data.ConfigStore;
import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.console.server.tls.Certs;
import com.pointblue.console.server.tls.Probe;
import com.pointblue.console.server.tls.TrustStore;
import com.pointblue.dirxml.dev.json.Json;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.naming.NamingException;

/**
 * Directories a person enters at sign-in: when an administrator allows it, someone signs
 * in to any LDAPS address with their full DN and password, and works there with their own eDirectory
 * rights only (an editor grant over the whole tree; eDirectory decides). No role mappings, presets,
 * Identity Manager or console settings; changes ask for the address to be typed, as production does.
 *
 * <p>A certificate the console does not trust is shown to the person, who confirms its fingerprint.
 * The acceptance lasts for that sign-in, and is kept as theirs ({@code user:<subject>}) only once the
 * bind succeeds. A name mismatch is accepted the same way, as a host exception of their own. A
 * configured directory's address is refused: it has its own sign-in, and only administrators trust
 * its certificates.
 *
 *   GET  /api/v2/sign-in/options        {otherDirectories}
 *   POST /api/v2/session/other          {host, port, name, password, accept?: {probeId, confirm, index?}}
 *   GET  /api/v2/console/settings       {otherDirectories}   (admins)
 *   PUT  /api/v2/console/settings       {otherDirectories}   (admins, recent sign-in)
 */
final class OtherDirectory {

    static final String VIA = "user-directory";

    private final Server server;

    /** The directories entered this run, by id; a session's {@link Server#directoryOf} finds them here. */
    final Map<String, DirectoryConfig> entered = new ConcurrentHashMap<>();

    OtherDirectory(Server server) {
        this.server = server;
    }

    boolean handles(String method, String path) {
        return path.equals("/api/v2/sign-in/options") || path.equals("/api/v2/session/other") || path.equals("/api/v2/console/settings");
    }

    void handle(HttpExchange ex, String method, String path) throws IOException {
        switch (method + " " + path) {
            case "GET /api/v2/sign-in/options" -> Http.json(ex, 200, Map.of("otherDirectories", enabled()));
            case "POST /api/v2/session/other" -> signIn(ex);
            case "GET /api/v2/console/settings" -> {
                server.session(ex, Role.ADMIN);
                Http.json(ex, 200, settings());
            }
            case "PUT /api/v2/console/settings" -> {
                Sessions.Session s = server.session(ex, Role.ADMIN);
                server.stepUp(s);
                Map<String, Object> b = Http.body(ex);
                // either setting, or both; what is left out stays as it is
                Boolean on = b.containsKey("otherDirectories") ? Boolean.TRUE.equals(b.get("otherDirectories")) : null;
                List<String> proxies = null;
                if (b.get("trustedProxies") instanceof List<?> l) {
                    proxies = new ArrayList<>();
                    for (Object o : l) {
                        try {
                            String n = Proxies.normalize(String.valueOf(o));
                            if (!proxies.contains(n)) {
                                proxies.add(n);
                            }
                        } catch (IllegalArgumentException x) {
                            throw new Http.Problem(400, "bad-request", x.getMessage());
                        }
                    }
                } else if (b.containsKey("trustedProxies")) {
                    throw new Http.Problem(400, "bad-request", "trustedProxies is a list of addresses or CIDR ranges");
                }
                List<String> newProxies = proxies;
                String what = on != null && proxies != null ? "console settings" : on != null ? "other directories " + (on ? "allowed" : "refused") : "trusted proxies";
                try {
                    server.config.update(server.config.version(), s.principal.dn(), what, doc -> {
                        if (on != null) {
                            doc.put("userDirectories", new LinkedHashMap<>(Map.of("enabled", on)));
                        }
                        if (newProxies != null) {
                            doc.put("trustedProxies", List.copyOf(newProxies));
                        }
                    });
                } catch (ConfigStore.Conflict c) {
                    throw new Http.Problem(409, "conflict", "the configuration changed meanwhile; try again");
                }
                if (on != null) {
                    server.audit.log(Server.who(s), "settings.other-directories", "console", Map.of("enabled", on), "ok");
                }
                if (newProxies != null) {
                    server.audit.log(Server.who(s), "settings.trusted-proxies", "console", Map.of("proxies", newProxies), "ok");
                }
                Http.json(ex, 200, settings());
            }
            default -> throw new Http.Problem(405, "method-not-allowed", method + " " + path);
        }
    }

    private Map<String, Object> settings() {
        return Map.of("otherDirectories", enabled(), "trustedProxies", trustedProxies());
    }

    /** Reverse proxies whose X-Forwarded-For is believed (addresses or CIDR ranges, normalized when saved). */
    List<String> trustedProxies() {
        Object t = server.config.read().get("trustedProxies");
        List<String> out = new ArrayList<>();
        if (t instanceof List<?> l) {
            l.forEach(o -> out.add(String.valueOf(o)));
        }
        return out;
    }

    boolean enabled() {
        Object u = server.config.read().get("userDirectories");
        return u instanceof Map<?, ?> m && Boolean.TRUE.equals(m.get("enabled"));
    }

    /** The personal trust subject: who, at which address (no whitespace, as trust scopes require). */
    static String subject(String dn, String host, int port) {
        return URLEncoder.encode(dn.trim().toLowerCase(Locale.ROOT), StandardCharsets.UTF_8) + "@" + host.toLowerCase(Locale.ROOT) + ":" + port;
    }

    /** A URL-safe id for an address, the same for everyone who enters it. */
    static String idOf(String host, int port) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest((host.toLowerCase(Locale.ROOT) + ":" + port).getBytes(StandardCharsets.UTF_8));
            return "u-" + HexFormat.of().formatHex(h, 0, 6);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private void signIn(HttpExchange ex) throws IOException {
        if (!enabled()) {
            throw new Http.Problem(403, "not-allowed", "signing in to other directories is not allowed here");
        }
        Map<String, Object> b = Http.body(ex);
        String client = server.client(ex);
        String host = Http.string(b, "host", true).trim();
        int port = Http.integer(b, "port", 636);
        String dn = Http.string(b, "name", true).trim();
        if (!host.matches("[A-Za-z0-9.:\\-\\[\\]]{1,253}") || port < 1 || port > 65535) {
            throw new Http.Problem(400, "bad-address", "the address is a host name or IP address, and a port from 1 to 65535");
        }
        if (!dn.contains("=")) {
            throw new Http.Problem(400, "full-name-required", "use your full name (DN), such as cn=jsmith,ou=users,o=acme");
        }
        String nameKey = host.toLowerCase(Locale.ROOT) + ":" + port + "|" + dn.toLowerCase(Locale.ROOT);
        if (!server.failedByClient.allowed(client) || !server.failedByName.allowed(nameKey)) {
            throw new Http.Problem(429, "too-many-attempts", "too many failed sign-ins; wait a few minutes");
        }
        for (DirectoryConfig d : DirectoryConfig.all(server.config.read())) {
            if (d.host().equalsIgnoreCase(host) && d.port() == port) {
                throw new Http.Problem(409, "configured-directory", "this is " + d.name() + "; sign in to it from the list",
                    Map.of("directory", d.id()));
            }
        }
        String subject = subject(dn, host, port);
        String scope = "user:" + subject;
        String id = idOf(host, port);
        AuditLog.Actor who = new AuditLog.Actor(dn, dn, VIA);

        // a certificate the person accepted on the previous attempt: trusted for this bind, kept if it succeeds
        Accepted accepted = accept(b, client, host, port, scope, dn);
        char[] pw = Http.string(b, "password", true).toCharArray();
        Ldap l;
        try {
            l = Ldap.connect(server.trust, new Ldap.Target(id, host, port), subject, dn, pw, Server.T);
        } catch (Ldap.Untrusted u) {
            accepted.undo();
            Probe.Result r;
            try {
                r = server.probes.probe(host, port, "pre:" + client, Server.T);
            } catch (IOException io) {
                throw new Http.Problem(502, "unreachable", host + ":" + port + ": " + io.getMessage());
            }
            server.audit.log(who, "sign-in.other", host + ":" + port, Map.of("client", client, "reason", u.cause.reason.name().toLowerCase(Locale.ROOT)), "untrusted");
            Map<String, Object> probe = server.probeJson(r, id, subject);
            throw new Http.Problem(409, "untrusted-certificate", u.getMessage(),
                Map.of("reason", u.cause.reason.name().toLowerCase(Locale.ROOT).replace('_', '-'), "probe", probe));
        } catch (Ldap.BadCredentials e) {
            accepted.undo();
            server.failedByClient.record(client);
            server.failedByName.record(nameKey);
            server.audit.log(who, "sign-in.other", host + ":" + port, Map.of("client", client), "refused");
            throw new Http.Problem(401, "bad-credentials", "the name or password is incorrect");
        } catch (NamingException e) {
            accepted.undo();
            throw new Http.Problem(502, "unreachable", host + ":" + port + ": " + e.getMessage());
        } finally {
            java.util.Arrays.fill(pw, '\0');
        }
        server.failedByClient.clear(client);
        server.failedByName.clear(nameKey);
        String name = dn.split(",")[0].replaceFirst("^[^=]*=", "");
        DirectoryConfig d = new DirectoryConfig(id, host + ":" + port, host, port, "production", true, List.of(), List.of(), List.of(), List.of(), false, 0,
            DirectoryConfig.Duplicates.ERROR, null, null, List.of(), List.of(), Map.of(), null);
        entered.put(id, d);
        Sessions.Principal p = new Sessions.Principal(subject, l.boundDn() == null ? dn : l.boundDn(), name, id, Set.of(Role.EDITOR), VIA);
        Sessions.Session session = server.sessions.create(p, l, null, "Identity Manager is not available for a directory you entered yourself");
        server.audit.log(new AuditLog.Actor(subject, p.dn(), VIA), "sign-in", host + ":" + port,
            Map.of("client", client, "accepted", accepted.what()), "ok");
        ex.getResponseHeaders().add("Set-Cookie", Server.COOKIE + "=" + session.id + "; Path=/; Secure; HttpOnly; SameSite=Strict");
        Http.json(ex, 200, server.me(session));
    }

    /** What a sign-in added to the person's trust before binding: removed again if the bind fails. */
    private static final class Accepted {
        private final List<IoAction> undo = new java.util.ArrayList<>();
        private final List<String> what = new java.util.ArrayList<>();

        interface IoAction {
            void run() throws IOException;
        }

        void undo() throws IOException {
            for (IoAction a : undo) {
                a.run();
            }
        }

        String what() {
            return String.join("; ", what);
        }
    }

    private Accepted accept(Map<String, Object> b, String client, String host, int port, String scope, String dn) throws IOException {
        Accepted acc = new Accepted();
        if (!(b.get("accept") instanceof Map<?, ?> raw)) {
            return acc;
        }
        Map<String, Object> a = Json.asMap(raw);
        Probe.Result r = server.probes.get(Http.string(a, "probeId", true), "pre:" + client);
        if (r == null || !r.host().equalsIgnoreCase(host) || r.port() != port) {
            throw new Http.Problem(409, "probe-expired", "that certificate is no longer on offer; sign in again to see it");
        }
        X509Certificate[] chain = r.chain().toArray(new X509Certificate[0]);
        TrustStore.Evaluation ev = server.trust.evaluate(chain, host, port, idOf(host, port), scope.substring("user:".length()));
        String confirm = Http.string(a, "confirm", true);
        if (ev.reason() == TrustStore.Reason.HOSTNAME) {
            // the chain is trusted already; only the name differs: a host exception of the person's own
            if (!TrustStore.confirmed(chain[0], confirm)) {
                throw new Http.Problem(400, "confirmation-mismatch", "type the last 8 hex digits of the certificate's SHA-256 fingerprint");
            }
            exceptHost(acc, host, port, chain[0], dn, scope);
            return acc;
        }
        int index = Http.integer(a, "index", ev.reason() == TrustStore.Reason.PIN_CHANGED ? 0 : Probe.recommended(r.chain()));
        if (index < 0 || index >= chain.length) {
            throw new Http.Problem(400, "bad-field", "index is 0-" + (chain.length - 1));
        }
        X509Certificate cert = chain[index];
        if (!TrustStore.confirmed(cert, confirm)) {
            throw new Http.Problem(400, "confirmation-mismatch", "type the last 8 hex digits of the certificate's SHA-256 fingerprint");
        }
        String key = TrustStore.keyOf(Certs.id(cert), scope);
        boolean had = server.trust.entries().stream().anyMatch(e -> e.key().equals(key));
        boolean authority = Certs.selfSigned(cert) || cert.getBasicConstraints() >= 0;
        server.trust.add(cert, authority ? TrustStore.Kind.CA : TrustStore.Kind.PINNED_SERVER, scope, dn, "sign-in", host + ":" + port);
        acc.what.add((authority ? "ca " : "pinned ") + Certs.sha256(cert));
        if (!had) {
            acc.undo.add(() -> server.trust.remove(key));
        }
        // the server's certificate may also name other hosts than the one entered (NAT, a tunnel): the
        // person saw that with the chain, so the same confirmation accepts it at this address too
        if (!Certs.matches(chain[0], host)) {
            exceptHost(acc, host, port, chain[0], dn, scope);
        }
        return acc;
    }

    private void exceptHost(Accepted acc, String host, int port, X509Certificate leaf, String dn, String scope) throws IOException {
        boolean had = server.trust.hostExceptions().stream()
            .anyMatch(h -> h.host().equalsIgnoreCase(host) && h.port() == port && h.scope().equals(scope) && h.leafId().equals(Certs.id(leaf)));
        server.trust.addHostException(host, port, leaf, dn, scope);
        acc.what.add("host-exception " + Certs.sha256(leaf));
        if (!had) {
            acc.undo.add(() -> server.trust.removeHostException(host, port, scope));
        }
    }
}
