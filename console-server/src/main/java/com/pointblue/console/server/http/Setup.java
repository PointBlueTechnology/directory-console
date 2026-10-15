package com.pointblue.console.server.http;

import com.pointblue.console.server.audit.AuditLog;
import com.pointblue.console.server.data.ConfigStore;
import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.console.server.tls.Certs;
import com.pointblue.console.server.tls.Probe;
import com.pointblue.console.server.tls.TrustStore;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;

/**
 * The setup wizard's API (DESIGN-directory-console.md section 5.2), served only in bootstrap mode and
 * only to requests carrying the setup token ({@code X-Setup-Token}). The steps build a draft in memory;
 * {@code finish} writes the first configuration, ends bootstrap mode and switches the server to normal
 * operation. Trust entries added during setup are written as they are accepted.
 *
 * <pre>
 *   GET  /api/v2/setup                    the draft and which steps are done
 *   PUT  /api/v2/setup/directory          {id, name, host, port, tier}
 *   POST /api/v2/setup/probe              the directory's certificate chain
 *   POST /api/v2/setup/trust              {probeId, index, confirm} or {pem}
 *   POST /api/v2/setup/authority          {dn, password}: an eDirectory admin with supervisor rights
 *   PUT  /api/v2/setup/service-account    {dn, password} (optional)
 *   PUT  /api/v2/setup/login              {duplicates: choose|error, searchBases: [...]}
 *   POST /api/v2/setup/finish
 *   POST /api/v2/setup/first-sign-in      {host, port?, dn, password, accept?: {probeId, confirm, index?}}
 * </pre>
 *
 * {@code first-sign-in} is the whole of setup in one step, as the web UI's first sign-in does it: the
 * tree's certificate (offered to the person as a 409 with the probe when the console does not trust it,
 * and trusted once they confirm its fingerprint and the bind succeeds), a tree administrator's
 * credentials, then the configuration (production tier, no service account, the administrator as
 * break-glass) and the end of bootstrap. The browser then signs in as usual. The service account,
 * sign-in options and tier are set afterwards in Settings.
 */
final class Setup {

    static final String SESSION = "setup";
    private static final Duration T = Duration.ofSeconds(10);

    private final Server server;
    private String id;
    private String name;
    private String host;
    private int port;
    private String tier;
    private boolean trusted;
    private String adminDn;
    private String saDn;
    private String saPassword;
    private String duplicates = "choose";
    private List<String> searchBases = List.of();

    Setup(Server server) {
        this.server = server;
    }

    synchronized void handle(HttpExchange ex, String path, String method) throws IOException {
        switch (method + " " + path) {
            case "GET /api/v2/setup" -> Http.json(ex, 200, state());
            case "PUT /api/v2/setup/directory" -> directory(Http.body(ex), ex);
            case "POST /api/v2/setup/probe" -> probe(ex);
            case "POST /api/v2/setup/trust" -> trust(Http.body(ex), ex);
            case "POST /api/v2/setup/authority" -> authority(Http.body(ex), ex);
            case "PUT /api/v2/setup/service-account" -> serviceAccount(Http.body(ex), ex);
            case "PUT /api/v2/setup/login" -> login(Http.body(ex), ex);
            case "POST /api/v2/setup/finish" -> finish(ex);
            case "POST /api/v2/setup/first-sign-in" -> firstSignIn(Http.body(ex), ex);
            default -> throw new Http.Problem(404, "not-found", "no setup step " + method + " " + path);
        }
    }

    private Map<String, Object> state() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("consoleCertificate", Map.of("sha256", Certs.sha256(server.tls.certificate()), "names", Certs.names(server.tls.certificate())));
        Map<String, Object> d = new LinkedHashMap<>();
        if (id != null) {
            d.put("id", id);
            d.put("name", name);
            d.put("host", host);
            d.put("port", port);
            d.put("tier", tier);
        }
        m.put("directory", d);
        m.put("trusted", trusted);
        m.put("admin", adminDn);
        m.put("serviceAccount", saDn == null ? null : Map.of("dn", saDn));
        m.put("login", Map.of("duplicates", duplicates, "searchBases", searchBases));
        m.put("ready", id != null && trusted && adminDn != null);
        return m;
    }

    private void directory(Map<String, Object> b, HttpExchange ex) throws IOException {
        String newId = Http.string(b, "id", true);
        if (!newId.matches("[A-Za-z0-9_.-]{1,64}")) {
            throw new Http.Problem(400, "bad-field", "id is 1-64 letters, digits, '.', '_' or '-'");
        }
        String newHost = Http.string(b, "host", true).trim();
        int newPort = Http.integer(b, "port", 636);
        if (newPort < 1 || newPort > 65535) {
            throw new Http.Problem(400, "bad-field", "port is 1-65535");
        }
        String newTier = Http.string(b, "tier", false);
        if (newTier != null && !newTier.equals("production") && !newTier.equals("lab")) {
            throw new Http.Problem(400, "bad-field", "tier is production or lab");
        }
        boolean moved = !newHost.equalsIgnoreCase(String.valueOf(host)) || newPort != port || !newId.equals(id);
        id = newId;
        name = b.get("name") == null ? newId : Http.string(b, "name", false);
        host = newHost;
        port = newPort;
        tier = newTier == null ? "production" : newTier;
        if (moved) {
            trusted = false;
            adminDn = null;
            saDn = null;
            saPassword = null;
        }
        Http.json(ex, 200, state());
    }

    private void needDirectory() {
        if (id == null) {
            throw new Http.Problem(409, "step-order", "set the directory first (PUT /api/v2/setup/directory)");
        }
    }

    private void probe(HttpExchange ex) throws IOException {
        needDirectory();
        Probe.Result r;
        try {
            r = server.probes.probe(host, port, SESSION, T);
        } catch (IOException e) {
            throw new Http.Problem(502, "probe-failed", host + ":" + port + ": " + e.getMessage());
        }
        Http.json(ex, 200, server.probeJson(r, id, null));
    }

    private void trust(Map<String, Object> b, HttpExchange ex) throws IOException {
        needDirectory();
        X509Certificate cert;
        String how;
        if (b.get("pem") != null) {
            try {
                List<X509Certificate> certs = Certs.parse(Http.string(b, "pem", true).getBytes(StandardCharsets.US_ASCII));
                cert = certs.get(certs.size() - 1);
            } catch (GeneralSecurityException e) {
                throw new Http.Problem(400, "bad-certificate", "the uploaded certificate could not be read: " + e.getMessage());
            }
            how = "upload";
        } else {
            Probe.Result r = server.probes.get(Http.string(b, "probeId", true), SESSION);
            if (r == null) {
                throw new Http.Problem(409, "probe-expired", "that probe is unknown or expired; probe again");
            }
            int index = Http.integer(b, "index", Probe.recommended(r.chain()));
            if (index < 0 || index >= r.chain().size()) {
                throw new Http.Problem(400, "bad-field", "index is 0-" + (r.chain().size() - 1));
            }
            cert = r.chain().get(index);
            if (!TrustStore.confirmed(cert, Http.string(b, "confirm", false))) {
                throw new Http.Problem(400, "confirmation-mismatch", "type the last 8 hex digits of the certificate's SHA-256 fingerprint to trust it");
            }
            how = "bootstrap-probe";
        }
        TrustStore.Kind kind = Certs.selfSigned(cert) || cert.getBasicConstraints() >= 0 ? TrustStore.Kind.CA : TrustStore.Kind.PINNED_SERVER;
        TrustStore.Entry e = server.trust.add(cert, kind, "directory:" + id, "bootstrap", how);
        server.audit.log(AuditLog.Actor.SYSTEM, "trust.add", e.id(), Map.of("scope", e.scope(), "kind", kind.name(), "how", how, "sha256", Certs.sha256(cert)), "ok");
        // check it now lets a connection through, so the next step does not fail on trust
        try {
            List<X509Certificate> chain = Probe.read(host, port, T);
            TrustStore.Evaluation ev = server.trust.evaluate(chain.toArray(new X509Certificate[0]), host, port, id, null);
            if (!ev.trusted() && ev.reason() == TrustStore.Reason.HOSTNAME && Boolean.TRUE.equals(b.get("hostException"))) {
                // reached by a name the certificate does not carry (a tunnel, a load balancer, NAT): accept exactly
                // this certificate at exactly this host and port, as the host exceptions of DESIGN 6.4 do after setup
                server.trust.addHostException(host, port, chain.get(0), "bootstrap");
                server.audit.log(AuditLog.Actor.SYSTEM, "trust.host-exception", host + ":" + port, Map.of("sha256", Certs.sha256(chain.get(0)),
                    "names", Certs.names(chain.get(0))), "ok");
                ev = server.trust.evaluate(chain.toArray(new X509Certificate[0]), host, port, id, null);
            }
            trusted = ev.trusted();
            Map<String, Object> out = new LinkedHashMap<>(e.json());
            out.put("connection", Map.of("trusted", ev.trusted(), "reason", ev.reason() == null ? "" : ev.reason().name().toLowerCase(), "message", ev.message()));
            Http.json(ex, 200, out);
        } catch (IOException io) {
            throw new Http.Problem(502, "probe-failed", "trusted, but the directory could not be reached to check: " + io.getMessage());
        }
    }

    private void authority(Map<String, Object> b, HttpExchange ex) throws IOException {
        needDirectory();
        String dn = Http.string(b, "dn", true).trim();
        char[] pw = Http.string(b, "password", true).toCharArray();
        try (Ldap l = Ldap.connect(server.trust, new Ldap.Target(id, host, port), null, dn, pw, T)) {
            if (!supervisorOfTree(l, dn)) {
                server.audit.log(new AuditLog.Actor(dn, dn, "setup"), "setup.authority", id, Map.of(), "refused: not supervisor");
                throw new Http.Problem(403, "not-tree-admin", dn + " signed in but does not have supervisor rights to the tree; use a tree administrator");
            }
            adminDn = dn;
            server.audit.log(new AuditLog.Actor(dn, dn, "setup"), "setup.authority", id, Map.of(), "ok");
            Http.json(ex, 200, state());
        } catch (Ldap.Untrusted u) {
            throw new Http.Problem(409, "untrusted-certificate", u.getMessage(), Map.of("reason", u.cause.reason.name().toLowerCase()));
        } catch (Ldap.BadCredentials e) {
            server.audit.log(new AuditLog.Actor(dn, dn, "setup"), "setup.authority", id, Map.of(), "refused: bad credentials");
            throw new Http.Problem(401, "bad-credentials", e.getMessage());
        } catch (NamingException e) {
            throw new Http.Problem(502, "directory-error", e.getMessage());
        } finally {
            java.util.Arrays.fill(pw, '\0');
        }
    }

    /** Supervisor entry rights (0x10) on the tree root, or else on every top-level container. */
    static boolean supervisorOfTree(Ldap l, String dn) throws NamingException {
        try {
            if ((l.effectivePrivileges("", dn, "[Entry Rights]") & 0x10) != 0) {
                return true;
            }
        } catch (NamingException e) {
            // the root is not addressable here: check the top-level containers instead
        }
        List<Ldap.Entry> tops = l.search("", "(objectClass=*)", null, SearchControls.ONELEVEL_SCOPE, new String[] {"1.1"}, 1000);
        if (tops.isEmpty()) {
            return false;
        }
        for (Ldap.Entry t : tops) {
            if ((l.effectivePrivileges(t.dn(), dn, "[Entry Rights]") & 0x10) == 0) {
                return false;
            }
        }
        return true;
    }

    private void serviceAccount(Map<String, Object> b, HttpExchange ex) throws IOException {
        needDirectory();
        String dn = Http.string(b, "dn", true).trim();
        String pw = Http.string(b, "password", true);
        try (Ldap l = Ldap.connect(server.trust, new Ldap.Target(id, host, port), null, dn, pw.toCharArray(), T)) {
            saDn = l.boundDn();
            saPassword = pw;
            server.audit.log(AuditLog.Actor.SYSTEM, "setup.service-account", id, Map.of("dn", dn), "ok");
            Http.json(ex, 200, state());
        } catch (Ldap.Untrusted u) {
            throw new Http.Problem(409, "untrusted-certificate", u.getMessage());
        } catch (Ldap.BadCredentials e) {
            throw new Http.Problem(401, "bad-credentials", e.getMessage());
        } catch (NamingException e) {
            throw new Http.Problem(502, "directory-error", e.getMessage());
        }
    }

    private void login(Map<String, Object> b, HttpExchange ex) throws IOException {
        String dup = Http.string(b, "duplicates", false);
        if (dup != null && !dup.equals("choose") && !dup.equals("error")) {
            throw new Http.Problem(400, "bad-field", "duplicates is choose or error");
        }
        if (dup != null) {
            duplicates = dup;
        }
        if (b.get("searchBases") instanceof List<?> l) {
            List<String> bases = new ArrayList<>();
            l.forEach(o -> bases.add(String.valueOf(o)));
            searchBases = List.copyOf(bases);
        }
        Http.json(ex, 200, state());
    }

    private void finish(HttpExchange ex) throws IOException {
        if (id == null || !trusted || adminDn == null) {
            throw new Http.Problem(409, "not-ready", "set the directory, trust its certificate and prove authority first");
        }
        try {
            server.config.update(0, adminDn, "bootstrap", doc -> {
                Map<String, Object> dir = new LinkedHashMap<>();
                dir.put("name", name);
                dir.put("host", host);
                dir.put("port", port);
                dir.put("tier", tier);
                Map<String, Object> login = new LinkedHashMap<>();
                login.put("direct", true);
                login.put("duplicates", duplicates);
                login.put("searchBases", searchBases);
                dir.put("login", login);
                if (saDn != null) {
                    dir.put("serviceAccount", Map.of("dn", saDn, "password", server.config.seal(saPassword, "directories/" + id + "/serviceAccount/password")));
                }
                dir.put("roles", List.of());
                dir.put("breakGlass", List.of(adminDn));
                doc.put("directories", Map.of(id, dir));
                doc.put("console", Map.of("publicUrl", server.publicUrl));
            });
        } catch (ConfigStore.Conflict c) {
            throw new Http.Problem(409, "already-configured", c.getMessage());
        }
        saPassword = null;
        server.audit.log(new AuditLog.Actor(adminDn, adminDn, "setup"), "setup.finish", id,
            Map.of("directory", host + ":" + port, "breakGlass", adminDn, "serviceAccount", saDn == null ? "none" : saDn, "duplicates", duplicates), "ok");
        server.leaveBootstrap();
        Http.json(ex, 200, Map.of("configured", true, "directory", id, "next", "sign in as " + adminDn));
    }

    /** The setup id used for trust while the tree's own name is not yet known. */
    private static final String PROVISIONAL = "setup";

    private void firstSignIn(Map<String, Object> b, HttpExchange ex) throws IOException {
        String newHost = Http.string(b, "host", true).trim();
        int newPort = Http.integer(b, "port", 636);
        if (!newHost.matches("[A-Za-z0-9.:\\-\\[\\]]{1,253}") || newPort < 1 || newPort > 65535) {
            throw new Http.Problem(400, "bad-address", "the address is a host name or IP address, and a port from 1 to 65535");
        }
        String dn = Http.string(b, "dn", true).trim();
        if (!dn.contains("=")) {
            throw new Http.Problem(400, "full-name-required", "use the administrator's full name (DN), such as cn=admin,o=system");
        }
        String scope = "directory:" + PROVISIONAL;
        List<Runnable> undo = new ArrayList<>();
        X509Certificate acceptedCa = null;
        TrustStore.Kind acceptedKind = null;
        if (b.get("accept") instanceof Map<?, ?> raw) {
            Map<String, Object> a = com.pointblue.dirxml.dev.json.Json.asMap(raw);
            Probe.Result r = server.probes.get(Http.string(a, "probeId", true), SESSION);
            if (r == null || !r.host().equalsIgnoreCase(newHost) || r.port() != newPort) {
                throw new Http.Problem(409, "probe-expired", "that certificate is no longer on offer; sign in again to see it");
            }
            X509Certificate[] chain = r.chain().toArray(new X509Certificate[0]);
            TrustStore.Evaluation ev = server.trust.evaluate(chain, newHost, newPort, PROVISIONAL, null);
            String confirm = Http.string(a, "confirm", true);
            X509Certificate leaf = chain[0];
            if (ev.reason() != TrustStore.Reason.HOSTNAME) {
                int index = Http.integer(a, "index", Probe.recommended(r.chain()));
                if (index < 0 || index >= chain.length) {
                    throw new Http.Problem(400, "bad-field", "index is 0-" + (chain.length - 1));
                }
                X509Certificate cert = chain[index];
                if (!TrustStore.confirmed(cert, confirm)) {
                    throw new Http.Problem(400, "confirmation-mismatch", "type the last 8 hex digits of the certificate's SHA-256 fingerprint");
                }
                acceptedKind = Certs.selfSigned(cert) || cert.getBasicConstraints() >= 0 ? TrustStore.Kind.CA : TrustStore.Kind.PINNED_SERVER;
                acceptedCa = cert;
                String key = TrustStore.keyOf(Certs.id(cert), scope);
                server.trust.add(cert, acceptedKind, scope, "bootstrap", "first-sign-in");
                undo.add(() -> quietly(() -> server.trust.remove(key)));
            } else if (!TrustStore.confirmed(leaf, confirm)) {
                throw new Http.Problem(400, "confirmation-mismatch", "type the last 8 hex digits of the certificate's SHA-256 fingerprint");
            }
            // reached by a name the certificate does not carry (a tunnel, a load balancer, NAT): the person
            // saw the names with the chain, so the same confirmation accepts exactly this certificate here
            if (!Certs.matches(leaf, newHost)) {
                server.trust.addHostException(newHost, newPort, leaf, "bootstrap");
                undo.add(() -> quietly(() -> server.trust.removeHostException(newHost, newPort)));
            }
        }
        char[] pw = Http.string(b, "password", true).toCharArray();
        String treeName;
        try (Ldap l = Ldap.connect(server.trust, new Ldap.Target(PROVISIONAL, newHost, newPort), null, dn, pw, T)) {
            if (!supervisorOfTree(l, dn)) {
                undo.forEach(Runnable::run);
                server.audit.log(new AuditLog.Actor(dn, dn, "setup"), "setup.authority", newHost + ":" + newPort, Map.of(), "refused: not supervisor");
                throw new Http.Problem(403, "not-tree-admin", dn + " signed in but does not have supervisor rights to the tree; use a tree administrator");
            }
            Ldap.Entry root = l.read("", "directoryTreeName");
            treeName = root == null ? null : root.first("directoryTreeName");
        } catch (Ldap.Untrusted u) {
            undo.forEach(Runnable::run);
            Probe.Result r;
            try {
                r = server.probes.probe(newHost, newPort, SESSION, T);
            } catch (IOException io) {
                throw new Http.Problem(502, "unreachable", newHost + ":" + newPort + ": " + io.getMessage());
            }
            throw new Http.Problem(409, "untrusted-certificate", u.getMessage(),
                Map.of("reason", u.cause.reason.name().toLowerCase(Locale.ROOT).replace('_', '-'), "probe", server.probeJson(r, PROVISIONAL, null)));
        } catch (Ldap.BadCredentials e) {
            undo.forEach(Runnable::run);
            server.audit.log(new AuditLog.Actor(dn, dn, "setup"), "setup.authority", newHost + ":" + newPort, Map.of(), "refused: bad credentials");
            throw new Http.Problem(401, "bad-credentials", "the name or password is incorrect");
        } catch (NamingException e) {
            undo.forEach(Runnable::run);
            Throwable why = e.getRootCause() == null ? e : e.getRootCause();
            throw new Http.Problem(502, "unreachable", "the console could not reach " + newHost + ":" + newPort
                + (why.getMessage() == null || why.getMessage().contains(newHost) ? "" : " (" + why.getMessage() + ")")
                + ". Check the address and port, and that the console's container can reach that network.");
        } finally {
            java.util.Arrays.fill(pw, '\0');
        }
        // the tree's own name names it in the console; its trust moves from the provisional scope to it
        String newId = treeName == null ? "" : treeName.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9_.-]+", "-").replaceAll("^-+|-+$", "");
        if (newId.isEmpty() || newId.length() > 64) {
            newId = "tree";
        }
        if (acceptedCa != null) {
            server.trust.remove(TrustStore.keyOf(Certs.id(acceptedCa), scope));
            server.trust.add(acceptedCa, acceptedKind, "directory:" + newId, "bootstrap", "first-sign-in");
            server.audit.log(AuditLog.Actor.SYSTEM, "trust.add", newId, Map.of("scope", "directory:" + newId, "kind", acceptedKind.name(),
                "how", "first-sign-in", "sha256", Certs.sha256(acceptedCa)), "ok");
        }
        id = newId;
        name = treeName == null ? newHost : treeName;
        host = newHost;
        port = newPort;
        tier = "production";
        trusted = true;
        adminDn = dn;
        saDn = null;
        saPassword = null;
        server.audit.log(new AuditLog.Actor(dn, dn, "setup"), "setup.authority", id, Map.of(), "ok");
        finish(ex);
    }

    private interface IoAction {
        void run() throws IOException;
    }

    private static void quietly(IoAction a) {
        try {
            a.run();
        } catch (IOException e) {
            // best effort: the entry is left, scoped to setup only
        }
    }
}
