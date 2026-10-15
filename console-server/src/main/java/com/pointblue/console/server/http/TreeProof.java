package com.pointblue.console.server.http;

import com.pointblue.console.server.audit.AuditLog;
import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.console.server.tls.Certs;
import com.pointblue.console.server.tls.Probe;
import com.pointblue.console.server.tls.TrustStore;
import com.pointblue.dirxml.dev.json.Json;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.naming.NamingException;

/**
 * Proving a tree before the console takes it on, as setup's first sign-in and Settings > Trees do: its
 * certificate (offered to the person as a 409 with the probe when the console does not trust it, and
 * trusted once they confirm its fingerprint and the bind succeeds), and a tree administrator's
 * credentials with Supervisor rights over the tree. Trust is added under a provisional scope while the
 * tree has no id, removed again if the bind fails, and moved to the tree's own scope by {@link #settle}.
 */
final class TreeProof {

    static final Duration T = Duration.ofSeconds(10);

    /** A proven tree: its name from the root DSE (null when it gives none), and the CA the person accepted, if any. */
    record Proven(String host, int port, String dn, String treeName, X509Certificate acceptedCa, TrustStore.Kind kind, String provisionalScope) {
    }

    private TreeProof() {
    }

    /**
     * Check the address, accept a confirmed certificate, bind as {@code dn} and require Supervisor rights.
     * {@code probes} names whose probes this is (a probe is only good to the one it was shown to);
     * {@code provisional} is the id trust is held under until {@link #settle}.
     */
    static Proven prove(Server server, String probes, String provisional, Map<String, Object> b, AuditLog.Actor actor) throws IOException {
        String host = Http.string(b, "host", true).trim();
        int port = Http.integer(b, "port", 636);
        if (!host.matches("[A-Za-z0-9.:\\-\\[\\]]{1,253}") || port < 1 || port > 65535) {
            throw new Http.Problem(400, "bad-address", "the address is a host name or IP address, and a port from 1 to 65535");
        }
        String dn = Http.string(b, "dn", true).trim();
        if (!dn.contains("=")) {
            throw new Http.Problem(400, "full-name-required", "use the administrator's full name (DN), such as cn=admin,o=system");
        }
        String scope = "directory:" + provisional;
        List<IoAction> undo = new ArrayList<>();
        X509Certificate acceptedCa = null;
        TrustStore.Kind acceptedKind = null;
        if (b.get("accept") instanceof Map<?, ?> raw) {
            Map<String, Object> a = Json.asMap(raw);
            Probe.Result r = server.probes.get(Http.string(a, "probeId", true), probes);
            if (r == null || !r.host().equalsIgnoreCase(host) || r.port() != port) {
                throw new Http.Problem(409, "probe-expired", "that certificate is no longer on offer; sign in again to see it");
            }
            X509Certificate[] chain = r.chain().toArray(new X509Certificate[0]);
            TrustStore.Evaluation ev = server.trust.evaluate(chain, host, port, provisional, null);
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
                server.trust.add(cert, acceptedKind, scope, actor.dn() == null ? "bootstrap" : actor.dn(), "tree-proof");
                undo.add(() -> server.trust.remove(key));
            } else if (!TrustStore.confirmed(leaf, confirm)) {
                throw new Http.Problem(400, "confirmation-mismatch", "type the last 8 hex digits of the certificate's SHA-256 fingerprint");
            }
            // reached by a name the certificate does not carry (a tunnel, a load balancer, NAT): the person
            // saw the names with the chain, so the same confirmation accepts exactly this certificate here
            if (!Certs.matches(leaf, host)) {
                boolean had = server.trust.hostExceptions().stream().anyMatch(h -> h.host().equalsIgnoreCase(host) && h.port() == port && h.scope().equals("global"));
                server.trust.addHostException(host, port, leaf, actor.dn() == null ? "bootstrap" : actor.dn());
                if (!had) {
                    undo.add(() -> server.trust.removeHostException(host, port));
                }
            }
        }
        char[] pw = Http.string(b, "password", true).toCharArray();
        try (Ldap l = Ldap.connect(server.trust, new Ldap.Target(provisional, host, port), null, dn, pw, T)) {
            if (!Setup.supervisorOfTree(l, dn)) {
                undo(undo);
                server.audit.log(actor, "tree.prove", host + ":" + port, Map.of("dn", dn), "refused: not supervisor");
                throw new Http.Problem(403, "not-tree-admin", dn + " signed in but does not have supervisor rights to the tree; use a tree administrator");
            }
            Ldap.Entry root = l.read("", "directoryTreeName");
            String treeName = root == null ? null : root.first("directoryTreeName");
            return new Proven(host, port, dn, treeName, acceptedCa, acceptedKind, scope);
        } catch (Ldap.Untrusted u) {
            undo(undo);
            Probe.Result r;
            try {
                r = server.probes.probe(host, port, probes, T);
            } catch (IOException io) {
                throw new Http.Problem(502, "unreachable", "the console could not reach " + host + ":" + port + " (" + io.getMessage() + ")");
            }
            throw new Http.Problem(409, "untrusted-certificate", u.getMessage(),
                Map.of("reason", u.cause.reason.name().toLowerCase(Locale.ROOT).replace('_', '-'), "probe", server.probeJson(r, provisional, null)));
        } catch (Ldap.BadCredentials e) {
            undo(undo);
            server.audit.log(actor, "tree.prove", host + ":" + port, Map.of("dn", dn), "refused: bad credentials");
            throw new Http.Problem(401, "bad-credentials", "the name or password is incorrect");
        } catch (NamingException e) {
            undo(undo);
            Throwable why = e.getRootCause() == null ? e : e.getRootCause();
            throw new Http.Problem(502, "unreachable", "the console could not reach " + host + ":" + port
                + (why.getMessage() == null || why.getMessage().contains(host) ? "" : " (" + why.getMessage() + ")")
                + ". Check the address and port, and that the console's container can reach that network.");
        } finally {
            java.util.Arrays.fill(pw, '\0');
        }
    }

    /** Move an accepted CA from the provisional scope to the tree's own. */
    static void settle(Server server, Proven p, String id) throws IOException {
        if (p.acceptedCa() == null) {
            return;
        }
        server.trust.remove(TrustStore.keyOf(Certs.id(p.acceptedCa()), p.provisionalScope()));
        server.trust.add(p.acceptedCa(), p.kind(), "directory:" + id, p.dn(), "tree-proof");
        server.audit.log(AuditLog.Actor.SYSTEM, "trust.add", id, Map.of("scope", "directory:" + id, "kind", p.kind().name(),
            "how", "tree-proof", "sha256", Certs.sha256(p.acceptedCa())), "ok");
    }

    /** A tree id from a name: lower-case letters, digits, '.', '_' and '-'; {@code fallback} when nothing is left. */
    static String idFrom(String name, String fallback) {
        String id = name == null ? "" : name.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9_.-]+", "-").replaceAll("^-+|-+$", "");
        return id.isEmpty() || id.length() > 64 ? fallback : id;
    }

    private interface IoAction {
        void run() throws IOException;
    }

    private static void undo(List<IoAction> undo) {
        for (IoAction a : undo) {
            try {
                a.run();
            } catch (IOException e) {
                // best effort: what is left is scoped to the provisional id only
            }
        }
    }
}
