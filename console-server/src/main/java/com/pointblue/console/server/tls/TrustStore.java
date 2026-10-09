package com.pointblue.console.server.tls;

import com.pointblue.console.auth.TrustManagers;
import com.pointblue.console.server.data.DataDir;
import com.pointblue.dirxml.dev.json.Json;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * The certificates the console trusts for directory connections, beside (never inside) the JDK's own
 * store: {@code trust/<sha256>.pem} with {@code <sha256>.json} metadata, and
 * {@code trust/host-exceptions.json}.
 *
 * <p>An entry is a {@code ca} (a chain that validates to it is trusted: eDirectory's tree CA) or a
 * {@code pinned-server} (exactly that leaf is trusted), in a scope: {@code global},
 * {@code directory:<id>} or {@code user:<subject>}. Host names are always verified; a host exception
 * accepts one exact {@code host:port} for one exact leaf fingerprint, so it stops matching when the
 * certificate changes. Nothing here trusts everything.
 */
public final class TrustStore {

    public enum Kind { CA, PINNED_SERVER }

    public record Entry(String id, X509Certificate cert, Kind kind, String scope, String addedBy, Instant addedAt, String how) {
        public Map<String, Object> json() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id);
            m.put("sha256", Certs.sha256(cert));
            m.put("kind", kind.name().toLowerCase(Locale.ROOT).replace('_', '-'));
            m.put("scope", scope);
            m.put("subject", cert.getSubjectX500Principal().getName());
            m.put("issuer", cert.getIssuerX500Principal().getName());
            m.put("notAfter", cert.getNotAfter().toInstant().toString());
            m.put("addedBy", addedBy);
            m.put("addedAt", addedAt.toString());
            m.put("how", how);
            return m;
        }
    }

    public record HostException(String host, int port, String leafId, String addedBy, Instant addedAt) {
    }

    /** Why a chain was refused; a sign-in maps it to an {@code untrusted-certificate} problem. */
    public enum Reason { UNTRUSTED, HOSTNAME, PIN_CHANGED, EXPIRED }

    public static final class Untrusted extends CertificateException {
        public final Reason reason;
        public final transient List<X509Certificate> chain;

        Untrusted(Reason reason, String message, X509Certificate[] chain) {
            super(message);
            this.reason = reason;
            this.chain = List.of(chain);
        }
    }

    private final Path dir;
    private final X509TrustManager jdk;

    public TrustStore(DataDir data) throws IOException {
        this.dir = data.trust();
        try {
            this.jdk = TrustManagers.jdkDefault();
        } catch (GeneralSecurityException e) {
            throw new IOException("the JDK's default trust: " + e.getMessage(), e);
        }
    }

    // ---- entries --------------------------------------------------------------------------------

    public synchronized List<Entry> entries() throws IOException {
        List<Entry> out = new ArrayList<>();
        try (Stream<Path> s = Files.list(dir)) {
            for (Path meta : s.filter(p -> p.getFileName().toString().matches("[0-9a-f]{64}\\.json")).sorted().toList()) {
                Map<String, Object> m = Json.asMap(Json.parse(Files.readString(meta, StandardCharsets.UTF_8)));
                String id = Json.asString(m.get("id"));
                X509Certificate c;
                try {
                    c = Certs.parse(Files.readAllBytes(dir.resolve(id + ".pem"))).get(0);
                } catch (GeneralSecurityException e) {
                    throw new IOException("trust entry " + id + " is unreadable: " + e.getMessage(), e);
                }
                if (!Certs.id(c).equals(id)) {
                    throw new IOException("trust entry " + id + " holds a different certificate");
                }
                out.add(new Entry(id, c, Kind.valueOf(Json.asString(m.get("kind")).toUpperCase(Locale.ROOT).replace('-', '_')),
                    Json.asString(m.get("scope")), Json.asString(m.get("addedBy")), Instant.parse(Json.asString(m.get("addedAt"))), Json.asString(m.get("how"))));
            }
        }
        return out;
    }

    /** Add (or re-scope) a trusted certificate. */
    public synchronized Entry add(X509Certificate cert, Kind kind, String scope, String by, String how) throws IOException {
        checkScope(scope);
        Entry e = new Entry(Certs.id(cert), cert, kind, scope, by, Instant.now(), how);
        DataDir.write(dir.resolve(e.id + ".pem"), Certs.pem(cert).getBytes(StandardCharsets.US_ASCII));
        DataDir.write(dir.resolve(e.id + ".json"), Json.pretty(e.json()).getBytes(StandardCharsets.UTF_8));
        return e;
    }

    public synchronized boolean remove(String id) throws IOException {
        if (!id.matches("[0-9a-f]{64}")) {
            return false;
        }
        boolean had = Files.deleteIfExists(dir.resolve(id + ".json"));
        Files.deleteIfExists(dir.resolve(id + ".pem"));
        return had;
    }

    public synchronized List<HostException> hostExceptions() throws IOException {
        Path f = dir.resolve("host-exceptions.json");
        List<HostException> out = new ArrayList<>();
        if (Files.exists(f)) {
            for (Object o : Json.asList(Json.parse(Files.readString(f, StandardCharsets.UTF_8)))) {
                Map<String, Object> m = Json.asMap(o);
                out.add(new HostException(Json.asString(m.get("host")), Json.asInt(m.get("port"), 0), Json.asString(m.get("leafId")),
                    Json.asString(m.get("addedBy")), Instant.parse(Json.asString(m.get("addedAt")))));
            }
        }
        return out;
    }

    public synchronized void addHostException(String host, int port, X509Certificate leaf, String by) throws IOException {
        List<HostException> all = new ArrayList<>(hostExceptions());
        all.removeIf(h -> h.host.equalsIgnoreCase(host) && h.port == port);
        all.add(new HostException(host.toLowerCase(Locale.ROOT), port, Certs.id(leaf), by, Instant.now()));
        List<Map<String, Object>> json = new ArrayList<>();
        for (HostException h : all) {
            json.add(Map.of("host", h.host, "port", h.port, "leafId", h.leafId, "addedBy", h.addedBy, "addedAt", h.addedAt.toString()));
        }
        DataDir.write(dir.resolve("host-exceptions.json"), Json.pretty(json).getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Whether {@code typed} is the last eight hex digits of {@code cert}'s fingerprint: what a person
     * types to confirm a certificate they read from a probe. Separators and case are ignored.
     */
    public static boolean confirmed(X509Certificate cert, String typed) {
        if (typed == null) {
            return false;
        }
        String t = typed.replace(":", "").replace(" ", "").toLowerCase(Locale.ROOT);
        return MessageDigest.isEqual(Certs.tail(cert, 8).getBytes(StandardCharsets.US_ASCII), t.getBytes(StandardCharsets.US_ASCII));
    }

    private static void checkScope(String scope) {
        if (scope == null || !(scope.equals("global") || scope.matches("directory:[A-Za-z0-9_.-]{1,64}") || scope.matches("user:[^\\s]{1,256}"))) {
            throw new IllegalArgumentException("scope is global, directory:<id> or user:<subject>, not " + scope);
        }
    }

    // ---- verification ---------------------------------------------------------------------------

    /** The outcome of checking a chain for a host, without connecting. */
    public record Evaluation(boolean trusted, Reason reason, boolean hostnameMatches, String message) {
    }

    /**
     * Check {@code chain} as presented by {@code host:port} for a connection to directory
     * {@code directoryId} by {@code subject} (either may be null).
     */
    public Evaluation evaluate(X509Certificate[] chain, String host, int port, String directoryId, String subject) throws IOException {
        try {
            trustManager(host, port, directoryId, subject).checkServerTrusted(chain, "UNKNOWN");
            return new Evaluation(true, null, Certs.matches(chain[0], host), "trusted");
        } catch (Untrusted u) {
            return new Evaluation(false, u.reason, Certs.matches(chain[0], host), u.getMessage());
        } catch (CertificateException e) {
            return new Evaluation(false, Reason.UNTRUSTED, Certs.matches(chain[0], host), e.getMessage());
        }
    }

    /** The trust manager for one connection. Entries are read when it is made. */
    public X509ExtendedTrustManager trustManager(String host, int port, String directoryId, String subject) throws IOException {
        List<Entry> inScope = new ArrayList<>();
        for (Entry e : entries()) {
            if (e.scope.equals("global") || e.scope.equals("directory:" + directoryId) || e.scope.equals("user:" + subject)) {
                inScope.add(e);
            }
        }
        List<HostException> exceptions = hostExceptions();
        return new Checker(host, port, inScope, exceptions);
    }

    private final class Checker extends X509ExtendedTrustManager {
        private final String host;
        private final int port;
        private final List<Entry> entries;
        private final List<HostException> exceptions;

        Checker(String host, int port, List<Entry> entries, List<HostException> exceptions) {
            this.host = host;
            this.port = port;
            this.entries = entries;
            this.exceptions = exceptions;
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            if (chain == null || chain.length == 0) {
                throw new Untrusted(Reason.UNTRUSTED, "the server presented no certificate", new X509Certificate[0]);
            }
            X509Certificate leaf = chain[0];
            String leafId = Certs.id(leaf);
            try {
                leaf.checkValidity();
            } catch (CertificateException e) {
                throw new Untrusted(Reason.EXPIRED, "the server's certificate is not valid now (" + leaf.getNotAfter().toInstant() + ")", chain);
            }
            boolean pinned = entries.stream().anyMatch(e -> e.kind == Kind.PINNED_SERVER && e.id.equals(leafId));
            if (!pinned) {
                boolean chainTrusted = validates(jdk, chain);
                List<X509Certificate> anchors = entries.stream().filter(e -> e.kind == Kind.CA).map(Entry::cert).toList();
                if (!chainTrusted && !anchors.isEmpty()) {
                    try {
                        chainTrusted = validates(TrustManagers.of(anchors), chain);
                    } catch (GeneralSecurityException e) {
                        chainTrusted = false;
                    }
                }
                if (!chainTrusted) {
                    boolean hadPin = entries.stream().anyMatch(e -> e.kind == Kind.PINNED_SERVER);
                    throw hadPin
                        ? new Untrusted(Reason.PIN_CHANGED, "the server's certificate is not the one pinned for this directory: it changed, or this is not the expected server", chain)
                        : new Untrusted(Reason.UNTRUSTED, "the server's certificate is not trusted: probe it and trust the tree CA, or import the CA certificate", chain);
                }
            }
            if (!Certs.matches(leaf, host)) {
                boolean excepted = exceptions.stream().anyMatch(h -> h.host.equalsIgnoreCase(host) && h.port == port && h.leafId.equals(leafId));
                if (!excepted) {
                    throw new Untrusted(Reason.HOSTNAME, "the certificate is for " + Certs.names(leaf) + ", not " + host
                        + ": connect by one of those names, or add a host exception", chain);
                }
            }
        }

        private boolean validates(X509TrustManager tm, X509Certificate[] chain) {
            try {
                // the non-socket variant: the host name is checked above, with the exceptions
                tm.checkServerTrusted(chain, chain[0].getPublicKey().getAlgorithm().equals("EC") ? "ECDHE_ECDSA" : "RSA");
                return true;
            } catch (CertificateException e) {
                return false;
            }
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
            checkServerTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
            checkServerTrusted(chain, authType);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException("a directory connection does not accept clients");
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
            checkClientTrusted(chain, authType);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
            checkClientTrusted(chain, authType);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
