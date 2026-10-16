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
 *
 * <p>A server certificate pinned from a probe remembers the address it was taken at. When that
 * address later presents another certificate, the connection is refused as {@code pin-changed} and an
 * alert is kept ({@code trust/alerts.json}) until an administrator trusts the new certificate or
 * dismisses it.
 */
public final class TrustStore {

    public enum Kind { CA, PINNED_SERVER }

    /** {@code pinnedAt}: for a pinned server certificate taken from a probe, its {@code host:port}; else null. */
    public record Entry(String id, X509Certificate cert, Kind kind, String scope, String addedBy, Instant addedAt, String how, String pinnedAt) {
        public Entry(String id, X509Certificate cert, Kind kind, String scope, String addedBy, Instant addedAt, String how) {
            this(id, cert, kind, scope, addedBy, addedAt, how, null);
        }

        /** Where the entry is kept: the fingerprint, with a suffix for a person's own (it may sit beside an administrator's). */
        public String key() {
            return keyOf(id, scope);
        }

        public Map<String, Object> json() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id);
            m.put("key", key());
            m.put("sha256", Certs.sha256(cert));
            m.put("kind", kind.name().toLowerCase(Locale.ROOT).replace('_', '-'));
            m.put("scope", scope);
            m.put("subject", cert.getSubjectX500Principal().getName());
            m.put("issuer", cert.getIssuerX500Principal().getName());
            m.put("notBefore", cert.getNotBefore().toInstant().toString());
            m.put("notAfter", cert.getNotAfter().toInstant().toString());
            m.put("names", Certs.names(cert));
            m.put("selfSigned", Certs.selfSigned(cert));
            m.put("addedBy", addedBy);
            m.put("addedAt", addedAt.toString());
            m.put("how", how);
            if (pinnedAt != null) {
                m.put("pinnedAt", pinnedAt);
            }
            return m;
        }
    }

    /**
     * A pinned address that presented another certificate: {@code pinned} the ids pinned there,
     * {@code presented} what it showed, seen {@code count} times on real connections.
     */
    public record Alert(String host, int port, String directoryId, List<String> pinned, String presentedId, String presentedSha256,
                        String presentedSubject, Instant firstSeen, Instant lastSeen, int count) {
        public Map<String, Object> json() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("host", host);
            m.put("port", port);
            if (directoryId != null) {
                m.put("directory", directoryId);
            }
            m.put("pinned", pinned);
            m.put("presentedId", presentedId);
            m.put("presentedSha256", presentedSha256);
            m.put("presentedSubject", presentedSubject);
            m.put("firstSeen", firstSeen.toString());
            m.put("lastSeen", lastSeen.toString());
            m.put("count", count);
            return m;
        }
    }

    /** Told once per new alert (an address, a presented certificate): the audit log. */
    public interface AlertListener {
        void raised(Alert a);
    }

    private volatile AlertListener listener = a -> { };

    public void onAlert(AlertListener l) {
        this.listener = l;
    }

    /** {@code scope}: global, or one person's ({@code user:<subject>}) for a directory they entered themselves. */
    public record HostException(String host, int port, String leafId, String addedBy, Instant addedAt, String scope) {
        public HostException(String host, int port, String leafId, String addedBy, Instant addedAt) {
            this(host, port, leafId, addedBy, addedAt, "global");
        }

        boolean inScope(String directoryId, String subject) {
            return scope.equals("global") || scope.equals("directory:" + directoryId) || scope.equals("user:" + subject);
        }
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

    /** An entry's key: its fingerprint, or for a person's own ({@code user:} scope) the fingerprint and a scope suffix. */
    public static String keyOf(String id, String scope) {
        if (!scope.startsWith("user:")) {
            return id;
        }
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(scope.getBytes(StandardCharsets.UTF_8));
            return id + "-" + java.util.HexFormat.of().formatHex(h, 0, 6);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public synchronized List<Entry> entries() throws IOException {
        List<Entry> out = new ArrayList<>();
        try (Stream<Path> s = Files.list(dir)) {
            for (Path meta : s.filter(p -> p.getFileName().toString().matches("[0-9a-f]{64}(-[0-9a-f]{12})?\\.json")).sorted().toList()) {
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
                    Json.asString(m.get("scope")), Json.asString(m.get("addedBy")), Instant.parse(Json.asString(m.get("addedAt"))), Json.asString(m.get("how")),
                    m.get("pinnedAt") == null ? null : Json.asString(m.get("pinnedAt"))));
            }
        }
        return out;
    }

    /** Add (or re-scope) a trusted certificate. */
    public synchronized Entry add(X509Certificate cert, Kind kind, String scope, String by, String how) throws IOException {
        return add(cert, kind, scope, by, how, null);
    }

    /**
     * Add (or re-scope) a trusted certificate; a pinned server certificate taken at {@code pinnedAt}
     * ({@code host:port}) replaces what was pinned at that address before, and resolves its alerts.
     */
    public synchronized Entry add(X509Certificate cert, Kind kind, String scope, String by, String how, String pinnedAt) throws IOException {
        checkScope(scope);
        Entry e = new Entry(Certs.id(cert), cert, kind, scope, by, Instant.now(), how, kind == Kind.PINNED_SERVER ? pinnedAt : null);
        if (e.pinnedAt != null) {
            for (Entry old : entries()) {
                if (old.kind == Kind.PINNED_SERVER && e.pinnedAt.equalsIgnoreCase(old.pinnedAt) && old.scope.equals(scope) && !old.id.equals(e.id)) {
                    remove(old.key());
                }
            }
        }
        DataDir.write(dir.resolve(e.id + ".pem"), Certs.pem(cert).getBytes(StandardCharsets.US_ASCII));
        DataDir.write(dir.resolve(e.key() + ".json"), Json.pretty(e.json()).getBytes(StandardCharsets.UTF_8));
        List<Alert> alerts = new ArrayList<>(alerts());
        if (alerts.removeIf(a -> a.presentedId.equals(e.id))) {
            writeAlerts(alerts);
        }
        return e;
    }

    // ---- alerts ---------------------------------------------------------------------------------

    public synchronized List<Alert> alerts() throws IOException {
        Path f = dir.resolve("alerts.json");
        List<Alert> out = new ArrayList<>();
        if (Files.exists(f)) {
            for (Object o : Json.asList(Json.parse(Files.readString(f, StandardCharsets.UTF_8)))) {
                Map<String, Object> m = Json.asMap(o);
                List<String> pinned = new ArrayList<>();
                for (Object p : Json.asList(m.get("pinned"))) {
                    pinned.add(String.valueOf(p));
                }
                out.add(new Alert(Json.asString(m.get("host")), Json.asInt(m.get("port"), 0), m.get("directory") == null ? null : Json.asString(m.get("directory")),
                    pinned, Json.asString(m.get("presentedId")), Json.asString(m.get("presentedSha256")), Json.asString(m.get("presentedSubject")),
                    Instant.parse(Json.asString(m.get("firstSeen"))), Instant.parse(Json.asString(m.get("lastSeen"))), Json.asInt(m.get("count"), 1)));
            }
        }
        return out;
    }

    /** Dismiss the alerts for {@code host:port}; false when there are none. */
    public synchronized boolean dismissAlerts(String host, int port) throws IOException {
        List<Alert> all = new ArrayList<>(alerts());
        if (!all.removeIf(a -> a.host.equalsIgnoreCase(host) && a.port == port)) {
            return false;
        }
        writeAlerts(all);
        return true;
    }

    private void writeAlerts(List<Alert> all) throws IOException {
        List<Map<String, Object>> json = new ArrayList<>();
        for (Alert a : all) {
            json.add(a.json());
        }
        DataDir.write(dir.resolve("alerts.json"), Json.pretty(json).getBytes(StandardCharsets.UTF_8));
    }

    private void raise(String host, int port, String directoryId, List<String> pinned, X509Certificate leaf) {
        Alert raised = null;
        synchronized (this) {
            try {
                List<Alert> all = new ArrayList<>(alerts());
                String id = Certs.id(leaf);
                Instant now = Instant.now();
                boolean found = false;
                for (int i = 0; i < all.size(); i++) {
                    Alert a = all.get(i);
                    if (a.host.equalsIgnoreCase(host) && a.port == port && a.presentedId.equals(id)) {
                        all.set(i, new Alert(a.host, a.port, a.directoryId, a.pinned, a.presentedId, a.presentedSha256, a.presentedSubject, a.firstSeen, now, a.count + 1));
                        found = true;
                    }
                }
                if (!found) {
                    raised = new Alert(host.toLowerCase(Locale.ROOT), port, directoryId, pinned, id, Certs.sha256(leaf),
                        leaf.getSubjectX500Principal().getName(), now, now, 1);
                    all.add(raised);
                }
                writeAlerts(all);
            } catch (IOException e) {
                // the connection is refused either way; an unwritable alert must not hide that
            }
        }
        if (raised != null) {
            listener.raised(raised);
        }
    }

    /** Remove the entry with this key (see {@link Entry#key()}); the certificate file goes with its last entry. */
    public synchronized boolean remove(String key) throws IOException {
        if (!key.matches("[0-9a-f]{64}(-[0-9a-f]{12})?")) {
            return false;
        }
        boolean had = Files.deleteIfExists(dir.resolve(key + ".json"));
        String id = key.substring(0, 64);
        try (Stream<Path> s = Files.list(dir)) {
            if (s.noneMatch(p -> p.getFileName().toString().startsWith(id) && p.getFileName().toString().endsWith(".json"))) {
                Files.deleteIfExists(dir.resolve(id + ".pem"));
            }
        }
        return had;
    }

    public synchronized List<HostException> hostExceptions() throws IOException {
        Path f = dir.resolve("host-exceptions.json");
        List<HostException> out = new ArrayList<>();
        if (Files.exists(f)) {
            for (Object o : Json.asList(Json.parse(Files.readString(f, StandardCharsets.UTF_8)))) {
                Map<String, Object> m = Json.asMap(o);
                out.add(new HostException(Json.asString(m.get("host")), Json.asInt(m.get("port"), 0), Json.asString(m.get("leafId")),
                    Json.asString(m.get("addedBy")), Instant.parse(Json.asString(m.get("addedAt"))),
                    m.get("scope") == null ? "global" : Json.asString(m.get("scope"))));
            }
        }
        return out;
    }

    public synchronized void addHostException(String host, int port, X509Certificate leaf, String by) throws IOException {
        addHostException(host, port, leaf, by, "global");
    }

    /** Accept {@code leaf} at exactly {@code host:port} for {@code scope}, replacing what that scope had there. */
    public synchronized void addHostException(String host, int port, X509Certificate leaf, String by, String scope) throws IOException {
        checkScope(scope);
        List<HostException> all = new ArrayList<>(hostExceptions());
        all.removeIf(h -> h.host.equalsIgnoreCase(host) && h.port == port && h.scope.equals(scope));
        all.add(new HostException(host.toLowerCase(Locale.ROOT), port, Certs.id(leaf), by, Instant.now(), scope));
        writeHostExceptions(all);
    }

    /** Remove the host exceptions for exactly {@code host:port}, in every scope; false when there are none. */
    public synchronized boolean removeHostException(String host, int port) throws IOException {
        return removeHostException(host, port, null);
    }

    /** As {@link #removeHostException(String, int)}, in {@code scope} only (null: every scope). */
    public synchronized boolean removeHostException(String host, int port, String scope) throws IOException {
        List<HostException> all = new ArrayList<>(hostExceptions());
        if (!all.removeIf(h -> h.host.equalsIgnoreCase(host) && h.port == port && (scope == null || h.scope.equals(scope)))) {
            return false;
        }
        writeHostExceptions(all);
        return true;
    }

    private void writeHostExceptions(List<HostException> all) throws IOException {
        List<Map<String, Object>> json = new ArrayList<>();
        for (HostException h : all) {
            json.add(Map.of("host", h.host, "port", h.port, "leafId", h.leafId, "addedBy", h.addedBy, "addedAt", h.addedAt.toString(), "scope", h.scope));
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
            checker(host, port, directoryId, subject, false).checkServerTrusted(chain, "UNKNOWN");
            return new Evaluation(true, null, Certs.matches(chain[0], host), "trusted");
        } catch (Untrusted u) {
            return new Evaluation(false, u.reason, Certs.matches(chain[0], host), u.getMessage());
        } catch (CertificateException e) {
            return new Evaluation(false, Reason.UNTRUSTED, Certs.matches(chain[0], host), e.getMessage());
        }
    }

    /** The trust manager for one connection. Entries are read when it is made. */
    public X509ExtendedTrustManager trustManager(String host, int port, String directoryId, String subject) throws IOException {
        return checker(host, port, directoryId, subject, true);
    }

    /** {@code alerting}: a real connection, whose refusal for a changed pin raises an alert (a probe's does not). */
    private Checker checker(String host, int port, String directoryId, String subject, boolean alerting) throws IOException {
        List<Entry> inScope = new ArrayList<>();
        for (Entry e : entries()) {
            if (e.scope.equals("global") || e.scope.equals("directory:" + directoryId) || e.scope.equals("user:" + subject)) {
                inScope.add(e);
            }
        }
        List<HostException> exceptions = hostExceptions().stream().filter(h -> h.inScope(directoryId, subject)).toList();
        return new Checker(host, port, directoryId, inScope, exceptions, alerting);
    }

    private final class Checker extends X509ExtendedTrustManager {
        private final String host;
        private final int port;
        private final String directoryId;
        private final List<Entry> entries;
        private final List<HostException> exceptions;
        private final boolean alerting;

        Checker(String host, int port, String directoryId, List<Entry> entries, List<HostException> exceptions, boolean alerting) {
            this.host = host;
            this.port = port;
            this.directoryId = directoryId;
            this.entries = entries;
            this.exceptions = exceptions;
            this.alerting = alerting;
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
                    // a pin taken at this address (or, from before addresses were kept, any pin in scope)
                    String here = host + ":" + port;
                    List<String> pins = entries.stream()
                        .filter(e -> e.kind == Kind.PINNED_SERVER && (e.pinnedAt == null || e.pinnedAt.equalsIgnoreCase(here))).map(Entry::id).toList();
                    if (pins.isEmpty()) {
                        throw new Untrusted(Reason.UNTRUSTED, "the server's certificate is not trusted: probe it and trust the directory CA, or import the CA certificate", chain);
                    }
                    if (alerting) {
                        raise(host, port, directoryId, pins, leaf);
                    }
                    throw new Untrusted(Reason.PIN_CHANGED, "the server's certificate is not the one pinned for this address: it changed, or this is not the expected server."
                        + " Administrators have been alerted", chain);
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
