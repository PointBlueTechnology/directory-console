package com.pointblue.console.server.http;

import com.pointblue.console.server.acme.Acme;
import com.pointblue.console.server.acme.Dns;
import com.pointblue.console.server.auth.Role;
import com.pointblue.console.server.auth.Sessions;
import com.pointblue.console.server.data.ConfigStore;
import com.pointblue.console.server.tls.Certs;
import com.pointblue.console.server.tls.TrustStore;
import com.pointblue.dirxml.dev.json.Json;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.net.URI;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * The console's own TLS certificate from an ACME CA (Let's Encrypt, or an internal one such as step-ca), proven
 * with DNS-01: the console publishes each name's challenge as a TXT record through an RFC 2136 dynamic update
 * signed with TSIG, waits until the zone's server answers it, and removes it afterwards. The certificate is
 * installed live; once a day it is renewed when 30 days or fewer remain.
 *
 * <p>Configuration ({@code acme}): {enabled, directoryUrl, email, names: [...], dns: {host, port, zone, keyName,
 * algorithm, secret (sealed)}, accountKey (sealed), account}. The ACME server's certificate must be from a public
 * CA or a CA the console trusts for every directory. Turned off for tests with {@code console.acmeCheck=off}.
 *
 * <pre>
 * GET  /api/v2/console/acme                 settings, the current certificate, the last attempt
 * PUT  /api/v2/console/acme                 settings
 * POST /api/v2/console/acme/dns-test | issue
 * POST /api/v2/console/certificate          upload: {"pkcs12", "password"} or {"certificate", "key", "password"?}, "anyName"?
 * </pre>
 */
final class AcmeService {

    static final String LETS_ENCRYPT = "https://acme-v02.api.letsencrypt.org/directory";
    private static final int RENEW_DAYS = 30;

    private final Server server;
    private volatile ScheduledExecutorService timer;
    private volatile Map<String, Object> last = Map.of();

    AcmeService(Server server) {
        this.server = server;
    }

    boolean handles(String path) {
        return path.startsWith("/api/v2/console/acme") || path.equals("/api/v2/console/certificate");
    }

    void start() {
        if ("off".equals(System.getProperty("console.acmeCheck"))) {
            return;
        }
        ScheduledExecutorService t = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread th = new Thread(r, "acme");
            th.setDaemon(true);
            return th;
        });
        t.scheduleAtFixedRate(() -> {
            if (Boolean.TRUE.equals(config().get("enabled")) && due()) {
                issue("schedule", null);
            }
        }, 10, 24 * 60, TimeUnit.MINUTES);
        timer = t;
    }

    void stop() {
        ScheduledExecutorService t = timer;
        if (t != null) {
            t.shutdownNow();
        }
    }

    void handle(HttpExchange ex, String method, String path) throws IOException {
        switch (method + " " + path) {
            case "GET /api/v2/console/acme" -> {
                server.session(ex, Role.ADMIN);
                Http.json(ex, 200, state());
            }
            case "PUT /api/v2/console/acme" -> {
                Sessions.Session s = server.session(ex, Role.ADMIN);
                server.stepUp(s);
                save(s, Http.body(ex));
                Http.json(ex, 200, state());
            }
            case "POST /api/v2/console/acme/dns-test" -> {
                server.session(ex, Role.ADMIN);
                Http.json(ex, 200, dnsTest());
            }
            case "POST /api/v2/console/acme/issue" -> {
                Sessions.Session s = server.session(ex, Role.ADMIN);
                server.stepUp(s);
                issue("request", s);
                Http.json(ex, 200, state());
            }
            case "POST /api/v2/console/certificate" -> {
                Sessions.Session s = server.session(ex, Role.ADMIN);
                server.stepUp(s);
                upload(s, Http.body(ex));
                Http.json(ex, 200, state());
            }
            default -> throw new Http.Problem(405, "method-not-allowed", method + " " + path);
        }
    }

    /**
     * An uploaded certificate, installed for the next connection: {"pkcs12": base64, "password"} or {"certificate":
     * PEM chain, "key": PEM, "password"?}. It must belong to the key, be in date and name the console's public host
     * ({"anyName": true} when a proxy in front connects by another name). Refused while ACME renews automatically,
     * which would replace it.
     */
    private void upload(Sessions.Session s, Map<String, Object> b) throws IOException {
        if (Boolean.TRUE.equals(config().get("enabled"))) {
            throw new Http.Problem(409, "acme-on", "the console gets its certificate by ACME, which would replace this one: turn that off first");
        }
        String pw = b.get("password") == null ? "" : Http.string(b, "password", false);
        char[] password = pw.toCharArray();
        com.pointblue.console.server.tls.Upload.Identity id;
        try {
            if (b.get("pkcs12") != null) {
                byte[] file;
                try {
                    file = Base64.getMimeDecoder().decode(Http.string(b, "pkcs12", true));
                } catch (IllegalArgumentException e) {
                    throw new Http.Problem(400, "bad-field", "pkcs12 is the file, base64-encoded");
                }
                id = com.pointblue.console.server.tls.Upload.pkcs12(file, password);
            } else {
                id = com.pointblue.console.server.tls.Upload.pem(Http.string(b, "certificate", true), Http.string(b, "key", true), password);
            }
        } catch (java.security.GeneralSecurityException e) {
            throw new Http.Problem(400, "bad-certificate", e.getMessage());
        } finally {
            java.util.Arrays.fill(password, '\0');
        }
        X509Certificate leaf = id.chain()[0];
        Instant now = Instant.now();
        if (leaf.getNotAfter().toInstant().isBefore(now) || leaf.getNotBefore().toInstant().isAfter(now)) {
            throw new Http.Problem(400, "bad-certificate", "the certificate is not valid now: from " + leaf.getNotBefore().toInstant() + " until " + leaf.getNotAfter().toInstant());
        }
        String host = URI.create(server.publicUrl).getHost();
        if (!Boolean.TRUE.equals(b.get("anyName")) && host != null && !Certs.matches(leaf, host)) {
            throw new Http.Problem(400, "wrong-name", "the certificate is for " + String.join(", ", Certs.names(leaf)) + ", not " + host
                + ", the address browsers use; browsers would refuse it");
        }
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("subject", leaf.getSubjectX500Principal().getName());
        detail.put("issuer", leaf.getIssuerX500Principal().getName());
        detail.put("notAfter", leaf.getNotAfter().toInstant().toString());
        detail.put("sha256", Certs.sha256(leaf));
        detail.put("chain", id.chain().length);
        try {
            server.tls.install(id.key(), id.chain());
        } catch (java.security.GeneralSecurityException e) {
            server.audit.log(Server.who(s), "console.certificate.upload", "console", detail, "failed");
            throw new Http.Problem(400, "bad-certificate", e.getMessage());
        }
        server.audit.log(Server.who(s), "console.certificate.upload", "console", detail, "ok");
    }

    // ---- settings ---------------------------------------------------------------------------------

    Map<String, Object> config() {
        return server.config.read().get("acme") instanceof Map<?, ?> m ? Json.asMap(m) : Map.of();
    }

    Map<String, Object> state() {
        Map<String, Object> c = config();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("enabled", Boolean.TRUE.equals(c.get("enabled")));
        m.put("directoryUrl", c.getOrDefault("directoryUrl", LETS_ENCRYPT));
        m.put("email", c.get("email"));
        m.put("names", c.getOrDefault("names", List.of()));
        if (c.get("dns") instanceof Map<?, ?> d) {
            Map<String, Object> dns = new LinkedHashMap<>(Json.asMap(d));
            dns.put("secret", dns.get("secret") != null ? Map.of("set", true) : null);
            m.put("dns", dns);
        } else {
            m.put("dns", null);
        }
        m.put("account", c.get("account"));
        X509Certificate cert = server.tls.certificate();
        m.put("current", Map.of("subject", cert.getSubjectX500Principal().getName(), "issuer", cert.getIssuerX500Principal().getName(),
            "notAfter", cert.getNotAfter().toInstant().toString(), "sha256", Certs.sha256(cert), "names", Certs.names(cert),
            "selfSigned", Certs.selfSigned(cert), "chain", server.tls.chain().length));
        m.put("publicHost", URI.create(server.publicUrl).getHost());
        m.put("last", last);
        return m;
    }

    private void save(Sessions.Session s, Map<String, Object> b) throws IOException {
        Map<String, Object> before = config();
        Map<String, Object> next = new LinkedHashMap<>(before);
        next.put("enabled", Boolean.TRUE.equals(b.get("enabled")));
        String dir = b.get("directoryUrl") == null ? LETS_ENCRYPT : String.valueOf(b.get("directoryUrl")).trim();
        URI u;
        try {
            u = URI.create(dir);
        } catch (IllegalArgumentException x) {
            throw new Http.Problem(400, "bad-field", dir + " is not a URL");
        }
        if (!"https".equals(u.getScheme()) || u.getHost() == null) {
            throw new Http.Problem(400, "bad-field", "the ACME directory is an https:// URL");
        }
        if (!dir.equals(before.get("directoryUrl"))) {
            next.remove("account"); // a new CA: a new account
        }
        next.put("directoryUrl", dir);
        if (b.get("email") != null && !String.valueOf(b.get("email")).isBlank()) {
            try {
                next.put("email", Mail.address(String.valueOf(b.get("email"))));
            } catch (IllegalArgumentException x) {
                throw new Http.Problem(400, "bad-field", x.getMessage());
            }
        } else {
            next.remove("email");
        }
        List<String> names = new ArrayList<>();
        if (b.get("names") instanceof List<?> l) {
            for (Object o : l) {
                String n = String.valueOf(o).trim().toLowerCase(Locale.ROOT);
                if (!n.matches("(\\*\\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]")) {
                    throw new Http.Problem(400, "bad-field", n + " is not a DNS name");
                }
                names.add(n);
            }
        }
        if (Boolean.TRUE.equals(b.get("enabled")) && names.isEmpty()) {
            throw new Http.Problem(400, "bad-field", "names lists the console's DNS names");
        }
        next.put("names", names);
        if (b.get("dns") instanceof Map<?, ?> dm) {
            Map<String, Object> d = Json.asMap(dm);
            Map<String, Object> dns = new LinkedHashMap<>();
            String host = Http.string(d, "host", true).trim();
            if (!host.matches("[A-Za-z0-9.:\\[\\]-]{1,253}")) {
                throw new Http.Problem(400, "bad-field", "dns.host is a host name or address");
            }
            dns.put("host", host);
            int port = d.get("port") instanceof Number n ? n.intValue() : 53;
            if (port < 1 || port > 65535) {
                throw new Http.Problem(400, "bad-field", "dns.port is 1 to 65535");
            }
            dns.put("port", port);
            String zone = Http.string(d, "zone", true).trim().toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
            for (String n : names) {
                if (!(n.replaceFirst("^\\*\\.", "").equals(zone) || n.replaceFirst("^\\*\\.", "").endsWith("." + zone))) {
                    throw new Http.Problem(400, "bad-field", n + " is not in the zone " + zone);
                }
            }
            dns.put("zone", zone);
            dns.put("keyName", Http.string(d, "keyName", true).trim());
            String alg = d.get("algorithm") == null ? "hmac-sha256" : String.valueOf(d.get("algorithm")).toLowerCase(Locale.ROOT);
            if (!List.of("hmac-sha256", "hmac-sha512").contains(alg)) {
                throw new Http.Problem(400, "bad-field", "dns.algorithm is hmac-sha256 or hmac-sha512");
            }
            dns.put("algorithm", alg);
            if (d.get("secret") instanceof String sec && !sec.isBlank()) {
                try {
                    Dns.secret(sec);
                } catch (IllegalArgumentException x) {
                    throw new Http.Problem(400, "bad-field", "dns.secret is the TSIG key's secret, base64 as the DNS server shows it");
                }
                dns.put("secret", server.config.seal(sec.trim(), "acme/dns/secret"));
            } else if (before.get("dns") instanceof Map<?, ?> od && Json.asMap(od).get("secret") != null) {
                dns.put("secret", Json.asMap(od).get("secret"));
            }
            next.put("dns", dns);
        }
        try {
            server.config.update(server.config.version(), s.principal.dn(), "ACME settings", doc -> doc.put("acme", next));
        } catch (ConfigStore.Conflict c) {
            throw new Http.Problem(409, "conflict", "the configuration changed meanwhile; try again");
        }
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("enabled", next.get("enabled"));
        detail.put("directoryUrl", dir);
        detail.put("names", names);
        server.audit.log(Server.who(s), "settings.acme", "console", detail, "ok");
    }

    private Dns.Server dnsServer() {
        Map<String, Object> c = config();
        if (!(c.get("dns") instanceof Map<?, ?> dm)) {
            throw new Http.Problem(409, "not-configured", "no DNS server is set for the challenge");
        }
        Map<String, Object> d = Json.asMap(dm);
        String secret = server.config.secret("acme/dns/secret");
        if (secret == null) {
            throw new Http.Problem(409, "not-configured", "the TSIG key's secret is not set");
        }
        return new Dns.Server(String.valueOf(d.get("host")), ((Number) d.get("port")).intValue(), String.valueOf(d.get("zone")),
            String.valueOf(d.get("keyName")), String.valueOf(d.get("algorithm")), Dns.secret(secret));
    }

    /** Add a test record, read it back from the server, remove it. */
    Map<String, Object> dnsTest() {
        Dns.Server s = dnsServer();
        String name = "_acme-challenge-test." + s.zone();
        String value = "directory-console-" + Instant.now().getEpochSecond();
        Map<String, Object> r = new LinkedHashMap<>();
        try {
            Dns.addTxt(s, name, value);
            boolean seen = Dns.txt(s, name).contains(value);
            Dns.deleteTxt(s, name, value);
            r.put("ok", seen);
            if (!seen) {
                r.put("error", "the update was accepted but " + s.host() + " does not answer it");
            }
        } catch (IOException | RuntimeException x) {
            r.put("ok", false);
            r.put("error", x.getMessage() == null ? x.getClass().getSimpleName() : x.getMessage());
        }
        return r;
    }

    // ---- issuing ----------------------------------------------------------------------------------

    /** Whether the console's certificate needs renewing: not from this ACME setup's names, or 30 days or fewer left. */
    boolean due() {
        X509Certificate c = server.tls.certificate();
        if (Duration.between(Instant.now(), c.getNotAfter().toInstant()).toDays() <= RENEW_DAYS) {
            return true;
        }
        try {
            List<String> have = new ArrayList<>();
            if (c.getSubjectAlternativeNames() != null) {
                c.getSubjectAlternativeNames().forEach(san -> have.add(String.valueOf(san.get(1)).toLowerCase(Locale.ROOT)));
            }
            Object names = config().get("names");
            return names instanceof List<?> l && !have.containsAll(l.stream().map(String::valueOf).toList());
        } catch (java.security.cert.CertificateParsingException e) {
            return true;
        }
    }

    /** Get a certificate for the configured names and install it; records the outcome. */
    synchronized void issue(String why, Sessions.Session s) {
        Map<String, Object> outcome = new LinkedHashMap<>();
        outcome.put("at", Instant.now().toString());
        outcome.put("why", why);
        List<String> steps = new ArrayList<>();
        try {
            Map<String, Object> c = config();
            @SuppressWarnings("unchecked")
            List<String> names = (List<String>) c.getOrDefault("names", List.of());
            if (names.isEmpty()) {
                throw new IOException("no names are set");
            }
            Dns.Server dns = dnsServer();
            Acme acme = new Acme(URI.create(String.valueOf(c.getOrDefault("directoryUrl", LETS_ENCRYPT))), accountKey(), tls(), Updates.proxy());
            String account = acme.account(c.get("email") == null ? null : String.valueOf(c.get("email")));
            steps.add("account " + account);
            if (!account.equals(c.get("account"))) {
                remember("account", account);
            }
            Map<String, Object> order = acme.order(names);
            steps.add("order " + order.get("url"));
            for (Object a : (List<?>) order.get("authorizations")) {
                Map<String, Object> authz = acme.fetch(String.valueOf(a));
                if ("valid".equals(authz.get("status"))) {
                    continue;
                }
                String domain = String.valueOf(Json.asMap(authz.get("identifier")).get("value"));
                Map<String, Object> ch = null;
                for (Object o : (List<?>) authz.get("challenges")) {
                    if ("dns-01".equals(Json.asMap(o).get("type"))) {
                        ch = Json.asMap(o);
                    }
                }
                if (ch == null) {
                    throw new IOException("the CA offers no DNS-01 challenge for " + domain);
                }
                String record = "_acme-challenge." + domain;
                String value = acme.dnsValue(String.valueOf(ch.get("token")));
                Dns.addTxt(dns, record, value);
                try {
                    // the zone's server answers it before the CA is told to look
                    for (int i = 0; i < 30 && !Dns.txt(dns, record).contains(value); i++) {
                        Thread.sleep(2000);
                    }
                    acme.respond(String.valueOf(ch.get("url")));
                    Map<String, Object> done = acme.await(String.valueOf(a), Duration.ofMinutes(3));
                    if (!"valid".equals(done.get("status"))) {
                        throw new IOException("the CA did not accept " + domain + ": " + challengeError(done));
                    }
                    steps.add(domain + " proven");
                } finally {
                    try {
                        Dns.deleteTxt(dns, record, value);
                    } catch (IOException x) {
                        steps.add("could not remove " + record + ": " + x.getMessage());
                    }
                }
            }
            KeyPair key = ec();
            byte[] csr = csr(key, names);
            acme.finalizeOrder(String.valueOf(order.get("finalize")), csr);
            Map<String, Object> done = acme.await(String.valueOf(order.get("url")), Duration.ofMinutes(3));
            if (!"valid".equals(done.get("status")) || done.get("certificate") == null) {
                throw new IOException("the order ended " + done.get("status"));
            }
            X509Certificate[] chain = acme.certificate(String.valueOf(done.get("certificate")));
            server.tls.install(key.getPrivate(), chain);
            outcome.put("ok", true);
            outcome.put("notAfter", chain[0].getNotAfter().toInstant().toString());
            outcome.put("issuer", chain[0].getIssuerX500Principal().getName());
        } catch (Exception x) {
            if (x instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            outcome.put("ok", false);
            outcome.put("error", x.getMessage() == null ? x.getClass().getSimpleName() : x.getMessage());
        }
        outcome.put("steps", steps);
        last = outcome;
        try {
            server.audit.log(s == null ? new com.pointblue.console.server.audit.AuditLog.Actor("console", null, "schedule") : Server.who(s),
                "acme.issue", "console", outcome, Boolean.TRUE.equals(outcome.get("ok")) ? "ok" : "failed");
        } catch (IOException x) {
            // the outcome is kept in memory and shown
        }
    }

    private static String challengeError(Map<String, Object> authz) {
        for (Object o : (List<?>) authz.getOrDefault("challenges", List.of())) {
            Map<String, Object> ch = Json.asMap(o);
            if (ch.get("error") instanceof Map<?, ?> e) {
                return String.valueOf(Json.asMap(e).get("detail"));
            }
        }
        return String.valueOf(authz.get("status"));
    }

    private void remember(String key, Object value) throws IOException {
        try {
            server.config.update(server.config.version(), "console", "ACME " + key, doc -> {
                Map<String, Object> a = doc.get("acme") instanceof Map<?, ?> m ? Json.asMap(m) : new LinkedHashMap<>();
                a.put(key, value);
                doc.put("acme", a);
            });
        } catch (ConfigStore.Conflict c) {
            // kept next time
        }
    }

    /** The account key: made once (P-256) and kept sealed in the configuration. */
    private KeyPair accountKey() throws Exception {
        String sealed = server.config.secret("acme/accountKey");
        if (sealed != null && sealed.contains(":")) {
            String[] parts = sealed.split(":");
            KeyFactory f = KeyFactory.getInstance("EC");
            return new KeyPair(f.generatePublic(new java.security.spec.X509EncodedKeySpec(Base64.getDecoder().decode(parts[1]))),
                f.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(parts[0]))));
        }
        KeyPair kp = ec();
        String encoded = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded()) + ":" + Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
        server.config.update(server.config.version(), "console", "ACME account key", doc -> {
            Map<String, Object> a = doc.get("acme") instanceof Map<?, ?> m ? Json.asMap(m) : new LinkedHashMap<>();
            a.put("accountKey", server.config.seal(encoded, "acme/accountKey"));
            doc.put("acme", a);
        });
        return kp;
    }

    private static KeyPair ec() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }

    /** A CSR for the names (the first also as the common name), signed with the new key. */
    private static byte[] csr(KeyPair key, List<String> names) throws Exception {
        org.bouncycastle.asn1.x509.GeneralName[] sans = names.stream()
            .map(n -> new org.bouncycastle.asn1.x509.GeneralName(org.bouncycastle.asn1.x509.GeneralName.dNSName, n))
            .toArray(org.bouncycastle.asn1.x509.GeneralName[]::new);
        org.bouncycastle.asn1.x509.ExtensionsGenerator ext = new org.bouncycastle.asn1.x509.ExtensionsGenerator();
        ext.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, false, new org.bouncycastle.asn1.x509.GeneralNames(sans));
        org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder b = new org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder(
            new org.bouncycastle.asn1.x500.X500Name("CN=" + names.get(0).replaceFirst("^\\*\\.", "")), key.getPublic());
        b.addAttribute(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, ext.generate());
        return b.build(new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withECDSA").build(key.getPrivate())).getEncoded();
    }

    /** TLS to the ACME server: the JDK's public CAs and the CAs the console trusts for every directory. */
    private SSLContext tls() throws Exception {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        TrustManagerFactory jdk = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        jdk.init((KeyStore) null);
        int i = 0;
        for (TrustManager tm : jdk.getTrustManagers()) {
            if (tm instanceof X509TrustManager x) {
                for (X509Certificate c : x.getAcceptedIssuers()) {
                    ks.setCertificateEntry("jdk" + i++, c);
                }
            }
        }
        for (TrustStore.Entry e : server.trust.entries()) {
            if (e.kind() == TrustStore.Kind.CA && "global".equals(e.scope())) {
                ks.setCertificateEntry("console" + i++, e.cert());
            }
        }
        TrustManagerFactory f = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        f.init(ks);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, f.getTrustManagers(), null);
        return ctx;
    }
}
