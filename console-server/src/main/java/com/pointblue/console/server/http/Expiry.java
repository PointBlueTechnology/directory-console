package com.pointblue.console.server.http;

import com.pointblue.console.server.auth.DirectoryConfig;
import com.pointblue.console.server.auth.Role;
import com.pointblue.console.server.auth.Sessions;
import com.pointblue.console.server.data.ConfigStore;
import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.console.server.tls.Certs;
import com.pointblue.console.server.tls.TrustStore;
import com.pointblue.dirxml.dev.json.Json;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Certificate expiry monitoring. Once a day (and on request) the console looks at its own TLS certificate, the
 * certificates in its trust store, and, for each directory with a service account, the directory's CA, server
 * certificates and trusted roots. Anything expired or expiring within the warning window is reported to admins,
 * logged in the audit log, and sent to the configured e-mail recipients and webhooks: once when it enters the
 * window, again at 7 days, and once when it has expired.
 *
 * <pre>
 * GET  /api/v2/console/expiry           settings (secrets shown only as set), the last check's findings and errors
 * PUT  /api/v2/console/expiry           {enabled, warnDays, email?, webhooks} (recent sign-in)
 * POST /api/v2/console/expiry/check     check now
 * POST /api/v2/console/expiry/test      send a test notice to every recipient and webhook
 * </pre>
 *
 * All of them need the admin role.
 *
 * <p>Configuration ({@code expiry} in the console's configuration): {enabled, warnDays, email: {host, port,
 * security, user, password (sealed), from, to: [...]}, webhooks: [{url, secret (sealed)}]}. Turned off for tests
 * with {@code console.expiryCheck=off}.
 */
final class Expiry {

    static final int DEFAULT_WARN_DAYS = 30;
    private static final String SECRET = "expiry/email/password";

    private final Server server;
    private volatile ScheduledExecutorService timer;
    private volatile Map<String, Object> last = Map.of();

    Expiry(Server server) {
        this.server = server;
    }

    boolean handles(String path) {
        return path.startsWith("/api/v2/console/expiry");
    }

    void start() {
        if ("off".equals(System.getProperty("console.expiryCheck"))) {
            return;
        }
        ScheduledExecutorService t = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread th = new Thread(r, "expiry-check");
            th.setDaemon(true);
            return th;
        });
        t.scheduleAtFixedRate(() -> {
            if (Boolean.TRUE.equals(settings().get("enabled"))) {
                check(true);
            }
        }, 5, 24 * 60, TimeUnit.MINUTES);
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
            case "GET /api/v2/console/expiry" -> {
                server.session(ex, Role.ADMIN);
                Http.json(ex, 200, state());
            }
            case "PUT /api/v2/console/expiry" -> {
                Sessions.Session s = server.session(ex, Role.ADMIN);
                server.stepUp(s);
                save(s, Http.body(ex));
                Http.json(ex, 200, state());
            }
            case "POST /api/v2/console/expiry/check" -> {
                server.session(ex, Role.ADMIN);
                check(false);
                Http.json(ex, 200, state());
            }
            case "POST /api/v2/console/expiry/test" -> {
                Sessions.Session s = server.session(ex, Role.ADMIN);
                List<Map<String, Object>> results = notify("Directory Console: a test notification",
                    "This is a test of the certificate expiry notifications, sent by " + s.principal.dn() + ".", List.of());
                server.audit.log(Server.who(s), "expiry.test", "console", Map.of("results", results), "ok");
                Http.json(ex, 200, Map.of("results", results));
            }
            default -> throw new Http.Problem(405, "method-not-allowed", method + " " + path);
        }
    }

    // ---- settings ---------------------------------------------------------------------------------

    /** The settings, with secrets shown only as set or not. */
    Map<String, Object> settings() {
        Map<String, Object> e = server.config.read().get("expiry") instanceof Map<?, ?> m ? Json.asMap(m) : Map.of();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("enabled", !Boolean.FALSE.equals(e.get("enabled")));
        out.put("warnDays", e.get("warnDays") instanceof Number n ? n.intValue() : DEFAULT_WARN_DAYS);
        if (e.get("email") instanceof Map<?, ?> em) {
            Map<String, Object> mail = new LinkedHashMap<>(Json.asMap(em));
            mail.put("password", mail.get("password") != null ? Map.of("set", true) : null);
            out.put("email", mail);
        } else {
            out.put("email", null);
        }
        List<Map<String, Object>> hooks = new ArrayList<>();
        Map<String, Object> secrets = e.get("webhookSecrets") instanceof Map<?, ?> sm ? Json.asMap(sm) : Map.of();
        if (e.get("webhooks") instanceof List<?> l) {
            for (Object o : l) {
                Map<String, Object> h = new LinkedHashMap<>(Json.asMap(o));
                h.put("secret", secrets.get(String.valueOf(h.get("id"))) != null ? Map.of("set", true) : null);
                hooks.add(h);
            }
        }
        out.put("webhooks", hooks);
        return out;
    }

    private void save(Sessions.Session s, Map<String, Object> b) throws IOException {
        Map<String, Object> before = server.config.read().get("expiry") instanceof Map<?, ?> m ? Json.asMap(m) : Map.of();
        Map<String, Object> next = new LinkedHashMap<>();
        next.put("enabled", !Boolean.FALSE.equals(b.get("enabled")));
        int warn = b.get("warnDays") instanceof Number n ? n.intValue() : DEFAULT_WARN_DAYS;
        if (warn < 1 || warn > 365) {
            throw new Http.Problem(400, "bad-field", "warnDays is 1 to 365");
        }
        next.put("warnDays", warn);
        if (b.get("email") instanceof Map<?, ?> em) {
            Map<String, Object> e = Json.asMap(em);
            Map<String, Object> mail = new LinkedHashMap<>();
            String host = Http.string(e, "host", true).trim();
            if (!host.matches("[A-Za-z0-9.:\\[\\]-]{1,253}")) {
                throw new Http.Problem(400, "bad-field", "email.host is a host name or address");
            }
            mail.put("host", host);
            String security = e.get("security") == null ? "starttls" : String.valueOf(e.get("security"));
            if (!List.of("starttls", "tls", "none").contains(security)) {
                throw new Http.Problem(400, "bad-field", "email.security is starttls, tls or none");
            }
            mail.put("security", security);
            int port = e.get("port") instanceof Number n ? n.intValue() : security.equals("tls") ? 465 : 587;
            if (port < 1 || port > 65535) {
                throw new Http.Problem(400, "bad-field", "email.port is 1 to 65535");
            }
            mail.put("port", port);
            try {
                mail.put("from", Mail.address(Http.string(e, "from", true)));
                List<String> to = new ArrayList<>();
                if (e.get("to") instanceof List<?> l) {
                    for (Object o : l) {
                        to.add(Mail.address(String.valueOf(o)));
                    }
                }
                if (to.isEmpty()) {
                    throw new IllegalArgumentException("email.to needs at least one address");
                }
                mail.put("to", to);
            } catch (IllegalArgumentException x) {
                throw new Http.Problem(400, "bad-field", x.getMessage());
            }
            String user = e.get("user") == null ? "" : String.valueOf(e.get("user")).trim();
            if (!user.isEmpty()) {
                if (security.equals("none")) {
                    throw new Http.Problem(400, "bad-field", "a mail password is sent only over TLS: choose starttls or tls");
                }
                mail.put("user", user);
                if (e.get("password") instanceof String pw && !pw.isEmpty()) {
                    mail.put("password", server.config.seal(pw, SECRET));
                } else if (before.get("email") instanceof Map<?, ?> old && Json.asMap(old).get("password") != null) {
                    mail.put("password", Json.asMap(old).get("password"));
                }
            }
            next.put("email", mail);
        }
        List<Map<String, Object>> hooks = new ArrayList<>();
        Map<String, Object> oldSecrets = before.get("webhookSecrets") instanceof Map<?, ?> os ? Json.asMap(os) : Map.of();
        Map<String, Object> secrets = new LinkedHashMap<>();
        if (b.get("webhooks") instanceof List<?> l) {
            if (l.size() > 5) {
                throw new Http.Problem(400, "bad-field", "at most 5 webhooks");
            }
            for (Object o : l) {
                Map<String, Object> h = Json.asMap(o);
                String url = Http.string(h, "url", true).trim();
                URI u;
                try {
                    u = URI.create(url);
                } catch (IllegalArgumentException x) {
                    throw new Http.Problem(400, "bad-field", url + " is not a URL");
                }
                boolean loopback = "http".equals(u.getScheme()) && List.of("127.0.0.1", "localhost", "[::1]").contains(String.valueOf(u.getHost()));
                if (!("https".equals(u.getScheme()) || loopback) || u.getHost() == null) {
                    throw new Http.Problem(400, "bad-field", "a webhook is an https:// URL (http:// only to this host)");
                }
                String id = hookId(url);
                Map<String, Object> hook = new LinkedHashMap<>();
                hook.put("url", url);
                hook.put("id", id);
                if (h.get("secret") instanceof String sec && !sec.isEmpty()) {
                    secrets.put(id, server.config.seal(sec, "expiry/webhookSecrets/" + id));
                } else if (!Boolean.TRUE.equals(h.get("clearSecret")) && oldSecrets.get(id) != null) {
                    secrets.put(id, oldSecrets.get(id));
                }
                hooks.add(hook);
            }
        }
        next.put("webhookSecrets", secrets);
        next.put("webhooks", hooks);
        try {
            server.config.update(server.config.version(), s.principal.dn(), "certificate expiry settings", doc -> doc.put("expiry", next));
        } catch (ConfigStore.Conflict c) {
            throw new Http.Problem(409, "conflict", "the configuration changed meanwhile; try again");
        }
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("enabled", next.get("enabled"));
        detail.put("warnDays", warn);
        detail.put("email", next.get("email") == null ? null : Json.asMap(next.get("email")).get("to"));
        detail.put("webhooks", hooks.stream().map(h -> h.get("url")).toList());
        server.audit.log(Server.who(s), "settings.expiry", "console", detail, "ok");
    }

    /** A webhook's key for its secret: from its URL, so a secret follows its webhook. */
    static String hookId(String url) {
        try {
            return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(url.getBytes(StandardCharsets.UTF_8))).substring(0, 16);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    // ---- the check --------------------------------------------------------------------------------

    /** What admins see: the settings and the last check's findings. */
    Map<String, Object> state() {
        Map<String, Object> m = new LinkedHashMap<>(last);
        m.put("settings", settings());
        return m;
    }

    /** One certificate to watch. */
    record Watched(String key, String kind, String name, String where, Instant notAfter) {
    }

    /** Every certificate the console can see now, with the errors that kept it from seeing others. */
    List<Watched> watched(List<String> errors) {
        List<Watched> out = new ArrayList<>();
        X509Certificate own = server.tls.certificate();
        out.add(new Watched(Certs.sha256(own), "console", "The console's TLS certificate", "console", own.getNotAfter().toInstant()));
        try {
            for (TrustStore.Entry t : server.trust.entries()) {
                out.add(new Watched(Certs.sha256(t.cert()), "trusted", t.cert().getSubjectX500Principal().getName(), "console trust store",
                    t.cert().getNotAfter().toInstant()));
            }
        } catch (IOException e) {
            errors.add("the console's trust store: " + e.getMessage());
        }
        for (DirectoryConfig d : DirectoryConfig.all(server.config.read())) {
            if (d.serviceAccountDn() == null) {
                continue;
            }
            String pw = server.config.secret(d.serviceAccountPasswordPath());
            if (pw == null) {
                continue;
            }
            try (Ldap l = Ldap.connect(server.trust, d.target(), null, d.serviceAccountDn(), pw.toCharArray(), Server.T)) {
                Map<String, Object> pki = server.security.pki(l);
                Map<String, Object> ca = Json.asMap(pki.get("ca"));
                if (ca.get("certificates") instanceof List<?> cs) {
                    for (Object o : cs) {
                        add(out, Json.asMap(o), "ca", "Organizational CA " + ca.getOrDefault("name", ""), d.name());
                    }
                }
                for (Object o : (List<?>) pki.getOrDefault("serverCertificates", List.of())) {
                    Map<String, Object> k = Json.asMap(o);
                    if (k.get("certificate") != null) {
                        add(out, Json.asMap(k.get("certificate")), "server", String.valueOf(k.get("name")), d.name());
                    }
                }
                for (Object o : (List<?>) pki.getOrDefault("trustedRoots", List.of())) {
                    Map<String, Object> r = Json.asMap(o);
                    if (r.get("certificate") != null) {
                        add(out, Json.asMap(r.get("certificate")), "trusted-root", String.valueOf(r.get("name")), d.name());
                    }
                }
            } catch (Exception e) {
                errors.add(d.name() + ": " + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            }
        }
        return out;
    }

    private static void add(List<Watched> out, Map<String, Object> c, String kind, String name, String where) {
        if (c.get("notAfter") == null) {
            return;
        }
        String key = c.get("sha256") != null ? String.valueOf(c.get("sha256")) : kind + ":" + where + ":" + name + ":" + c.get("serial");
        out.add(new Watched(key, kind, name, where, Instant.parse(String.valueOf(c.get("notAfter")))));
    }

    /** The level a certificate has reached: expired, within 7 days, within the warning window, or fine (null). */
    static String level(Instant notAfter, Instant now, int warnDays) {
        if (!notAfter.isAfter(now)) {
            return "expired";
        }
        long days = Duration.between(now, notAfter).toDays();
        return days < 7 ? "7days" : days < warnDays ? "warn" : null;
    }

    /** Look now; with {@code send}, notify about certificates that reached a new level since they were last notified. */
    synchronized void check(boolean send) {
        Instant now = Instant.now();
        int warn = (Integer) settings().get("warnDays");
        List<String> errors = new ArrayList<>();
        List<Map<String, Object>> findings = new ArrayList<>();
        Map<String, String> notified = readNotified();
        Map<String, String> next = new LinkedHashMap<>();
        List<Map<String, Object>> fresh = new ArrayList<>();
        for (Watched w : watched(errors)) {
            String lvl = level(w.notAfter(), now, warn);
            if (lvl == null) {
                continue;
            }
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("kind", w.kind());
            f.put("name", w.name());
            f.put("where", w.where());
            f.put("notAfter", w.notAfter().toString());
            f.put("days", Duration.between(now, w.notAfter()).toDays());
            f.put("level", lvl);
            findings.add(f);
            next.put(w.key(), lvl);
            if (!lvl.equals(notified.get(w.key()))) {
                fresh.add(f);
            }
        }
        findings.sort((a, b) -> String.valueOf(a.get("notAfter")).compareTo(String.valueOf(b.get("notAfter"))));
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("checkedAt", now.toString());
        m.put("findings", findings);
        m.put("errors", errors);
        if (send && !fresh.isEmpty()) {
            try {
                server.audit.log(new com.pointblue.console.server.audit.AuditLog.Actor("console", null, "schedule"), "expiry.found", "console",
                    Map.of("certificates", fresh), "ok");
            } catch (IOException x) {
                errors.add("the audit log: " + x.getMessage());
            }
            StringBuilder body = new StringBuilder("Certificates that need attention:\n\n");
            for (Map<String, Object> f : fresh) {
                body.append("- ").append(f.get("name")).append(" (").append(f.get("where")).append("): ")
                    .append("expired".equals(f.get("level")) ? "expired " : "expires ").append(f.get("notAfter").toString(), 0, 10)
                    .append("expired".equals(f.get("level")) ? "" : " (in " + f.get("days") + " days)").append('\n');
            }
            body.append("\nSee Certificates and Security > Certificates in Directory Console").append(server.publicUrl == null ? "" : " (" + server.publicUrl + ")").append(".\n");
            m.put("sent", notify("Directory Console: " + fresh.size() + " certificate" + (fresh.size() == 1 ? "" : "s") + " expiring or expired", body.toString(), fresh));
            writeNotified(next);
        } else if (send) {
            writeNotified(next);
        }
        last = m;
    }

    private Path notifiedFile() {
        return server.data.root().resolve("expiry-notified.json");
    }

    private Map<String, String> readNotified() {
        try {
            Path f = notifiedFile();
            if (Files.exists(f)) {
                Map<String, String> out = new LinkedHashMap<>();
                Json.asMap(Json.parse(Files.readString(f))).forEach((k, v) -> out.put(k, String.valueOf(v)));
                return out;
            }
        } catch (IOException | RuntimeException e) {
            // start afresh: at worst a notice is sent again
        }
        return Map.of();
    }

    private void writeNotified(Map<String, String> m) {
        try {
            Files.writeString(notifiedFile(), Json.compact(m));
        } catch (IOException e) {
            // the next check notifies again
        }
    }

    // ---- notifications ----------------------------------------------------------------------------

    /** Send to every configured destination; each answers {destination, ok, error?}. Never throws. */
    List<Map<String, Object>> notify(String subject, String body, List<Map<String, Object>> certificates) {
        List<Map<String, Object>> results = new ArrayList<>();
        Map<String, Object> e = server.config.read().get("expiry") instanceof Map<?, ?> m ? Json.asMap(m) : Map.of();
        if (e.get("email") instanceof Map<?, ?> em) {
            Map<String, Object> mail = Json.asMap(em);
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("destination", "e-mail to " + String.join(", ", ((List<?>) mail.get("to")).stream().map(String::valueOf).toList()));
            try {
                List<String> to = ((List<?>) mail.get("to")).stream().map(String::valueOf).toList();
                Mail.send(new Mail.Smtp(String.valueOf(mail.get("host")), ((Number) mail.get("port")).intValue(),
                    Mail.Security.valueOf(String.valueOf(mail.get("security")).toUpperCase(java.util.Locale.ROOT)),
                    mail.get("user") == null ? null : String.valueOf(mail.get("user")), server.config.secret(SECRET), String.valueOf(mail.get("from"))),
                    to, subject, body);
                r.put("ok", true);
            } catch (IOException | RuntimeException x) {
                r.put("ok", false);
                r.put("error", x.getMessage() == null ? x.getClass().getSimpleName() : x.getMessage());
            }
            results.add(r);
        }
        if (e.get("webhooks") instanceof List<?> l) {
            for (int i = 0; i < l.size(); i++) {
                Map<String, Object> h = Json.asMap(l.get(i));
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("destination", String.valueOf(h.get("url")));
                try {
                    Map<String, Object> payload = new LinkedHashMap<>();
                    payload.put("event", certificates.isEmpty() ? "test" : "certificates.expiring");
                    payload.put("subject", subject);
                    payload.put("text", body);
                    payload.put("certificates", certificates);
                    payload.put("console", server.publicUrl);
                    payload.put("sentAt", Instant.now().toString());
                    String json = Json.compact(payload);
                    HttpRequest.Builder req = HttpRequest.newBuilder(URI.create(String.valueOf(h.get("url")))).timeout(Duration.ofSeconds(15))
                        .header("Content-Type", "application/json").header("User-Agent", "directory-console/" + server.updates.version())
                        .POST(HttpRequest.BodyPublishers.ofString(json));
                    String secret = h.get("id") == null ? null : server.config.secret("expiry/webhookSecrets/" + h.get("id"));
                    if (secret != null) {
                        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
                        mac.init(new javax.crypto.spec.SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
                        req.header("X-Console-Signature", "sha256=" + java.util.HexFormat.of().formatHex(mac.doFinal(json.getBytes(StandardCharsets.UTF_8))));
                    }
                    HttpClient.Builder cb = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10));
                    java.net.ProxySelector proxy = Updates.proxy();
                    if (proxy != null) {
                        cb.proxy(proxy);
                    }
                    HttpResponse<String> resp = cb.build().send(req.build(), HttpResponse.BodyHandlers.ofString());
                    r.put("ok", resp.statusCode() / 100 == 2);
                    if (resp.statusCode() / 100 != 2) {
                        r.put("error", "HTTP " + resp.statusCode());
                    }
                } catch (InterruptedException x) {
                    Thread.currentThread().interrupt();
                    r.put("ok", false);
                    r.put("error", "interrupted");
                } catch (Exception x) {
                    r.put("ok", false);
                    r.put("error", x.getMessage() == null ? x.getClass().getSimpleName() : x.getMessage());
                }
                results.add(r);
            }
        }
        return results;
    }
}
