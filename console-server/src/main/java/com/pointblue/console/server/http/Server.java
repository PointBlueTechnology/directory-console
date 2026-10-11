package com.pointblue.console.server.http;

import com.pointblue.console.server.audit.AuditLog;
import com.pointblue.console.server.auth.DirectLogin;
import com.pointblue.console.server.auth.DirectoryConfig;
import com.pointblue.console.server.auth.Role;
import com.pointblue.console.server.auth.Sessions;
import com.pointblue.console.server.auth.Throttle;
import com.pointblue.console.server.data.ConfigStore;
import com.pointblue.console.server.data.DataDir;
import com.pointblue.console.server.data.SecretBox;
import com.pointblue.console.server.tls.Certs;
import com.pointblue.console.server.tls.ConsoleTls;
import com.pointblue.console.server.tls.Probe;
import com.pointblue.console.server.tls.TrustStore;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import javax.net.ssl.SSLParameters;

/**
 * The Directory Console HTTPS server. Until the first configuration exists it is in bootstrap mode
 * (only health and the token-guarded setup API answer); afterwards it serves the API to signed-in
 * people. Every response carries the security headers; requests naming another host are refused (DNS
 * rebinding); a state-changing request from a browser must come from this origin and, with a session,
 * carry its CSRF token.
 */
public final class Server {

    static final String COOKIE = "__Host-console";
    static final Duration STEP_UP = Duration.ofMinutes(10);
    private static final Duration T = Duration.ofSeconds(10);

    final DataDir data;
    final ConfigStore config;
    final AuditLog audit;
    final TrustStore trust;
    final ConsoleTls tls;
    final Probe probes = new Probe();
    final Sessions sessions = new Sessions(Duration.ofMinutes(30), Duration.ofHours(12));
    final DirectLogin login;
    final com.pointblue.console.server.auth.OidcLogin oidc;
    final String publicUrl;
    private final Set<String> hosts;
    private final Throttle failedByClient = new Throttle(10, Duration.ofMinutes(1));
    private final Throttle failedByName = new Throttle(5, Duration.ofMinutes(5));
    private final HttpsServer http;
    private volatile Bootstrap bootstrap;
    private volatile Setup setup;
    final Objects objects = new Objects(this);
    private final Idm idm = new Idm(this);
    private final Settings settings = new Settings(this);
    private final StaticFiles ui = new StaticFiles("web");

    /** Open the data directory and listen on {@code port}. {@code publicUrl} is how browsers reach this server. */
    public Server(DataDir data, int port, String publicUrl, PrintStream out) throws IOException, GeneralSecurityException {
        this.data = data;
        this.config = new ConfigStore(data, SecretBox.open(data.keys().resolve("config.key")));
        this.audit = new AuditLog(data);
        this.trust = new TrustStore(data);
        URI pub = URI.create(publicUrl);
        List<String> names = new ArrayList<>(List.of(pub.getHost(), "localhost", "127.0.0.1"));
        String hostname = System.getenv("HOSTNAME");
        if (hostname != null && !hostname.isBlank() && !names.contains(hostname)) {
            names.add(hostname);
        }
        this.tls = ConsoleTls.loadOrGenerate(data, names.stream().distinct().toList());
        this.publicUrl = publicUrl.replaceAll("/+$", "");
        this.hosts = Set.copyOf(names.stream().map(h -> h.toLowerCase(Locale.ROOT)).toList());
        this.login = new DirectLogin(trust);
        this.oidc = new com.pointblue.console.server.auth.OidcLogin(trust, this.publicUrl);
        this.login.engines(com.pointblue.console.server.idm.Engines.detect());
        this.http = HttpsServer.create(new InetSocketAddress(port), 64);
        http.setHttpsConfigurator(new HttpsConfigurator(tls.context()) {
            @Override
            public void configure(HttpsParameters p) {
                SSLParameters sp = tls.context().getDefaultSSLParameters();
                sp.setProtocols(new String[] {"TLSv1.3", "TLSv1.2"});
                p.setSSLParameters(sp);
            }
        });
        http.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        http.createContext("/", this::handle);
        if (config.empty()) {
            bootstrap = new Bootstrap(data, tls, this.publicUrl, out);
            setup = new Setup(this);
        }
        audit.log(AuditLog.Actor.SYSTEM, "startup", null, Map.of("mode", bootstrap == null ? "configured" : "bootstrap",
            "consoleCertificate", Certs.sha256(tls.certificate())), "ok");
    }

    public void start() {
        http.start();
    }

    public void stop() {
        http.stop(1);
    }

    public int port() {
        return http.getAddress().getPort();
    }

    public boolean bootstrapping() {
        return bootstrap != null;
    }

    /** Called by setup's finish: the configuration exists now. */
    void leaveBootstrap() throws IOException {
        if (bootstrap != null) {
            bootstrap.finish();
        }
        bootstrap = null;
        setup = null;
    }

    // ---- request handling -------------------------------------------------------------------------

    private void handle(HttpExchange ex) {
        try (ex) {
            headers(ex);
            String path = ex.getRequestURI().getPath();
            String method = ex.getRequestMethod();
            try {
                checkHost(ex);
                checkOrigin(ex, method);
                route(ex, path, method);
            } catch (Http.Problem p) {
                Http.problem(ex, p);
            } catch (RuntimeException e) {
                Http.problem(ex, new Http.Problem(500, "internal", "unexpected error: " + e.getClass().getSimpleName()));
            } catch (LinkageError e) {
                // a library class is missing (an engine jar not mounted): answer, never drop the connection
                Http.problem(ex, new Http.Problem(500, "missing-library", "a library this needs is not installed: " + e.getMessage()));
            }
        } catch (IOException e) {
            // the client went away
        }
    }

    private void headers(HttpExchange ex) {
        var h = ex.getResponseHeaders();
        h.set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'");
        h.set("X-Content-Type-Options", "nosniff");
        h.set("Referrer-Policy", "no-referrer");
        h.set("Cache-Control", "no-store");
        h.set("Cross-Origin-Opener-Policy", "same-origin");
        if (!Certs.selfSigned(tls.certificate())) {
            h.set("Strict-Transport-Security", "max-age=31536000");
        }
    }

    private void checkHost(HttpExchange ex) {
        String host = ex.getRequestHeaders().getFirst("Host");
        if (host == null) {
            throw new Http.Problem(400, "bad-host", "a Host header is required");
        }
        String h = host.toLowerCase(Locale.ROOT).replaceAll(":\\d+$", "").replaceAll("^\\[(.*)]$", "$1");
        if (!hosts.contains(h)) {
            throw new Http.Problem(421, "misdirected", "this console does not answer to " + host);
        }
    }

    private void checkOrigin(HttpExchange ex, String method) {
        if (method.equals("GET") || method.equals("HEAD")) {
            return;
        }
        String origin = ex.getRequestHeaders().getFirst("Origin");
        if (origin == null) {
            return;   // not a browser cross-site request; sessions still need the CSRF token
        }
        String host = ex.getRequestHeaders().getFirst("Host");
        if (!origin.equalsIgnoreCase("https://" + host)) {
            throw new Http.Problem(403, "cross-origin", "requests must come from this console's own page");
        }
    }

    private void route(HttpExchange ex, String path, String method) throws IOException {
        if (path.equals("/api/v2/health/live")) {
            Http.json(ex, 200, Map.of("status", "live"));
            return;
        }
        if (path.equals("/api/v2/health/ready")) {
            if (bootstrap != null) {
                Http.json(ex, 503, Map.of("status", "setup-required"));
            } else {
                Http.json(ex, 200, Map.of("status", "ready"));
            }
            return;
        }
        if (!path.startsWith("/api/")) {
            // the web UI, in bootstrap mode too (it then shows where to find the setup token)
            ui.serve(ex, path, method);
            return;
        }
        Bootstrap b = bootstrap;
        if (b != null) {
            if (!path.startsWith("/api/v2/setup")) {
                throw new Http.Problem(503, "setup-required", "Directory Console is not configured yet; finish setup with the token in the container log");
            }
            if (!b.check(ex.getRequestHeaders().getFirst("X-Setup-Token"), Http.client(ex))) {
                throw new Http.Problem(401, "setup-token", "a valid X-Setup-Token header is required");
            }
            setup.handle(ex, path, method);
            return;
        }
        if (path.startsWith("/api/v2/setup")) {
            throw new Http.Problem(404, "not-found", "setup is finished");
        }
        if (path.startsWith("/api/v2/trees/") && path.matches("/api/v2/trees/[^/]+/idm(/.*)?")) {
            idm.handle(ex, path, method);
            return;
        }
        if (path.matches("/api/v2/directories/[^/]+/.+")) {
            settings.handle(ex, path, method);
            return;
        }
        if (path.startsWith("/api/v2/trees/")) {
            objects.handle(ex, path, method);
            return;
        }
        switch (method + " " + path) {
            case "GET /api/v2/directories" -> directories(ex);
            case "POST /api/v2/session" -> signIn(ex);
            case "GET /api/v2/oidc/start" -> oidcStart(ex);
            case "GET /api/v2/oidc/callback" -> oidcCallback(ex);
            case "GET /api/v2/session" -> Http.json(ex, 200, me(session(ex, null)));
            case "DELETE /api/v2/session" -> signOut(ex);
            case "GET /api/v2/trust/certificates" -> trustList(ex);
            case "POST /api/v2/trust/probe" -> trustProbe(ex);
            case "POST /api/v2/trust/certificates" -> trustAdd(ex);
            case "POST /api/v2/trust/host-exceptions" -> hostException(ex);
            case "GET /api/v2/config" -> {
                session(ex, Role.ADMIN);
                Http.json(ex, 200, config.redacted());
            }
            case "GET /api/v2/audit/verify" -> {
                session(ex, Role.ADMIN);
                AuditLog.Verification v = audit.verify();
                Http.json(ex, 200, Map.of("intact", v.intact(), "lines", v.lines(), "problem", v.problem() == null ? "" : v.problem()));
            }
            default -> {
                if (method.equals("DELETE") && path.startsWith("/api/v2/trust/certificates/")) {
                    trustRemove(ex, path.substring("/api/v2/trust/certificates/".length()));
                } else {
                    throw new Http.Problem(404, "not-found", method + " " + path);
                }
            }
        }
    }

    // ---- sessions -------------------------------------------------------------------------------

    /** The caller's session, refusing without one, without {@code role}, or without the CSRF token on a write. */
    Sessions.Session session(HttpExchange ex, Role role) {
        Sessions.Session s = sessions.get(Http.cookie(ex, COOKIE));
        if (s == null) {
            throw new Http.Problem(401, "sign-in-required", "sign in first");
        }
        if (!ex.getRequestMethod().equals("GET")) {
            String token = ex.getRequestHeaders().getFirst("X-CSRF-Token");
            if (token == null || !java.security.MessageDigest.isEqual(token.getBytes(StandardCharsets.US_ASCII), s.csrf.getBytes(StandardCharsets.US_ASCII))) {
                throw new Http.Problem(403, "csrf", "the X-CSRF-Token header is missing or wrong");
            }
        }
        if (role != null && !s.principal.has(role)) {
            throw new Http.Problem(403, "forbidden", "this needs the " + role.id() + " role");
        }
        return s;
    }

    void stepUp(Sessions.Session s) {
        if (!sessions.recentlyAuthenticated(s, STEP_UP)) {
            throw new Http.Problem(403, "step-up-required", "sign in again to make this change (it needs a sign-in within the last 10 minutes)");
        }
    }

    /** The audit actor for a session. */
    private static AuditLog.Actor who(Sessions.Session s) {
        return new AuditLog.Actor(s.principal.subject(), s.principal.dn(), s.principal.via());
    }

    private Map<String, Object> me(Sessions.Session s) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", s.principal.name());
        m.put("dn", s.principal.dn());
        m.put("directory", s.principal.directoryId());
        m.put("roles", s.principal.roles().stream().map(Role::id).sorted().toList());
        m.put("grants", s.principal.grants().stream().map(g -> {
            Map<String, Object> gm = new LinkedHashMap<>();
            gm.put("role", g.role() == null ? null : g.role().id());
            gm.put("scopes", g.scopes());
            gm.put("presets", g.presets());
            return gm;
        }).toList());
        m.put("via", s.principal.via());
        m.put("csrf", s.csrf);
        return m;
    }

    private void directories(HttpExchange ex) throws IOException {
        List<Map<String, Object>> out = new ArrayList<>();
        for (DirectoryConfig d : DirectoryConfig.all(config.read())) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", d.id());
            m.put("name", d.name());
            m.put("direct", d.directLogin());
            if (d.oidc() != null) {
                m.put("sso", d.oidc().label());
            }
            out.add(m);
        }
        Http.json(ex, 200, out);
    }

    private void signIn(HttpExchange ex) throws IOException {
        Map<String, Object> b = Http.body(ex);
        String client = Http.client(ex);
        String dirId = Http.string(b, "directory", true);
        String name = Http.string(b, "name", false);
        String choice = Http.string(b, "choice", false);
        String nameKey = dirId + "|" + String.valueOf(name).toLowerCase(Locale.ROOT);
        if (!failedByClient.allowed(client) || (name != null && !failedByName.allowed(nameKey))) {
            throw new Http.Problem(429, "too-many-attempts", "too many failed sign-ins; wait a few minutes");
        }
        DirectoryConfig d = DirectoryConfig.find(config.read(), dirId);
        if (d == null) {
            throw new Http.Problem(404, "unknown-directory", "no directory " + dirId);
        }
        char[] pw = Http.string(b, "password", true).toCharArray();
        DirectLogin.Outcome o = login.login(d, config.secret(d.serviceAccountPasswordPath()), name, pw, choice);
        java.util.Arrays.fill(pw, '\0');
        AuditLog.Actor who = new AuditLog.Actor(name == null ? "(choice)" : name, null, "direct");
        switch (o) {
            case DirectLogin.SignedIn s -> {
                failedByClient.clear(client);
                failedByName.clear(nameKey);
                Sessions.Session session = sessions.create(s.principal(), s.connection(), s.engine(), s.engineProblem());
                audit.log(new AuditLog.Actor(s.principal().subject(), s.principal().dn(), s.principal().via()), "sign-in", dirId,
                    Map.of("roles", s.principal().roles().stream().map(Role::id).sorted().toList(), "client", client), "ok");
                ex.getResponseHeaders().add("Set-Cookie", COOKIE + "=" + session.id + "; Path=/; Secure; HttpOnly; SameSite=Strict");
                Http.json(ex, 200, me(session));
            }
            case DirectLogin.Choose c -> {
                failedByClient.record(client);   // a choose step counts like a failure toward the per-address limit
                audit.log(who, "sign-in.choose", dirId, Map.of("candidates", c.candidates().size(), "client", client), "choose");
                List<Map<String, Object>> list = new ArrayList<>();
                for (DirectLogin.Candidate cand : c.candidates()) {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("choice", cand.token());
                    m.put("context", cand.context());
                    if (cand.label() != null) {
                        m.put("label", cand.label());
                    }
                    list.add(m);
                }
                throw new Http.Problem(409, "choose-account", "More than one account has this name. Choose yours and sign in again.", Map.of("candidates", list));
            }
            case DirectLogin.Refused r -> {
                if (r.code().equals("bad-credentials") || r.code().equals("ambiguous")) {
                    failedByClient.record(client);
                    if (name != null) {
                        failedByName.record(nameKey);
                    }
                }
                audit.log(who, "sign-in", dirId, Map.of("client", client, "code", r.code()), "refused");
                int status = switch (r.code()) {
                    case "bad-credentials" -> 401;
                    case "untrusted-certificate", "ambiguous", "choice-expired", "full-name-required" -> 409;
                    case "no-role", "not-allowed" -> 403;
                    default -> 503;
                };
                Map<String, Object> extra = r.untrusted() == null ? Map.of()
                    : Map.of("reason", r.untrusted().reason.name().toLowerCase(Locale.ROOT), "hint", "an administrator can probe the directory and trust its certificate");
                throw new Http.Problem(status, r.code(), r.message(), extra);
            }
        }
    }

    static final String OIDC_COOKIE = "__Host-console-oidc";

    /**
     * Begin single sign-on: redirect to the provider. The state also goes into a short-lived cookie
     * (SameSite=Lax, so it comes back on the provider's top-level redirect), and the callback must
     * match it: a sign-in started in another browser cannot be finished in this one.
     */
    private void oidcStart(HttpExchange ex) throws IOException {
        Map<String, String> q = Http.query(ex);
        DirectoryConfig d = DirectoryConfig.find(config.read(), q.getOrDefault("directory", ""));
        if (d == null || d.oidc() == null) {
            throw new Http.Problem(404, "no-sso", "single sign-on is not configured for that directory");
        }
        if (!failedByClient.allowed(Http.client(ex))) {
            throw new Http.Problem(429, "too-many-attempts", "too many failed sign-ins; wait a few minutes");
        }
        com.pointblue.console.auth.OidcClient.Start start;
        try {
            start = oidc.start(d, config.secret(d.oidcSecretPath()), safeNext(q.get("next")));
        } catch (IOException e) {
            audit.log(new AuditLog.Actor("(sso)", null, "oidc"), "sign-in", d.id(), Map.of("client", Http.client(ex), "code", "provider"), "refused");
            redirect(ex, "/?sso-error=provider");
            return;
        }
        ex.getResponseHeaders().add("Set-Cookie", OIDC_COOKIE + "=" + start.state() + "; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600");
        redirect(ex, start.url());
    }

    private void oidcCallback(HttpExchange ex) throws IOException {
        Map<String, String> q = Http.query(ex);
        String client = Http.client(ex);
        ex.getResponseHeaders().add("Set-Cookie", OIDC_COOKIE + "=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0");
        String state = q.get("state");
        String cookie = Http.cookie(ex, OIDC_COOKIE);
        String dirId = oidc.directoryOf(state);
        AuditLog.Actor anon = new AuditLog.Actor("(sso)", null, "oidc");
        if (dirId == null || cookie == null || !java.security.MessageDigest.isEqual(cookie.getBytes(StandardCharsets.US_ASCII), state.getBytes(StandardCharsets.US_ASCII))) {
            failedByClient.record(client);
            audit.log(anon, "sign-in", dirId, Map.of("client", client, "code", "state"), "refused");
            redirect(ex, "/?sso-error=state");
            return;
        }
        DirectoryConfig d = DirectoryConfig.find(config.read(), dirId);
        Object o = d == null ? new com.pointblue.console.server.auth.OidcLogin.Refused("not-configured", "")
            : oidc.finish(d, config.secret(d.oidcSecretPath()), config.secret(d.serviceAccountPasswordPath()), q);
        if (o instanceof com.pointblue.console.server.auth.OidcLogin.SignedIn si) {
            failedByClient.clear(client);
            Sessions.Session session = sessions.create(si.principal(), si.connection(), null, com.pointblue.console.server.auth.OidcLogin.NO_ENGINE);
            audit.log(new AuditLog.Actor(si.principal().subject(), si.principal().dn(), "oidc"), "sign-in", dirId,
                Map.of("roles", si.principal().roles().stream().map(Role::id).sorted().toList(), "client", client), "ok");
            ex.getResponseHeaders().add("Set-Cookie", COOKIE + "=" + session.id + "; Path=/; Secure; HttpOnly; SameSite=Strict");
            redirect(ex, safeNext(si.next()));
            return;
        }
        com.pointblue.console.server.auth.OidcLogin.Refused r = (com.pointblue.console.server.auth.OidcLogin.Refused) o;
        failedByClient.record(client);
        audit.log(anon, "sign-in", dirId, Map.of("client", client, "code", r.code(), "detail", r.message()), "refused");
        redirect(ex, "/?sso-error=" + r.code());
    }

    /** A same-site path to return to after sign-in; anything else becomes "/". */
    static String safeNext(String next) {
        return next != null && next.startsWith("/") && !next.startsWith("//") && !next.startsWith("/\\") && !next.contains("\r") && !next.contains("\n") ? next : "/";
    }

    private static void redirect(HttpExchange ex, String location) throws IOException {
        ex.getResponseHeaders().set("Location", location);
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.sendResponseHeaders(302, -1);
        ex.close();
    }

    private void signOut(HttpExchange ex) throws IOException {
        Sessions.Session s = session(ex, null);
        sessions.remove(s.id);
        audit.log(who(s), "sign-out", null, Map.of(), "ok");
        ex.getResponseHeaders().add("Set-Cookie", COOKIE + "=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0");
        Http.json(ex, 204, Map.of());
    }

    // ---- trust ----------------------------------------------------------------------------------

    private void trustList(HttpExchange ex) throws IOException {
        session(ex, Role.ADMIN);
        List<Map<String, Object>> out = new ArrayList<>();
        for (TrustStore.Entry e : trust.entries()) {
            out.add(e.json());
        }
        List<Map<String, Object>> exceptions = new ArrayList<>();
        for (TrustStore.HostException h : trust.hostExceptions()) {
            exceptions.add(Map.of("host", h.host(), "port", h.port(), "leafId", h.leafId(), "addedBy", h.addedBy(), "addedAt", h.addedAt().toString()));
        }
        Http.json(ex, 200, Map.of("certificates", out, "hostExceptions", exceptions));
    }

    private void trustProbe(HttpExchange ex) throws IOException {
        Sessions.Session s = session(ex, Role.ADMIN);
        Map<String, Object> b = Http.body(ex);
        String dirId = Http.string(b, "directory", false);
        String host = Http.string(b, "host", false);
        int port = Http.integer(b, "port", 636);
        if (dirId != null) {
            DirectoryConfig d = DirectoryConfig.find(config.read(), dirId);
            if (d == null) {
                throw new Http.Problem(404, "unknown-directory", "no directory " + dirId);
            }
            host = d.host();
            port = d.port();
        }
        if (host == null) {
            throw new Http.Problem(400, "missing-field", "directory, or host and port, is required");
        }
        try {
            Probe.Result r = probes.probe(host, port, s.id, T);
            Http.json(ex, 200, probeJson(r, dirId, s.principal.subject()));
        } catch (IOException e) {
            throw new Http.Problem(502, "probe-failed", host + ":" + port + ": " + e.getMessage());
        }
    }

    Map<String, Object> probeJson(Probe.Result r, String directoryId, String subject) throws IOException {
        X509Certificate[] chain = r.chain().toArray(new X509Certificate[0]);
        TrustStore.Evaluation ev = trust.evaluate(chain, r.host(), r.port(), directoryId, subject);
        List<Map<String, Object>> certs = new ArrayList<>();
        for (int i = 0; i < chain.length; i++) {
            X509Certificate c = chain[i];
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("index", i);
            m.put("subject", c.getSubjectX500Principal().getName());
            m.put("issuer", c.getIssuerX500Principal().getName());
            m.put("sha256", Certs.sha256(c));
            m.put("notBefore", c.getNotBefore().toInstant().toString());
            m.put("notAfter", c.getNotAfter().toInstant().toString());
            m.put("names", Certs.names(c));
            m.put("selfSigned", Certs.selfSigned(c));
            certs.add(m);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("probeId", r.id());
        out.put("host", r.host());
        out.put("port", r.port());
        out.put("status", ev.trusted() ? "trusted" : ev.reason().name().toLowerCase(Locale.ROOT).replace('_', '-'));
        out.put("message", ev.message());
        out.put("hostnameMatches", ev.hostnameMatches());
        out.put("chain", certs);
        out.put("recommended", Probe.recommended(r.chain()));
        out.put("confirm", "type the last 8 hex digits of the chosen certificate's SHA-256 fingerprint; check it independently first, "
            + "in iManager's certificate view or with: openssl s_client -connect " + r.host() + ":" + r.port() + " -showcerts");
        return out;
    }

    private void trustAdd(HttpExchange ex) throws IOException {
        Sessions.Session s = session(ex, Role.ADMIN);
        stepUp(s);
        Map<String, Object> b = Http.body(ex);
        String scope = b.get("scope") == null ? "global" : Http.string(b, "scope", true);
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
            Probe.Result r = probes.get(Http.string(b, "probeId", true), s.id);
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
            how = "probe";
        }
        String kindText = Http.string(b, "kind", false);
        TrustStore.Kind kind = kindText == null
            ? (Certs.selfSigned(cert) || cert.getBasicConstraints() >= 0 ? TrustStore.Kind.CA : TrustStore.Kind.PINNED_SERVER)
            : (kindText.equals("pinned-server") ? TrustStore.Kind.PINNED_SERVER : TrustStore.Kind.CA);
        TrustStore.Entry e;
        try {
            e = trust.add(cert, kind, scope, s.principal.dn(), how);
        } catch (IllegalArgumentException bad) {
            throw new Http.Problem(400, "bad-field", bad.getMessage());
        }
        audit.log(who(s), "trust.add", e.id(), Map.of("scope", scope, "kind", kind.name(), "how", how, "sha256", Certs.sha256(cert)), "ok");
        Http.json(ex, 201, e.json());
    }

    private void trustRemove(HttpExchange ex, String id) throws IOException {
        Sessions.Session s = session(ex, Role.ADMIN);
        stepUp(s);
        boolean removed = trust.remove(id);
        audit.log(who(s), "trust.remove", id, Map.of(), removed ? "ok" : "not-found");
        if (!removed) {
            throw new Http.Problem(404, "not-found", "no trusted certificate " + id);
        }
        Http.json(ex, 204, Map.of());
    }

    private void hostException(HttpExchange ex) throws IOException {
        Sessions.Session s = session(ex, Role.ADMIN);
        stepUp(s);
        Map<String, Object> b = Http.body(ex);
        Probe.Result r = probes.get(Http.string(b, "probeId", true), s.id);
        if (r == null) {
            throw new Http.Problem(409, "probe-expired", "that probe is unknown or expired; probe again");
        }
        X509Certificate leaf = r.chain().get(0);
        if (!TrustStore.confirmed(leaf, Http.string(b, "confirm", false))) {
            throw new Http.Problem(400, "confirmation-mismatch", "type the last 8 hex digits of the server certificate's fingerprint");
        }
        trust.addHostException(r.host(), r.port(), leaf, s.principal.dn());
        audit.log(who(s), "trust.host-exception", r.host() + ":" + r.port(), Map.of("leaf", Certs.sha256(leaf)), "ok");
        Http.json(ex, 201, Map.of("host", r.host(), "port", r.port(), "leaf", Certs.sha256(leaf)));
    }
}
