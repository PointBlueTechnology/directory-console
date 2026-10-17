package com.pointblue.console.server.http;

import com.pointblue.console.server.auth.Role;
import com.pointblue.console.server.auth.Sessions;
import com.pointblue.console.server.data.ConfigStore;
import com.pointblue.dirxml.dev.json.Json;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The console's own version, and whether a newer release exists. Once a day, and when an admin asks, the
 * console reads the latest release from GitHub's public API. It sends nothing about the installation, only
 * the request itself. On by default; admins can turn it off for consoles that must not call out. A check that
 * fails changes nothing else: it is recorded with its reason, and admins see that the console could not check.
 *
 * <pre>
 * GET  /api/v2/console/version          {version}; for admins also {update: {enabled, latest, newer, url, checkedAt, error}}
 * PUT  /api/v2/console/updates          {"enabled": true|false} (admins, recent sign-in)
 * POST /api/v2/console/updates/check    check now (admins)
 * </pre>
 *
 * The release URL can be changed with {@code CONSOLE_UPDATE_URL} (or the system property
 * {@code console.updateUrl}), and the scheduled check turned off with {@code console.updateCheck=off}
 * (tests). An {@code HTTPS_PROXY} in the environment is used.
 */
final class Updates {

    static final String RELEASES = "https://api.github.com/repos/PointBlueTechnology/directory-console/releases/latest";
    private static final Pattern VERSION = Pattern.compile("v?(\\d+)\\.(\\d+)\\.(\\d+)");

    private final Server server;
    private final String version;
    private final URI releases;
    private volatile ScheduledExecutorService timer;
    private volatile Map<String, Object> last = Map.of();

    Updates(Server server) {
        this.server = server;
        String v = Updates.class.getPackage().getImplementationVersion();
        this.version = v == null ? "development" : v;
        String url = System.getProperty("console.updateUrl", System.getenv().getOrDefault("CONSOLE_UPDATE_URL", RELEASES));
        this.releases = URI.create(url);
    }

    String version() {
        return version;
    }

    boolean handles(String path) {
        return path.equals("/api/v2/console/version") || path.startsWith("/api/v2/console/updates");
    }

    /** The daily check: first two minutes after start, so a starting console is not held up. */
    void start() {
        if ("off".equals(System.getProperty("console.updateCheck"))) {
            return;
        }
        ScheduledExecutorService t = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread th = new Thread(r, "update-check");
            th.setDaemon(true);
            return th;
        });
        t.scheduleAtFixedRate(() -> {
            if (enabled()) {
                check();
            }
        }, 2, 24 * 60, TimeUnit.MINUTES);
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
            case "GET /api/v2/console/version" -> {
                Sessions.Session s = server.session(ex, null);
                Map<String, Object> out = new LinkedHashMap<>();
                out.put("version", version);
                if (s.principal.has(Role.ADMIN)) {
                    out.put("update", state());
                }
                Http.json(ex, 200, out);
            }
            case "PUT /api/v2/console/updates" -> {
                Sessions.Session s = server.session(ex, Role.ADMIN);
                server.stepUp(s);
                if (!(Http.body(ex).get("enabled") instanceof Boolean on)) {
                    throw new Http.Problem(400, "bad-request", "enabled is true or false");
                }
                try {
                    server.config.update(server.config.version(), s.principal.dn(), "update check " + (on ? "on" : "off"),
                        doc -> doc.put("updateCheck", new LinkedHashMap<>(Map.of("enabled", on))));
                } catch (ConfigStore.Conflict c) {
                    throw new Http.Problem(409, "conflict", "the configuration changed meanwhile; try again");
                }
                server.audit.log(Server.who(s), "settings.update-check", "console", Map.of("enabled", on), "ok");
                if (on) {
                    check();
                }
                Http.json(ex, 200, state());
            }
            case "POST /api/v2/console/updates/check" -> {
                server.session(ex, Role.ADMIN);
                check();
                Http.json(ex, 200, state());
            }
            default -> throw new Http.Problem(405, "method-not-allowed", method + " " + path);
        }
    }

    boolean enabled() {
        Object u = server.config.read().get("updateCheck");
        return !(u instanceof Map<?, ?> m) || !Boolean.FALSE.equals(m.get("enabled"));
    }

    /** What admins see: the switch, and the last check's outcome. */
    Map<String, Object> state() {
        Map<String, Object> m = new LinkedHashMap<>(last);
        m.put("enabled", enabled());
        m.put("current", version);
        return m;
    }

    /** Ask for the latest release now; never throws. */
    synchronized void check() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("checkedAt", Instant.now().toString());
        try {
            HttpClient.Builder b = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).followRedirects(HttpClient.Redirect.NORMAL);
            ProxySelector proxy = proxy();
            if (proxy != null) {
                b.proxy(proxy);
            }
            HttpResponse<String> r = b.build().send(HttpRequest.newBuilder(releases).timeout(Duration.ofSeconds(15))
                .header("Accept", "application/vnd.github+json").header("User-Agent", "directory-console/" + version).GET().build(),
                HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() != 200) {
                throw new IOException("the release server answered HTTP " + r.statusCode());
            }
            Map<String, Object> rel = Json.asMap(Json.parse(r.body()));
            String tag = String.valueOf(rel.get("tag_name"));
            if (!VERSION.matcher(tag).find()) {
                throw new IOException("the latest release has no version number (" + tag + ")");
            }
            String latest = tag.replaceFirst("^v", "");
            m.put("latest", latest);
            m.put("url", rel.get("html_url"));
            m.put("published", rel.get("published_at"));
            m.put("newer", newer(latest, version));
        } catch (IOException | RuntimeException e) {
            m.put("error", e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
            // keep what the last good check found
            for (String k : new String[] {"latest", "url", "published", "newer"}) {
                if (last.get(k) != null) {
                    m.put(k, last.get(k));
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            m.put("error", "interrupted");
        }
        last = Map.copyOf(withoutNulls(m));
    }

    private static Map<String, Object> withoutNulls(Map<String, Object> m) {
        Map<String, Object> out = new LinkedHashMap<>();
        m.forEach((k, v) -> {
            if (v != null) {
                out.put(k, v);
            }
        });
        return out;
    }

    /** Whether {@code latest} is a later version than {@code current}; null when {@code current} is not a version (a development build). */
    static Boolean newer(String latest, String current) {
        int[] a = parse(latest);
        int[] b = parse(current);
        if (a == null || b == null) {
            return null;
        }
        for (int i = 0; i < 3; i++) {
            if (a[i] != b[i]) {
                return a[i] > b[i];
            }
        }
        return false;
    }

    private static int[] parse(String v) {
        Matcher m = v == null ? null : VERSION.matcher(v);
        if (m == null || !m.find()) {
            return null;
        }
        return new int[] {Integer.parseInt(m.group(1)), Integer.parseInt(m.group(2)), Integer.parseInt(m.group(3))};
    }

    /** HTTPS_PROXY from the environment (Java does not read it), else the JVM's own settings. */
    static ProxySelector proxy() {
        String p = System.getenv("HTTPS_PROXY");
        if (p == null) {
            p = System.getenv("https_proxy");
        }
        if (p == null || p.isBlank()) {
            return null;
        }
        try {
            URI u = URI.create(p.contains("://") ? p : "http://" + p);
            return u.getHost() == null ? null : ProxySelector.of(new InetSocketAddress(u.getHost(), u.getPort() > 0 ? u.getPort() : 80));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
