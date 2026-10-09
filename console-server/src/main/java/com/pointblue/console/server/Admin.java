package com.pointblue.console.server;

import com.pointblue.console.server.audit.AuditLog;
import com.pointblue.console.server.data.DataDir;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * Host-side commands, run inside the container ({@code docker exec console java -jar /app/console.jar admin …}).
 * Only someone who can exec into the container or read its volume runs these, which is the same root of
 * trust as the bootstrap token; nothing here is reachable over the network.
 *
 * <pre>
 *   admin health            exit 0 when this host's console answers /api/v2/health/live (the container HEALTHCHECK)
 *   admin reset-bootstrap   return to bootstrap mode on the next start (DESIGN section 5.3)
 *   admin verify-audit      check the audit chain
 * </pre>
 */
final class Admin {

    private Admin() {
    }

    static int run(String[] args, Path dataPath, int port) throws Exception {
        String cmd = args.length > 1 ? args[1] : "";
        return switch (cmd) {
            case "health" -> health(dataPath, port);
            case "reset-bootstrap" -> resetBootstrap(dataPath);
            case "verify-audit" -> verifyAudit(dataPath);
            default -> {
                System.err.println("usage: admin health | reset-bootstrap | verify-audit");
                yield 2;
            }
        };
    }

    /** GET /api/v2/health/live on loopback, trusting exactly the console's own certificate from the volume. */
    private static int health(Path dataPath, int port) {
        try {
            DataDir d = new DataDir(dataPath);
            char[] pw = Files.readString(d.keys().resolve("tls.password"), StandardCharsets.UTF_8).toCharArray();
            KeyStore p12 = KeyStore.getInstance("PKCS12");
            try (InputStream in = Files.newInputStream(d.tls().resolve("console.p12"))) {
                p12.load(in, pw);
            }
            Certificate leaf = p12.getCertificateChain("console")[0];
            KeyStore trust = KeyStore.getInstance("PKCS12");
            trust.load(null, null);
            trust.setCertificateEntry("console", leaf);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trust);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, tmf.getTrustManagers(), null);
            // the console's certificate names 127.0.0.1, so the usual host-name check holds against the pinned certificate
            HttpClient c = HttpClient.newBuilder().sslContext(ctx).connectTimeout(Duration.ofSeconds(3)).build();
            HttpResponse<String> r = c.send(HttpRequest.newBuilder(URI.create("https://127.0.0.1:" + port + "/api/v2/health/live"))
                .timeout(Duration.ofSeconds(3)).GET().build(), HttpResponse.BodyHandlers.ofString());
            return r.statusCode() == 200 ? 0 : 1;
        } catch (Exception e) {
            System.err.println("health: " + e.getMessage());
            return 1;
        }
    }

    /**
     * Move the current configuration into the history as a reset copy, so the next start is bootstrap mode
     * with a fresh setup token. The trust store, the console's certificate and the encryption key stay:
     * setup can reuse what was trusted, and the old configuration can still be restored.
     */
    private static int resetBootstrap(Path dataPath) throws IOException {
        DataDir d = new DataDir(dataPath);
        Path current = d.config().resolve("current.json");
        if (!Files.exists(current)) {
            System.out.println("Not configured: the console is already in bootstrap mode.");
            return 0;
        }
        String stamp = Instant.now().toString().replace(":", "");
        Path kept = d.history().resolve("reset-" + stamp + ".json");
        Files.move(current, kept, StandardCopyOption.ATOMIC_MOVE);
        new AuditLog(d).log(new AuditLog.Actor("host", null, "admin"), "bootstrap.reset", null, Map.of("kept", kept.getFileName().toString()), "ok");
        System.out.println("Configuration moved to " + kept + ".\nRestart the container: it starts in bootstrap mode and prints a new setup token.");
        return 0;
    }

    private static int verifyAudit(Path dataPath) throws IOException {
        AuditLog.Verification v = new AuditLog(new DataDir(dataPath)).verify();
        System.out.println(v.intact() ? "intact: " + v.lines() + " lines" : "BROKEN after " + v.lines() + " lines: " + v.problem());
        return v.intact() ? 0 : 1;
    }
}
