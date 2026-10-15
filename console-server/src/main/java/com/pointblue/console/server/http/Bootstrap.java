package com.pointblue.console.server.http;

import com.pointblue.console.server.auth.Throttle;
import com.pointblue.console.server.data.DataDir;
import com.pointblue.console.server.tls.Certs;
import com.pointblue.console.server.tls.ConsoleTls;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;

/**
 * Bootstrap mode's one-time setup token (DESIGN-directory-console.md section 5.1): 128 random bits,
 * valid 60 minutes, printed to the container log and written to {@code bootstrap.txt} (owner-only)
 * together with the console certificate's fingerprint, so the person setting up can check that the
 * browser reached this console before typing anything. Being able to read either is the root of trust.
 *
 * <p>Presented tokens are compared in constant time and limited to five tries a minute per client;
 * after twenty failures, or when it expires, the token is replaced and the new one printed.
 */
public final class Bootstrap {

    static final Duration VALID = Duration.ofMinutes(60);
    static final int MAX_FAILURES = 20;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final DataDir data;
    private final ConsoleTls tls;
    private final String url;
    private final PrintStream out;
    private final Clock clock;
    private final Throttle perClient = new Throttle(5, Duration.ofMinutes(1));
    private String token;
    private Instant issued;
    private int failures;

    public Bootstrap(DataDir data, ConsoleTls tls, String url, PrintStream out) throws IOException {
        this(data, tls, url, out, Clock.systemUTC());
    }

    Bootstrap(DataDir data, ConsoleTls tls, String url, PrintStream out, Clock clock) throws IOException {
        this.data = data;
        this.tls = tls;
        this.url = url;
        this.out = out;
        this.clock = clock;
        issue();
    }

    public synchronized boolean active() {
        return token != null;
    }

    /** Whether {@code presented} is the current token; counts and limits failures. */
    public synchronized boolean check(String presented, String client) throws IOException {
        if (token == null) {
            return false;
        }
        if (!perClient.allowed(client)) {
            throw new Http.Problem(429, "too-many-attempts", "too many setup attempts from this address; wait a minute");
        }
        if (issued.plus(VALID).isBefore(clock.instant())) {
            issue();
            throw new Http.Problem(401, "setup-token-expired", "the setup token expired; a new one is in the container log and bootstrap.txt");
        }
        boolean ok = presented != null && MessageDigest.isEqual(token.getBytes(StandardCharsets.US_ASCII), presented.trim().getBytes(StandardCharsets.US_ASCII));
        if (!ok) {
            perClient.record(client);
            if (++failures >= MAX_FAILURES) {
                issue();
            }
        }
        return ok;
    }

    /** Setup is finished: the token is gone for good and bootstrap.txt deleted. */
    public synchronized void finish() throws IOException {
        token = null;
        Files.deleteIfExists(data.bootstrapFile());
    }

    /** For tests: the current token. */
    synchronized String token() {
        return token;
    }

    private void issue() throws IOException {
        byte[] b = new byte[16];
        RANDOM.nextBytes(b);
        token = HexFormat.of().formatHex(b);
        issued = clock.instant();
        failures = 0;
        String fp = Certs.sha256(tls.certificate());
        String text = """
            Directory Console is not configured yet. Within 60 minutes, open the setup URL and
            sign in to your eDirectory tree as an administrator:

              Setup URL:   %s/setup#token=%s
              Setup token: %s

            Before entering anything, check that your browser shows this certificate fingerprint
            (SHA-256) for the console:

              %s

            This token is printed only here and in this file; a restart replaces it.
            """.formatted(url, token, token, fp);
        DataDir.write(data.bootstrapFile(), text.getBytes(StandardCharsets.UTF_8));
        out.println(text);
        out.flush();
    }
}
