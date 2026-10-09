package com.pointblue.console.server.tls;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Reads the certificate chain a server presents, without trusting it: a TLS handshake whose trust
 * manager records the chain and then refuses, so nothing is ever sent over the connection. Results are
 * kept for ten minutes, bound to the session that made them, and are what a trust decision refers to.
 */
public final class Probe {

    public record Result(String id, String session, String host, int port, List<X509Certificate> chain, Instant at) {
    }

    private static final Duration KEEP = Duration.ofMinutes(10);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Map<String, Result> results = new ConcurrentHashMap<>();

    /** Connect, record the chain, keep it for {@code session}. */
    public Result probe(String host, int port, String session, Duration timeout) throws IOException {
        if (host == null || host.isBlank() || port < 1 || port > 65535) {
            throw new IllegalArgumentException("a probe needs a host and a port 1-65535");
        }
        List<X509Certificate> chain = read(host, port, timeout);
        results.values().removeIf(r -> r.at.plus(KEEP).isBefore(Instant.now()));
        byte[] b = new byte[18];
        RANDOM.nextBytes(b);
        Result r = new Result("p_" + Base64.getUrlEncoder().withoutPadding().encodeToString(b), session, host, port, chain, Instant.now());
        results.put(r.id, r);
        return r;
    }

    /** A kept result, only for the session that made it; null when unknown, expired or someone else's. */
    public Result get(String id, String session) {
        Result r = id == null ? null : results.get(id);
        if (r == null || !r.session.equals(session) || r.at.plus(KEEP).isBefore(Instant.now())) {
            return null;
        }
        return r;
    }

    /** The chain {@code host:port} presents. */
    public static List<X509Certificate> read(String host, int port, Duration timeout) throws IOException {
        X509Certificate[][] seen = new X509Certificate[1][];
        X509TrustManager recorder = new X509TrustManager() {
            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                seen[0] = chain.clone();
                throw new CertificateException("recorded; not trusted by a probe");
            }

            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                throw new CertificateException("no clients");
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[] {recorder}, null);
            try (Socket raw = new Socket()) {
                raw.connect(new InetSocketAddress(host, port), (int) timeout.toMillis());
                raw.setSoTimeout((int) timeout.toMillis());
                try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket(raw, host, port, true)) {
                    s.startHandshake();
                } catch (SSLException expected) {
                    // the recorder refused: that is how a probe ends
                }
            }
        } catch (GeneralSecurityException e) {
            throw new IOException("TLS: " + e.getMessage(), e);
        }
        if (seen[0] == null || seen[0].length == 0) {
            throw new IOException(host + ":" + port + " did not present a certificate (not a TLS port?)");
        }
        return List.of(seen[0]);
    }

    /** The index of the certificate to recommend trusting: the self-signed root if presented, else the top of the chain. */
    public static int recommended(List<X509Certificate> chain) {
        for (int i = chain.size() - 1; i >= 0; i--) {
            if (Certs.selfSigned(chain.get(i))) {
                return i;
            }
        }
        return chain.size() - 1;
    }
}
