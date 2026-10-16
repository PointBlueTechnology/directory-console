package com.pointblue.console.server.http;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/** Test access to a running {@link Server}: an HTTP client that trusts exactly its certificate, and its data directory. */
public final class ServerClient {

    /** Longest a test waits for a connection or a response: a request the server never answers fails instead of hanging the build. */
    public static final Duration TIMEOUT = Duration.ofSeconds(30);

    private ServerClient() {
    }

    /**
     * Where a test server listens: 127.0.0.1, a port of the system's choosing. Not the wildcard address: on macOS the
     * system can give a wildcard listener a port another process already holds on 127.0.0.1, and connections to
     * 127.0.0.1 then reach that process (a request that never answers, or "Unrecognized SSL message").
     */
    public static InetSocketAddress loopback() {
        return new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
    }

    /** A request to the server that fails after {@link #TIMEOUT} rather than waiting for ever. */
    public static HttpRequest.Builder request(URI uri) {
        return HttpRequest.newBuilder(uri).timeout(TIMEOUT);
    }

    public static HttpClient trusting(Server server) throws Exception {
        return HttpClient.newBuilder().sslContext(trustingContext(server)).connectTimeout(TIMEOUT).build();
    }

    /** TLS that trusts exactly the server's certificate. */
    public static SSLContext trustingContext(Server server) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setCertificateEntry("console", server.tls.certificate());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tmf.getTrustManagers(), null);
        return ctx;
    }

    public static Path dataDir(Server server) {
        return server.data.root();
    }
}
