package com.pointblue.console.server.http;

import java.net.http.HttpClient;
import java.nio.file.Path;
import java.security.KeyStore;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/** Test access to a running {@link Server}: an HTTP client that trusts exactly its certificate, and its data directory. */
public final class ServerClient {

    private ServerClient() {
    }

    public static HttpClient trusting(Server server) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setCertificateEntry("console", server.tls.certificate());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tmf.getTrustManagers(), null);
        return HttpClient.newBuilder().sslContext(ctx).build();
    }

    public static Path dataDir(Server server) {
        return server.data.root();
    }
}
