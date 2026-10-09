package com.pointblue.console.auth;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * TLS trust built from the JDK's own store plus certificates the operator added (a private CA, a
 * reverse proxy's internal root, an eDirectory tree CA). The JDK's store is never modified.
 */
public final class TrustManagers {

    private TrustManagers() {
    }

    /** The JDK's default trust. */
    public static X509TrustManager jdkDefault() throws GeneralSecurityException {
        TrustManagerFactory f = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        f.init((KeyStore) null);
        return (X509TrustManager) f.getTrustManagers()[0];
    }

    /** Trust exactly these certificates (as anchors). */
    public static X509TrustManager of(Collection<? extends Certificate> anchors) throws GeneralSecurityException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        try {
            ks.load(null, null);
        } catch (IOException e) {
            throw new GeneralSecurityException(e);
        }
        int n = 0;
        for (Certificate c : anchors) {
            ks.setCertificateEntry("extra-" + n++, c);
        }
        TrustManagerFactory f = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        f.init(ks);
        return (X509TrustManager) f.getTrustManagers()[0];
    }

    /** Every certificate in a PEM (or DER) file. */
    public static Collection<? extends Certificate> read(Path file) throws IOException {
        try (InputStream in = Files.newInputStream(file)) {
            return CertificateFactory.getInstance("X.509").generateCertificates(in);
        } catch (CertificateException e) {
            throw new IOException(file + ": " + e.getMessage(), e);
        }
    }

    /** A chain is trusted when {@code first} accepts it, or else {@code second} does. */
    public static X509TrustManager either(X509TrustManager first, X509TrustManager second) {
        return new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                first.checkClientTrusted(chain, authType);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                try {
                    first.checkServerTrusted(chain, authType);
                } catch (CertificateException e) {
                    second.checkServerTrusted(chain, authType);
                }
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                X509Certificate[] p = first.getAcceptedIssuers();
                X509Certificate[] q = second.getAcceptedIssuers();
                X509Certificate[] all = Arrays.copyOf(p, p.length + q.length);
                System.arraycopy(q, 0, all, p.length, q.length);
                return all;
            }
        };
    }

    /** The JDK's trust plus the certificates in {@code pem}. */
    public static X509TrustManager jdkPlus(Path pem) throws IOException {
        try {
            return either(jdkDefault(), of(read(pem)));
        } catch (GeneralSecurityException e) {
            throw new IOException(pem + ": " + e.getMessage(), e);
        }
    }

    /** A TLS context that verifies servers with {@code trust}. */
    public static SSLContext sslContext(X509TrustManager trust) throws GeneralSecurityException {
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[] {trust}, null);
        return ctx;
    }
}
