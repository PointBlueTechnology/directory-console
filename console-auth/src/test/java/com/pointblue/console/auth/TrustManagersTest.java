package com.pointblue.console.auth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.X509TrustManager;
import org.junit.Test;

public class TrustManagersTest {

    /** A trust manager that accepts or refuses everything, and counts calls. */
    private static X509TrustManager fixed(boolean accept, AtomicInteger calls, X509Certificate... issuers) {
        return new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                calls.incrementAndGet();
                if (!accept) {
                    throw new CertificateException("refused");
                }
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                checkClientTrusted(chain, authType);
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return issuers;
            }
        };
    }

    @Test
    public void theSecondIsAskedOnlyWhenTheFirstRefuses() throws Exception {
        AtomicInteger a = new AtomicInteger(), b = new AtomicInteger();
        TrustManagers.either(fixed(true, a), fixed(true, b)).checkServerTrusted(new X509Certificate[0], "RSA");
        assertEquals(1, a.get());
        assertEquals(0, b.get());
        TrustManagers.either(fixed(false, a), fixed(true, b)).checkServerTrusted(new X509Certificate[0], "RSA");
        assertEquals(1, b.get());
        assertThrows(CertificateException.class,
            () -> TrustManagers.either(fixed(false, a), fixed(false, b)).checkServerTrusted(new X509Certificate[0], "RSA"));
    }

    @Test
    public void jdkDefaultHasAnchorsAndAnEmptyExtraAddsNone() throws Exception {
        X509TrustManager jdk = TrustManagers.jdkDefault();
        assertTrue(jdk.getAcceptedIssuers().length > 0);
        X509TrustManager both = TrustManagers.either(jdk, fixed(false, new AtomicInteger()));
        assertEquals(jdk.getAcceptedIssuers().length, both.getAcceptedIssuers().length);
        TrustManagers.sslContext(both);   // builds
    }
}
