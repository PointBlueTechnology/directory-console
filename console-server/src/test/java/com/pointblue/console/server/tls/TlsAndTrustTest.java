package com.pointblue.console.server.tls;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.pointblue.console.server.data.DataDir;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class TlsAndTrustTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private static final Duration T = Duration.ofSeconds(5);

    // ---- console TLS ----------------------------------------------------------------------------

    @Test
    public void aGeneratedIdentityIsKeptAndServed() throws Exception {
        DataDir d = new DataDir(tmp.newFolder().toPath());
        ConsoleTls tls = ConsoleTls.loadOrGenerate(d, List.of("console.acme.local", "localhost", "127.0.0.1"));
        X509Certificate first = tls.certificate();
        assertTrue(Certs.matches(first, "console.acme.local"));
        assertTrue(Certs.matches(first, "127.0.0.1"));
        assertEquals("reloaded, not regenerated", Certs.id(first), Certs.id(ConsoleTls.loadOrGenerate(d, List.of("other")).certificate()));
        try (ServerSocket ss = TestPki.serve(tls.context())) {
            assertEquals(Certs.id(first), Certs.id(Probe.read("127.0.0.1", ss.getLocalPort(), T).get(0)));
        }
    }

    @Test
    public void installSwapsTheServedCertificateWithoutARestartAndRefusesAForeignKey() throws Exception {
        DataDir d = new DataDir(tmp.newFolder().toPath());
        ConsoleTls tls = ConsoleTls.loadOrGenerate(d, List.of("localhost"));
        try (ServerSocket ss = TestPki.serve(tls.context())) {
            KeyPair kp = Certs.ecKeyPair();
            X509Certificate next = Certs.selfSigned(kp, List.of("console.acme.local"), Duration.ofDays(90));
            tls.install(kp.getPrivate(), new X509Certificate[] {next});
            assertEquals(Certs.id(next), Certs.id(Probe.read("127.0.0.1", ss.getLocalPort(), T).get(0)));
            X509Certificate stranger = Certs.selfSigned(Certs.ecKeyPair(), List.of("x"), Duration.ofDays(1));
            assertThrows(GeneralSecurityException.class, () -> tls.install(kp.getPrivate(), new X509Certificate[] {stranger}));
            assertEquals("a refused install changes nothing", Certs.id(next), Certs.id(tls.certificate()));
        }
        assertEquals("kept across a restart", Certs.id(ConsoleTls.loadOrGenerate(d, List.of("localhost")).certificate()),
            Certs.id(ConsoleTls.loadOrGenerate(d, List.of("localhost")).certificate()));
    }

    @Test
    public void aCsrNamesTheHosts() throws Exception {
        var csr = Certs.csr(Certs.ecKeyPair(), List.of("console.acme.local", "10.0.4.30"));
        assertTrue(Certs.pem(csr).startsWith("-----BEGIN CERTIFICATE REQUEST-----"));
        assertEquals("CN=console.acme.local", csr.getSubject().toString());
    }

    // ---- probe and trust ------------------------------------------------------------------------

    @Test
    public void aProbeRecordsTheChainAndRecommendsTheTreeCa() throws Exception {
        TestPki pki = new TestPki("ACME_TREE");
        TestPki.Server edir = pki.server("edir1", List.of("edir1.acme.local", "127.0.0.1"));
        try (ServerSocket ss = TestPki.listen(edir.key(), edir.cert(), pki.ca)) {
            Probe probes = new Probe();
            Probe.Result r = probes.probe("127.0.0.1", ss.getLocalPort(), "session-a", T);
            assertEquals(2, r.chain().size());
            assertEquals(Certs.id(edir.cert()), Certs.id(r.chain().get(0)));
            assertEquals(1, Probe.recommended(r.chain()));
            assertEquals(r, probes.get(r.id(), "session-a"));
            assertNull("bound to the session that made it", probes.get(r.id(), "session-b"));
        }
    }

    @Test
    public void untrustedUntilTheTreeCaIsTrustedForThatDirectoryOnly() throws Exception {
        TrustStore ts = new TrustStore(new DataDir(tmp.newFolder().toPath()));
        TestPki pki = new TestPki("ACME_TREE");
        X509Certificate[] chain = {pki.server("edir1", List.of("edir1.acme.local")).cert(), pki.ca};
        TrustStore.Evaluation before = ts.evaluate(chain, "edir1.acme.local", 636, "prod", null);
        assertFalse(before.trusted());
        assertEquals(TrustStore.Reason.UNTRUSTED, before.reason());

        ts.add(pki.ca, TrustStore.Kind.CA, "directory:prod", "cn=admin,o=system", "probe");
        assertTrue(ts.evaluate(chain, "edir1.acme.local", 636, "prod", null).trusted());
        assertFalse("scoped to prod", ts.evaluate(chain, "edir1.acme.local", 636, "lab", null).trusted());
        X509Certificate[] renewed = {pki.server("edir1", List.of("edir1.acme.local")).cert(), pki.ca};
        assertTrue("a renewed server certificate from the same CA stays trusted", ts.evaluate(renewed, "edir1.acme.local", 636, "prod", null).trusted());

        assertEquals(1, ts.entries().size());
        assertTrue(ts.remove(ts.entries().get(0).id()));
        assertFalse(ts.evaluate(chain, "edir1.acme.local", 636, "prod", null).trusted());
    }

    @Test
    public void aHostNameMismatchNeedsAnExceptionForThatExactCertificate() throws Exception {
        TrustStore ts = new TrustStore(new DataDir(tmp.newFolder().toPath()));
        TestPki pki = new TestPki("T");
        ts.add(pki.ca, TrustStore.Kind.CA, "global", "admin", "upload");
        X509Certificate leaf = pki.server("edir1", List.of("edir1.acme.local")).cert();
        X509Certificate[] chain = {leaf, pki.ca};
        TrustStore.Evaluation e = ts.evaluate(chain, "10.0.4.21", 636, "prod", null);
        assertEquals(TrustStore.Reason.HOSTNAME, e.reason());
        assertFalse(e.hostnameMatches());
        ts.addHostException("10.0.4.21", 636, leaf, "admin");
        assertTrue(ts.evaluate(chain, "10.0.4.21", 636, "prod", null).trusted());
        assertFalse("another port is not excepted", ts.evaluate(chain, "10.0.4.21", 1636, "prod", null).trusted());
        X509Certificate[] renewed = {pki.server("edir1", List.of("edir1.acme.local")).cert(), pki.ca};
        assertEquals("the exception is for that certificate only", TrustStore.Reason.HOSTNAME,
            ts.evaluate(renewed, "10.0.4.21", 636, "prod", null).reason());
    }

    @Test
    public void aPinnedLeafIsTrustedAndAChangedOneIsReportedAsSuch() throws Exception {
        TrustStore ts = new TrustStore(new DataDir(tmp.newFolder().toPath()));
        TestPki pki = new TestPki("T");
        X509Certificate leaf = pki.server("edir1", List.of("edir1")).cert();
        ts.add(leaf, TrustStore.Kind.PINNED_SERVER, "directory:prod", "admin", "probe");
        assertTrue(ts.evaluate(new X509Certificate[] {leaf, pki.ca}, "edir1", 636, "prod", null).trusted());
        X509Certificate other = pki.server("edir1", List.of("edir1")).cert();
        assertEquals(TrustStore.Reason.PIN_CHANGED, ts.evaluate(new X509Certificate[] {other, pki.ca}, "edir1", 636, "prod", null).reason());
    }

    @Test
    public void personalTrustAppliesOnlyToThatPerson() throws Exception {
        TrustStore ts = new TrustStore(new DataDir(tmp.newFolder().toPath()));
        TestPki pki = new TestPki("T");
        ts.add(pki.ca, TrustStore.Kind.CA, "user:alice", "alice", "probe");
        X509Certificate[] chain = {pki.server("lab1", List.of("lab1")).cert(), pki.ca};
        assertTrue(ts.evaluate(chain, "lab1", 636, null, "alice").trusted());
        assertFalse(ts.evaluate(chain, "lab1", 636, null, "bob").trusted());
        assertThrows(IllegalArgumentException.class, () -> ts.add(pki.ca, TrustStore.Kind.CA, "everyone", "x", "probe"));
    }

    @Test
    public void confirmationIsTheLastEightHexDigits() throws Exception {
        X509Certificate c = new TestPki("T").ca;
        String id = Certs.id(c);
        assertTrue(TrustStore.confirmed(c, id.substring(56)));
        assertTrue(TrustStore.confirmed(c, Certs.sha256(c).substring(Certs.sha256(c).length() - 11)));   // "AB:CD:EF:12"
        assertFalse(TrustStore.confirmed(c, id.substring(55, 63)));
        assertFalse(TrustStore.confirmed(c, ""));
        assertFalse(TrustStore.confirmed(c, null));
    }

    @Test
    public void aRealConnectionUsesTheTrustManager() throws Exception {
        TrustStore ts = new TrustStore(new DataDir(tmp.newFolder().toPath()));
        TestPki pki = new TestPki("T");
        TestPki.Server edir = pki.server("edir1", List.of("127.0.0.1"));
        try (ServerSocket ss = TestPki.listen(edir.key(), edir.cert(), pki.ca)) {
            assertThrows(javax.net.ssl.SSLHandshakeException.class, () -> handshake(ts, ss.getLocalPort()));
            ts.add(pki.ca, TrustStore.Kind.CA, "directory:prod", "admin", "upload");
            assertArrayEquals(new X509Certificate[] {edir.cert(), pki.ca}, handshake(ts, ss.getLocalPort()));
        }
    }

    private static X509Certificate[] handshake(TrustStore ts, int port) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[] {ts.trustManager("127.0.0.1", port, "prod", null)}, null);
        try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket(InetAddress.getLoopbackAddress(), port)) {
            s.startHandshake();
            return (X509Certificate[]) s.getSession().getPeerCertificates();
        }
    }
}
