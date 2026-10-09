package com.pointblue.console.server.tls;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** An eDirectory-like PKI for tests: a self-signed "Organizational CA" and server certificates it signs. */
public final class TestPki {

    public final KeyPair caKey;
    public final X509Certificate ca;

    public TestPki(String tree) throws Exception {
        caKey = Certs.ecKeyPair();
        X500Name name = new X500Name("OU=Organizational CA,O=" + tree);
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(name, BigInteger.ONE,
            Date.from(Instant.now().minusSeconds(60)), Date.from(Instant.now().plus(Duration.ofDays(3650))), name, caKey.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        ca = new JcaX509CertificateConverter().getCertificate(b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(caKey.getPrivate())));
    }

    public record Server(KeyPair key, X509Certificate cert) {
    }

    /** A server certificate for {@code names} (DNS names or IPs), signed by this CA. */
    public Server server(String cn, List<String> names) throws Exception {
        KeyPair kp = Certs.ecKeyPair();
        GeneralName[] sans = names.stream().map(n -> Certs.isIp(n) ? new GeneralName(GeneralName.iPAddress, n) : new GeneralName(GeneralName.dNSName, n)).toArray(GeneralName[]::new);
        // the issuer must be the CA's subject exactly (encoded form, not a re-parsed string) for path building
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(X500Name.getInstance(ca.getSubjectX500Principal().getEncoded()), BigInteger.valueOf(System.nanoTime()),
            Date.from(Instant.now().minusSeconds(60)), Date.from(Instant.now().plus(Duration.ofDays(365))), new X500Name("CN=" + cn + ",O=TREE"), kp.getPublic());
        b.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(sans));
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(caKey.getPrivate())));
        return new Server(kp, cert);
    }

    /** A TLS listener on loopback presenting {@code server}'s chain (leaf + CA) to every client, until closed. */
    public static ServerSocket listen(KeyPair key, X509Certificate... chain) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("s", key.getPrivate(), "pw".toCharArray(), chain);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "pw".toCharArray());
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);
        return serve(ctx);
    }

    public static ServerSocket serve(SSLContext ctx) throws IOException {
        SSLServerSocket ss = (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(0, 5, InetAddress.getLoopbackAddress());
        Thread t = new Thread(() -> {
            while (!ss.isClosed()) {
                try (SSLSocket s = (SSLSocket) ss.accept()) {
                    s.setSoTimeout(2000);
                    try {
                        s.startHandshake();
                    } catch (IOException ignored) {
                        // clients that refuse the chain (a probe) end the handshake
                    }
                } catch (IOException e) {
                    return;
                }
            }
        });
        t.setDaemon(true);
        t.start();
        return ss;
    }
}
