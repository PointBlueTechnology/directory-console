package com.pointblue.console.server.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;

/** Certificate helpers: fingerprints, PEM, self-signed certificates and CSRs for the console's own TLS. */
public final class Certs {

    private static final SecureRandom RANDOM = new SecureRandom();

    private Certs() {
    }

    /** {@code 4A:91:…:7E} — the form iManager and {@code openssl x509 -fingerprint -sha256} print. */
    public static String sha256(Certificate c) {
        try {
            return HexFormat.ofDelimiter(":").withUpperCase().formatHex(MessageDigest.getInstance("SHA-256").digest(c.getEncoded()));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The fingerprint without separators, lowercase: the trust store's file name and id. */
    public static String id(Certificate c) {
        return sha256(c).replace(":", "").toLowerCase(Locale.ROOT);
    }

    /** The last {@code n} hex digits of the fingerprint, the confirmation a person types. */
    public static String tail(Certificate c, int n) {
        String id = id(c);
        return id.substring(id.length() - n);
    }

    public static String pem(Object certOrKeyOrCsr) {
        StringWriter w = new StringWriter();
        try (JcaPEMWriter p = new JcaPEMWriter(w)) {
            p.writeObject(certOrKeyOrCsr);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return w.toString();
    }

    /** Every certificate in PEM, DER or PKCS#7 bytes. */
    public static List<X509Certificate> parse(byte[] bytes) throws GeneralSecurityException {
        Collection<? extends Certificate> all = CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(bytes));
        List<X509Certificate> out = new ArrayList<>();
        for (Certificate c : all) {
            out.add((X509Certificate) c);
        }
        if (out.isEmpty()) {
            throw new GeneralSecurityException("no certificate found");
        }
        return out;
    }

    public static boolean selfSigned(X509Certificate c) {
        if (!c.getSubjectX500Principal().equals(c.getIssuerX500Principal())) {
            return false;
        }
        try {
            c.verify(c.getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    public static KeyPair ecKeyPair() throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"), RANDOM);
        return g.generateKeyPair();
    }

    /** A self-signed server certificate for {@code names} (host names or IP addresses), valid for {@code validity}. */
    public static X509Certificate selfSigned(KeyPair kp, List<String> names, Duration validity) throws GeneralSecurityException {
        try {
            X500Name subject = new X500Name("CN=" + names.get(0).replaceAll("[,+=\"\\\\<>;]", "_") + ",O=Directory Console");
            Instant now = Instant.now();
            X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(subject, new BigInteger(127, RANDOM),
                Date.from(now.minus(Duration.ofMinutes(5))), Date.from(now.plus(validity)), subject, kp.getPublic());
            b.addExtension(Extension.subjectAlternativeName, false, sans(names));
            b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            b.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
            b.addExtension(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(kp.getPublic()));
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(kp.getPrivate());
            return new JcaX509CertificateConverter().getCertificate(b.build(signer));
        } catch (GeneralSecurityException e) {
            throw e;
        } catch (Exception e) {
            throw new GeneralSecurityException("building a certificate: " + e.getMessage(), e);
        }
    }

    /** A PKCS#10 request for {@code names}, for a CA the admin uses. */
    public static PKCS10CertificationRequest csr(KeyPair kp, List<String> names) throws GeneralSecurityException {
        try {
            ExtensionsGenerator ext = new ExtensionsGenerator();
            ext.addExtension(Extension.subjectAlternativeName, false, sans(names));
            Extensions extensions = ext.generate();
            return new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=" + names.get(0).replaceAll("[,+=\"\\\\<>;]", "_")), kp.getPublic())
                .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions)
                .build(new JcaContentSignerBuilder("SHA256withECDSA").build(kp.getPrivate()));
        } catch (Exception e) {
            throw new GeneralSecurityException("building a CSR: " + e.getMessage(), e);
        }
    }

    private static GeneralNames sans(List<String> names) {
        List<GeneralName> out = new ArrayList<>();
        for (String n : names) {
            out.add(isIp(n) ? new GeneralName(GeneralName.iPAddress, n) : new GeneralName(GeneralName.dNSName, n));
        }
        return new GeneralNames(out.toArray(new GeneralName[0]));
    }

    static boolean isIp(String s) {
        return s.matches("\\d{1,3}(\\.\\d{1,3}){3}") || s.contains(":");
    }

    /** DNS names and IP addresses the certificate is for (SANs; the CN only when there are none). */
    public static List<String> names(X509Certificate c) {
        List<String> out = new ArrayList<>();
        try {
            if (c.getSubjectAlternativeNames() != null) {
                for (List<?> san : c.getSubjectAlternativeNames()) {
                    int type = (Integer) san.get(0);
                    if (type == 2 || type == 7) {
                        out.add(String.valueOf(san.get(1)));
                    }
                }
            }
        } catch (GeneralSecurityException e) {
            // unparsable SANs: fall through to the CN
        }
        if (out.isEmpty()) {
            String dn = c.getSubjectX500Principal().getName();
            for (String part : dn.split(",")) {
                if (part.trim().toUpperCase(Locale.ROOT).startsWith("CN=")) {
                    out.add(part.trim().substring(3));
                }
            }
        }
        return out;
    }

    /**
     * Whether {@code host} is one of the certificate's names: exact (case-ignored), a single-label
     * wildcard ({@code *.acme.local}), or an IP address in an IP SAN.
     */
    public static boolean matches(X509Certificate c, String host) {
        String h = host.toLowerCase(Locale.ROOT);
        for (String n : names(c)) {
            String name = n.toLowerCase(Locale.ROOT);
            if (name.equals(h)) {
                return true;
            }
            if (isIp(h) && isIp(name)) {
                try {
                    if (InetAddress.getByName(name).equals(InetAddress.getByName(h))) {
                        return true;
                    }
                } catch (IOException e) {
                    // not an address after all
                }
            }
            if (name.startsWith("*.") && !isIp(h)) {
                int dot = h.indexOf('.');
                if (dot > 0 && h.substring(dot + 1).equals(name.substring(2))) {
                    return true;
                }
            }
        }
        return false;
    }
}
