package com.pointblue.console.server.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;

/**
 * A certificate an administrator uploads for the console's own HTTPS: a PKCS#12 file, or PEM (the certificate
 * with its chain, and the private key: PKCS#8, PKCS#1 or SEC1, plain or encrypted with a password). The chain is
 * put in order, the server's own certificate first, whatever order it came in.
 */
public final class Upload {

    public record Identity(PrivateKey key, X509Certificate[] chain) {
    }

    /** Bouncy Castle as an instance, not registered: OpenSSL's encrypted keys use ciphers the JDK names differently. */
    private static final java.security.Provider BC = new org.bouncycastle.jce.provider.BouncyCastleProvider();

    private Upload() {
    }

    public static Identity pkcs12(byte[] file, char[] password) throws GeneralSecurityException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try {
            ks.load(new ByteArrayInputStream(file), password);
        } catch (IOException e) {
            throw new GeneralSecurityException("the PKCS#12 file could not be opened: the password is wrong, or it is not a PKCS#12 file");
        }
        for (var e = ks.aliases(); e.hasMoreElements(); ) {
            String a = e.nextElement();
            if (ks.isKeyEntry(a)) {
                Certificate[] c = ks.getCertificateChain(a);
                List<X509Certificate> certs = new ArrayList<>();
                for (Certificate x : c == null ? new Certificate[0] : c) {
                    certs.add((X509Certificate) x);
                }
                PrivateKey key = (PrivateKey) ks.getKey(a, password);
                return new Identity(key, order(key, certs));
            }
        }
        throw new GeneralSecurityException("the PKCS#12 file has no private key");
    }

    public static Identity pem(String certificates, String key, char[] password) throws GeneralSecurityException {
        List<X509Certificate> certs = Certs.parse(certificates.getBytes(StandardCharsets.US_ASCII));
        if (certs.isEmpty()) {
            throw new GeneralSecurityException("no certificate was found in the PEM text");
        }
        PrivateKey k = privateKey(key, password);
        return new Identity(k, order(k, certs));
    }

    private static PrivateKey privateKey(String pem, char[] password) throws GeneralSecurityException {
        JcaPEMKeyConverter conv = new JcaPEMKeyConverter();
        try (PEMParser p = new PEMParser(new StringReader(pem))) {
            Object o = p.readObject();
            while (o != null && !(o instanceof PrivateKeyInfo || o instanceof PEMKeyPair || o instanceof PEMEncryptedKeyPair
                || o instanceof PKCS8EncryptedPrivateKeyInfo)) {
                o = p.readObject();   // skip certificates pasted in with the key
            }
            if (o == null) {
                throw new GeneralSecurityException("no private key was found in the PEM text");
            }
            boolean encrypted = o instanceof PEMEncryptedKeyPair || o instanceof PKCS8EncryptedPrivateKeyInfo;
            if (encrypted && (password == null || password.length == 0)) {
                throw new GeneralSecurityException("the private key is encrypted: give its password");
            }
            try {
                if (o instanceof PKCS8EncryptedPrivateKeyInfo enc) {
                    return conv.getPrivateKey(enc.decryptPrivateKeyInfo(new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider(BC).build(password)));
                }
                if (o instanceof PEMEncryptedKeyPair enc) {
                    return conv.getPrivateKey(enc.decryptKeyPair(new JcePEMDecryptorProviderBuilder().setProvider(BC).build(password)).getPrivateKeyInfo());
                }
            } catch (Exception e) {
                throw new GeneralSecurityException("the private key could not be decrypted: the password is wrong");
            }
            // only the private part: a SEC1 key may leave out its public half
            return conv.getPrivateKey(o instanceof PEMKeyPair kp ? kp.getPrivateKeyInfo() : (PrivateKeyInfo) o);
        } catch (IOException e) {
            throw new GeneralSecurityException("the private key could not be read: " + e.getMessage());
        }
    }

    /** The certificate whose key is {@code key}, then each issuer found among the rest; certificates not in that line are left out. */
    static X509Certificate[] order(PrivateKey key, List<X509Certificate> certs) throws GeneralSecurityException {
        X509Certificate leaf = null;
        for (X509Certificate c : certs) {
            try {
                if (ConsoleTls.belongs(key, c)) {
                    leaf = c;
                    break;
                }
            } catch (GeneralSecurityException e) {
                // another kind of key (an RSA certificate for an EC key): not this one
            }
        }
        if (leaf == null) {
            throw new GeneralSecurityException("none of the certificates belongs to this private key");
        }
        List<X509Certificate> out = new ArrayList<>(List.of(leaf));
        X509Certificate at = leaf;
        while (!at.getIssuerX500Principal().equals(at.getSubjectX500Principal())) {
            X509Certificate next = null;
            for (X509Certificate c : certs) {
                if (!out.contains(c) && c.getSubjectX500Principal().equals(at.getIssuerX500Principal())) {
                    try {
                        at.verify(c.getPublicKey());
                        next = c;
                        break;
                    } catch (GeneralSecurityException e) {
                        // the same name, another key: keep looking
                    }
                }
            }
            if (next == null) {
                break;
            }
            out.add(next);
            at = next;
        }
        return out.toArray(new X509Certificate[0]);
    }
}
