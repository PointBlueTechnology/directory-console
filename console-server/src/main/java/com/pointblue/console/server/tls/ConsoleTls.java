package com.pointblue.console.server.tls;

import com.pointblue.console.server.data.DataDir;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

/**
 * The console's own HTTPS identity: a key and certificate chain in {@code tls/console.p12}, protected
 * by a random password in {@code keys/tls.password} (both owner-only).
 *
 * <p>The SSL context's key manager reads the current identity on every handshake, so {@link #install}
 * (an upload, a signed CSR coming back, an ACME renewal) takes effect for the next connection without a
 * restart, and the previous certificate serves until the new one is in place.
 */
public final class ConsoleTls {

    private static final String ALIAS = "console";
    private static final SecureRandom RANDOM = new SecureRandom();

    private record Identity(PrivateKey key, X509Certificate[] chain) {
    }

    private final Path p12;
    private final Path passwordFile;
    private volatile Identity current;
    private final SSLContext context;

    private ConsoleTls(Path p12, Path passwordFile, Identity id) throws GeneralSecurityException {
        this.p12 = p12;
        this.passwordFile = passwordFile;
        this.current = id;
        this.context = SSLContext.getInstance("TLS");
        context.init(new KeyManager[] {new Swappable()}, null, null);
    }

    /**
     * The stored identity, or a newly generated self-signed one for {@code names} (the container's host
     * names, {@code localhost}, and the public host when set).
     */
    public static ConsoleTls loadOrGenerate(DataDir data, List<String> names) throws IOException, GeneralSecurityException {
        Path p12 = data.tls().resolve("console.p12");
        Path pw = data.keys().resolve("tls.password");
        if (Files.exists(p12) && Files.exists(pw)) {
            char[] password = Files.readString(pw, StandardCharsets.UTF_8).toCharArray();
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (InputStream in = Files.newInputStream(p12)) {
                ks.load(in, password);
            }
            return new ConsoleTls(p12, pw, identity(ks, password));
        }
        KeyPair kp = Certs.ecKeyPair();
        X509Certificate cert = Certs.selfSigned(kp, names, Duration.ofDays(397));
        ConsoleTls t = new ConsoleTls(p12, pw, new Identity(kp.getPrivate(), new X509Certificate[] {cert}));
        t.save();
        return t;
    }

    public SSLContext context() {
        return context;
    }

    /** The leaf certificate currently served. */
    public X509Certificate certificate() {
        return current.chain[0];
    }

    public X509Certificate[] chain() {
        return current.chain.clone();
    }

    /** Serve {@code key} with {@code chain} from the next handshake on, and keep it. The chain must match the key. */
    public void install(PrivateKey key, X509Certificate[] chain) throws IOException, GeneralSecurityException {
        if (chain.length == 0 || !belongs(key, chain[0])) {
            throw new GeneralSecurityException("the certificate does not belong to this private key");
        }
        chain[0].checkValidity();
        Identity previous = current;
        current = new Identity(key, chain.clone());
        try {
            save();
        } catch (IOException | GeneralSecurityException e) {
            current = previous;
            throw e;
        }
    }

    /** Import a PKCS#12 file (key + chain) from an upload. */
    public void installPkcs12(byte[] bytes, char[] password) throws IOException, GeneralSecurityException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new java.io.ByteArrayInputStream(bytes), password);
        String alias = null;
        for (var e = ks.aliases(); e.hasMoreElements(); ) {
            String a = e.nextElement();
            if (ks.isKeyEntry(a)) {
                alias = a;
                break;
            }
        }
        if (alias == null) {
            throw new GeneralSecurityException("the PKCS#12 file has no private key");
        }
        Certificate[] c = ks.getCertificateChain(alias);
        X509Certificate[] chain = new X509Certificate[c.length];
        for (int i = 0; i < c.length; i++) {
            chain[i] = (X509Certificate) c[i];
        }
        install((PrivateKey) ks.getKey(alias, password), chain);
    }

    /** Whether {@code key} is the private half of {@code leaf}'s key: sign a nonce with one, verify with the other. */
    static boolean belongs(PrivateKey key, X509Certificate leaf) throws GeneralSecurityException {
        byte[] nonce = new byte[32];
        RANDOM.nextBytes(nonce);
        String alg = key.getAlgorithm().equals("EC") ? "SHA256withECDSA" : "SHA256withRSA";
        java.security.Signature s = java.security.Signature.getInstance(alg);
        s.initSign(key);
        s.update(nonce);
        byte[] sig = s.sign();
        java.security.Signature v = java.security.Signature.getInstance(alg);
        v.initVerify(leaf.getPublicKey());
        v.update(nonce);
        return v.verify(sig);
    }

    private void save() throws IOException, GeneralSecurityException {
        byte[] pwBytes = new byte[24];
        RANDOM.nextBytes(pwBytes);
        char[] password = Base64.getUrlEncoder().withoutPadding().encodeToString(pwBytes).toCharArray();
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry(ALIAS, current.key, password, current.chain);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ks.store(out, password);
        // password first: a crash between the two leaves a password that opens nothing, and the next
        // start regenerates; the other order could leave a keystore nothing opens
        DataDir.write(passwordFile, new String(password).getBytes(StandardCharsets.UTF_8));
        DataDir.write(p12, out.toByteArray());
    }

    private static Identity identity(KeyStore ks, char[] password) throws GeneralSecurityException {
        Certificate[] c = ks.getCertificateChain(ALIAS);
        X509Certificate[] chain = new X509Certificate[c.length];
        for (int i = 0; i < c.length; i++) {
            chain[i] = (X509Certificate) c[i];
        }
        return new Identity((PrivateKey) ks.getKey(ALIAS, password), chain);
    }

    /** Hands JSSE whatever identity is current at handshake time. */
    private final class Swappable extends X509ExtendedKeyManager {
        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return new String[] {ALIAS};
        }

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            return matches(keyType) ? ALIAS : null;
        }

        @Override
        public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
            return matches(keyType) ? ALIAS : null;
        }

        private boolean matches(String keyType) {
            String alg = current.key.getAlgorithm();
            return keyType.equals(alg) || (alg.equals("EC") && keyType.startsWith("EC"));
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            return current.chain.clone();
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            return current.key;
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return null;
        }

        @Override
        public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
            return null;
        }
    }
}
