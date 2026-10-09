package com.pointblue.console.server.data;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Seals the secrets kept in the configuration (an OIDC client secret, the console service account's
 * password, ACME and DNS-provider credentials) with AES-256-GCM. The 256-bit key is generated once,
 * at bootstrap, into {@code keys/config.key} (owner-only).
 *
 * <p>Each sealed value names what it is for (the associated data, such as
 * {@code directories/prod/serviceAccount/password}), so a sealed value copied into another field
 * does not open there.
 */
public final class SecretBox {

    private static final String PREFIX = "v1:";
    private static final int IV = 12;
    private static final int TAG_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final SecretKeySpec key;

    private SecretBox(byte[] key) {
        this.key = new SecretKeySpec(key, "AES");
    }

    /** The key in {@code keyFile}, generating it when absent. */
    public static SecretBox open(Path keyFile) throws IOException {
        if (!Files.exists(keyFile)) {
            byte[] k = new byte[32];
            RANDOM.nextBytes(k);
            DataDir.write(keyFile, k);
        }
        byte[] k = Files.readAllBytes(keyFile);
        if (k.length != 32) {
            throw new IOException(keyFile + " is not a 256-bit key (" + k.length + " bytes)");
        }
        return new SecretBox(k);
    }

    /** {@code v1:<base64 of iv || ciphertext+tag>} */
    public String seal(String plaintext, String purpose) {
        try {
            byte[] iv = new byte[IV];
            RANDOM.nextBytes(iv);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            c.updateAAD(purpose.getBytes(StandardCharsets.UTF_8));
            byte[] ct = c.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return PREFIX + Base64.getEncoder().encodeToString(ByteBuffer.allocate(IV + ct.length).put(iv).put(ct).array());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("sealing a secret: " + e.getMessage(), e);
        }
    }

    /** The plaintext; refuses a value sealed under another key or for another purpose. */
    public String open(String sealed, String purpose) {
        if (sealed == null || !sealed.startsWith(PREFIX)) {
            throw new IllegalArgumentException("not a sealed value");
        }
        try {
            byte[] all = Base64.getDecoder().decode(sealed.substring(PREFIX.length()));
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, all, 0, IV));
            c.updateAAD(purpose.getBytes(StandardCharsets.UTF_8));
            return new String(c.doFinal(all, IV, all.length - IV), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalArgumentException("a sealed value does not open (wrong key, or sealed for another field)");
        }
    }
}
