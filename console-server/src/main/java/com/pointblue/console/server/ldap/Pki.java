package com.pointblue.console.server.ldap;

import com.pointblue.dirxml.dev.json.Json;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.naming.NamingException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

/**
 * eDirectory's PKI LDAP extended operations (9.2.4 and later), as Identity Console 26.1's eDirAPI
 * calls them (read from its binary, 2026-10-13): one OID per area, a request value of two OCTET
 * STRINGs (a verb and a JSON payload) and a response value holding JSON. A refusal comes back as
 * {@code {"code": -NNN, "message": …}} with LDAP success. DNs are in eDirectory's dotted form
 * ({@code cn=a.ou=b.o=c}).
 *
 * <p>Measured on a lab tree (9.2.8): server certificates (create, list) and user certificates (create, list)
 * work. A run that also revoked a user certificate, sent a {@code deleteCertificate} eDirectory could
 * not decode, and issued a CRL was followed by ndsd crashing (heap corruption): those verbs are not used
 * here until each has been tried on its own.
 */
public final class Pki {

    private static final String BASE = "2.16.840.1.113719.1.27.100.";
    public static final String SERVER_CERTIFICATES = BASE + "105";
    public static final String USER_CERTIFICATES = BASE + "107";

    private Pki() {
    }

    /** eDirectory refused the operation: its error code and message. */
    public static final class Refused extends Exception {
        public final int code;

        public Refused(int code, String message) {
            super(message == null || message.isBlank() ? "eDirectory PKI error " + code : message + " (" + code + ")");
            this.code = code;
        }
    }

    /**
     * What to make: {@code algorithm} rsa, ec256 or ec384; {@code signature} sha256, sha384 or sha512;
     * {@code names} subject alternative names as {@code dns:host}, {@code ip:addr}, {@code email:x} or
     * {@code uri:x}.
     */
    public record Spec(String name, String algorithm, int rsaBits, String signature, int validityYears, String subject,
                       List<String> names, boolean exportable, String email) {
    }

    /** {@code cn=a\,b,ou=c.d,o=e} → {@code cn=a,b.ou=c\.d.o=e}: eDirectory's typed dotted form. */
    public static String dotted(String dn) {
        LdapName n = Names.parse(dn);
        StringBuilder b = new StringBuilder();
        for (int i = n.size() - 1; i >= 0; i--) {
            Rdn r = n.getRdns().get(i);
            if (b.length() > 0) {
                b.append('.');
            }
            String v = String.valueOf(r.getValue()).replace("\\", "\\\\").replace(".", "\\.");
            b.append(r.getType()).append('=').append(v);
        }
        return b.toString();
    }

    static byte[] request(String verb, String payload) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.writeBytes(Ber.tlv(0x04, verb.getBytes(StandardCharsets.UTF_8)));
        o.writeBytes(Ber.tlv(0x04, payload.getBytes(StandardCharsets.UTF_8)));
        return o.toByteArray();
    }

    /** The JSON in a response value (an OCTET STRING holding it); empty when there is none. */
    static Map<String, Object> decode(byte[] value) throws Refused {
        if (value == null || value.length == 0) {
            return Map.of();
        }
        String s = new String(value, StandardCharsets.UTF_8);
        int i = s.indexOf('{');
        if (i < 0) {
            return Map.of();
        }
        Map<String, Object> m = Json.asMap(Json.parse(s.substring(i, s.lastIndexOf('}') + 1)));
        int code = Json.asInt(m.get("code"), 0);
        if (code != 0) {
            throw new Refused(code, m.get("message") == null ? null : String.valueOf(m.get("message")));
        }
        return m;
    }

    public static Map<String, Object> call(Ldap l, String oid, String verb, Map<String, Object> payload) throws NamingException, Refused {
        return decode(l.extended(oid, request(verb, Json.compact(payload))));
    }

    /** The certificates eDirectory holds for a user, by name. */
    public static List<Map<String, Object>> userCertificates(Ldap l, String userDn) throws NamingException, Refused {
        return certificates(call(l, USER_CERTIFICATES, "getCertificates", Map.of("userDN", dotted(userDn))));
    }

    /** A server certificate (key material object) on {@code serverDn}, signed by the tree CA. */
    public static void createServerCertificate(Ldap l, String serverDn, Spec spec) throws NamingException, Refused {
        Map<String, Object> p = payload(spec, true);
        p.put("serverDN", dotted(serverDn));
        call(l, SERVER_CERTIFICATES, "createCertificate", p);
    }

    /** A user certificate, made on {@code serverDn} (the CA's host) for {@code userDn}. */
    public static void createUserCertificate(Ldap l, String serverDn, String userDn, Spec spec) throws NamingException, Refused {
        Map<String, Object> p = payload(spec, false);
        p.put("serverDN", dotted(serverDn));
        p.put("userDN", dotted(userDn));
        if (spec.email() != null && !spec.email().isBlank()) {
            p.put("emailAddress", spec.email());
        }
        call(l, USER_CERTIFICATES, "createCertificate", p);
    }

    /**
     * A server certificate with its private key and chain, as a PKCS#12 file protected by {@code password}
     * (PBES2 with AES, or the older PBES1 for software that cannot read PBES2). Identity Console calls this
     * "backupCertificate" (read from its browser code, 2026-10-16). eDirectory refuses it when the key was
     * not made exportable.
     */
    public static byte[] backupServerCertificate(Ldap l, String serverDn, String name, String password, boolean pbes2)
            throws NamingException, Refused {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("serverDN", dotted(serverDn));
        p.put("certificateName", name);
        return backup(l, SERVER_CERTIFICATES, p, password, pbes2);
    }

    /** As {@link #backupServerCertificate}, for one of a user's certificates. */
    public static byte[] backupUserCertificate(Ldap l, String userDn, String name, String password, boolean pbes2)
            throws NamingException, Refused {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("userDN", dotted(userDn));
        p.put("certificateName", name);
        return backup(l, USER_CERTIFICATES, p, password, pbes2);
    }

    private static byte[] backup(Ldap l, String oid, Map<String, Object> p, String password, boolean pbes2) throws NamingException, Refused {
        p.put("password", password);
        p.put("certProtectionAlgorithm", pbes2 ? 1 : 0);
        Object file = call(l, oid, "backupCertificate", p).get("certificate");
        if (file == null || String.valueOf(file).isBlank()) {
            throw new Refused(-1, "eDirectory returned no file");
        }
        byte[] pfx = java.util.Base64.getMimeDecoder().decode(String.valueOf(file));
        return pbes2 ? pbes2(pfx, password.toCharArray()) : pfx;
    }

    /**
     * The same PKCS#12 file protected with PBES2 (AES-256, HMAC-SHA-256) under the same password.
     * eDirectory 9.2.8 ignores certProtectionAlgorithm and always uses PBES1 (SHA1-3DES for the key,
     * RC2-40 for the certificates; measured on ig4, 2026-10-16), which OpenSSL 3 opens only with -legacy.
     */
    static byte[] pbes2(byte[] pfx, char[] password) throws Refused {
        try {
            java.security.KeyStore in = java.security.KeyStore.getInstance("PKCS12");
            in.load(new java.io.ByteArrayInputStream(pfx), password);
            java.security.KeyStore out = java.security.KeyStore.getInstance("PKCS12");
            out.load(null, null);
            java.security.KeyStore.PasswordProtection protection = new java.security.KeyStore.PasswordProtection(password, "PBEWithHmacSHA256AndAES_256",
                new javax.crypto.spec.PBEParameterSpec(new java.security.SecureRandom().generateSeed(16), 10_000));
            for (String alias : java.util.Collections.list(in.aliases())) {
                if (in.isKeyEntry(alias)) {
                    out.setEntry(alias, in.getEntry(alias, new java.security.KeyStore.PasswordProtection(password)), protection);
                } else if (in.isCertificateEntry(alias)) {
                    out.setCertificateEntry(alias, in.getCertificate(alias));
                }
            }
            ByteArrayOutputStream o = new ByteArrayOutputStream();
            out.store(o, password);
            return o.toByteArray();
        } catch (java.security.GeneralSecurityException | java.io.IOException x) {
            throw new Refused(-1, "eDirectory's file could not be re-protected with PBES2: " + x.getMessage());
        }
    }

    /** A private key and its chain, read from a PKCS#12 file and checked. */
    public record KeyAndChain(java.security.PrivateKey key, java.security.cert.X509Certificate[] chain) {
    }

    /**
     * The key and chain in a PKCS#12 file, or an explanation of what is wrong with it: a wrong password, no private
     * key, or more than one. Checked here so eDirectory is never sent a file it would refuse.
     */
    public static KeyAndChain readPkcs12(byte[] pfx, char[] password) {
        try {
            java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
            ks.load(new java.io.ByteArrayInputStream(pfx), password);
            java.security.PrivateKey key = null;
            java.security.cert.Certificate[] chain = null;
            for (String alias : java.util.Collections.list(ks.aliases())) {
                if (ks.isKeyEntry(alias)) {
                    if (key != null) {
                        throw new IllegalArgumentException("the file holds more than one private key");
                    }
                    key = (java.security.PrivateKey) ks.getKey(alias, password);
                    chain = ks.getCertificateChain(alias);
                }
            }
            if (key == null || chain == null || chain.length == 0) {
                throw new IllegalArgumentException("the file holds no private key with its certificate");
            }
            java.security.cert.X509Certificate[] x = new java.security.cert.X509Certificate[chain.length];
            for (int i = 0; i < chain.length; i++) {
                x[i] = (java.security.cert.X509Certificate) chain[i];
            }
            return new KeyAndChain(key, x);
        } catch (java.io.IOException e) {
            throw new IllegalArgumentException("the file could not be opened: a wrong password, or not a PKCS#12 file");
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalArgumentException("the file could not be read: " + e.getMessage());
        }
    }

    /** Whether a PKCS#12 file is already in the form eDirectory exports: key PBE-SHA1-3DES, certificates PBE-SHA1-RC2-40. */
    public static boolean edirForm(byte[] pfx) {
        String hex = java.util.HexFormat.of().formatHex(pfx);
        return hex.contains("2a864886f70d010c0103") && hex.contains("2a864886f70d010c0106") && !hex.contains("2a864886f70d01050d");
    }

    /**
     * Import a key and chain as a new server certificate {@code name} on {@code serverDn} (Identity Console's
     * importCertificate: {serverDN, certificateName, fileContent, password}). On ig4 (9.2.8, 2026-10-17) eDirectory
     * imported a file it had exported itself, and refused (-1443, "wrong password") a file re-written with Bouncy
     * Castle in the very same layout (algorithms, iterations, one-iteration MAC, bag order and attributes): pass
     * only files in eDirectory's form ({@link #edirForm}), unchanged.
     */
    public static void importServerCertificate(Ldap l, String serverDn, String name, byte[] pfx, String password) throws NamingException, Refused {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("serverDN", dotted(serverDn));
        p.put("certificateName", name);
        p.put("fileContent", java.util.Base64.getEncoder().encodeToString(pfx));
        p.put("password", password);
        call(l, SERVER_CERTIFICATES, "importCertificate", p);
    }

    /** RFC 5280 revocation reasons the CA accepts (7 is unused; 8, remove from CRL, is not a revocation). */
    public static final java.util.Set<Integer> REASONS = java.util.Set.of(0, 1, 2, 3, 4, 5, 6, 9, 10);

    /**
     * Revoke a server certificate ({@code serverDn} and the certificate's name) on the CRL configuration
     * {@code crlConfigurationDn}. It shows in the CRL from that configuration's next issue.
     */
    public static void revokeServerCertificate(Ldap l, String serverDn, String name, String crlConfigurationDn, int reason, String comment)
            throws NamingException, Refused {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("serverDN", dotted(serverDn));
        p.put("certificateName", name);
        revoke(l, SERVER_CERTIFICATES, p, crlConfigurationDn, reason, comment);
    }

    /** As {@link #revokeServerCertificate}, for one of a user's certificates (tried on a lab tree, 2026-10-13). */
    public static void revokeUserCertificate(Ldap l, String userDn, String name, String crlConfigurationDn, int reason, String comment)
            throws NamingException, Refused {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("userDN", dotted(userDn));
        p.put("certificateName", name);
        revoke(l, USER_CERTIFICATES, p, crlConfigurationDn, reason, comment);
    }

    private static void revoke(Ldap l, String oid, Map<String, Object> p, String crlConfigurationDn, int reason, String comment)
            throws NamingException, Refused {
        if (!REASONS.contains(reason)) {
            throw new IllegalArgumentException("a revocation reason is one of " + new java.util.TreeSet<>(REASONS));
        }
        p.put("crlConfigurationDN", dotted(crlConfigurationDn));
        p.put("reasonCode", reason);
        if (comment != null && !comment.isBlank()) {
            p.put("comment", comment);
        }
        call(l, oid, "revokeCertificate", p);
    }

    /** The request fields, with Identity Console's numeric codes. */
    static Map<String, Object> payload(Spec s, boolean server) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("certificateName", s.name());
        boolean ec = !s.algorithm().equals("rsa");
        p.put("keyAlgorithm", switch (s.algorithm()) {
            case "ec256" -> 2;
            case "ec384" -> 4;
            default -> 1;
        });
        p.put("keySize", switch (s.algorithm()) {
            case "ec256" -> 256;
            case "ec384" -> 384;
            default -> s.rsaBits();
        });
        int sig = switch (s.signature()) {
            case "sha384" -> 16;
            case "sha512" -> 32;
            default -> 8;
        };
        p.put("signatureAlgorithm", ec ? sig * 8 : sig);   // 64/128/256 with ECDSA
        // key usage: digital signature, and key encipherment for RSA
        p.put("keyUsage", ec ? 0x8000 : 0x8000 | 0x2000);
        p.put("keyUsageExtensionFlag", 0);
        // extended key usage: server authentication (servers); user authentication and e-mail protection (users)
        p.put("extendedKeyUsage", server ? 0x2 : 0x4 | 0x10);
        p.put("extendedKeyUsageFlag", 0);
        p.put("allowExportPrivateKey", s.exportable() ? 1 : 0);
        p.put("validityPeriod", s.validityYears());
        p.put("subjectDN", dotted(s.subject()));
        List<Map<String, Object>> sans = new ArrayList<>();
        for (String n : s.names()) {
            int colon = n.indexOf(':');
            String kind = n.substring(0, colon);
            int type = switch (kind) {
                case "email" -> 1;
                case "dns" -> 2;
                case "uri" -> 6;
                case "ip" -> 7;
                default -> throw new IllegalArgumentException("a name is dns:, ip:, email: or uri:");
            };
            sans.add(Map.of("type", type, "value", n.substring(colon + 1)));
        }
        if (!sans.isEmpty()) {
            p.put("subjectAltNames", sans);
        }
        return p;
    }

    private static List<Map<String, Object>> certificates(Map<String, Object> r) {
        List<Map<String, Object>> out = new ArrayList<>();
        Object list = r.get("certificates");
        if (list instanceof List<?> items) {
            for (Object o : items) {
                Map<String, Object> c = Json.asMap(o);
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("name", c.get("certificateName"));
                m.put("subject", c.get("subjectDN"));
                m.put("issuer", c.get("issuerName"));
                m.put("serial", c.get("serialNumber"));
                // the JSON's dates were six hours ahead of the certificate's on a lab tree (CDT, 2026-10-13): read the certificate's own
                java.security.cert.X509Certificate x = parse(c.get("certificate"));
                m.put("notBefore", x != null ? x.getNotBefore().toInstant().toString() : epoch(c.get("effectiveDate")));
                m.put("notAfter", x != null ? x.getNotAfter().toInstant().toString() : epoch(c.get("expiryDate")));
                m.put("keySize", c.get("keySize"));
                m.put("certificate", c.get("certificate"));
                out.add(m);
            }
        }
        return out;
    }

    private static java.security.cert.X509Certificate parse(Object base64) {
        if (base64 == null) {
            return null;
        }
        try {
            return (java.security.cert.X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(java.util.Base64.getMimeDecoder().decode(String.valueOf(base64))));
        } catch (java.security.cert.CertificateException | IllegalArgumentException e) {
            return null;
        }
    }

    private static String epoch(Object seconds) {
        long s = seconds instanceof Number n ? n.longValue() : Long.parseLong(String.valueOf(seconds));
        return java.time.Instant.ofEpochSecond(s).toString();
    }
}
