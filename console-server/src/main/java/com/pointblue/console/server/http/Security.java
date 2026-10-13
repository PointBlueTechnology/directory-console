package com.pointblue.console.server.http;

import com.pointblue.console.server.auth.DirectoryConfig;
import com.pointblue.console.server.auth.Role;
import com.pointblue.console.server.auth.Sessions;
import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.console.server.ldap.Names;
import com.pointblue.dirxml.dev.json.Json;
import com.sun.net.httpserver.HttpExchange;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.naming.NamingException;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;

/**
 * Security services (Phase 6a, inventory section 5): the tree's PKI as LDAP objects (read-only),
 * password policies and their assignments, challenge sets, and the NMAS Login Policy. Verified on ig4
 * by spikes/Phase6Probe and Phase6Assign (2026-10-12).
 *
 * <pre>
 * GET    /api/v2/trees/{tree}/security/pki                                   CA, server certificates, trusted roots, CRLs
 * GET    /api/v2/trees/{tree}/security/password-policies
 * POST   /api/v2/trees/{tree}/security/password-policies                     {"name", "description", "rules", "options", "challengeSet"}
 * GET    /api/v2/trees/{tree}/security/password-policies/{guid}
 * PATCH  /api/v2/trees/{tree}/security/password-policies/{guid}              {"description", "rules", "options", "challengeSet"}
 * DELETE /api/v2/trees/{tree}/security/password-policies/{guid}              X-Confirm-Count: its assignments, when it has any
 * POST   /api/v2/trees/{tree}/security/password-policies/{guid}/assignments  {"target": guid}
 * DELETE /api/v2/trees/{tree}/security/password-policies/{guid}/assignments/{target}
 * GET    /api/v2/trees/{tree}/security/objects/{guid}/password-policy        assignments on it and its containers, and the Login Policy's
 * GET    /api/v2/trees/{tree}/security/challenge-sets
 * POST   /api/v2/trees/{tree}/security/challenge-sets                        {"name", "description", "required", "random", "randomCount", "minResponse", "maxResponse"}
 * GET    /api/v2/trees/{tree}/security/challenge-sets/{guid}
 * PATCH  /api/v2/trees/{tree}/security/challenge-sets/{guid}
 * DELETE /api/v2/trees/{tree}/security/challenge-sets/{guid}
 * GET    /api/v2/trees/{tree}/security/login-policy                          sequences, the default, the login methods
 * </pre>
 *
 * Writes change who can sign in and how, so they need an editor grant for the whole tree and, on
 * production, the directory's name typed.
 */
final class Security {

    static final String POLICIES = "cn=Password Policies,cn=Security";

    private final Server server;

    Security(Server server) {
        this.server = server;
    }

    void handle(HttpExchange ex, String path, String method) throws IOException {
        String[] p = path.substring("/api/v2/trees/".length()).split("/", -1);
        Sessions.Session s = server.session(ex, null);
        if (s.principal.roles().isEmpty()) {
            throw new Http.Problem(403, "forbidden", "you have no Directory Console role");
        }
        if (!p[0].equals(s.principal.directoryId())) {
            throw new Http.Problem(404, "unknown-tree", "you are signed in to " + s.principal.directoryId() + ", not " + p[0]);
        }
        Ldap l = s.ldap();
        String route = method + " " + String.join("/", Arrays.copyOfRange(p, 2, p.length))
            .replaceAll("^(password-policies|challenge-sets|objects)/[0-9a-f]{32}", "$1/{guid}")
            .replaceAll("assignments/[0-9a-f]{32}$", "assignments/{target}");
        String guid = p.length > 3 ? p[3] : null;
        if (!method.equals("GET")) {
            if (!s.principal.may(Role.EDITOR, "")) {
                throw new Http.Problem(403, "forbidden", "security settings need an editor role for the whole tree");
            }
            DirectoryConfig d = server.directoryOf(s);
            if (d != null && d.production()) {
                String typed = ex.getRequestHeaders().getFirst("X-Confirm-Directory");
                if (typed == null || !typed.trim().equalsIgnoreCase(d.name())) {
                    throw new Http.Problem(409, "confirm-directory", "this changes the production directory " + d.name() + "; type its name to confirm");
                }
            }
        }
        try {
            switch (route) {
                case "GET pki" -> Http.json(ex, 200, pki(l));
                case "GET password-policies" -> Http.json(ex, 200, policies(l));
                case "POST password-policies" -> createPolicy(ex, l, s);
                case "GET password-policies/{guid}" -> Http.json(ex, 200, policy(l, guid));
                case "PATCH password-policies/{guid}" -> updatePolicy(ex, l, s, guid);
                case "DELETE password-policies/{guid}" -> deletePolicy(ex, l, s, guid);
                case "POST password-policies/{guid}/assignments" -> assign(ex, l, s, guid, Http.string(Http.body(ex), "target", true), true);
                case "DELETE password-policies/{guid}/assignments/{target}" -> assign(ex, l, s, guid, p[5], false);
                case "GET objects/{guid}/password-policy" -> Http.json(ex, 200, policyFor(l, guid));
                case "GET challenge-sets" -> Http.json(ex, 200, challengeSets(l));
                case "POST challenge-sets" -> createChallengeSet(ex, l, s);
                case "GET challenge-sets/{guid}" -> Http.json(ex, 200, challengeSet(l, guid));
                case "PATCH challenge-sets/{guid}" -> updateChallengeSet(ex, l, s, guid);
                case "DELETE challenge-sets/{guid}" -> deleteChallengeSet(ex, l, s, guid);
                case "GET login-policy" -> Http.json(ex, 200, loginPolicy(l));
                default -> throw new Http.Problem(404, "not-found", method + " " + path);
            }
        } catch (NamingException e) {
            throw server.objects.problem(s, Ldap.Failure.of(e));
        } catch (IllegalArgumentException e) {
            throw new Http.Problem(400, "bad-request", e.getMessage());
        }
    }

    /** The Security container (eDirectory keeps it at the tree root as cn=Security) with its pointers to the CA and the Login Policy. */
    private Ldap.Entry securityContainer(Ldap l) throws NamingException {
        Ldap.Entry sec = l.read("cn=Security", "nDSPKITreeCADN", "sASLoginPolicyDN");
        if (sec != null) {
            return sec;
        }
        List<Ldap.Entry> found = l.search("", "(objectClass=sASSecurity)", null, SearchControls.SUBTREE_SCOPE, new String[] {"nDSPKITreeCADN", "sASLoginPolicyDN"}, 1);
        return found.isEmpty() ? null : found.get(0);
    }

    /** Where new policies and challenge sets go: eDirectory's standard container, or the first password policy container found. */
    private String policiesContainer(Ldap l) throws NamingException {
        if (l.read(POLICIES, "cn") != null) {
            return POLICIES;
        }
        List<Ldap.Entry> found = l.search("", "(objectClass=nspmPasswordPolicyContainer)", null, SearchControls.SUBTREE_SCOPE, new String[] {"cn"}, 1);
        if (found.isEmpty()) {
            throw new Http.Problem(409, "no-policy-container", "this tree has no password policy container (" + POLICIES + ")");
        }
        return found.get(0).dn();
    }

    private void audit(Sessions.Session s, String action, String target, Map<String, Object> detail, Ldap.Failure f) throws IOException {
        server.objects.audit(s, action, target, detail, f);
    }

    private static String guidOf(Ldap.Entry e) {
        List<Object> g = e.attributes().get("guid");
        return g == null || g.isEmpty() ? null : Names.guidHex(g.get(0));
    }

    private static Map<String, Object> ref(Ldap.Entry e) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("guid", guidOf(e));
        m.put("dn", e.dn());
        m.put("name", Names.identity(e.dn()).get("name"));
        return m;
    }

    private Map<String, Object> refOf(Ldap l, String dn) throws NamingException {
        Ldap.Entry e = dn == null ? null : l.read(dn, "GUID");
        if (e == null) {
            return dn == null ? null : Map.of("dn", dn, "name", String.valueOf(Names.identity(dn).get("name")));
        }
        return ref(e);
    }

    // ---- PKI ----------------------------------------------------------------------------------------

    private static final String[] KMO = {"GUID", "cn", "hostServer", "nDSPKIPublicKeyCertificate", "nDSPKICertificateChain", "nDSPKINotAfter", "nDSPKISubjectName"};

    private Map<String, Object> pki(Ldap l) throws NamingException {
        Map<String, Object> out = new LinkedHashMap<>();
        // the Organizational CA
        Ldap.Entry sec = securityContainer(l);
        Map<String, Object> ca = null;
        if (sec != null && sec.first("nDSPKITreeCADN") != null) {
            Ldap.Entry c = l.read(sec.first("nDSPKITreeCADN"), "GUID", "cn", "hostServer", "nDSPKIPublicKeyCertificate", "nDSPKIPublicKeyCertificateEC",
                "ndspkiDefaultRSAKeySize", "ndspkiDefaultCertificateLife", "nDSPKISubjectName");
            if (c != null) {
                ca = ref(c);
                ca.put("host", c.first("hostServer"));
                ca.put("defaultRsaKeySize", c.first("ndspkiDefaultRSAKeySize"));
                ca.put("defaultLifeYears", c.first("ndspkiDefaultCertificateLife"));
                List<Map<String, Object>> certs = new ArrayList<>();
                for (String a : new String[] {"nDSPKIPublicKeyCertificate", "nDSPKIPublicKeyCertificateEC"}) {
                    Map<String, Object> cert = cert(bytes(c, a));
                    if (cert != null) {
                        certs.add(cert);
                    }
                }
                ca.put("certificates", certs);
            }
        }
        out.put("ca", ca);

        // which key material the LDAP servers and SAS services use
        Map<String, List<String>> usedBy = new LinkedHashMap<>();
        for (Ldap.Entry ls : l.search("", "(objectClass=ldapServer)", null, SearchControls.SUBTREE_SCOPE, new String[] {"cn", "ldapKeyMaterialName", "ldapHostServer"}, 200)) {
            String kmo = ls.first("ldapKeyMaterialName");
            String host = ls.first("ldapHostServer");
            if (kmo != null && host != null) {
                usedBy.computeIfAbsent(kmoKey(kmo + " - " + Names.identity(host).get("name"), Names.parent(host)), k -> new ArrayList<>()).add(String.valueOf(ls.first("cn")));
            }
        }
        for (Ldap.Entry sas : l.search("", "(objectClass=sASService)", null, SearchControls.SUBTREE_SCOPE, new String[] {"cn", "nDSPKIKeyMaterialDN"}, 200)) {
            for (Object dn : sas.attributes().getOrDefault("ndspkikeymaterialdn", List.of())) {
                usedBy.computeIfAbsent(Names.canonical(String.valueOf(dn)), k -> new ArrayList<>()).add(String.valueOf(sas.first("cn")));
            }
        }
        List<Map<String, Object>> kmos = new ArrayList<>();
        for (Ldap.Entry k : l.search("", "(objectClass=nDSPKIKeyMaterial)", null, SearchControls.SUBTREE_SCOPE, KMO, 2000)) {
            Map<String, Object> m = ref(k);
            m.put("server", k.first("hostServer") == null ? null : Map.of("dn", k.first("hostServer"), "name", String.valueOf(Names.identity(k.first("hostServer")).get("name"))));
            m.put("usedBy", usedBy.getOrDefault(Names.canonical(k.dn()), List.of()));
            m.put("certificate", cert(bytes(k, "nDSPKIPublicKeyCertificate")));
            List<Map<String, Object>> chain = new ArrayList<>();
            for (Object v : k.attributes().getOrDefault("ndspkicertificatechain", List.of())) {
                Map<String, Object> c = v instanceof byte[] b ? cert(chainValue(b)) : null;
                if (c != null) {
                    chain.add(c);
                }
            }
            m.put("chain", chain);
            kmos.add(m);
        }
        kmos.sort((a, b) -> String.valueOf(a.get("name")).compareToIgnoreCase(String.valueOf(b.get("name"))));
        out.put("serverCertificates", kmos);

        List<Map<String, Object>> roots = new ArrayList<>();
        for (Ldap.Entry t : l.search("", "(objectClass=nDSPKITrustedRootObject)", null, SearchControls.SUBTREE_SCOPE,
                new String[] {"GUID", "cn", "nDSPKITrustedRootCertificate"}, 2000)) {
            Map<String, Object> m = ref(t);
            m.put("container", Names.parent(t.dn()));
            m.put("certificate", cert(bytes(t, "nDSPKITrustedRootCertificate")));
            roots.add(m);
        }
        out.put("trustedRoots", roots);

        List<Map<String, Object>> crls = new ArrayList<>();
        for (Ldap.Entry c : l.search("", "(objectClass=ndspkiCRLConfiguration)", null, SearchControls.SUBTREE_SCOPE,
                new String[] {"GUID", "cn", "hostServer", "ndspkiCRLType", "ndspkiIssueTime", "ndspkiNextIssueTime", "ndspkiCRLNumber", "ndspkiStatus",
                    "ndspkiDistributionPoints", "ndspkiDistributionPointDN"}, 200)) {
            Map<String, Object> m = ref(c);
            m.put("type", "1".equals(c.first("ndspkiCRLType")) ? "ec" : "rsa");
            m.put("issued", iso(c.first("ndspkiIssueTime")));
            m.put("nextIssue", iso(c.first("ndspkiNextIssueTime")));
            m.put("number", c.first("ndspkiCRLNumber"));
            m.put("status", c.first("ndspkiStatus"));
            m.put("host", c.first("hostServer"));
            m.put("distributionPoints", c.attributes().getOrDefault("ndspkidistributionpoints", List.of()).stream().map(String::valueOf).toList());
            String dp = c.first("ndspkiDistributionPointDN");
            if (dp != null) {
                Ldap.Entry point = l.read(dp, "certificateRevocationList;binary", "certificateRevocationList");
                byte[] der = point == null ? null : firstBytes(point, "certificaterevocationlist;binary", "certificaterevocationlist");
                if (der != null) {
                    try {
                        X509CRL crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(new ByteArrayInputStream(der));
                        m.put("thisUpdate", crl.getThisUpdate().toInstant().toString());
                        m.put("nextUpdate", crl.getNextUpdate() == null ? null : crl.getNextUpdate().toInstant().toString());
                        m.put("revoked", crl.getRevokedCertificates() == null ? 0 : crl.getRevokedCertificates().size());
                        m.put("der", Base64.getEncoder().encodeToString(der));
                    } catch (Exception e) {
                        m.put("crlError", e.getMessage());
                    }
                }
            }
            crls.add(m);
        }
        out.put("crls", crls);
        return out;
    }

    private static String kmoKey(String cn, String container) {
        return Names.canonical(Names.child(container, "cn", cn));
    }

    /** A value of nDSPKICertificateChain: four bytes of header (seen on ig4: 00000100, 01000100), then the DER certificate. */
    static byte[] chainValue(byte[] v) {
        if (v.length > 6 && v[4] == 0x30 && (v[5] & 0xff) == 0x82) {
            return Arrays.copyOfRange(v, 4, v.length);
        }
        return v.length > 1 && v[0] == 0x30 ? v : null;
    }

    private static byte[] bytes(Ldap.Entry e, String attr) {
        return firstBytes(e, attr.toLowerCase(Locale.ROOT), attr.toLowerCase(Locale.ROOT) + ";binary");
    }

    private static byte[] firstBytes(Ldap.Entry e, String... keys) {
        for (String k : keys) {
            List<Object> v = e.attributes().get(k);
            if (v != null && !v.isEmpty() && v.get(0) instanceof byte[] b) {
                return b;
            }
        }
        return null;
    }

    /** A certificate as JSON: names, validity, key, usages, fingerprint, and the DER (base64) for download. */
    static Map<String, Object> cert(byte[] der) {
        if (der == null) {
            return null;
        }
        try {
            X509Certificate c = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("subject", c.getSubjectX500Principal().getName());
            m.put("issuer", c.getIssuerX500Principal().getName());
            m.put("serial", c.getSerialNumber().toString(16));
            m.put("notBefore", c.getNotBefore().toInstant().toString());
            m.put("notAfter", c.getNotAfter().toInstant().toString());
            m.put("signatureAlgorithm", c.getSigAlgName());
            if (c.getPublicKey() instanceof RSAPublicKey r) {
                m.put("key", "RSA " + r.getModulus().bitLength());
            } else if (c.getPublicKey() instanceof ECPublicKey ec) {
                m.put("key", "EC " + ec.getParams().getCurve().getField().getFieldSize());
            } else {
                m.put("key", c.getPublicKey().getAlgorithm());
            }
            List<String> san = new ArrayList<>();
            if (c.getSubjectAlternativeNames() != null) {
                for (List<?> n : c.getSubjectAlternativeNames()) {
                    san.add((Integer.valueOf(2).equals(n.get(0)) ? "DNS:" : Integer.valueOf(7).equals(n.get(0)) ? "IP:" : "") + n.get(1));
                }
            }
            m.put("subjectAltNames", san);
            boolean[] ku = c.getKeyUsage();
            List<String> usages = new ArrayList<>();
            String[] names = {"digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"};
            for (int i = 0; ku != null && i < ku.length && i < names.length; i++) {
                if (ku[i]) {
                    usages.add(names[i]);
                }
            }
            m.put("keyUsage", usages);
            m.put("extendedKeyUsage", c.getExtendedKeyUsage() == null ? List.of() : c.getExtendedKeyUsage());
            m.put("ca", c.getBasicConstraints() >= 0);
            m.put("sha256", HexFormat.ofDelimiter(":").withUpperCase().formatHex(MessageDigest.getInstance("SHA-256").digest(der)));
            m.put("der", Base64.getEncoder().encodeToString(der));
            return m;
        } catch (Exception e) {
            return Map.of("error", "not a certificate: " + e.getMessage());
        }
    }

    /** eDirectory's generalized times (yyyyMMddHHmmss, with or without Z) as ISO-8601. */
    static String iso(String t) {
        if (t == null || !t.matches("\\d{12,14}Z?")) {
            return t;
        }
        String v = t.replace("Z", "");
        String sec = v.length() >= 14 ? v.substring(12, 14) : "00";
        return v.substring(0, 4) + "-" + v.substring(4, 6) + "-" + v.substring(6, 8) + "T" + v.substring(8, 10) + ":" + v.substring(10, 12) + ":" + sec + "Z";
    }

    // ---- password policies ----------------------------------------------------------------------------

    /** Rule name → attribute and kind ("int", "bool", "days" (seconds stored), "hours", "text", "list"). */
    static final Map<String, String[]> RULES = new LinkedHashMap<>();

    static {
        String[][] r = {
            {"minLength", "passwordMinimumLength", "int"}, {"maxLength", "nspmMaximumLength", "int"}, {"caseSensitive", "nspmCaseSensitive", "bool"},
            {"minUpper", "nspmMinUpperCaseCharacters", "int"}, {"maxUpper", "nspmMaxUpperCaseCharacters", "int"},
            {"minLower", "nspmMinLowerCaseCharacters", "int"}, {"maxLower", "nspmMaxLowerCaseCharacters", "int"},
            {"numericAllowed", "nspmNumericCharactersAllowed", "bool"}, {"numericFirst", "nspmNumericAsFirstCharacter", "bool"},
            {"numericLast", "nspmNumericAsLastCharacter", "bool"}, {"minNumeric", "nspmMinNumericCharacters", "int"}, {"maxNumeric", "nspmMaxNumericCharacters", "int"},
            {"specialAllowed", "nspmSpecialCharactersAllowed", "bool"}, {"specialFirst", "nspmSpecialAsFirstCharacter", "bool"},
            {"specialLast", "nspmSpecialAsLastCharacter", "bool"}, {"minSpecial", "nspmMinSpecialCharacters", "int"}, {"maxSpecial", "nspmMaxSpecialCharacters", "int"},
            {"maxRepeated", "nspmMaxRepeatedCharacters", "int"}, {"maxConsecutive", "nspmMaxConsecutiveCharacters", "int"}, {"minUnique", "nspmMinUniqueCharacters", "int"},
            {"excludeList", "nspmExcludeList", "list"}, {"disallowedAttributes", "nspmDisallowedAttributeValues", "list"},
            {"uniqueRequired", "passwordUniqueRequired", "bool"}, {"historyLimit", "nspmPasswordHistoryLimit", "int"},
            {"historyExpirationDays", "nspmPasswordHistoryExpiration", "days"}, {"expirationDays", "passwordExpirationInterval", "days"},
            {"minLifetimeHours", "nspmMinPasswordLifetime", "hours"}, {"graceLogins", "loginGraceLimit", "int"}, {"allowChange", "passwordAllowChange", "bool"},
            {"adminsDoNotExpire", "nspmAdminsDoNotExpirePassword", "bool"}, {"changeMessage", "nspmChangePasswordMessage", "text"},
            {"verifyExisting", "nsimPwdRuleEnforcement", "bool"},
        };
        for (String[] x : r) {
            RULES.put(x[0], new String[] {x[1], x[2]});
        }
    }

    /**
     * nspmConfigurationOptions bits, as Identity Console 26.1.1 reads and writes them (its
     * parsePasswordConfigurationAttribute): two are inverted, set meaning "do not synchronize".
     */
    static final Map<String, Integer> OPTIONS = new LinkedHashMap<>();

    static {
        OPTIONS.put("universalPassword", 0x100);
        OPTIONS.put("advancedRules", 0x200);
        OPTIONS.put("userRetrieve", 0x10);
        OPTIONS.put("adminRetrieve", 0x20);
        OPTIONS.put("syncDistribution", 0x40);
        OPTIONS.put("removeNds", 0x01);
        OPTIONS.put("syncNds", -0x02);
        OPTIONS.put("syncSimple", -0x04);
    }

    static Map<String, Object> options(int v) {
        Map<String, Object> m = new LinkedHashMap<>();
        OPTIONS.forEach((k, bit) -> m.put(k, bit < 0 ? (v & -bit) == 0 : (v & bit) != 0));
        return m;
    }

    static int optionsValue(int current, Map<String, Object> changes) {
        int v = current;
        for (Map.Entry<String, Object> e : changes.entrySet()) {
            Integer bit = OPTIONS.get(e.getKey());
            if (bit == null) {
                throw new IllegalArgumentException("unknown option " + e.getKey() + " (one of " + OPTIONS.keySet() + ")");
            }
            boolean on = Boolean.TRUE.equals(e.getValue());
            boolean set = bit < 0 ? !on : on;
            int b = Math.abs(bit);
            v = set ? v | b : v & ~b;
        }
        return v;
    }

    private static final String[] POLICY_ATTRS;

    static {
        List<String> a = new ArrayList<>(List.of("GUID", "cn", "description", "nspmConfigurationOptions", "nsimAssignments", "nsimChallengeSetDN",
            "nsimForgottenAction", "nsimForgottenLoginConfig"));
        RULES.values().forEach(r -> a.add(r[0]));
        POLICY_ATTRS = a.toArray(new String[0]);
    }

    private List<Map<String, Object>> policies(Ldap l) throws NamingException {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Ldap.Entry e : l.search("", "(objectClass=nspmPasswordPolicy)", null, SearchControls.SUBTREE_SCOPE, POLICY_ATTRS, 500)) {
            Map<String, Object> m = ref(e);
            m.put("description", e.first("description"));
            int opts = intOr(e.first("nspmConfigurationOptions"), 0);
            m.put("universalPassword", (opts & 0x100) != 0);
            m.put("minLength", e.first("passwordMinimumLength"));
            m.put("maxLength", e.first("nspmMaximumLength"));
            m.put("assignments", e.attributes().getOrDefault("nsimassignments", List.of()).size());
            out.add(m);
        }
        out.sort((a, b) -> String.valueOf(a.get("name")).compareToIgnoreCase(String.valueOf(b.get("name"))));
        return out;
    }

    private static int intOr(String s, int dflt) {
        try {
            return s == null ? dflt : Integer.parseInt(s.trim());
        } catch (NumberFormatException e) {
            return dflt;
        }
    }

    private Ldap.Entry policyEntry(Ldap l, String guid) throws NamingException {
        Ldap.Entry e = server.objects.byGuid(l, guid, POLICY_ATTRS);
        Ldap.Entry cls = l.read(e.dn(), "objectClass");
        if (cls == null || cls.attributes().getOrDefault("objectclass", List.of()).stream().noneMatch(c -> String.valueOf(c).equalsIgnoreCase("nspmPasswordPolicy"))) {
            throw new Http.Problem(404, "not-a-password-policy", guid + " is not a password policy");
        }
        return e;
    }

    private Map<String, Object> policy(Ldap l, String guid) throws NamingException {
        Ldap.Entry e = policyEntry(l, guid);
        Map<String, Object> m = ref(e);
        m.put("description", e.first("description"));
        Map<String, Object> rules = new LinkedHashMap<>();
        RULES.forEach((k, r) -> {
            List<Object> v = e.attributes().get(r[0].toLowerCase(Locale.ROOT));
            Object val = null;
            if (v != null && !v.isEmpty()) {
                String s0 = String.valueOf(v.get(0));
                val = switch (r[1]) {
                    case "int" -> intOr(s0, 0);
                    case "bool" -> s0.equalsIgnoreCase("TRUE");
                    case "days" -> intOr(s0, 0) / 86400;
                    case "hours" -> intOr(s0, 0) / 3600;
                    case "list" -> v.stream().map(String::valueOf).toList();
                    default -> s0;
                };
            }
            rules.put(k, val);
        });
        m.put("rules", rules);
        m.put("options", options(intOr(e.first("nspmConfigurationOptions"), 0)));
        m.put("challengeSet", refOf(l, e.first("nsimChallengeSetDN")));
        m.put("forgotten", forgotten(e.first("nsimForgottenAction"), e.first("nsimForgottenLoginConfig")));
        List<Map<String, Object>> assignments = new ArrayList<>();
        for (Object dn : e.attributes().getOrDefault("nsimassignments", List.of())) {
            Map<String, Object> r = refOf(l, String.valueOf(dn));
            if (r != null) {
                assignments.add(r);
            }
        }
        m.put("assignments", assignments);
        return m;
    }

    /** {@code <ForgottenPassword><Enabled>…</Enabled><Sequence><Authentication><![CDATA[…]]></Authentication><Action>…</Action></Sequence></ForgottenPassword>} */
    static Map<String, Object> forgotten(String xml, String loginConfig) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("enabled", xml != null && xml.contains("<Enabled>true</Enabled>"));
        Matcher a = Pattern.compile("<Action>([^<]*)</Action>").matcher(xml == null ? "" : xml);
        m.put("action", a.find() && !a.group(1).isEmpty() ? a.group(1) : null);
        Matcher auth = Pattern.compile("<Authentication><!\\[CDATA\\[(.*?)]]></Authentication>", Pattern.DOTALL).matcher(xml == null ? "" : xml);
        String at = auth.find() ? auth.group(1).trim() : "";
        m.put("authentication", at.isEmpty() ? List.of() : List.of(at.split("[;,]")));
        m.put("loginConfig", "TRUE".equalsIgnoreCase(loginConfig));
        return m;
    }

    @SuppressWarnings("unchecked")
    private List<ModificationItem> policyMods(Map<String, Object> b, Ldap.Entry current) {
        List<ModificationItem> mods = new ArrayList<>();
        if (b.containsKey("description")) {
            Object d = b.get("description");
            if (d == null || String.valueOf(d).isBlank()) {
                if (current != null && current.first("description") != null) {
                    mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute("description")));
                }
            } else {
                mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("description", String.valueOf(d))));
            }
        }
        if (b.get("rules") instanceof Map<?, ?> rules) {
            for (Map.Entry<?, ?> r : rules.entrySet()) {
                String[] def = RULES.get(String.valueOf(r.getKey()));
                if (def == null) {
                    throw new IllegalArgumentException("unknown rule " + r.getKey());
                }
                Object v = r.getValue();
                if (v == null) {
                    if (current == null || current.attributes().containsKey(def[0].toLowerCase(Locale.ROOT))) {
                        mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute(def[0])));
                    }
                    continue;
                }
                BasicAttribute a = new BasicAttribute(def[0]);
                switch (def[1]) {
                    case "int" -> a.add(String.valueOf(number(r.getKey(), v, 0, 1_000_000)));
                    case "days" -> a.add(String.valueOf((long) number(r.getKey(), v, 0, 36500) * 86400));
                    case "hours" -> a.add(String.valueOf((long) number(r.getKey(), v, 0, 876000) * 3600));
                    case "bool" -> a.add(Boolean.TRUE.equals(v) ? "TRUE" : "FALSE");
                    case "list" -> {
                        if (!(v instanceof List<?> list)) {
                            throw new IllegalArgumentException(r.getKey() + " is a list");
                        }
                        list.forEach(x -> a.add(String.valueOf(x)));
                        if (list.isEmpty()) {
                            if (current == null || current.attributes().containsKey(def[0].toLowerCase(Locale.ROOT))) {
                                mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute(def[0])));
                            }
                            continue;
                        }
                    }
                    default -> a.add(String.valueOf(v));
                }
                mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, a));
            }
        }
        if (b.get("options") instanceof Map<?, ?> o) {
            int now = current == null ? 0 : intOr(current.first("nspmConfigurationOptions"), 0);
            mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("nspmConfigurationOptions",
                String.valueOf(optionsValue(now, (Map<String, Object>) o)))));
        }
        return mods;
    }

    private static int number(Object field, Object v, int min, int max) {
        int n;
        try {
            n = v instanceof Number x ? x.intValue() : Integer.parseInt(String.valueOf(v));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(field + " is a whole number");
        }
        if (n < min || n > max) {
            throw new IllegalArgumentException(field + " is between " + min + " and " + max);
        }
        return n;
    }

    private void challengeSetLink(Ldap l, Map<String, Object> b, List<ModificationItem> mods, Ldap.Entry current) throws NamingException {
        if (!b.containsKey("challengeSet")) {
            return;
        }
        Object cs = b.get("challengeSet");
        if (cs == null) {
            if (current != null && current.first("nsimChallengeSetDN") != null) {
                mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute("nsimChallengeSetDN")));
                mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute("nsimChallengeSetGUID")));
            }
            return;
        }
        Ldap.Entry set = server.objects.byGuid(l, String.valueOf(cs), "objectClass", "GUID");
        if (set.attributes().getOrDefault("objectclass", List.of()).stream().noneMatch(c -> String.valueOf(c).equalsIgnoreCase("nsimChallengeSet"))) {
            throw new Http.Problem(400, "not-a-challenge-set", cs + " is not a challenge set");
        }
        mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("nsimChallengeSetDN", set.dn())));
        mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("nsimChallengeSetGUID", Names.guidBytes(String.valueOf(cs)))));
    }

    private void createPolicy(HttpExchange ex, Ldap l, Sessions.Session s) throws IOException, NamingException {
        Map<String, Object> b = Http.body(ex);
        String name = Http.string(b, "name", true).trim();
        if (name.isEmpty()) {
            throw new Http.Problem(400, "missing-field", "a policy needs a name");
        }
        String dn = Names.child(policiesContainer(l), "cn", name);
        Map<String, List<Object>> attrs = new LinkedHashMap<>();
        attrs.put("objectClass", List.of("nspmPasswordPolicy"));
        attrs.put("cn", List.of(name));
        Map<String, Object> body = new LinkedHashMap<>(b);
        // a new policy starts with Universal Password and advanced rules on, as iManager's wizard does, unless told otherwise
        Map<String, Object> opts = new LinkedHashMap<>(Map.of("universalPassword", true, "advancedRules", true, "syncNds", true, "syncSimple", true));
        if (b.get("options") instanceof Map<?, ?> o) {
            o.forEach((k, v) -> opts.put(String.valueOf(k), v));
        }
        body.put("options", opts);
        Map<String, Object> detail = Map.of("dn", dn);
        // everything is validated before anything is written
        List<ModificationItem> mods = policyMods(body, null);
        challengeSetLink(l, b, mods, null);
        try {
            l.create(dn, attrs);
            if (!mods.isEmpty()) {
                l.modify(dn, mods);
            }
        } catch (NamingException x) {
            audit(s, "password-policy.create", null, detail, Ldap.Failure.of(x));
            throw x;
        }
        audit(s, "password-policy.create", null, detail, null);
        Ldap.Entry made = l.read(dn, "GUID");
        Http.json(ex, 201, policy(l, guidOf(made)));
    }

    private void updatePolicy(HttpExchange ex, Ldap l, Sessions.Session s, String guid) throws IOException, NamingException {
        Map<String, Object> b = Http.body(ex);
        Ldap.Entry e = policyEntry(l, guid);
        List<ModificationItem> mods = policyMods(b, e);
        challengeSetLink(l, b, mods, e);
        Map<String, Object> detail = Map.of("dn", e.dn(), "attributes", mods.stream().map(m -> m.getAttribute().getID()).distinct().toList());
        if (!mods.isEmpty()) {
            try {
                l.modify(e.dn(), mods);
            } catch (NamingException x) {
                audit(s, "password-policy.modify", guid, detail, Ldap.Failure.of(x));
                throw x;
            }
            audit(s, "password-policy.modify", guid, detail, null);
        }
        Http.json(ex, 200, policy(l, guid));
    }

    /** eDirectory allows deleting an assigned policy and silently clears every target's nspmPasswordPolicyDN (ig4): the count is confirmed first. */
    private void deletePolicy(HttpExchange ex, Ldap l, Sessions.Session s, String guid) throws IOException, NamingException {
        Ldap.Entry e = policyEntry(l, guid);
        int assigned = e.attributes().getOrDefault("nsimassignments", List.of()).size();
        String confirmed = ex.getRequestHeaders().getFirst("X-Confirm-Count");
        if (assigned > 0 && !String.valueOf(assigned).equals(confirmed)) {
            throw new Http.Problem(409, "confirm-count", e.dn() + " is assigned to " + assigned + " object(s); deleting it unassigns them. Send X-Confirm-Count: " + assigned,
                Map.of("count", assigned));
        }
        Map<String, Object> detail = Map.of("dn", e.dn(), "assignments", assigned);
        try {
            l.delete(e.dn());
        } catch (NamingException x) {
            audit(s, "password-policy.delete", guid, detail, Ldap.Failure.of(x));
            throw x;
        }
        audit(s, "password-policy.delete", guid, detail, null);
        Http.json(ex, 204, Map.of());
    }

    /**
     * Assign (or unassign) a policy: eDirectory does not link the target's nspmPasswordPolicyDN and the
     * policy's nsimAssignments (ig4), so both are written, as iManager does. A target already assigned
     * another policy is taken off that policy's list. The Login Policy object counts as the tree.
     */
    private void assign(HttpExchange ex, Ldap l, Sessions.Session s, String guid, String targetGuid, boolean on) throws IOException, NamingException {
        Ldap.Entry policy = policyEntry(l, guid);
        if (!Names.guid(targetGuid)) {
            throw new Http.Problem(400, "bad-guid", "target is an object's GUID");
        }
        Ldap.Entry target = server.objects.byGuid(l, targetGuid, "nspmPasswordPolicyDN", "objectClass");
        String previous = target.first("nspmPasswordPolicyDN");
        Map<String, Object> detail = new LinkedHashMap<>(Map.of("policy", policy.dn(), "target", target.dn()));
        try {
            if (on) {
                if (previous != null && !Names.same(previous, policy.dn())) {
                    detail.put("replaced", previous);
                    try {
                        l.modify(previous, List.of(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute("nsimAssignments", target.dn()))));
                    } catch (NamingException ignored) {
                        // not listed there
                    }
                }
                l.modify(target.dn(), List.of(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("nspmPasswordPolicyDN", policy.dn()))));
                boolean listed = policy.attributes().getOrDefault("nsimassignments", List.of()).stream().anyMatch(x -> Names.same(String.valueOf(x), target.dn()));
                if (!listed) {
                    l.modify(policy.dn(), List.of(new ModificationItem(DirContext.ADD_ATTRIBUTE, new BasicAttribute("nsimAssignments", target.dn()))));
                }
            } else {
                if (previous != null && Names.same(previous, policy.dn())) {
                    l.modify(target.dn(), List.of(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute("nspmPasswordPolicyDN"))));
                }
                boolean listed = policy.attributes().getOrDefault("nsimassignments", List.of()).stream().anyMatch(x -> Names.same(String.valueOf(x), target.dn()));
                if (listed) {
                    l.modify(policy.dn(), List.of(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute("nsimAssignments", target.dn()))));
                }
            }
        } catch (NamingException x) {
            audit(s, on ? "password-policy.assign" : "password-policy.unassign", guid, detail, Ldap.Failure.of(x));
            throw x;
        }
        audit(s, on ? "password-policy.assign" : "password-policy.unassign", guid, detail, null);
        Http.json(ex, 200, policy(l, guid));
    }

    /** The policy assignments that could apply to an object: its own, its containers' (nearest first), and the Login Policy's (the tree's). */
    private Map<String, Object> policyFor(Ldap l, String guid) throws NamingException {
        Ldap.Entry e = server.objects.byGuid(l, guid, "nspmPasswordPolicyDN");
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("own", refOf(l, e.first("nspmPasswordPolicyDN")));
        List<Map<String, Object>> containers = new ArrayList<>();
        String dn = e.dn();
        while (!dn.isEmpty()) {
            dn = Names.parent(dn);
            if (dn.isEmpty()) {
                break;
            }
            Ldap.Entry c = l.read(dn, "nspmPasswordPolicyDN");
            if (c != null && c.first("nspmPasswordPolicyDN") != null) {
                containers.add(Map.of("container", dn, "policy", refOf(l, c.first("nspmPasswordPolicyDN"))));
            }
        }
        m.put("containers", containers);
        Ldap.Entry sec = securityContainer(l);
        String lpDn = sec == null || sec.first("sASLoginPolicyDN") == null ? "cn=Login Policy,cn=Security" : sec.first("sASLoginPolicyDN");
        Ldap.Entry lp = l.read(lpDn, "nspmPasswordPolicyDN");
        m.put("loginPolicy", lp == null ? null : refOf(l, lp.first("nspmPasswordPolicyDN")));
        return m;
    }

    // ---- challenge sets ---------------------------------------------------------------------------------

    private static final String[] SET_ATTRS = {"GUID", "cn", "description", "nsimRequiredQuestions", "nsimRandomQuestions", "nsimNumberRandomQuestions",
        "nsimMinResponseLength", "nsimMaxResponseLength", "objectClass"};

    private List<Map<String, Object>> challengeSets(Ldap l) throws NamingException {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Ldap.Entry e : l.search("", "(objectClass=nsimChallengeSet)", null, SearchControls.SUBTREE_SCOPE, SET_ATTRS, 500)) {
            Map<String, Object> m = ref(e);
            m.put("description", e.first("description"));
            m.put("required", questions(e.first("nsimRequiredQuestions")).size());
            m.put("random", questions(e.first("nsimRandomQuestions")).size());
            m.put("randomCount", intOr(e.first("nsimNumberRandomQuestions"), 0));
            out.add(m);
        }
        out.sort((a, b) -> String.valueOf(a.get("name")).compareToIgnoreCase(String.valueOf(b.get("name"))));
        return out;
    }

    private Ldap.Entry setEntry(Ldap l, String guid) throws NamingException {
        Ldap.Entry e = server.objects.byGuid(l, guid, SET_ATTRS);
        if (e.attributes().getOrDefault("objectclass", List.of()).stream().noneMatch(c -> String.valueOf(c).equalsIgnoreCase("nsimChallengeSet"))) {
            throw new Http.Problem(404, "not-a-challenge-set", guid + " is not a challenge set");
        }
        return e;
    }

    private Map<String, Object> challengeSet(Ldap l, String guid) throws NamingException {
        Ldap.Entry e = setEntry(l, guid);
        Map<String, Object> m = ref(e);
        m.put("description", e.first("description"));
        m.put("required", questions(e.first("nsimRequiredQuestions")));
        m.put("random", questions(e.first("nsimRandomQuestions")));
        m.put("randomCount", intOr(e.first("nsimNumberRandomQuestions"), 0));
        m.put("minResponse", e.first("nsimMinResponseLength") == null ? null : intOr(e.first("nsimMinResponseLength"), 0));
        m.put("maxResponse", e.first("nsimMaxResponseLength") == null ? null : intOr(e.first("nsimMaxResponseLength"), 0));
        return m;
    }

    private static final Pattern QUESTION = Pattern.compile(
        "<UserDefined\\s+([^>]*?)/>|<Question\\s+([^>]*)>\\s*<!\\[CDATA\\[(.*?)]]>\\s*</Question>", Pattern.DOTALL);

    /** {@code <RequiredQuestions><UserDefined MaxLength MinLength/><AdminDefined><Question MaxLength MinLength><![CDATA[…]]></Question></AdminDefined></RequiredQuestions>}, in order. */
    static List<Map<String, Object>> questions(String xml) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (xml == null) {
            return out;
        }
        Matcher m = QUESTION.matcher(xml);
        while (m.find()) {
            Map<String, Object> q = new LinkedHashMap<>();
            String attrs = m.group(1) != null ? m.group(1) : m.group(2);
            q.put("kind", m.group(1) != null ? "user" : "admin");
            q.put("text", m.group(3));
            q.put("min", lengthAttr(attrs, "MinLength"));
            q.put("max", lengthAttr(attrs, "MaxLength"));
            out.add(q);
        }
        return out;
    }

    private static Integer lengthAttr(String attrs, String name) {
        Matcher m = Pattern.compile(name + "=\"(\\d+)\"").matcher(attrs);
        return m.find() ? Integer.valueOf(m.group(1)) : null;
    }

    /** The XML eDirectory stores: user-defined slots first, then the administrator's questions (as iManager writes it). */
    static String questionsXml(String element, Object list) {
        if (!(list instanceof List<?> qs)) {
            throw new IllegalArgumentException(element + " is a list of questions");
        }
        StringBuilder user = new StringBuilder();
        StringBuilder admin = new StringBuilder();
        for (Object o : qs) {
            Map<String, Object> q = Json.asMap(o);
            int min = number("min", q.getOrDefault("min", 1), 1, 255);
            int max = number("max", q.getOrDefault("max", 255), 1, 255);
            if (min > max) {
                throw new IllegalArgumentException("a question's minimum length is above its maximum");
            }
            if ("user".equals(q.get("kind"))) {
                user.append("<UserDefined MaxLength=\"").append(max).append("\" MinLength=\"").append(min).append("\"/>");
            } else {
                String text = String.valueOf(q.get("text") == null ? "" : q.get("text")).trim();
                if (text.isEmpty()) {
                    throw new IllegalArgumentException("an administrator's question needs its text");
                }
                admin.append("<Question MaxLength=\"").append(max).append("\" MinLength=\"").append(min).append("\"><![CDATA[")
                    .append(text.replace("]]>", "]]]]><![CDATA[>")).append("]]></Question>");
            }
        }
        return "<" + element + ">" + user + (admin.length() > 0 ? "<AdminDefined>" + admin + "</AdminDefined>" : "") + "</" + element + ">";
    }

    private List<ModificationItem> setMods(Map<String, Object> b, Ldap.Entry current) {
        List<ModificationItem> mods = new ArrayList<>();
        if (b.containsKey("description")) {
            Object d = b.get("description");
            if (d == null || String.valueOf(d).isBlank()) {
                if (current != null && current.first("description") != null) {
                    mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute("description")));
                }
            } else {
                mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("description", String.valueOf(d))));
            }
        }
        if (b.containsKey("required")) {
            mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("nsimRequiredQuestions", questionsXml("RequiredQuestions", b.get("required")))));
        }
        if (b.containsKey("random")) {
            mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("nsimRandomQuestions", questionsXml("RandomQuestions", b.get("random")))));
        }
        if (b.containsKey("randomCount")) {
            int n = number("randomCount", b.get("randomCount"), 0, 100);
            if (b.get("random") instanceof List<?> r && n > r.size()) {
                throw new IllegalArgumentException("randomCount is at most the number of random questions");
            }
            mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("nsimNumberRandomQuestions", String.valueOf(n))));
        }
        for (String[] k : new String[][] {{"minResponse", "nsimMinResponseLength"}, {"maxResponse", "nsimMaxResponseLength"}}) {
            if (b.containsKey(k[0])) {
                Object v = b.get(k[0]);
                if (v == null) {
                    if (current != null && current.first(k[1]) != null) {
                        mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute(k[1])));
                    }
                } else {
                    mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(k[1], String.valueOf(number(k[0], v, 1, 255)))));
                }
            }
        }
        return mods;
    }

    private void createChallengeSet(HttpExchange ex, Ldap l, Sessions.Session s) throws IOException, NamingException {
        Map<String, Object> b = Http.body(ex);
        String name = Http.string(b, "name", true).trim();
        if (name.isEmpty()) {
            throw new Http.Problem(400, "missing-field", "a challenge set needs a name");
        }
        String dn = Names.child(policiesContainer(l), "cn", name);
        List<ModificationItem> mods = setMods(b, null);
        Map<String, Object> detail = Map.of("dn", dn);
        try {
            l.create(dn, new LinkedHashMap<>(Map.of("objectClass", List.of("nsimChallengeSet"), "cn", List.of(name))));
            if (!mods.isEmpty()) {
                l.modify(dn, mods);
            }
        } catch (NamingException x) {
            audit(s, "challenge-set.create", null, detail, Ldap.Failure.of(x));
            throw x;
        }
        audit(s, "challenge-set.create", null, detail, null);
        Http.json(ex, 201, challengeSet(l, guidOf(l.read(dn, "GUID"))));
    }

    private void updateChallengeSet(HttpExchange ex, Ldap l, Sessions.Session s, String guid) throws IOException, NamingException {
        Map<String, Object> b = Http.body(ex);
        Ldap.Entry e = setEntry(l, guid);
        List<ModificationItem> mods = setMods(b, e);
        Map<String, Object> detail = Map.of("dn", e.dn(), "attributes", mods.stream().map(m -> m.getAttribute().getID()).distinct().toList());
        if (!mods.isEmpty()) {
            try {
                l.modify(e.dn(), mods);
            } catch (NamingException x) {
                audit(s, "challenge-set.modify", guid, detail, Ldap.Failure.of(x));
                throw x;
            }
            audit(s, "challenge-set.modify", guid, detail, null);
        }
        Http.json(ex, 200, challengeSet(l, guid));
    }

    private void deleteChallengeSet(HttpExchange ex, Ldap l, Sessions.Session s, String guid) throws IOException, NamingException {
        Ldap.Entry e = setEntry(l, guid);
        List<Ldap.Entry> users = l.search("", "(&(objectClass=nspmPasswordPolicy)(nsimChallengeSetDN={0}))", new Object[] {e.dn()},
            SearchControls.SUBTREE_SCOPE, new String[] {"cn"}, 50);
        if (!users.isEmpty()) {
            throw new Http.Problem(409, "in-use", "password policies use this challenge set: " + users.stream().map(Ldap.Entry::dn).toList(),
                Map.of("policies", users.stream().map(Ldap.Entry::dn).toList()));
        }
        Map<String, Object> detail = Map.of("dn", e.dn());
        try {
            l.delete(e.dn());
        } catch (NamingException x) {
            audit(s, "challenge-set.delete", guid, detail, Ldap.Failure.of(x));
            throw x;
        }
        audit(s, "challenge-set.delete", guid, detail, null);
        Http.json(ex, 204, Map.of());
    }

    // ---- NMAS ---------------------------------------------------------------------------------------------

    /** The Login Policy's sequences ("name;grade;methods", as stored), the default, and the installed login methods. */
    private Map<String, Object> loginPolicy(Ldap l) throws NamingException {
        Map<String, Object> m = new LinkedHashMap<>();
        Ldap.Entry sec = securityContainer(l);
        String lpDn = sec == null || sec.first("sASLoginPolicyDN") == null ? "cn=Login Policy,cn=Security" : sec.first("sASLoginPolicyDN");
        String root = sec == null ? "cn=Security" : sec.dn();
        Ldap.Entry lp = l.read(lpDn, "sASLoginSequence", "sasDefaultLoginSequence", "nspmPasswordPolicyDN");
        List<Map<String, Object>> seqs = new ArrayList<>();
        if (lp != null) {
            for (Object v : lp.attributes().getOrDefault("sasloginsequence", List.of())) {
                String[] parts = String.valueOf(v).split(";", 3);
                Map<String, Object> q = new LinkedHashMap<>();
                q.put("name", parts[0]);
                q.put("grade", parts.length > 1 ? parts[1] : null);
                q.put("methods", parts.length > 2 ? List.of(parts[2].split(",")) : List.of());
                seqs.add(q);
            }
            String d = lp.first("sasDefaultLoginSequence");
            m.put("defaultSequence", d == null || d.equals("<no default>") ? null : d);
            m.put("passwordPolicy", refOf(l, lp.first("nspmPasswordPolicyDN")));
        }
        m.put("sequences", seqs);
        List<Map<String, Object>> methods = new ArrayList<>();
        for (String container : new String[] {"cn=Authorized Login Methods," + root, "cn=Authorized Post Login Methods," + root}) {
            List<Ldap.Entry> found;
            try {
                found = l.search(container, "(objectClass=*)", null, SearchControls.ONELEVEL_SCOPE,
                    new String[] {"GUID", "cn", "description", "sASMethodVendor", "sASMethodIdentifier", "objectClass"}, 200);
            } catch (javax.naming.NameNotFoundException e) {
                continue;
            }
            for (Ldap.Entry e : found) {
                Map<String, Object> x = ref(e);
                x.put("description", e.first("description"));
                x.put("vendor", e.first("sASMethodVendor"));
                x.put("postLogin", container.contains("Post"));
                methods.add(x);
            }
        }
        m.put("methods", methods);
        return m;
    }
}
