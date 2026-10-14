package com.pointblue.console.server.http;

import com.pointblue.console.server.auth.DirectoryConfig;
import com.pointblue.console.server.auth.Role;
import com.pointblue.console.server.auth.Sessions;
import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.console.server.ldap.Names;
import com.pointblue.console.server.ldap.Eba;
import com.pointblue.console.server.ldap.Pki;
import com.pointblue.console.server.ldap.Servers;
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
            .replaceAll("^pki/(servers|server-certificates|ldap-servers)/[0-9a-f]{32}", "pki/$1/{guid}")
            .replaceAll("^login-policy/sequences/[^/]+$", "login-policy/sequences/{name}")
            .replaceAll("^objects/\\{guid\\}/certificates/[^/]+/revoke$", "objects/{guid}/certificates/{name}/revoke")
            .replaceAll("assignments/[0-9a-f]{32}$", "assignments/{target}");
        String guid = p.length > 3 && p[2].equals("pki") ? (p.length > 4 ? p[4] : null) : p.length > 3 ? p[3] : null;
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
                case "GET eba" -> Http.json(ex, 200, eba(l));
                case "POST login-policy/sequences" -> changeSequence(ex, l, s, null);
                case "PATCH login-policy/sequences/{name}" -> changeSequence(ex, l, s, java.net.URLDecoder.decode(p[4], java.nio.charset.StandardCharsets.UTF_8));
                case "DELETE login-policy/sequences/{name}" -> deleteSequence(ex, l, s, java.net.URLDecoder.decode(p[4], java.nio.charset.StandardCharsets.UTF_8));
                case "POST pki/servers/{guid}/certificates" -> createServerCertificate(ex, l, s, guid);
                case "GET pki/servers/{guid}/default-certificates" -> Http.json(ex, 200, defaultCertificates(l, guid));
                case "POST pki/servers/{guid}/default-certificates" -> repairDefaultCertificates(ex, l, s, guid);
                case "PUT pki/ldap-servers/{guid}/certificate" -> useForLdap(ex, l, s, guid);
                case "DELETE pki/server-certificates/{guid}" -> deleteServerCertificate(ex, l, s, guid);
                case "POST pki/server-certificates/{guid}/revoke" -> revokeServerCertificate(ex, l, s, guid);
                case "POST objects/{guid}/certificates/{name}/revoke" ->
                    revokeUserCertificate(ex, l, s, guid, java.net.URLDecoder.decode(p[5], java.nio.charset.StandardCharsets.UTF_8));
                case "GET objects/{guid}/certificates" -> Http.json(ex, 200, Map.of("items", userCertificates(l, guid)));
                case "POST objects/{guid}/certificates" -> createUserCertificate(ex, l, s, guid);
                default -> throw new Http.Problem(404, "not-found", method + " " + path);
            }
        } catch (NamingException e) {
            throw server.objects.problem(s, Ldap.Failure.of(e));
        } catch (IllegalArgumentException e) {
            throw new Http.Problem(400, "bad-request", e.getMessage());
        }
    }

    // ---- PKI operations (6b) ----------------------------------------------------------------------

    /** The request's certificate: name, key (rsa with 2048-4096 bits, or ec256/ec384), signature, years, subject, names. */
    private static Pki.Spec spec(Map<String, Object> b, String defaultSubject, boolean exportableByDefault) {
        String name = Http.string(b, "name", true).trim();
        if (!name.matches("[A-Za-z0-9 _.-]{1,64}")) {
            throw new IllegalArgumentException("a certificate name is 1-64 letters, digits, spaces, dots, dashes or underscores");
        }
        String algorithm = b.get("algorithm") == null ? "rsa" : Http.string(b, "algorithm", true);
        if (!List.of("rsa", "ec256", "ec384").contains(algorithm)) {
            throw new IllegalArgumentException("algorithm is rsa, ec256 or ec384");
        }
        int bits = Http.integer(b, "rsaBits", 2048);
        if (algorithm.equals("rsa") && !List.of(2048, 3072, 4096).contains(bits)) {
            throw new IllegalArgumentException("an RSA key is 2048, 3072 or 4096 bits");
        }
        String signature = b.get("signature") == null ? "sha256" : Http.string(b, "signature", true);
        if (!List.of("sha256", "sha384", "sha512").contains(signature)) {
            throw new IllegalArgumentException("signature is sha256, sha384 or sha512");
        }
        int years = Http.integer(b, "validityYears", 2);
        if (years < 1 || years > 10) {
            throw new IllegalArgumentException("validity is 1 to 10 years");
        }
        String subject = b.get("subject") == null || String.valueOf(b.get("subject")).isBlank() ? defaultSubject : Http.string(b, "subject", true).trim();
        Names.parse(subject);
        List<String> names = new ArrayList<>();
        if (b.get("names") instanceof List<?> list) {
            if (list.size() > 20) {
                throw new IllegalArgumentException("at most 20 alternative names");
            }
            for (Object o : list) {
                String n = String.valueOf(o).trim();
                if (!n.matches("(dns:[A-Za-z0-9*.-]{1,253}|ip:[0-9A-Fa-f.:]{2,45}|email:[^\\s@]+@[^\\s@]+|uri:\\S{1,500})")) {
                    throw new IllegalArgumentException("an alternative name is dns:host, ip:address, email:address or uri:…; not " + n);
                }
                names.add(n);
            }
        }
        boolean exportable = b.get("exportable") == null ? exportableByDefault : Boolean.TRUE.equals(b.get("exportable"));
        String email = b.get("email") == null ? null : String.valueOf(b.get("email")).trim();
        return new Pki.Spec(name, algorithm, bits, signature, years, subject, names, exportable, email);
    }

    /** {@code POST pki/servers/{guid}/certificates}: a server certificate (key material object) on that server, from the tree CA. */
    private void createServerCertificate(HttpExchange ex, Ldap l, Sessions.Session s, String serverGuid) throws IOException, NamingException {
        Ldap.Entry srv = Servers.find(l, serverGuid);
        if (srv == null) {
            throw new Http.Problem(404, "no-such-server", "no eDirectory server has GUID " + serverGuid);
        }
        String serverName = String.valueOf(srv.first("cn"));
        Map<String, Object> b = Http.body(ex);
        Pki.Spec spec = spec(b, "cn=" + serverName, true);
        String kmo = Names.child(Names.parent(srv.dn()), "cn", spec.name() + " - " + serverName);
        if (l.read(kmo, "cn") != null) {
            throw new Http.Problem(409, "exists", "the server already has a certificate named " + spec.name());
        }
        Map<String, Object> detail = new LinkedHashMap<>(Map.of("server", srv.dn(), "name", spec.name(), "algorithm", spec.algorithm(), "years", spec.validityYears()));
        try {
            Pki.createServerCertificate(l, srv.dn(), spec);
        } catch (Pki.Refused r) {
            detail.put("code", r.code);
            audit(s, "pki.server-certificate.create", null, detail, null);
            throw new Http.Problem(409, "pki-refused", r.getMessage(), Map.of("code", r.code));
        }
        Ldap.Entry made = l.read(kmo, KMO);
        audit(s, "pki.server-certificate.create", made == null ? kmo : Names.guidHex(made.first("GUID")), detail, null);
        Map<String, Object> out = made == null ? Map.of("dn", kmo) : kmoJson(made);
        Http.json(ex, 201, out);
    }

    private Map<String, Object> kmoJson(Ldap.Entry k) {
        Map<String, Object> m = ref(k);
        m.put("server", k.first("hostServer") == null ? null : Map.of("dn", k.first("hostServer"), "name", String.valueOf(Names.identity(k.first("hostServer")).get("name"))));
        m.put("certificate", cert(bytes(k, "nDSPKIPublicKeyCertificate")));
        return m;
    }

    /**
     * {@code DELETE pki/server-certificates/{guid}}: a server certificate's key material object. Refused
     * while an LDAP server uses it: the server would have no certificate to offer. (The SAS Service's list
     * of its server's key material objects is not a use; eDirectory drops the reference with the object.)
     */
    private void deleteServerCertificate(HttpExchange ex, Ldap l, Sessions.Session s, String guid) throws IOException, NamingException {
        Ldap.Entry k = server.objects.byGuid(l, guid, "objectClass", "cn", "hostServer");
        if (k == null || k.attributes().getOrDefault("objectclass", List.of()).stream().noneMatch(o -> String.valueOf(o).equalsIgnoreCase("nDSPKIKeyMaterial"))) {
            throw new Http.Problem(404, "not-found", "no server certificate has GUID " + guid);
        }
        List<String> users = new ArrayList<>();
        for (Ldap.Entry ls : l.search("", "(objectClass=ldapServer)", null, SearchControls.SUBTREE_SCOPE, new String[] {"cn", "ldapKeyMaterialName", "ldapHostServer"}, 200)) {
            String name = ls.first("ldapKeyMaterialName");
            String host = ls.first("ldapHostServer");
            if (name != null && host != null && Names.same(k.dn(), Names.child(Names.parent(host), "cn", name + " - " + Names.identity(host).get("name")))) {
                users.add(String.valueOf(ls.first("cn")));
            }
        }
        if (!users.isEmpty()) {
            throw new Http.Problem(409, "in-use", k.first("cn") + " is in use by " + String.join(", ", users) + "; choose another certificate there first",
                Map.of("usedBy", users));
        }
        try {
            l.delete(k.dn());
        } catch (NamingException x) {
            audit(s, "pki.server-certificate.delete", guid, Map.of("dn", k.dn()), Ldap.Failure.of(x));
            throw x;
        }
        audit(s, "pki.server-certificate.delete", guid, Map.of("dn", k.dn()), null);
        Http.json(ex, 204, Map.of());
    }

    // ---- default server certificates ---------------------------------------------------------------

    /**
     * eDirectory's default server certificates, as ndsconfig and Identity Console name them: RSA for
     * the server's DNS name, EC (when the tree CA has an EC key), and RSA for its IP address.
     */
    enum DefaultCert {
        DNS("SSL CertificateDNS"), EC("SSL EC CertificateDNS"), IP("SSL CertificateIP");

        final String cn;

        DefaultCert(String cn) {
            this.cn = cn;
        }

        String key() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    /** What a server's default certificates should be, and the state each is in. */
    private record DefaultsState(Ldap.Entry server, String tree, X509Certificate caRsa, X509Certificate caEc, int rsaBits, List<String> ips,
                                 List<String> dnsNames, Map<DefaultCert, Ldap.Entry> existing) {
    }

    private DefaultsState defaultsState(Ldap l, String serverGuid) throws NamingException {
        Ldap.Entry srv = Servers.find(l, serverGuid);
        if (srv == null) {
            throw new Http.Problem(404, "no-such-server", "no eDirectory server has GUID " + serverGuid);
        }
        Ldap.Entry sec = securityContainer(l);
        Ldap.Entry ca = sec == null || sec.first("nDSPKITreeCADN") == null ? null
            : l.read(sec.first("nDSPKITreeCADN"), "nDSPKIPublicKeyCertificate", "nDSPKIPublicKeyCertificateEC", "ndspkiDefaultRSAKeySize");
        if (ca == null) {
            throw new Http.Problem(409, "no-ca", "this tree has no Organizational CA to issue certificates");
        }
        X509Certificate rsa = x509(bytes(ca, "nDSPKIPublicKeyCertificate"));
        X509Certificate ec = x509(bytes(ca, "nDSPKIPublicKeyCertificateEC"));
        // the tree's name: the root DSE's, else the CA's O (eDirectory names its CA OU=Organizational CA,O=<tree>)
        Ldap.Entry root = l.read("", "directoryTreeName");
        String tree = root == null ? null : root.first("directoryTreeName");
        if ((tree == null || tree.isBlank()) && rsa != null) {
            tree = rdn(rsa.getSubjectX500Principal().getName(), "O");
        }
        List<String> ips = new ArrayList<>();
        for (Object a : srv.attributes().getOrDefault("networkaddress", List.of())) {
            // IPv4 only: eDirectory's own default certificates name the IPv4 address and no other (ig4, 2026-10-14)
            String ip = a instanceof byte[] b ? NetAddress.ipOnly(b) : null;
            if (ip != null && !ip.contains(":") && !ip.startsWith("127.") && !ips.contains(ip)) {
                ips.add(ip);
            }
        }
        Map<DefaultCert, Ldap.Entry> existing = new java.util.EnumMap<>(DefaultCert.class);
        String serverName = String.valueOf(srv.first("cn"));
        for (DefaultCert d : DefaultCert.values()) {
            Ldap.Entry k = l.read(Names.child(Names.parent(srv.dn()), "cn", d.cn + " - " + serverName), KMO);
            if (k != null) {
                existing.put(d, k);
            }
        }
        // DNS names: those the present certificates carry, else the server's own name
        List<String> dns = new ArrayList<>();
        for (DefaultCert d : List.of(DefaultCert.DNS, DefaultCert.EC)) {
            X509Certificate c = existing.containsKey(d) ? x509(bytes(existing.get(d), "nDSPKIPublicKeyCertificate")) : null;
            for (String n : sans(c, 2)) {
                if (!dns.contains(n)) {
                    dns.add(n);
                }
            }
        }
        if (dns.isEmpty()) {
            dns.add(serverName);
        }
        // the CA's default RSA key size, as eDirectory's own default certificates have it (4096 on ig4)
        int bits = List.of("2048", "3072", "4096").contains(String.valueOf(ca.first("ndspkiDefaultRSAKeySize"))) ? Integer.parseInt(ca.first("ndspkiDefaultRSAKeySize")) : 2048;
        return new DefaultsState(srv, tree, rsa, ec, bits, ips, dns, existing);
    }

    /** The addresses a replacement names: the server's own, else (none but loopback) those its certificates carry now. */
    private static List<String> suggestedIps(DefaultsState st) {
        if (!st.ips().isEmpty()) {
            return st.ips();
        }
        List<String> out = new ArrayList<>();
        for (Ldap.Entry k : st.existing().values()) {
            for (String ip : sans(x509(bytes(k, "nDSPKIPublicKeyCertificate")), 7)) {
                if (!out.contains(ip)) {
                    out.add(ip);
                }
            }
        }
        return out;
    }

    /** Why a default certificate needs replacing; empty when it is fine. */
    private static List<String> problems(DefaultsState st, DefaultCert d) {
        Ldap.Entry k = st.existing().get(d);
        if (k == null) {
            return List.of("missing");
        }
        X509Certificate c = x509(bytes(k, "nDSPKIPublicKeyCertificate"));
        if (c == null) {
            return List.of("its certificate cannot be read");
        }
        List<String> out = new ArrayList<>();
        java.time.Instant end = c.getNotAfter().toInstant();
        if (end.isBefore(java.time.Instant.now())) {
            out.add("expired " + end.toString().substring(0, 10));
        } else if (end.isBefore(java.time.Instant.now().plus(java.time.Duration.ofDays(30)))) {
            out.add("expires " + end.toString().substring(0, 10));
        }
        if (!signedBy(c, st.caRsa()) && !signedBy(c, st.caEc())) {
            out.add("not issued by the tree's CA");
        }
        List<String> named = sans(c, 7);
        for (String ip : st.ips()) {
            if (!named.contains(ip)) {
                out.add("does not name " + ip);
            }
        }
        return out;
    }

    /** {@code GET pki/servers/{guid}/default-certificates}: each default certificate, its state, and what a replacement would name. */
    private Map<String, Object> defaultCertificates(Ldap l, String serverGuid) throws NamingException {
        DefaultsState st = defaultsState(l, serverGuid);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("server", ref(st.server()));
        Ldap.Entry dse = l.read("", "dsaName");
        out.put("connected", dse != null && dse.first("dsaName") != null && Names.same(dse.first("dsaName"), st.server().dn()));
        out.put("tree", st.tree());
        out.put("ecAvailable", st.caEc() != null);
        out.put("ips", suggestedIps(st));
        out.put("dnsNames", st.dnsNames());
        List<Map<String, Object>> ldapServers = new ArrayList<>();
        Map<String, List<String>> usedBy = new LinkedHashMap<>();
        for (Ldap.Entry ls : l.search("", "(&(objectClass=ldapServer)(ldapHostServer={0}))", new Object[] {st.server().dn()}, SearchControls.SUBTREE_SCOPE,
                new String[] {"cn", "ldapKeyMaterialName", "GUID"}, 20)) {
            String kmo = ls.first("ldapKeyMaterialName");
            if (kmo != null) {
                usedBy.computeIfAbsent(kmo.toLowerCase(Locale.ROOT), k -> new ArrayList<>()).add(String.valueOf(ls.first("cn")));
            }
            Map<String, Object> m = ref(ls);
            m.put("certificate", kmo);
            ldapServers.add(m);
        }
        out.put("ldapServers", ldapServers);
        // newer copies made by this console ("<standard name> <date>"), newest first
        String serverName = String.valueOf(st.server().first("cn"));
        List<Ldap.Entry> mine = l.search(Names.parent(st.server().dn()), "(&(objectClass=nDSPKIKeyMaterial)(hostServer={0}))", new Object[] {st.server().dn()},
            SearchControls.ONELEVEL_SCOPE, KMO, 500);
        List<Map<String, Object>> certs = new ArrayList<>();
        for (DefaultCert d : DefaultCert.values()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("kind", d.key());
            m.put("name", d.cn);
            m.put("applicable", d != DefaultCert.EC || st.caEc() != null);
            Ldap.Entry k = st.existing().get(d);
            m.put("guid", k == null ? null : guidOf(k));
            m.put("certificate", k == null ? null : cert(bytes(k, "nDSPKIPublicKeyCertificate")));
            m.put("problems", problems(st, d));
            m.put("usedBy", usedBy.getOrDefault(d.cn.toLowerCase(Locale.ROOT), List.of()));
            List<Map<String, Object>> successors = new ArrayList<>();
            for (Ldap.Entry e : mine) {
                String cn = String.valueOf(e.first("cn"));
                String suffix = " - " + serverName;
                if (cn.startsWith(d.cn + " ") && cn.endsWith(suffix)) {
                    String name = cn.substring(0, cn.length() - suffix.length());
                    Map<String, Object> o = new LinkedHashMap<>();
                    o.put("guid", guidOf(e));
                    o.put("name", name);
                    o.put("certificate", cert(bytes(e, "nDSPKIPublicKeyCertificate")));
                    o.put("usedBy", usedBy.getOrDefault(name.toLowerCase(Locale.ROOT), List.of()));
                    successors.add(o);
                }
            }
            successors.sort((x, y) -> String.valueOf(y.get("name")).compareTo(String.valueOf(x.get("name"))));
            m.put("successors", successors);
            certs.add(m);
        }
        out.put("certificates", certs);
        return out;
    }

    /**
     * {@code POST pki/servers/{guid}/default-certificates}: new default certificates for one server.
     * Nothing is deleted: a certificate that is missing is made under its standard name; one that is
     * there gets a successor named "<standard name> <date>", which an LDAP server can then be given as a
     * separate step ({@code PUT pki/ldap-servers/{guid}/certificate}). Deleting a key material object and
     * making another under the same name crashed ndsd on ig4 (eDirectory 9.2.8, 2026-10-14); eDirectory's
     * own renewal (the PKI Health Check, with server self-provisioning on) replaces them in place, which
     * no LDAP operation offers. {@code replace} is "invalid" (only those with a problem, the default) or
     * "all"; {@code kinds} which to consider (dns, ec, ip); {@code dnsNames} and {@code ips} what they
     * name. Each server gets its own subject and addresses, and the DNS certificates carry their DNS names.
     */
    private void repairDefaultCertificates(HttpExchange ex, Ldap l, Sessions.Session s, String serverGuid) throws IOException, NamingException {
        DefaultsState st = defaultsState(l, serverGuid);
        Map<String, Object> b = Http.body(ex);
        String replace = b.get("replace") == null ? "invalid" : Http.string(b, "replace", true);
        if (!List.of("invalid", "all").contains(replace)) {
            throw new IllegalArgumentException("replace is invalid or all");
        }
        List<DefaultCert> kinds = new ArrayList<>();
        Object k = b.get("kinds");
        for (Object o : k instanceof List<?> list ? list : List.of("dns", "ec")) {
            DefaultCert d;
            try {
                d = DefaultCert.valueOf(String.valueOf(o).toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException x) {
                throw new IllegalArgumentException("a kind is dns, ec or ip");
            }
            if (d == DefaultCert.EC && st.caEc() == null) {
                continue;
            }
            if (!kinds.contains(d)) {
                kinds.add(d);
            }
        }
        kinds.sort(java.util.Comparator.naturalOrder());
        List<String> dnsNames = strings(b.get("dnsNames"), st.dnsNames());
        List<String> ips = strings(b.get("ips"), suggestedIps(st));
        for (String n : dnsNames) {
            if (!n.matches("[A-Za-z0-9*.-]{1,253}")) {
                throw new IllegalArgumentException("not a DNS name: " + n);
            }
        }
        for (String ip : ips) {
            if (!ip.matches("[0-9A-Fa-f.:]{2,45}")) {
                throw new IllegalArgumentException("not an IP address: " + ip);
            }
        }
        if (kinds.contains(DefaultCert.IP) && ips.isEmpty()) {
            throw new IllegalArgumentException("SSL CertificateIP needs an IP address");
        }
        int years = Http.integer(b, "validityYears", 2);
        if (years < 1 || years > 10) {
            throw new IllegalArgumentException("validity is 1 to 10 years");
        }
        String tree = st.tree() == null ? "tree" : st.tree();
        List<String> sans = new ArrayList<>();
        dnsNames.forEach(n -> sans.add("dns:" + n));
        ips.forEach(ip -> sans.add("ip:" + ip));

        List<Map<String, Object>> results = new ArrayList<>();
        for (DefaultCert d : kinds) {
            Map<String, Object> r = new LinkedHashMap<>(Map.of("kind", d.key(), "name", d.cn));
            results.add(r);
            List<String> problems = problems(st, d);
            if (replace.equals("invalid") && problems.isEmpty()) {
                r.put("action", "kept");
                r.put("status", "ok");
                continue;
            }
            Ldap.Entry old = st.existing().get(d);
            String name = old == null ? d.cn : successorName(l, st.server(), d.cn);
            Map<String, Object> detail = new LinkedHashMap<>(Map.of("server", st.server().dn(), "name", name, "replace", replace, "problems", problems));
            boolean ipCert = d == DefaultCert.IP;
            String host = ipCert ? ips.get(0) : dnsNames.isEmpty() ? String.valueOf(st.server().first("cn")) : dnsNames.get(0);
            // subject O=<tree>, CN=<host>, in that order, as eDirectory's own default certificates have it
            // (ig4); Pki sends a DN's RDNs in its written order, so the tree comes first here
            String subject = "o=" + javax.naming.ldap.Rdn.escapeValue(tree) + ",cn=" + javax.naming.ldap.Rdn.escapeValue(host);
            // RSA at the CA's default size and EC P-384, both signed with SHA-384, as eDirectory makes them
            Pki.Spec spec = new Pki.Spec(name, d == DefaultCert.EC ? "ec384" : "rsa", st.rsaBits(), "sha384", years,
                subject, ipCert ? ips.stream().map(ip -> "ip:" + ip).toList() : sans, true, null);
            r.put("action", "created");
            r.put("name", name);
            if (old != null) {
                r.put("replaces", d.cn);
            }
            try {
                Pki.createServerCertificate(l, st.server().dn(), spec);
                Ldap.Entry made = readSoon(l, Names.child(Names.parent(st.server().dn()), "cn", name + " - " + st.server().first("cn")));
                r.put("status", "ok");
                r.put("guid", made == null ? null : guidOf(made));
                r.put("certificate", made == null ? null : cert(bytes(made, "nDSPKIPublicKeyCertificate")));
                audit(s, "pki.default-certificate.create", made == null ? null : guidOf(made), detail, null);
            } catch (Pki.Refused x) {
                detail.put("code", x.code);
                audit(s, "pki.default-certificate.create", null, detail, null);
                r.put("status", "failed");
                r.put("detail", x.getMessage());
            } catch (NamingException x) {
                audit(s, "pki.default-certificate.create", null, detail, Ldap.Failure.of(x));
                r.put("status", "failed");
                r.put("detail", Ldap.Failure.of(x).getMessage());
            }
        }
        Http.json(ex, 200, Map.of("results", results));
    }

    /** "<standard name> <date>", with "-2", "-3"… when that is taken on this server. */
    private static String successorName(Ldap l, Ldap.Entry server, String standard) throws NamingException {
        String base = standard + " " + java.time.LocalDate.now(java.time.ZoneOffset.UTC);
        String container = Names.parent(server.dn());
        String serverName = String.valueOf(server.first("cn"));
        String name = base;
        for (int i = 2; l.read(Names.child(container, "cn", name + " - " + serverName), "cn") != null; i++) {
            name = base + "-" + i;
        }
        return name;
    }

    /**
     * {@code PUT pki/ldap-servers/{guid}/certificate}: the certificate an LDAP server offers
     * ({@code ldapKeyMaterialName}): one of its own server's key material objects, by GUID. It takes
     * effect when the LDAP server is refreshed.
     */
    private void useForLdap(HttpExchange ex, Ldap l, Sessions.Session s, String ldapGuid) throws IOException, NamingException {
        Ldap.Entry ls = server.objects.byGuid(l, ldapGuid, "objectClass", "cn", "ldapHostServer", "ldapKeyMaterialName");
        if (ls == null || ls.attributes().getOrDefault("objectclass", List.of()).stream().noneMatch(o -> String.valueOf(o).equalsIgnoreCase("ldapServer"))) {
            throw new Http.Problem(404, "not-found", "no LDAP server has GUID " + ldapGuid);
        }
        String kmoGuid = Http.string(Http.body(ex), "certificate", true);
        Ldap.Entry k = server.objects.byGuid(l, kmoGuid, "objectClass", "cn", "hostServer");
        if (k == null || k.attributes().getOrDefault("objectclass", List.of()).stream().noneMatch(o -> String.valueOf(o).equalsIgnoreCase("nDSPKIKeyMaterial"))) {
            throw new Http.Problem(404, "not-found", "no server certificate has GUID " + kmoGuid);
        }
        String host = ls.first("ldapHostServer");
        if (host == null || k.first("hostServer") == null || !Names.same(host, k.first("hostServer"))) {
            throw new Http.Problem(409, "other-server", k.first("cn") + " belongs to another server than " + ls.first("cn") + "'s");
        }
        // the LDAP server names a certificate without its " - <server>" suffix
        String cn = String.valueOf(k.first("cn"));
        String suffix = " - " + Names.identity(host).get("name");
        String name = cn.endsWith(suffix) ? cn.substring(0, cn.length() - suffix.length()) : cn;
        String before = ls.first("ldapKeyMaterialName");
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("ldapServer", ls.dn());
        detail.put("from", before);
        detail.put("to", name);
        try {
            l.modify(ls.dn(), List.of(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("ldapKeyMaterialName", name))));
        } catch (NamingException x) {
            audit(s, "ldap-server.certificate", ldapGuid, detail, Ldap.Failure.of(x));
            throw x;
        }
        audit(s, "ldap-server.certificate", ldapGuid, detail, null);
        Http.json(ex, 200, Map.of("ldapServer", ls.dn(), "certificate", name, "previous", before == null ? "" : before));
    }

    /** A new object, read back; eDirectory can take a moment to show it on this connection. */
    private static Ldap.Entry readSoon(Ldap l, String dn) throws NamingException {
        for (int i = 0; i < 20; i++) {
            Ldap.Entry e = l.read(dn, KMO);
            if (e != null) {
                return e;
            }
            try {
                Thread.sleep(500);
            } catch (InterruptedException x) {
                Thread.currentThread().interrupt();
                return null;
            }
        }
        return null;
    }

    private static List<String> strings(Object v, List<String> otherwise) {
        if (!(v instanceof List<?> list)) {
            return otherwise;
        }
        List<String> out = new ArrayList<>();
        for (Object o : list) {
            String t = String.valueOf(o).trim();
            if (!t.isEmpty() && !out.contains(t)) {
                out.add(t);
            }
        }
        return out;
    }

    private static X509Certificate x509(byte[] der) {
        try {
            return der == null ? null : (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean signedBy(X509Certificate c, X509Certificate ca) {
        if (ca == null) {
            return false;
        }
        try {
            c.verify(ca.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /** A certificate's subject alternative names of one type (2 DNS, 7 IP). */
    private static List<String> sans(X509Certificate c, int type) {
        List<String> out = new ArrayList<>();
        try {
            if (c != null && c.getSubjectAlternativeNames() != null) {
                for (List<?> n : c.getSubjectAlternativeNames()) {
                    if (Integer.valueOf(type).equals(n.get(0))) {
                        out.add(String.valueOf(n.get(1)));
                    }
                }
            }
        } catch (java.security.cert.CertificateParsingException e) {
            // no names, then
        }
        return out;
    }

    private static String rdn(String dn, String type) {
        try {
            for (javax.naming.ldap.Rdn r : new javax.naming.ldap.LdapName(dn).getRdns()) {
                if (r.getType().equalsIgnoreCase(type)) {
                    return String.valueOf(r.getValue());
                }
            }
        } catch (javax.naming.InvalidNameException e) {
            return null;
        }
        return null;
    }

    /** {@code GET objects/{guid}/certificates}: the certificates eDirectory holds for a user. */
    private List<Map<String, Object>> userCertificates(Ldap l, String guid) throws NamingException {
        Ldap.Entry u = server.objects.byGuid(l, guid, "cn");
        if (u == null) {
            throw new Http.Problem(404, "not-found", "no object has GUID " + guid);
        }
        try {
            return Pki.userCertificates(l, u.dn());
        } catch (Pki.Refused r) {
            throw new Http.Problem(409, "pki-refused", r.getMessage(), Map.of("code", r.code));
        }
    }

    /** {@code POST objects/{guid}/certificates}: a user certificate from the tree CA, made on the CA's host server. */
    private void createUserCertificate(HttpExchange ex, Ldap l, Sessions.Session s, String guid) throws IOException, NamingException {
        Ldap.Entry u = server.objects.byGuid(l, guid, "cn", "mail");
        if (u == null) {
            throw new Http.Problem(404, "not-found", "no object has GUID " + guid);
        }
        Map<String, Object> b = Http.body(ex);
        Pki.Spec spec = spec(b, u.dn(), false);
        if (spec.email() == null && u.first("mail") != null) {
            spec = new Pki.Spec(spec.name(), spec.algorithm(), spec.rsaBits(), spec.signature(), spec.validityYears(), spec.subject(), spec.names(), spec.exportable(), u.first("mail"));
        }
        String host = caHost(l);
        Map<String, Object> detail = new LinkedHashMap<>(Map.of("user", u.dn(), "name", spec.name(), "algorithm", spec.algorithm(), "years", spec.validityYears()));
        try {
            Pki.createUserCertificate(l, host, u.dn(), spec);
        } catch (Pki.Refused r) {
            detail.put("code", r.code);
            audit(s, "pki.user-certificate.create", guid, detail, null);
            throw new Http.Problem(409, "pki-refused", r.getMessage(), Map.of("code", r.code));
        }
        audit(s, "pki.user-certificate.create", guid, detail, null);
        Http.json(ex, 201, Map.of("items", userCertificates(l, guid)));
    }

    /** The revocation: an RFC 5280 reason code and an optional comment. */
    private record Revocation(int reason, String comment) {
        static Revocation of(Map<String, Object> b) {
            int reason = Http.integer(b, "reason", 0);
            if (!Pki.REASONS.contains(reason)) {
                throw new IllegalArgumentException("reason is an RFC 5280 code: 0 unspecified, 1 key compromise, 2 CA compromise, 3 affiliation changed,"
                    + " 4 superseded, 5 cessation of operation, 6 certificate hold, 9 privilege withdrawn, 10 AA compromise");
            }
            String c = b.get("comment") == null ? null : String.valueOf(b.get("comment")).trim();
            if (c != null && c.length() > 256) {
                throw new IllegalArgumentException("a comment is at most 256 characters");
            }
            return new Revocation(reason, c);
        }
    }

    /**
     * The CA's CRL configuration for a certificate with this key: its RSA list for RSA keys, its EC list
     * for EC keys (values {@code dn#n#}), and when the CRL is next issued.
     */
    private Map<String, String> crlFor(Ldap l, boolean ec) throws NamingException {
        Ldap.Entry sec = securityContainer(l);
        String caDn = sec == null ? null : sec.first("nDSPKITreeCADN");
        Ldap.Entry ca = caDn == null ? null : l.read(caDn, "ndspkiCRLConfigurationDNList", "ndspkiCRLECConfigurationDNList");
        String v = ca == null ? null : ca.first(ec ? "ndspkiCRLECConfigurationDNList" : "ndspkiCRLConfigurationDNList");
        if (v == null) {
            throw new Http.Problem(409, "no-crl", "the Organizational CA has no " + (ec ? "EC " : "") + "CRL configuration to revoke on");
        }
        String dn = v.split("#")[0];
        Ldap.Entry cfg = l.read(dn, "ndspkiNextIssueTime");
        Map<String, String> out = new LinkedHashMap<>();
        out.put("dn", dn);
        out.put("nextIssue", cfg == null ? null : iso(cfg.first("ndspkiNextIssueTime")));
        return out;
    }

    private static boolean ecKey(byte[] der) {
        try {
            X509Certificate c = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
            return c.getPublicKey() instanceof ECPublicKey;
        } catch (Exception e) {
            return false;
        }
    }

    /** {@code POST pki/server-certificates/{guid}/revoke}: {reason, comment}. */
    private void revokeServerCertificate(HttpExchange ex, Ldap l, Sessions.Session s, String guid) throws IOException, NamingException {
        Ldap.Entry k = server.objects.byGuid(l, guid, "objectClass", "cn", "hostServer", "nDSPKIPublicKeyCertificate");
        if (k == null || k.first("hostServer") == null
            || k.attributes().getOrDefault("objectclass", List.of()).stream().noneMatch(o -> String.valueOf(o).equalsIgnoreCase("nDSPKIKeyMaterial"))) {
            throw new Http.Problem(404, "not-found", "no server certificate has GUID " + guid);
        }
        Revocation r = Revocation.of(Http.body(ex));
        String host = k.first("hostServer");
        String suffix = " - " + Names.identity(host).get("name");
        String cn = String.valueOf(k.first("cn"));
        String name = cn.endsWith(suffix) ? cn.substring(0, cn.length() - suffix.length()) : cn;
        byte[] der = bytes(k, "nDSPKIPublicKeyCertificate");
        Map<String, String> crl = crlFor(l, der != null && ecKey(der));
        Map<String, Object> detail = new LinkedHashMap<>(Map.of("dn", k.dn(), "reason", r.reason(), "crl", crl.get("dn")));
        try {
            Pki.revokeServerCertificate(l, host, name, crl.get("dn"), r.reason(), r.comment());
        } catch (Pki.Refused x) {
            detail.put("code", x.code);
            audit(s, "pki.server-certificate.revoke", guid, detail, null);
            throw new Http.Problem(409, "pki-refused", x.getMessage(), Map.of("code", x.code));
        }
        audit(s, "pki.server-certificate.revoke", guid, detail, null);
        Http.json(ex, 200, revoked(crl));
    }

    /** {@code POST objects/{guid}/certificates/{name}/revoke}: {reason, comment}. */
    private void revokeUserCertificate(HttpExchange ex, Ldap l, Sessions.Session s, String guid, String name) throws IOException, NamingException {
        Ldap.Entry u = server.objects.byGuid(l, guid, "cn");
        Revocation r = Revocation.of(Http.body(ex));
        Map<String, Object> cert;
        try {
            cert = Pki.userCertificates(l, u.dn()).stream().filter(c -> name.equals(c.get("name"))).findFirst().orElse(null);
        } catch (Pki.Refused x) {
            throw new Http.Problem(409, "pki-refused", x.getMessage(), Map.of("code", x.code));
        }
        if (cert == null) {
            throw new Http.Problem(404, "not-found", u.first("cn") + " has no certificate named " + name);
        }
        byte[] der = cert.get("certificate") == null ? null : java.util.Base64.getMimeDecoder().decode(String.valueOf(cert.get("certificate")));
        Map<String, String> crl = crlFor(l, der != null && ecKey(der));
        Map<String, Object> detail = new LinkedHashMap<>(Map.of("user", u.dn(), "name", name, "reason", r.reason(), "crl", crl.get("dn")));
        try {
            Pki.revokeUserCertificate(l, u.dn(), name, crl.get("dn"), r.reason(), r.comment());
        } catch (Pki.Refused x) {
            detail.put("code", x.code);
            audit(s, "pki.user-certificate.revoke", guid, detail, null);
            throw new Http.Problem(409, "pki-refused", x.getMessage(), Map.of("code", x.code));
        }
        audit(s, "pki.user-certificate.revoke", guid, detail, null);
        Http.json(ex, 200, revoked(crl));
    }

    private static Map<String, Object> revoked(Map<String, String> crl) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("revoked", true);
        out.put("crlConfiguration", crl.get("dn"));
        out.put("listedFrom", crl.get("nextIssue"));
        return out;
    }

    /** The Organizational CA's host server (which makes user certificates), else the server this connection is on. */
    private String caHost(Ldap l) throws NamingException {
        Ldap.Entry sec = securityContainer(l);
        if (sec != null && sec.first("nDSPKITreeCADN") != null) {
            Ldap.Entry ca = l.read(sec.first("nDSPKITreeCADN"), "hostServer");
            if (ca != null && ca.first("hostServer") != null) {
                return ca.first("hostServer");
            }
        }
        return l.dsaName();
    }

    // ---- EBA (6b) -----------------------------------------------------------------------------------

    /**
     * The tree's EBA CA (found among the servers' NCP addresses), its certificate, each server's NCP
     * certificate and the requests awaiting approval; {@code available: false} when no server answers.
     */
    private Map<String, Object> eba(Ldap l) throws NamingException {
        List<String> candidates = new ArrayList<>();
        Map<String, Map<String, Object>> byGuid = new LinkedHashMap<>();
        for (Ldap.Entry srv : l.search("", "(objectClass=ncpServer)", null, SearchControls.SUBTREE_SCOPE, new String[] {"networkAddress", "GUID", "cn"}, 200)) {
            if (srv.attributes().get("guid") != null) {
                byGuid.put(Names.guidHex(srv.attributes().get("guid").get(0)), Map.of("dn", srv.dn(), "name", String.valueOf(srv.first("cn")),
                    "guid", Names.guidHex(srv.attributes().get("guid").get(0))));
            }
            List<String> tcp = new ArrayList<>();
            for (Object a : srv.attributes().getOrDefault("networkaddress", List.of())) {
                String text = a instanceof byte[] b ? Edir.networkAddress(b) : null;
                if (text != null && text.startsWith("tcp ")) {
                    tcp.add(text.substring(4));
                }
            }
            // the NCP port first: that is the address EBA knows a server by
            tcp.sort((x, y) -> Boolean.compare(!x.endsWith(":524"), !y.endsWith(":524")));
            candidates.addAll(tcp);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        String ca = Eba.findCa(l, candidates);
        out.put("available", ca != null);
        if (ca == null) {
            out.put("problem", "no server answered as the tree's EBA CA (tried " + String.join(", ", candidates) + ")");
            return out;
        }
        out.put("caAddress", ca);
        try {
            out.put("ca", Eba.caCertificate(l, ca));
            // an NCP certificate's subject is /UID=<the server's GUID>
            List<Map<String, Object>> ncp = Eba.ncpCertificates(l, ca);
            for (Map<String, Object> c : ncp) {
                String uid = String.valueOf(c.get("subject")).replaceFirst("^/UID=", "").replace("-", "").toLowerCase(Locale.ROOT);
                c.put("server", byGuid.get(uid));
            }
            out.put("ncpCertificates", ncp);
            out.put("pendingRequests", Eba.pendingCsrs(l, ca));
        } catch (Pki.Refused r) {
            throw new Http.Problem(409, "pki-refused", r.getMessage(), Map.of("code", r.code));
        }
        return out;
    }

    // ---- login sequences (6b) ----------------------------------------------------------------------

    private String loginPolicyDn(Ldap l) throws NamingException {
        Ldap.Entry sec = securityContainer(l);
        return sec == null || sec.first("sASLoginPolicyDN") == null ? "cn=Login Policy,cn=Security" : sec.first("sASLoginPolicyDN");
    }

    /** How many objects name this sequence as their default or among their authorized ones. */
    private int sequenceUsers(Ldap l, String name) throws NamingException {
        String f = "(|(sasDefaultLoginSequence={0})(sasAuthorizedLoginSequences={0}))";
        return l.search("", f, new Object[] {name}, SearchControls.SUBTREE_SCOPE, new String[] {"1.1"}, 1000).size();
    }

    /**
     * A sequence that is the default, or that objects name, changes how people log in: the request says
     * how many it reaches ({@code X-Confirm-Count}) or is refused with that count.
     */
    private void confirmReach(HttpExchange ex, Ldap l, Ldap.Entry lp, String name) throws NamingException {
        if (name.equals(lp.first("sasDefaultLoginSequence"))) {
            throw new Http.Problem(409, "default-sequence", name + " is the tree's default login sequence; choose another default first");
        }
        int users = sequenceUsers(l, name);
        if (users > 0 && !String.valueOf(users).equals(ex.getRequestHeaders().getFirst("X-Confirm-Count"))) {
            throw new Http.Problem(409, "confirm-count", users + " objects name " + name + " as their login sequence; confirm the count to change it",
                Map.of("count", users));
        }
    }

    /** {@code POST login-policy/sequences} (a new one) or {@code PATCH …/{name}}: {name, methods, any}. */
    private void changeSequence(HttpExchange ex, Ldap l, Sessions.Session s, String existing) throws IOException, NamingException {
        Map<String, Object> b = Http.body(ex);
        String name = existing != null ? existing : Http.string(b, "name", true).trim();
        if (name.isEmpty() || name.length() > 64 || name.contains(";") || name.contains("|")) {
            throw new IllegalArgumentException("a sequence name is 1-64 characters without ; or |");
        }
        if (!(b.get("methods") instanceof List<?> raw) || raw.isEmpty()) {
            throw new IllegalArgumentException("methods lists the login methods in order");
        }
        List<String> methods = raw.stream().map(String::valueOf).map(String::trim).toList();
        boolean any = Boolean.TRUE.equals(b.get("any"));
        List<String> installed = new ArrayList<>();
        for (Object o : (List<?>) loginPolicy(l).get("methods")) {
            installed.add(String.valueOf(Json.asMap(o).get("name")));
        }
        for (String m : methods) {
            if (!installed.contains(m)) {
                throw new IllegalArgumentException("no installed login method is named " + m);
            }
            if (m.contains(";") || m.contains("|")) {
                throw new IllegalArgumentException("a method name with ; or | cannot be in a sequence");
            }
        }
        if (methods.stream().distinct().count() != methods.size()) {
            throw new IllegalArgumentException("each method once");
        }
        String lpDn = loginPolicyDn(l);
        Ldap.Entry lp = l.read(lpDn, "sASLoginSequence", "sASLoginPolicyUpdate", "sasDefaultLoginSequence", "sasAuthorizedLoginSequences");
        if (lp == null) {
            throw new Http.Problem(404, "no-login-policy", "this tree has no Login Policy");
        }
        String old = null;
        for (Object v : lp.attributes().getOrDefault("sasloginsequence", List.of())) {
            if (sequence(String.valueOf(v)).get("name").equals(name)) {
                old = String.valueOf(v);
            }
        }
        if (existing == null && old != null) {
            throw new Http.Problem(409, "exists", "there is already a sequence named " + name);
        }
        if (existing != null && old == null) {
            throw new Http.Problem(404, "not-found", "no sequence is named " + name);
        }
        if (existing != null) {
            confirmReach(ex, l, lp, name);
        }
        String value = sequenceValue(name, methods, any);
        List<ModificationItem> mods = new ArrayList<>();
        if (old != null) {
            mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute("sASLoginSequence", old)));
        }
        mods.add(new ModificationItem(DirContext.ADD_ATTRIBUTE, new BasicAttribute("sASLoginSequence", value)));
        // a policy with an authorized list only lets listed sequences be used: a new one joins it
        if (existing == null && lp.attributes().containsKey("sasauthorizedloginsequences") && !Boolean.FALSE.equals(b.get("authorized"))) {
            mods.add(new ModificationItem(DirContext.ADD_ATTRIBUTE, new BasicAttribute("sasAuthorizedLoginSequences", name)));
        }
        mods.add(updateCounter(lp));
        Map<String, Object> detail = new LinkedHashMap<>(Map.of("name", name, "value", value));
        if (old != null) {
            detail.put("was", old);
        }
        try {
            l.modify(lpDn, mods);
        } catch (NamingException x) {
            audit(s, existing == null ? "login-sequence.create" : "login-sequence.modify", null, detail, Ldap.Failure.of(x));
            throw x;
        }
        audit(s, existing == null ? "login-sequence.create" : "login-sequence.modify", null, detail, null);
        Http.json(ex, existing == null ? 201 : 200, loginPolicy(l));
    }

    /** {@code DELETE login-policy/sequences/{name}}. */
    private void deleteSequence(HttpExchange ex, Ldap l, Sessions.Session s, String name) throws IOException, NamingException {
        String lpDn = loginPolicyDn(l);
        Ldap.Entry lp = l.read(lpDn, "sASLoginSequence", "sASLoginPolicyUpdate", "sasDefaultLoginSequence", "sasAuthorizedLoginSequences");
        String old = null;
        for (Object v : lp == null ? List.of() : lp.attributes().getOrDefault("sasloginsequence", List.of())) {
            if (sequence(String.valueOf(v)).get("name").equals(name)) {
                old = String.valueOf(v);
            }
        }
        if (old == null) {
            throw new Http.Problem(404, "not-found", "no sequence is named " + name);
        }
        confirmReach(ex, l, lp, name);
        List<ModificationItem> mods = new ArrayList<>();
        mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute("sASLoginSequence", old)));
        if (lp.attributes().getOrDefault("sasauthorizedloginsequences", List.of()).stream().anyMatch(v -> name.equals(String.valueOf(v)))) {
            mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute("sasAuthorizedLoginSequences", name)));
        }
        mods.add(updateCounter(lp));
        try {
            l.modify(lpDn, mods);
        } catch (NamingException x) {
            audit(s, "login-sequence.delete", null, Map.of("name", name, "was", old), Ldap.Failure.of(x));
            throw x;
        }
        audit(s, "login-sequence.delete", null, Map.of("name", name, "was", old), null);
        Http.json(ex, 200, loginPolicy(l));
    }

    /** sASLoginPolicyUpdate counts changes; servers reread the policy when it moves (Identity Console adds 1 each time). */
    private static ModificationItem updateCounter(Ldap.Entry lp) {
        int n;
        try {
            n = Integer.parseInt(String.valueOf(lp.first("sASLoginPolicyUpdate")));
        } catch (NumberFormatException e) {
            n = 0;
        }
        return new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("sASLoginPolicyUpdate", String.valueOf(n + 1)));
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
        // a server's SAS Service lists every key material object on that server (eDirectory adds each new
        // one itself, ig4 2026-10-13): that is not a use, and is not shown as one
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

    /**
     * A login sequence as eDirectory keeps it: {@code name;grade;method;method…} when every method runs
     * in turn, {@code name;grade;method|method…} when any one will do (Identity Console 26.1's encoding;
     * a new sequence's grade is "Password").
     */
    static Map<String, Object> sequence(String value) {
        String[] parts = value.split(";", -1);
        Map<String, Object> q = new LinkedHashMap<>();
        q.put("name", parts[0]);
        q.put("grade", parts.length > 1 ? parts[1] : null);
        List<String> rest = parts.length > 2 ? List.of(parts).subList(2, parts.length) : List.of();
        boolean any = rest.size() == 1 && rest.get(0).contains("|");
        q.put("methods", any ? List.of(rest.get(0).split("\\|")) : rest.stream().filter(x -> !x.isEmpty()).toList());
        q.put("any", any);
        return q;
    }

    static String sequenceValue(String name, List<String> methods, boolean any) {
        return name + ";Password;" + String.join(any ? "|" : ";", methods);
    }

    /** The Login Policy's sequences, the default, the authorized list (null: all are), and the installed login methods. */
    private Map<String, Object> loginPolicy(Ldap l) throws NamingException {
        Map<String, Object> m = new LinkedHashMap<>();
        Ldap.Entry sec = securityContainer(l);
        String lpDn = sec == null || sec.first("sASLoginPolicyDN") == null ? "cn=Login Policy,cn=Security" : sec.first("sASLoginPolicyDN");
        String root = sec == null ? "cn=Security" : sec.dn();
        Ldap.Entry lp = l.read(lpDn, "sASLoginSequence", "sasDefaultLoginSequence", "nspmPasswordPolicyDN", "sasAuthorizedLoginSequences");
        List<Map<String, Object>> seqs = new ArrayList<>();
        if (lp != null) {
            for (Object v : lp.attributes().getOrDefault("sasloginsequence", List.of())) {
                seqs.add(sequence(String.valueOf(v)));
            }
            m.put("authorized", lp.attributes().containsKey("sasauthorizedloginsequences")
                ? lp.attributes().get("sasauthorizedloginsequences").stream().map(String::valueOf).toList() : null);
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
