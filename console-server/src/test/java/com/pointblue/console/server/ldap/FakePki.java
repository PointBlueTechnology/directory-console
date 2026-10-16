package com.pointblue.console.server.ldap;

import com.pointblue.console.server.tls.TestPki;
import com.pointblue.dirxml.dev.json.Json;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.listener.InMemoryExtendedOperationHandler;
import com.unboundid.ldap.listener.InMemoryRequestHandler;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.ResultCode;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * eDirectory's PKI extended operations for the fake directory (see Pki): server certificates become
 * key material objects signed by the fake tree CA; user certificates are kept in memory. Requests are
 * recorded in {@link #requests}; {@link #refuseNext} makes the next call answer with that error code.
 */
public final class FakePki extends InMemoryExtendedOperationHandler {

    private static final String P = "2.16.840.1.113719.1.27.100.";

    private final TestPki pki;
    public final List<Map<String, Object>> requests = java.util.Collections.synchronizedList(new ArrayList<>());
    /** user DN (lower case) → certificate name → certificate. */
    public final Map<String, Map<String, X509Certificate>> userCertificates = new ConcurrentHashMap<>();
    public volatile int refuseNext;
    /** The EBA CA's "address:port" (null: no EBA), and each server's NCP certificate: UID (the server's GUID, with dashes) → address. */
    public volatile String ebaCa;
    public final Map<String, String> ncp = new java.util.concurrent.ConcurrentHashMap<>();
    /** Certificate names whose private key may not be exported (backupCertificate refuses them). */
    public final java.util.Set<String> notExportable = java.util.concurrent.ConcurrentHashMap.newKeySet();
    /** What was revoked: "server|user DN (dotted) / certificate name / reason". */
    public final List<String> revoked = java.util.Collections.synchronizedList(new ArrayList<>());

    /** A server's GUID as EBA writes it in an NCP certificate's subject: upper-case hex with dashes (8-4-4-4-12). */
    public static String uid(byte[] guid) {
        String h = java.util.HexFormat.of().withUpperCase().formatHex(guid);
        return h.substring(0, 8) + "-" + h.substring(8, 12) + "-" + h.substring(12, 16) + "-" + h.substring(16, 20) + "-" + h.substring(20);
    }

    FakePki(TestPki pki) {
        this.pki = pki;
    }

    @Override
    public String getExtendedOperationHandlerName() {
        return "pki";
    }

    @Override
    public List<String> getSupportedExtendedRequestOIDs() {
        return List.of(P + "105", P + "107", P + "113", P + "117", P + "121");
    }

    /** {@code cn=a.ou=b\.c.o=d} → {@code cn=a,ou=b.c,o=d}. */
    static String ldap(String dotted) {
        List<String> parts = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        for (int i = 0; i < dotted.length(); i++) {
            char c = dotted.charAt(i);
            if (c == '\\' && i + 1 < dotted.length()) {
                cur.append(dotted.charAt(++i));
            } else if (c == '.') {
                parts.add(cur.toString());
                cur.setLength(0);
            } else {
                cur.append(c);
            }
        }
        parts.add(cur.toString());
        List<String> rdns = new ArrayList<>();
        for (String r : parts) {
            int eq = r.indexOf('=');
            rdns.add(new com.unboundid.ldap.sdk.RDN(r.substring(0, eq), r.substring(eq + 1)).toString());
        }
        return String.join(",", rdns);
    }

    @Override
    public ExtendedResult processExtendedOperation(InMemoryRequestHandler handler, int id, ExtendedRequest request) {
        String oid = request.getOID();
        String response = P + (Integer.parseInt(oid.substring(P.length())) + 1);
        try {
            // the value is two OCTET STRINGs one after the other: read them as a SEQUENCE's contents
            ASN1Element[] e = com.unboundid.asn1.ASN1Sequence.decodeAsSequence(new ASN1Element((byte) 0x30, request.getValue().getValue())).elements();
            String verb = ASN1OctetString.decodeAsOctetString(e[0]).stringValue();
            Map<String, Object> payload = Json.asMap(Json.parse(ASN1OctetString.decodeAsOctetString(e[1]).stringValue()));
            Map<String, Object> rec = new LinkedHashMap<>(payload);
            rec.put("verb", verb);
            rec.put("oid", oid);
            requests.add(rec);
            if (refuseNext != 0) {
                int code = refuseNext;
                refuseNext = 0;
                return json(id, response, Map.of("code", code, "message", "pki error"));
            }
            return switch (oid.substring(P.length()) + " " + verb) {
                case "105 createCertificate" -> createServer(handler, id, response, payload);
                case "107 createCertificate" -> createUser(handler, id, response, payload);
                case "113 GetUapCsrCertificates", "117 getCertificates", "121 getCACertificate" -> {
                    if (ebaCa == null || !ebaCa.equals(payload.get("serverIP"))) {
                        yield json(id, response, Map.of("code", -2104, "message", "EBA invalid EBA Server"));
                    }
                    long from = 1790184416L;
                    long to = 2105544416L;
                    if (verb.equals("GetUapCsrCertificates")) {
                        yield json(id, response, Map.of("CSR", List.of()));
                    }
                    if (verb.equals("getCACertificate")) {
                        yield json(id, response, Map.of("EBACAAddress", ebaCa, "certificateVersion", 3, "serialNumber", "2C3E1C97BF160A41B5692C3E1C97BF16",
                            "subjectName", "/CN=EBACA", "issuerName", "/CN=EBACA", "validitystart", from, "validityEnd", to,
                            "signatureAlgorithm", "ecdsa-with-SHA384", "EBARenewalFlag", 1));
                    }
                    List<Map<String, Object>> certs = new ArrayList<>();
                    int n = 0;
                    for (Map.Entry<String, String> server : ncp.entrySet()) {
                        certs.add(Map.of("EBACAAddress", ebaCa, "subjectNames", "ncp://" + server.getValue(), "certificateVersion", 3,
                            "serialNumber", String.format("%032X", ++n), "subjectName", "/UID=" + server.getKey(), "issuerName", "/CN=EBACA",
                            "validitystart", from, "validityEnd", to, "signatureAlgorithm", "ecdsa-with-SHA384"));
                    }
                    yield json(id, response, Map.of("SubjectNames", certs));
                }
                case "105 revokeCertificate", "107 revokeCertificate" -> {
                    String who = String.valueOf(payload.getOrDefault("serverDN", payload.get("userDN")));
                    if (payload.get("crlConfigurationDN") == null) {
                        yield json(id, response, Map.of("code", -1214, "message", "pki error: bad request syntax"));
                    }
                    revoked.add(who + " / " + payload.get("certificateName") + " / " + payload.get("reasonCode"));
                    yield new ExtendedResult(id, ResultCode.SUCCESS, null, null, null, response, null, null);
                }
                case "105 backupCertificate", "107 backupCertificate" -> backup(id, response, payload);
                case "107 getCertificates" -> json(id, response, Map.of("certificates", listUser(String.valueOf(payload.get("userDN")))));
                default -> new ExtendedResult(id, ResultCode.PROTOCOL_ERROR, "Could not decode LDAP Extension packet", null, null, null, null, null);
            };
        } catch (Exception x) {
            return new ExtendedResult(id, ResultCode.PROTOCOL_ERROR, "Could not decode LDAP Extension packet", null, null, null, null, null);
        }
    }

    private ExtendedResult createServer(InMemoryRequestHandler handler, int id, String response, Map<String, Object> p) throws Exception {
        String server = ldap(String.valueOf(p.get("serverDN")));
        Entry srv = handler.getEntry(server);
        if (srv == null) {
            return json(id, response, Map.of("code", -601));
        }
        String serverName = srv.getAttributeValue("cn");
        String name = String.valueOf(p.get("certificateName"));
        List<String> dns = new ArrayList<>();
        if (p.get("subjectAltNames") instanceof List<?> sans) {
            for (Object o : sans) {
                Map<String, Object> s = Json.asMap(o);
                if (Json.asInt(s.get("type"), 0) == 2 || Json.asInt(s.get("type"), 0) == 7) {
                    dns.add(String.valueOf(s.get("value")));
                }
            }
        }
        X509Certificate c = pki.server(name, dns.isEmpty() ? List.of(serverName) : dns).cert();
        String parent = srv.getParentDNString();
        Entry kmo = new Entry("cn=" + name + " - " + serverName + "," + parent);
        kmo.addAttribute("objectClass", "nDSPKIKeyMaterial");
        kmo.addAttribute("cn", name + " - " + serverName);
        kmo.addAttribute("hostServer", server);
        kmo.addAttribute("nDSPKIPublicKeyCertificate", c.getEncoded());
        byte[] guid = new byte[16];
        new java.security.SecureRandom().nextBytes(guid);
        kmo.addAttribute("GUID", guid);
        kmo.addAttribute("revision", "1");
        handler.addEntry(kmo, true);
        return new ExtendedResult(id, ResultCode.SUCCESS, null, null, null, response, null, null);
    }

    /** A PKCS#12 file holding a new key and certificate under the certificate's name, protected by the password. */
    private ExtendedResult backup(int id, String response, Map<String, Object> p) throws Exception {
        String name = String.valueOf(p.get("certificateName"));
        if (p.get("password") == null || String.valueOf(p.get("password")).isEmpty()) {
            return json(id, response, Map.of("code", -1214, "message", "pki error: bad request syntax"));
        }
        if (notExportable.contains(name)) {
            return json(id, response, Map.of("code", -1226, "message", "pki error: private key not exportable"));
        }
        TestPki.Server made = pki.server(name, List.of(name));
        java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        char[] pw = String.valueOf(p.get("password")).toCharArray();
        ks.setKeyEntry(name, made.key().getPrivate(), pw, new java.security.cert.Certificate[] {made.cert()});
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        ks.store(out, pw);
        return json(id, response, Map.of("certificate", java.util.Base64.getEncoder().encodeToString(out.toByteArray())));
    }

    private ExtendedResult createUser(InMemoryRequestHandler handler, int id, String response, Map<String, Object> p) throws Exception {
        String user = ldap(String.valueOf(p.get("userDN")));
        if (handler.getEntry(user) == null) {
            return json(id, response, Map.of("code", -601));
        }
        String name = String.valueOf(p.get("certificateName"));
        Map<String, X509Certificate> certs = userCertificates.computeIfAbsent(user.toLowerCase(Locale.ROOT), k -> new ConcurrentHashMap<>());
        if (certs.containsKey(name)) {
            return json(id, response, Map.of("code", -606, "message", "pki error: duplicate certificate name"));
        }
        certs.put(name, pki.server(name, List.of("user")).cert());
        return new ExtendedResult(id, ResultCode.SUCCESS, null, null, null, response, null, null);
    }

    private List<Map<String, Object>> listUser(String dotted) {
        List<Map<String, Object>> out = new ArrayList<>();
        Map<String, X509Certificate> certs = userCertificates.getOrDefault(ldap(dotted).toLowerCase(Locale.ROOT), Map.of());
        for (Map.Entry<String, X509Certificate> c : certs.entrySet()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("certificateName", c.getKey());
            m.put("certificateVersion", 3);
            m.put("subjectDN", c.getValue().getSubjectX500Principal().getName());
            m.put("issuerName", c.getValue().getIssuerX500Principal().getName());
            m.put("effectiveDate", c.getValue().getNotBefore().getTime() / 1000);
            m.put("expiryDate", c.getValue().getNotAfter().getTime() / 1000);
            m.put("serialNumber", c.getValue().getSerialNumber().toString(16).toUpperCase(Locale.ROOT));
            m.put("keySize", 256);
            try {
                m.put("certificate", Base64.getEncoder().encodeToString(c.getValue().getEncoded()));
            } catch (Exception x) {
                throw new IllegalStateException(x);
            }
            out.add(m);
        }
        return out;
    }

    /** eDirectory's shape: the response value is an OCTET STRING holding the JSON. */
    private static ExtendedResult json(int id, String oid, Map<String, Object> body) {
        byte[] inner = new ASN1OctetString(Json.compact(body).getBytes(StandardCharsets.UTF_8)).encode();
        return new ExtendedResult(id, ResultCode.SUCCESS, null, null, null, oid, new ASN1OctetString(inner), null);
    }
}
