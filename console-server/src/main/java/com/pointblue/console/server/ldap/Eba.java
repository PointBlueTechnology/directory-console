package com.pointblue.console.server.ldap;

import com.pointblue.dirxml.dev.json.Json;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.naming.NamingException;

/**
 * eDirectory's EBA (enhanced background authentication) operations, as Identity Console 26.1 calls
 * them: the PKI operations' encoding (see Pki) with {@code {"serverIP": "address:port"}}, the address
 * being an NCP server's (port 524). A server that is not the tree's EBA CA answers -2104 "EBA invalid
 * EBA Server" (measured on a lab tree, eDirectory 9.3.3, 2026-10-13; a bare address without the port gets
 * the same answer).
 */
public final class Eba {

    private static final String BASE = "2.16.840.1.113719.1.27.100.";
    static final String PENDING_CSRS = BASE + "113";
    static final String NCP_CERTIFICATES = BASE + "117";
    static final String CA_CERTIFICATE = BASE + "121";

    private Eba() {
    }

    /** The EBA CA's certificate: subject, serial, validity (epoch seconds), signature, and whether it may be renewed. */
    public static Map<String, Object> caCertificate(Ldap l, String address) throws NamingException, Pki.Refused {
        Map<String, Object> r = Pki.call(l, CA_CERTIFICATE, "getCACertificate", Map.of("serverIP", address));
        Map<String, Object> out = cert(r);
        out.put("renewable", Json.asInt(r.get("EBARenewalFlag"), 0) == 1);
        return out;
    }

    /** Each server's NCP certificate, issued by the EBA CA. */
    public static List<Map<String, Object>> ncpCertificates(Ldap l, String address) throws NamingException, Pki.Refused {
        Map<String, Object> r = Pki.call(l, NCP_CERTIFICATES, "getCertificates", Map.of("serverIP", address));
        List<Map<String, Object>> out = new ArrayList<>();
        if (r.get("SubjectNames") instanceof List<?> list) {
            for (Object o : list) {
                Map<String, Object> c = Json.asMap(o);
                Map<String, Object> m = cert(c);
                m.put("address", c.get("subjectNames"));
                out.add(m);
            }
        }
        return out;
    }

    /** Certificate requests from servers waiting for an administrator's approval. */
    public static List<Object> pendingCsrs(Ldap l, String address) throws NamingException, Pki.Refused {
        Object csrs = Pki.call(l, PENDING_CSRS, "GetUapCsrCertificates", Map.of("serverIP", address)).get("CSR");
        return csrs instanceof List<?> list ? new ArrayList<>(list) : List.of();
    }

    /**
     * The tree's EBA CA among {@code candidates} ("address:port"): the first that answers with NCP
     * certificates, as Identity Console looks for it; null when none does.
     */
    public static String findCa(Ldap l, List<String> candidates) throws NamingException {
        for (String a : candidates) {
            try {
                if (!ncpCertificates(l, a).isEmpty()) {
                    return a;
                }
            } catch (Pki.Refused r) {
                // not the EBA CA (-2104), or EBA is not configured
            }
        }
        return null;
    }

    private static Map<String, Object> cert(Map<String, Object> c) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("subject", c.get("subjectName"));
        m.put("issuer", c.get("issuerName"));
        m.put("serial", c.get("serialNumber"));
        m.put("notBefore", epoch(c.get("validitystart")));
        m.put("notAfter", epoch(c.get("validityEnd")));
        m.put("signatureAlgorithm", c.get("signatureAlgorithm"));
        return m;
    }

    private static String epoch(Object seconds) {
        if (!(seconds instanceof Number) && (seconds == null || String.valueOf(seconds).isBlank())) {
            return null;
        }
        long s = seconds instanceof Number n ? n.longValue() : Long.parseLong(String.valueOf(seconds));
        return java.time.Instant.ofEpochSecond(s).toString();
    }
}
