package com.pointblue.console.server.ldap;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.listener.InMemoryExtendedOperationHandler;
import com.unboundid.ldap.listener.InMemoryRequestHandler;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.ResultCode;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * eDirectory's partition operations for the fake directory: partitions and their replicas kept in
 * memory, answered in JLDAP's encodings (see Partitions). Operations complete at once; a removed
 * replica becomes a subordinate reference, as on ig4. Background processes and LDAP refresh are
 * recorded in {@link #triggered}.
 */
public final class FakePartitions extends InMemoryExtendedOperationHandler {

    private static final String P = "2.16.840.1.113719.1.27.100.";

    /** partition DN (lower case, "" for the tree root) → server DN → replica type. */
    public final Map<String, Map<String, Integer>> replicas = new ConcurrentHashMap<>();
    public final Map<String, String> names = new ConcurrentHashMap<>();
    public final List<String> triggered = java.util.Collections.synchronizedList(new ArrayList<>());

    public FakePartitions partition(String dn, Map<String, Integer> holders) {
        replicas.put(dn.toLowerCase(Locale.ROOT), new ConcurrentHashMap<>(holders));
        names.put(dn.toLowerCase(Locale.ROOT), dn);
        return this;
    }

    @Override
    public String getExtendedOperationHandlerName() {
        return "partitions";
    }

    @Override
    public List<String> getSupportedExtendedRequestOIDs() {
        List<String> out = new ArrayList<>();
        for (int n : new int[] {3, 5, 7, 9, 11, 13, 15, 17, 19, 47, 49, 51}) {
            out.add(P + n);
        }
        return out;
    }

    @Override
    public ExtendedResult processExtendedOperation(InMemoryRequestHandler handler, int id, ExtendedRequest request) {
        try {
            List<ASN1Element> v = elements(request.getValue() == null ? new byte[0] : request.getValue().getValue());
            String oid = request.getOID();
            switch (oid.substring(P.length())) {
                case "19" -> {
                    String server = str(v.get(0));
                    List<ASN1Element> out = new ArrayList<>();
                    replicas.forEach((part, holders) -> {
                        if (holders.keySet().stream().anyMatch(s -> s.equalsIgnoreCase(server))) {
                            out.add(new ASN1OctetString(names.get(part)));
                        }
                    });
                    return ok(id, new ASN1Sequence(out).encode());
                }
                case "17" -> {
                    String server = str(v.get(0));
                    String part = str(v.get(1)).toLowerCase(Locale.ROOT);
                    Map<String, Integer> holders = replicas.get(part);
                    Integer type = holders == null ? null : holders.entrySet().stream().filter(e -> e.getKey().equalsIgnoreCase(server)).map(Map.Entry::getValue).findFirst().orElse(null);
                    if (type == null) {
                        return new ExtendedResult(id, ResultCode.NO_SUCH_OBJECT, "no replica", null, null, null, null, null);
                    }
                    return ok(id, concat(new ASN1Integer(32000 + part.hashCode() % 500), new ASN1Integer(0), new ASN1Integer(1791753112), new ASN1Integer(1791753107),
                        new ASN1Integer(6), new ASN1OctetString(names.get(part)), new ASN1Integer(type), new ASN1Integer(0)));
                }
                case "13" -> {
                    return ok(id, new ASN1Integer(1200 / Math.max(1, replicas.size())).encode());
                }
                case "3" -> {
                    String dn = str(v.get(1));
                    Map<String, Integer> parent = replicas.get(parentOf(dn));
                    Map<String, Integer> holders = new ConcurrentHashMap<>();
                    (parent == null ? Map.<String, Integer>of() : parent).forEach((s, t) -> holders.put(s, t == 3 ? 3 : t));
                    partition(dn, holders);
                    return ok(id, null);
                }
                case "5" -> {
                    replicas.remove(str(v.get(1)).toLowerCase(Locale.ROOT));
                    return ok(id, null);
                }
                case "7", "15" -> {
                    int type = ASN1Integer.decodeAsInteger(v.get(1)).intValue();
                    replicas.get(str(v.get(3)).toLowerCase(Locale.ROOT)).put(str(v.get(2)), type);
                    return ok(id, null);
                }
                case "11" -> {
                    replicas.get(str(v.get(2)).toLowerCase(Locale.ROOT)).put(str(v.get(1)), 3);
                    return ok(id, null);
                }
                default -> {
                    triggered.add(oid + (v.isEmpty() ? "" : " " + str(v.get(0))));
                    return ok(id, null);
                }
            }
        } catch (Exception e) {
            return new ExtendedResult(id, ResultCode.PROTOCOL_ERROR, e.toString(), null, null, null, null, null);
        }
    }

    private static String parentOf(String dn) {
        int i = dn.indexOf(',');
        return i < 0 ? "" : dn.substring(i + 1).toLowerCase(Locale.ROOT);
    }

    private static ExtendedResult ok(int id, byte[] value) {
        return new ExtendedResult(id, ResultCode.SUCCESS, null, null, null, null, value == null ? null : new ASN1OctetString(value), null);
    }

    private static String str(ASN1Element e) {
        return ASN1OctetString.decodeAsOctetString(e).stringValue();
    }

    private static byte[] concat(ASN1Element... e) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        for (ASN1Element x : e) {
            byte[] enc = x.encode();
            b.write(enc, 0, enc.length);
        }
        return b.toByteArray();
    }

    private static List<ASN1Element> elements(byte[] data) throws Exception {
        List<ASN1Element> out = new ArrayList<>();
        java.io.ByteArrayInputStream in = new java.io.ByteArrayInputStream(data);
        ASN1Element e;
        while ((e = ASN1Element.readFrom(in)) != null) {
            out.add(e);
        }
        return out;
    }
}
