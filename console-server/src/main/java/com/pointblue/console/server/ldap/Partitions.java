package com.pointblue.console.server.ldap;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import javax.naming.NamingException;

/**
 * eDirectory partitions and replicas over LDAP extended operations. The encodings are Novell JLDAP's ({@code com.novell.ldap.extensions}),
 * the authoritative client: a request value is BER elements back to back, not a SEQUENCE. Verified on
 * a lab tree (two servers, eDirectory 9.2.8 and 9.3.2), 2026-10-11:
 * <ul>
 * <li>List replicas includes subordinate references (type 3): a server whose replica was removed keeps
 *     listing the partition as one.</li>
 * <li>Get replica info and the {@code Replica} attribute carry the replica state in the high 16 bits
 *     of the type while an operation is in progress (0x310001: read/write, split state 1).</li>
 * <li>A replica being added shows as a subordinate reference in state 0 until the copy completes;
 *     operations meanwhile fail with -654 (partition busy) or LDAP 51.</li>
 * </ul>
 */
public final class Partitions {

    private static final String BASE = "2.16.840.1.113719.1.27.100.";
    static final String SPLIT = BASE + "3";
    static final String MERGE = BASE + "5";
    static final String ADD_REPLICA = BASE + "7";
    static final String REFRESH_LDAP = BASE + "9";
    static final String REMOVE_REPLICA = BASE + "11";
    static final String ENTRY_COUNT = BASE + "13";
    static final String CHANGE_TYPE = BASE + "15";
    static final String REPLICA_INFO = BASE + "17";
    static final String LIST_REPLICAS = BASE + "19";
    static final String LIMBER = BASE + "49";
    static final String JANITOR = BASE + "47";
    static final String SKULKER = BASE + "51";

    /** Make sure every server holding a replica is up before starting (JLDAP's LDAP_ENSURE_SERVERS_UP). */
    static final int ENSURE_SERVERS_UP = 1;

    /** Replica types (low 16 bits). */
    public enum Type {
        MASTER, READ_WRITE, READ_ONLY, SUBORDINATE_REFERENCE, SPARSE_WRITE, SPARSE_READ;

        public static Type of(int code) {
            int t = code & 0xffff;
            return t >= 0 && t < values().length ? values()[t] : null;
        }

        public String id() {
            return name().toLowerCase().replace('_', '-');
        }
    }

    /** One server's view of one partition (get replica info). {@code type} is the low 16 bits; {@code transition} the high. */
    public record ReplicaInfo(String partitionDn, int partitionId, int state, int type, int transition, int modificationTime,
                              int purgeTime, int localPartitionId, int flags) {
    }

    /** One value of the {@code Replica} attribute on a partition root: a server's replica and its addresses. */
    public record ReplicaPointer(String serverDn, int type, int transition, long partitionId, long number, List<Address> addresses) {
    }

    /** A network address of a replica: eDirectory's address type (8 UDP, 9 TCP, 13 URL…) and its value. */
    public record Address(int type, String value) {
    }

    private Partitions() {
    }

    // ---- reads --------------------------------------------------------------------------------------

    /** The partitions (and subordinate references) {@code serverDn} holds; "" is the tree root. */
    public static List<String> list(Ldap l, String serverDn) throws NamingException {
        return decodeList(l.extended(LIST_REPLICAS, octets(serverDn)));
    }

    /**
     * eDirectory 9.2.8 answers with a SEQUENCE OF OCTET STRING (lab); 9.3.3 with one OCTET STRING holding
     * JSON, {@code {"partitions":["", "o=data"]}} (a second lab tree, 2026-10-12). Novell's JLDAP reads only the first.
     */
    static List<String> decodeList(byte[] r) {
        List<String> out = new ArrayList<>();
        if (r == null || r.length == 0) {
            return out;
        }
        Ber.Element top = Ber.read(r).get(0);
        if (top.tag() == 0x30) {
            for (Ber.Element e : top.children()) {
                out.add(new String(e.value(), StandardCharsets.UTF_8));
            }
            return out;
        }
        String text = new String(top.value(), StandardCharsets.UTF_8).trim();
        if (text.startsWith("{")) {
            Object partitions = com.pointblue.dirxml.dev.json.Json.asMap(com.pointblue.dirxml.dev.json.Json.parse(text)).get("partitions");
            if (partitions instanceof List<?> list) {
                list.forEach(x -> out.add(String.valueOf(x)));
            }
            return out;
        }
        out.add(text);
        return out;
    }

    public static ReplicaInfo info(Ldap l, String serverDn, String partitionDn) throws NamingException {
        return decodeInfo(l.extended(REPLICA_INFO, Ber.concat(octets(serverDn), octets(partitionDn))));
    }

    static ReplicaInfo decodeInfo(byte[] r) {
        List<Ber.Element> e = Ber.read(r);
        int type = (int) e.get(6).integer();
        return new ReplicaInfo(new String(e.get(5).value(), StandardCharsets.UTF_8), (int) e.get(0).integer(), (int) e.get(1).integer(),
            type & 0xffff, type >>> 16, (int) e.get(2).integer(), (int) e.get(3).integer(), (int) e.get(4).integer(), (int) e.get(7).integer());
    }

    /** The number of entries in the partition rooted at {@code partitionDn}, on the server the console is connected to. */
    public static int entryCount(Ldap l, String partitionDn) throws NamingException {
        return (int) Ber.read(l.extended(ENTRY_COUNT, octets(partitionDn))).get(0).integer();
    }

    /**
     * One {@code Replica} value: SEQUENCE { serverDN, type (state in the high 16 bits), partition ID on
     * that server, replica number, SEQUENCE OF SEQUENCE { address type, address } }. Read on a lab tree: the
     * third integer is 1 on the master and 2 on the read/write replica, and the second equals that
     * server's partition ID from get replica info. URL addresses (type 13) are UTF-16LE.
     */
    public static ReplicaPointer decodePointer(byte[] value) {
        List<Ber.Element> f = Ber.read(value).get(0).children();
        String server = new String(f.get(0).value(), StandardCharsets.UTF_8);
        int type = (int) f.get(1).integer();
        long id = f.size() > 2 ? f.get(2).integer() : -1;
        long number = f.size() > 3 && f.get(3).tag() == 0x02 ? f.get(3).integer() : -1;
        List<Address> addresses = new ArrayList<>();
        for (Ber.Element x : f) {
            if (x.tag() != 0x30) {
                continue;
            }
            for (Ber.Element a : x.children()) {
                if (a.tag() != 0x30) {
                    continue;
                }
                List<Ber.Element> p = a.children();
                if (p.size() == 2) {
                    addresses.add(new Address((int) p.get(0).integer(), address((int) p.get(0).integer(), p.get(1).value())));
                }
            }
        }
        return new ReplicaPointer(server, type & 0xffff, type >>> 16, id, number, addresses);
    }

    /** IPv4 as dotted text with its port (types 8 and 9: two bytes of port, four of address); URLs as text; others as hex. */
    public static String address(int type, byte[] v) {
        if ((type == 8 || type == 9) && v.length == 6) {
            return (v[2] & 0xff) + "." + (v[3] & 0xff) + "." + (v[4] & 0xff) + "." + (v[5] & 0xff) + ":" + (((v[0] & 0xff) << 8) | (v[1] & 0xff));
        }
        if (type == 13) {
            return new String(v, StandardCharsets.UTF_16LE).replace("\0", "");
        }
        return java.util.HexFormat.of().formatHex(v);
    }

    // ---- writes -------------------------------------------------------------------------------------

    /** Make {@code containerDn} the root of a new partition (split it from its parent). */
    public static void split(Ldap l, String containerDn) throws NamingException {
        l.extended(SPLIT, Ber.concat(Ber.integer(0x02, ENSURE_SERVERS_UP), octets(containerDn)));
    }

    /** Merge the partition rooted at {@code partitionDn} into its parent. */
    public static void merge(Ldap l, String partitionDn) throws NamingException {
        l.extended(MERGE, Ber.concat(Ber.integer(0x02, ENSURE_SERVERS_UP), octets(partitionDn)));
    }

    public static void addReplica(Ldap l, String partitionDn, String serverDn, Type type) throws NamingException {
        l.extended(ADD_REPLICA, Ber.concat(Ber.integer(0x02, ENSURE_SERVERS_UP), Ber.integer(0x02, type.ordinal()), octets(serverDn), octets(partitionDn)));
    }

    public static void removeReplica(Ldap l, String partitionDn, String serverDn) throws NamingException {
        l.extended(REMOVE_REPLICA, Ber.concat(Ber.integer(0x02, ENSURE_SERVERS_UP), octets(serverDn), octets(partitionDn)));
    }

    public static void changeType(Ldap l, String partitionDn, String serverDn, Type type) throws NamingException {
        l.extended(CHANGE_TYPE, Ber.concat(Ber.integer(0x02, ENSURE_SERVERS_UP), Ber.integer(0x02, type.ordinal()), octets(serverDn), octets(partitionDn)));
    }

    /**
     * Run a background process (limber, janitor or skulker) on {@code serverDn} now. The request value
     * is the server's DN as a BER octet string: with no value (as JLDAP's TriggerBackgroundProcessRequest
     * sends) eDirectory 9.2.8 answers "Could not convert to NDS Name" over JNDI; with another server's DN
     * it runs there (a lab tree, 2026-10-11).
     */
    public static void trigger(Ldap l, String process, String serverDn) throws NamingException {
        String oid = switch (process) {
            case "limber" -> LIMBER;
            case "janitor" -> JANITOR;
            case "skulker" -> SKULKER;
            default -> throw new IllegalArgumentException("a background process is limber, janitor or skulker");
        };
        l.extended(oid, octets(serverDn));
    }

    /** Re-read the LDAP Server object's configuration on the server the console is connected to. */
    public static void refreshLdapServer(Ldap l) throws NamingException {
        l.extended(REFRESH_LDAP, null);
    }

    static byte[] octets(String s) {
        return Ber.tlv(0x04, s.getBytes(StandardCharsets.UTF_8));
    }
}
