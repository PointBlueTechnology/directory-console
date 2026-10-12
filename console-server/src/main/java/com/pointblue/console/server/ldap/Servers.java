package com.pointblue.console.server.ldap;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;

/**
 * Where eDirectory servers are, and which of them hold a replica of an object: for operations on a
 * particular server's replica (per-replica attributes, {@code X-NDS_NEVER_SYNC}, such as Identity
 * Manager's start option and named passwords, which each server keeps for itself).
 */
public final class Servers {

    /** A server and the LDAPS address the console reaches it at. */
    public record Located(String guid, String dn, String name, String host, int port) {
    }

    /** A server holding a replica (not a subordinate reference) of an object's partition. */
    public record Holder(String guid, String dn, String name, Partitions.Type type) {
    }

    private Servers() {
    }

    /**
     * The server with this GUID and its address: {@code overrides} (server DN → "host:port", for
     * networks where the published addresses are not reachable) first; else the host of its LDAP
     * Server object's {@code ldaps://} interface, or its first TCP IPv4 network address, with that
     * interface's port (636 by default).
     */
    public static Located locate(Ldap l, String guid, Map<String, String> overrides) throws NamingException {
        Ldap.Entry srv = find(l, guid);
        if (srv == null) {
            return null;
        }
        String override = overrides == null ? null : overrides.entrySet().stream()
            .filter(e -> Names.same(e.getKey(), srv.dn())).map(Map.Entry::getValue).findFirst().orElse(null);
        if (override != null) {
            int colon = override.lastIndexOf(':');
            return new Located(guid, srv.dn(), srv.first("cn"), colon > 0 ? override.substring(0, colon) : override,
                colon > 0 ? Integer.parseInt(override.substring(colon + 1)) : 636);
        }
        String host = null;
        int port = 636;
        for (Ldap.Entry ls : l.search("", "(&(objectClass=ldapServer)(ldapHostServer={0}))", new Object[] {srv.dn()},
                SearchControls.SUBTREE_SCOPE, new String[] {"ldapInterfaces"}, 2)) {
            for (Object v : ls.attributes().getOrDefault("ldapinterfaces", List.of())) {
                String i = String.valueOf(v).trim().toLowerCase(Locale.ROOT);
                if (i.startsWith("ldaps://")) {
                    String hp = i.substring(8).replaceAll("/.*$", "");
                    int colon = hp.lastIndexOf(':');
                    if (colon >= 0) {
                        port = Integer.parseInt(hp.substring(colon + 1));
                        hp = hp.substring(0, colon);
                    }
                    if (!hp.isEmpty()) {
                        host = hp;
                    }
                }
            }
        }
        if (host == null) {
            for (Object a : srv.attributes().getOrDefault("networkaddress", List.of())) {
                if (a instanceof byte[] b && b.length == 8 && b[0] == '9' && b[1] == '#') {
                    host = (b[4] & 0xff) + "." + (b[5] & 0xff) + "." + (b[6] & 0xff) + "." + (b[7] & 0xff);
                    break;
                }
            }
        }
        if (host == null) {
            throw new NamingException("no LDAPS address is published for " + srv.dn() + "; set one for it in the directory's settings");
        }
        return new Located(guid, srv.dn(), srv.first("cn"), host, port);
    }

    /** The NCP Server object with this GUID (its {@code cn} and network addresses), or null. */
    public static Ldap.Entry find(Ldap l, String guid) throws NamingException {
        List<Ldap.Entry> found = l.search("", "(&(objectClass=ncpServer)(GUID={0}))", new Object[] {Names.guidBytes(guid)},
            SearchControls.SUBTREE_SCOPE, new String[] {"cn", "networkAddress"}, 2);
        return found.isEmpty() ? null : found.get(0);
    }

    /**
     * The servers holding a replica of the partition {@code dn} is in: the deepest partition root that
     * {@code dn} is at or under, and each server's replica of it that is not a subordinate reference.
     */
    public static List<Holder> holders(Ldap l, String dn) throws NamingException {
        List<Ldap.Entry> servers = l.search("", "(objectClass=ncpServer)", null, SearchControls.SUBTREE_SCOPE, new String[] {"GUID", "cn"}, 500);
        String best = null;
        java.util.Map<String, List<String>> held = new java.util.LinkedHashMap<>();
        for (Ldap.Entry s : servers) {
            List<String> parts;
            try {
                parts = Partitions.list(l, s.dn());
            } catch (NamingException e) {
                continue;
            }
            held.put(s.dn(), parts);
            for (String p : parts) {
                if ((p.isEmpty() || Names.within(dn, p)) && (best == null || depth(p) > depth(best))) {
                    best = p;
                }
            }
        }
        List<Holder> out = new ArrayList<>();
        if (best == null) {
            return out;
        }
        for (Ldap.Entry s : servers) {
            List<String> parts = held.get(s.dn());
            if (parts == null || parts.stream().noneMatch(sameAs(best))) {
                continue;
            }
            Partitions.ReplicaInfo info;
            try {
                info = Partitions.info(l, s.dn(), best);
            } catch (NamingException e) {
                continue;
            }
            Partitions.Type t = Partitions.Type.of(info.type());
            if (t != null && t != Partitions.Type.SUBORDINATE_REFERENCE) {
                out.add(new Holder(Names.guidHex(s.attributes().get("guid").get(0)), s.dn(), s.first("cn"), t));
            }
        }
        return out;
    }

    private static java.util.function.Predicate<String> sameAs(String p) {
        return x -> x.isEmpty() ? p.isEmpty() : !p.isEmpty() && Names.same(x, p);
    }

    private static int depth(String dn) {
        return dn.isEmpty() ? 0 : Names.parse(dn).size();
    }
}
