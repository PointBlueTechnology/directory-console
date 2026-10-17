package com.pointblue.console.server.http;

import com.pointblue.console.server.auth.DirectoryConfig;
import com.pointblue.console.server.auth.Role;
import com.pointblue.console.server.auth.Sessions;
import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.console.server.ldap.Names;
import com.pointblue.console.server.ldap.Partitions;
import com.pointblue.dirxml.dev.json.Json;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.naming.NamingException;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;

/**
 * eDirectory administration: servers, partitions and replicas, indexes,
 * schema changes, background processes. Verified on a lab tree.
 *
 * <pre>
 * GET    /api/v2/trees/{tree}/edir/servers                         NCP servers
 * GET    /api/v2/trees/{tree}/edir/servers/{guid}                  one server: its replicas and indexes
 * POST   /api/v2/trees/{tree}/edir/servers/{guid}/indexes          {"name", "attributes", "rule": "value|presence|substring"}
 * DELETE /api/v2/trees/{tree}/edir/servers/{guid}/indexes/{name}   a user-defined index
 * GET    /api/v2/trees/{tree}/edir/partitions                      every partition: entry count and replica ring
 * POST   /api/v2/trees/{tree}/edir/partitions                      {"container": guid}: split it from its parent
 * POST   /api/v2/trees/{tree}/edir/partitions/{id}/merge           into its parent
 * POST   /api/v2/trees/{tree}/edir/partitions/{id}/replicas        {"server": guid, "type": "read-write|read-only"}
 * PUT    /api/v2/trees/{tree}/edir/partitions/{id}/replicas/{guid} {"type"}
 * DELETE /api/v2/trees/{tree}/edir/partitions/{id}/replicas/{guid}
 * POST   /api/v2/trees/{tree}/edir/servers/{guid}/background       {"process": "limber|janitor|skulker"}
 * POST   /api/v2/trees/{tree}/edir/ldap-refresh                    re-read the connected server's LDAP configuration
 * POST   /api/v2/trees/{tree}/edir/schema/attributes               {"name", "oid"?, "syntax", "singleValue", "upperBound"?, "description"?}
 * POST   /api/v2/trees/{tree}/edir/schema/classes                  {"name", "oid"?, "kind", "superior", "must", "may", "container", "naming", "containment"}
 * POST   /api/v2/trees/{tree}/edir/schema/classes/{name}/may       {"attributes"}: add optional attributes
 * DELETE /api/v2/trees/{tree}/edir/schema/attributes/{name} | classes/{name}
 * </pre>
 *
 * A partition's id is its root's GUID, or {@code root} for the tree root. Reads need any role. Writes
 * change the whole tree's replication or schema, so they need an editor grant that reaches the tree
 * root (not a scoped one), and on a production directory the directory's name typed
 * ({@code X-Confirm-Directory}); eDirectory's own rights apply on top.
 */
final class Edir {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern NAME = Pattern.compile("[A-Za-z][A-Za-z0-9-]{0,62}");
    private static final Pattern OID = Pattern.compile("[0-2](\\.(0|[1-9][0-9]*))+");
    private static final List<String> RULES = List.of("value", "presence", "substring");
    /** Flags a new attribute may have, as eDirectory writes them in its schema. */
    static final Map<String, String> ATTRIBUTE_FLAGS = new java.util.LinkedHashMap<>(Map.of(
        "publicRead", "X-NDS_PUBLIC_READ", "serverRead", "X-NDS_SERVER_READ", "writeManaged", "X-NDS_NAME_VALUE_ACCESS",
        "perReplica", "X-NDS_PER_REPLICA", "notSyncImmediate", "X-NDS_NOT_SCHED_SYNC_IMMEDIATE"));
    private static final List<String> INDEX_TYPES = List.of("user", "attribute-creation", "system", "operational");

    private final Server server;

    Edir(Server server) {
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
        String route = method + " " + String.join("/", java.util.Arrays.copyOfRange(p, 2, p.length))
            .replaceAll("^(servers|partitions)/([0-9a-f]{32}|root)", "$1/{id}")
            .replaceAll("replicas/[0-9a-f]{32}$", "replicas/{server}")
            .replaceAll("indexes/[^/]+$", "indexes/{name}")
            .replaceAll("indexes/[^/]+/(state|copy)$", "indexes/{name}/$1")
            .replaceAll("^schema/(attributes|classes)/[^/]+", "schema/$1/{name}")
            .replaceAll("^ldap/(servers|groups)/[0-9a-f]{32}", "ldap/$1/{id}");
        String id = p.length > 3 && p[2].equals("ldap") ? (p.length > 4 ? p[4] : null) : p.length > 3 ? p[3] : null;
        if (!method.equals("GET")) {
            if (!s.principal.may(Role.EDITOR, "")) {
                throw new Http.Problem(403, "forbidden", "eDirectory administration needs an editor role for the whole directory");
            }
            confirm(ex, s);
        }
        try {
            switch (route) {
                case "GET servers" -> Http.json(ex, 200, servers(l));
                case "GET servers/{id}" -> Http.json(ex, 200, serverDetail(l, id));
                case "POST servers/{id}/indexes" -> addIndex(ex, l, s, id);
                case "DELETE servers/{id}/indexes/{name}" -> deleteIndex(ex, l, s, id, decode(p[5]));
                case "PUT servers/{id}/indexes/{name}/state" -> indexState(ex, l, s, id, decode(p[5]));
                case "POST servers/{id}/indexes/{name}/copy" -> copyIndex(ex, l, s, id, decode(p[5]));
                case "GET partitions" -> Http.json(ex, 200, partitions(l));
                case "POST partitions" -> split(ex, l, s);
                case "POST partitions/{id}/merge" -> partitionOp(ex, l, s, id, "partition.merge", (dn) -> Partitions.merge(l, dn));
                case "POST partitions/{id}/replicas" -> {
                    Map<String, Object> b = Http.body(ex);
                    String srv = dnOf(l, Http.string(b, "server", true));
                    Partitions.Type t = type(Http.string(b, "type", true));
                    partitionOp(ex, l, s, id, "replica.add", (dn) -> Partitions.addReplica(l, dn, srv, t));
                }
                case "PUT partitions/{id}/replicas/{server}" -> {
                    String srv = dnOf(l, p[5]);
                    Partitions.Type t = type(Http.string(Http.body(ex), "type", true));
                    partitionOp(ex, l, s, id, "replica.change-type", (dn) -> Partitions.changeType(l, dn, srv, t));
                }
                case "DELETE partitions/{id}/replicas/{server}" -> {
                    String srv = dnOf(l, p[5]);
                    partitionOp(ex, l, s, id, "replica.remove", (dn) -> Partitions.removeReplica(l, dn, srv));
                }
                case "POST servers/{id}/background" -> {
                    String process = Http.string(Http.body(ex), "process", true);
                    String srv = dnOf(l, id);
                    Partitions.trigger(l, process, srv);
                    audit(s, "edir.background", id, Map.of("process", process, "server", srv), null);
                    Http.json(ex, 204, Map.of());
                }
                case "GET ldap" -> Http.json(ex, 200, ldapConfigs(l));
                case "POST ldap/servers/{id}/refresh" -> refreshLdap(ex, s, id, false);
                case "POST ldap/servers/{id}/reload" -> refreshLdap(ex, s, id, true);
                case "GET ldap/servers/{id}" -> Http.json(ex, 200, ldapObject(l, id, "ldapServer"));
                case "PATCH ldap/servers/{id}" -> changeLdapObject(ex, l, s, id, "ldapServer");
                case "GET ldap/groups/{id}" -> Http.json(ex, 200, ldapObject(l, id, "ldapGroup"));
                case "PATCH ldap/groups/{id}" -> changeLdapObject(ex, l, s, id, "ldapGroup");
                case "POST ldap-refresh" -> {
                    Partitions.refreshLdapServer(l);
                    audit(s, "edir.ldap-refresh", null, Map.of(), null);
                    Http.json(ex, 204, Map.of());
                }
                case "POST schema/attributes" -> addAttribute(ex, l, s);
                case "POST schema/classes" -> addClass(ex, l, s);
                case "POST schema/classes/{name}/may" -> addMay(ex, l, s, decode(p[4]));
                case "DELETE schema/attributes/{name}" -> deleteSchema(ex, l, s, "attributeTypes", decode(p[4]));
                case "DELETE schema/classes/{name}" -> deleteSchema(ex, l, s, "objectClasses", decode(p[4]));
                default -> throw new Http.Problem(404, "not-found", method + " " + path);
            }
        } catch (NamingException e) {
            throw server.objects.problem(s, Ldap.Failure.of(e));
        } catch (IllegalArgumentException e) {
            throw new Http.Problem(400, "bad-request", e.getMessage());
        }
    }

    private static String decode(String segment) {
        return java.net.URLDecoder.decode(segment, java.nio.charset.StandardCharsets.UTF_8);
    }

    /** A production directory wants its name typed for these changes (the same gate as Identity Manager's). */
    private void confirm(HttpExchange ex, Sessions.Session s) {
        DirectoryConfig d = server.directoryOf(s);
        if (d != null && d.production()) {
            String typed = ex.getRequestHeaders().getFirst("X-Confirm-Directory");
            if (typed == null || !typed.trim().equalsIgnoreCase(d.name())) {
                throw new Http.Problem(409, "confirm-directory", "this changes the production directory " + d.name() + "; type its name to confirm");
            }
        }
    }

    private void audit(Sessions.Session s, String action, String target, Map<String, Object> detail, Ldap.Failure f) throws IOException {
        server.objects.audit(s, action, target, detail, f);
    }

    private String dnOf(Ldap l, String guid) throws NamingException {
        if (!Names.guid(guid)) {
            throw new Http.Problem(400, "bad-guid", "a server or object is named by its GUID");
        }
        return server.objects.dnOf(l, guid);
    }

    private static Partitions.Type type(String t) {
        return switch (t) {
            case "read-write" -> Partitions.Type.READ_WRITE;
            case "read-only" -> Partitions.Type.READ_ONLY;
            case "master" -> Partitions.Type.MASTER;
            default -> throw new IllegalArgumentException("a replica type is master, read-write or read-only");
        };
    }

    // ---- servers ------------------------------------------------------------------------------------

    private static final String[] SERVER_ATTRS = {"cn", "GUID", "version", "DSRevision", "status", "networkAddress", "indexDefinition"};

    private List<Map<String, Object>> servers(Ldap l) throws NamingException {
        String dsa = dsaName(l);
        List<Map<String, Object>> out = new ArrayList<>();
        for (Ldap.Entry e : l.search("", "(objectClass=ncpServer)", null, SearchControls.SUBTREE_SCOPE, SERVER_ATTRS, 200)) {
            out.add(serverJson(l, e, dsa));
        }
        out.sort((a, b) -> String.valueOf(a.get("name")).compareToIgnoreCase(String.valueOf(b.get("name"))));
        return out;
    }

    private Map<String, Object> serverJson(Ldap l, Ldap.Entry e, String dsa) throws NamingException {
        Map<String, Object> m = new LinkedHashMap<>(Names.identity(e.dn()));
        m.put("guid", Names.guidHex(e.attributes().getOrDefault("guid", List.of((Object) "")).get(0)));
        m.put("version", e.first("version"));
        m.put("dsRevision", e.first("DSRevision"));
        String status = e.first("status");
        m.put("status", "2".equals(status) ? "up" : "1".equals(status) ? "down" : status);
        m.put("connected", dsa != null && Names.same(dsa, e.dn()));
        List<String> addresses = new ArrayList<>();
        for (Object a : e.attributes().getOrDefault("networkaddress", List.of())) {
            if (a instanceof byte[] b) {
                String text = networkAddress(b);
                if (text != null && !addresses.contains(text)) {
                    addresses.add(text);
                }
            }
        }
        m.put("addresses", addresses);
        List<Ldap.Entry> ldap = l.search("", "(&(objectClass=ldapServer)(ldapHostServer={0}))", new Object[] {e.dn()}, SearchControls.SUBTREE_SCOPE, new String[] {"GUID"}, 2);
        m.put("ldapServer", ldap.isEmpty() ? null : Map.of("dn", ldap.get(0).dn(), "guid", Names.guidHex(ldap.get(0).attributes().get("guid").get(0))));
        return m;
    }

    /**
     * networkAddress over LDAP: the address type in ASCII digits, '#', then the raw address (lab:
     * {@code 9#} and six bytes, port then IPv4, for TCP). Only TCP and UDP IPv4 and URLs are shown.
     */
    static String networkAddress(byte[] b) {
        int hash = -1;
        for (int i = 0; i < Math.min(b.length, 4); i++) {
            if (b[i] == '#') {
                hash = i;
                break;
            }
            if (b[i] < '0' || b[i] > '9') {
                return null;
            }
        }
        if (hash <= 0) {
            return null;
        }
        int type = Integer.parseInt(new String(b, 0, hash, java.nio.charset.StandardCharsets.US_ASCII));
        if (type != 8 && type != 9 && type != 13) {
            return null;
        }
        byte[] rest = java.util.Arrays.copyOfRange(b, hash + 1, b.length);
        return (type == 9 ? "tcp " : type == 8 ? "udp " : "") + Partitions.address(type, rest);
    }

    private String dsaName(Ldap l) throws NamingException {
        Ldap.Entry root = l.read("", "dsaName");
        return root == null ? null : root.first("dsaName");
    }

    private Map<String, Object> serverDetail(Ldap l, String guid) throws NamingException {
        Ldap.Entry e = server.objects.byGuid(l, guid, SERVER_ATTRS);
        Map<String, Object> m = serverJson(l, e, dsaName(l));
        List<Map<String, Object>> replicas = new ArrayList<>();
        for (String part : Partitions.list(l, e.dn())) {
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("partition", part.isEmpty() ? Map.of("dn", "", "name", "[Root]", "id", "root") : partitionRef(l, part));
            try {
                r.putAll(infoJson(Partitions.info(l, e.dn(), part)));
            } catch (NamingException x) {
                r.put("error", Ldap.Failure.of(x).getMessage());
            }
            replicas.add(r);
        }
        m.put("replicas", replicas);
        List<Map<String, Object>> indexes = new ArrayList<>();
        for (Object v : e.attributes().getOrDefault("indexdefinition", List.of())) {
            Map<String, Object> ix = index(String.valueOf(v));
            if (ix != null) {
                indexes.add(ix);
            }
        }
        m.put("indexes", indexes);
        return m;
    }

    private Map<String, Object> partitionRef(Ldap l, String dn) throws NamingException {
        Map<String, Object> ref = new LinkedHashMap<>();
        ref.put("dn", dn);
        ref.put("name", Names.identity(dn).get("name"));
        Ldap.Entry e = l.read(dn, "GUID");
        ref.put("id", e == null || e.attributes().get("guid") == null ? null : Names.guidHex(e.attributes().get("guid").get(0)));
        return ref;
    }

    private static Map<String, Object> infoJson(Partitions.ReplicaInfo i) {
        Map<String, Object> m = new LinkedHashMap<>();
        Partitions.Type t = Partitions.Type.of(i.type());
        m.put("type", t == null ? String.valueOf(i.type()) : t.id());
        m.put("state", stateName(i.state()));
        m.put("transition", i.transition() == 0 ? null : stateName(i.transition()));
        m.put("busy", (i.flags() & 1) != 0);
        m.put("modified", i.modificationTime() > 0 ? java.time.Instant.ofEpochSecond(i.modificationTime() & 0xffffffffL).toString() : null);
        return m;
    }

    /** JLDAP ReplicationConstants.LDAP_RS_*. */
    static String stateName(int s) {
        return switch (s) {
            case 0 -> "on";
            case 1 -> "new";
            case 2 -> "dying";
            case 3 -> "locked";
            case 6 -> "transition-on";
            case 7 -> "dead";
            case 8 -> "begin-add";
            case 11 -> "master-start";
            case 12 -> "master-done";
            case 48, 49 -> "splitting";
            case 64, 65, 66 -> "joining";
            default -> "state " + s;
        };
    }

    // ---- indexes ------------------------------------------------------------------------------------

    /**
     * {@code indexDefinition}: version$name$state$rule$type$value-state$attribute[$attribute…]. On a lab tree every
     * index in use reads state 0 and value state 1; rule 0 value, 1 presence, 2 substring; type 0 user
     * defined, 1 added with an attribute, 2 required by the system, 3 operational.
     */
    static Map<String, Object> index(String v) {
        String[] f = v.split("\\$");
        if (f.length < 7) {
            return null;
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", f[1]);
        m.put("rule", ruleName(f[3]));
        int type = parse(f[4]);
        m.put("type", type >= 0 && type < INDEX_TYPES.size() ? INDEX_TYPES.get(type) : f[4]);
        m.put("state", switch (f[2]) {
            case "0" -> "online";
            case "1" -> "offline";
            case "2" -> "new";
            case "3" -> "pending";
            default -> f[2];
        });
        m.put("switchable", type == 0 || type == 1);
        m.put("attributes", List.of(java.util.Arrays.copyOfRange(f, 6, f.length)));
        m.put("removable", type == 0);
        m.put("raw", v);
        return m;
    }

    private static String ruleName(String r) {
        int n = parse(r);
        return n >= 0 && n < RULES.size() ? RULES.get(n) : r;
    }

    private static int parse(String s) {
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /**
     * {@code PUT servers/{id}/indexes/{name}/state}: {state: online | offline}. Only that value's state field
     * changes (Identity Console rewrites every value); limber then picks it up. User and auto-added indexes
     * only; system and operational ones belong to eDirectory.
     */
    private void indexState(HttpExchange ex, Ldap l, Sessions.Session s, String guid, String name) throws IOException, NamingException {
        String want = Http.string(Http.body(ex), "state", true);
        if (!List.of("online", "offline").contains(want)) {
            throw new Http.Problem(400, "bad-field", "state is online or offline");
        }
        Ldap.Entry e = server.objects.byGuid(l, guid, "indexDefinition");
        if (e == null) {
            throw new Http.Problem(404, "not-found", "no server has GUID " + guid);
        }
        List<String> matches = new ArrayList<>();
        for (Object v : e.attributes().getOrDefault("indexdefinition", List.of())) {
            Map<String, Object> ix = index(String.valueOf(v));
            if (ix != null && String.valueOf(ix.get("name")).equalsIgnoreCase(name)) {
                matches.add(String.valueOf(v));
            }
        }
        if (matches.isEmpty()) {
            throw new Http.Problem(404, "not-found", "this server has no index named " + name);
        }
        if (matches.size() > 1) {
            throw new Http.Problem(409, "ambiguous", "this server has " + matches.size() + " indexes named " + name);
        }
        String old = matches.get(0);
        Map<String, Object> ix = index(old);
        if (!Boolean.TRUE.equals(ix.get("switchable"))) {
            throw new Http.Problem(409, "not-switchable", "a " + ix.get("type") + " index belongs to eDirectory and stays online");
        }
        if (want.equals(ix.get("state"))) {
            Http.json(ex, 200, serverDetail(l, guid));
            return;
        }
        String[] f = old.split("\\$", -1);
        f[2] = want.equals("online") ? "0" : "1";
        String value = String.join("$", f);
        Map<String, Object> detail = Map.of("server", e.dn(), "index", name, "state", want);
        try {
            l.modify(e.dn(), List.of(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute("indexDefinition", old)),
                new ModificationItem(DirContext.ADD_ATTRIBUTE, new BasicAttribute("indexDefinition", value))));
            Partitions.trigger(l, "limber", e.dn());
        } catch (NamingException x) {
            audit(s, "index.state", guid, detail, Ldap.Failure.of(x));
            throw x;
        }
        audit(s, "index.state", guid, detail, null);
        Http.json(ex, 200, serverDetail(l, guid));
    }

    // ---- LDAP Server and LDAP Group objects ------------------------------------------------------------

    private Map<String, Object> ref(Ldap l, String dn) throws NamingException {
        if (dn == null) {
            return null;
        }
        Ldap.Entry e = l.read(dn, "GUID");
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("dn", dn);
        m.put("name", Names.identity(dn).get("name"));
        m.put("guid", e == null || e.attributes().get("guid") == null ? null : Names.guidHex(e.attributes().get("guid").get(0)));
        return m;
    }

    /** {@code GET ldap}: every LDAP Server object with its host server and group, and every LDAP Group with its servers. */
    private Map<String, Object> ldapConfigs(Ldap l) throws NamingException {
        List<Map<String, Object>> servers = new ArrayList<>();
        for (Ldap.Entry e : l.search("", "(objectClass=ldapServer)", null, javax.naming.directory.SearchControls.SUBTREE_SCOPE,
                new String[] {"GUID", "cn", "ldapHostServer", "ldapGroupDN", "ldapInterfaces", "ldapTLSRequired", "ldapKeyMaterialName"}, 500)) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("guid", Names.guidHex(e.attributes().get("guid").get(0)));
            m.put("dn", e.dn());
            m.put("name", String.valueOf(e.first("cn")));
            m.put("host", ref(l, e.first("ldapHostServer") == null ? null : String.valueOf(e.first("ldapHostServer"))));
            m.put("group", ref(l, e.first("ldapGroupDN") == null ? null : String.valueOf(e.first("ldapGroupDN"))));
            m.put("interfaces", e.attributes().getOrDefault("ldapinterfaces", List.of()).stream().map(String::valueOf).toList());
            m.put("tlsRequired", "TRUE".equalsIgnoreCase(String.valueOf(e.first("ldapTLSRequired"))));
            m.put("certificate", e.first("ldapKeyMaterialName") == null ? null : String.valueOf(e.first("ldapKeyMaterialName")));
            servers.add(m);
        }
        List<Map<String, Object>> groups = new ArrayList<>();
        for (Ldap.Entry e : l.search("", "(objectClass=ldapGroup)", null, javax.naming.directory.SearchControls.SUBTREE_SCOPE,
                new String[] {"GUID", "cn", "ldapServerList"}, 500)) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("guid", Names.guidHex(e.attributes().get("guid").get(0)));
            m.put("dn", e.dn());
            m.put("name", String.valueOf(e.first("cn")));
            List<Map<String, Object>> members = new ArrayList<>();
            for (Object d : e.attributes().getOrDefault("ldapserverlist", List.of())) {
                members.add(ref(l, String.valueOf(d)));
            }
            m.put("servers", members);
            groups.add(m);
        }
        return Map.of("servers", servers, "groups", groups);
    }

    private static final String[] LDAP_REFS = {"GUID", "objectClass", "cn", "ldapHostServer", "ldapGroupDN", "ldapServerList", "ldapKeyMaterialName", "extensionInfo"};

    private Ldap.Entry ldapEntry(Ldap l, String guid, String objectClass) throws NamingException {
        Map<String, LdapObjects.Field> fields = objectClass.equals("ldapServer") ? LdapObjects.SERVER : LdapObjects.GROUP;
        List<String> attrs = new ArrayList<>(List.of(LDAP_REFS));
        attrs.addAll(fields.keySet());
        l.binaryAttributes(List.of("ldapSSLConfig"));
        Ldap.Entry e = server.objects.byGuid(l, guid, attrs.toArray(String[]::new));
        if (e == null || e.attributes().getOrDefault("objectclass", List.of()).stream().noneMatch(o -> String.valueOf(o).equalsIgnoreCase(objectClass))) {
            throw new Http.Problem(404, "not-found", "no " + (objectClass.equals("ldapServer") ? "LDAP Server" : "LDAP Group") + " object has GUID " + guid);
        }
        return e;
    }

    /** {@code GET ldap/servers/{id}} or {@code ldap/groups/{id}}: the object's settings, and what it is linked to. */
    private Map<String, Object> ldapObject(Ldap l, String guid, String objectClass) throws NamingException {
        Ldap.Entry e = ldapEntry(l, guid, objectClass);
        boolean isServer = objectClass.equals("ldapServer");
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("guid", guid);
        m.put("dn", e.dn());
        m.put("name", String.valueOf(e.first("cn")));
        if (isServer) {
            m.put("host", ref(l, e.first("ldapHostServer") == null ? null : String.valueOf(e.first("ldapHostServer"))));
            m.put("group", ref(l, e.first("ldapGroupDN") == null ? null : String.valueOf(e.first("ldapGroupDN"))));
            m.put("certificate", e.first("ldapKeyMaterialName") == null ? null : String.valueOf(e.first("ldapKeyMaterialName")));
        } else {
            List<Map<String, Object>> members = new ArrayList<>();
            for (Object d : e.attributes().getOrDefault("ldapserverlist", List.of())) {
                members.add(ref(l, String.valueOf(d)));
            }
            m.put("servers", members);
        }
        m.put("settings", LdapObjects.read(e, isServer ? LdapObjects.SERVER : LdapObjects.GROUP));
        return m;
    }

    /**
     * {@code PATCH ldap/servers/{id}} or {@code ldap/groups/{id}}: {settings: {attribute: value | null}}. Only the
     * settings named change; the LDAP server applies them when refreshed.
     */
    private void changeLdapObject(HttpExchange ex, Ldap l, Sessions.Session s, String guid, String objectClass) throws IOException, NamingException {
        Map<String, Object> changes = Json.asMap(Http.body(ex).get("settings"));
        if (changes.isEmpty()) {
            throw new Http.Problem(400, "bad-request", "settings names the settings to change");
        }
        boolean isServer = objectClass.equals("ldapServer");
        Ldap.Entry e = ldapEntry(l, guid, objectClass);
        List<ModificationItem> mods = LdapObjects.modifications(changes, isServer ? LdapObjects.SERVER : LdapObjects.GROUP);
        // a removal of an attribute that is not there is an error in eDirectory: drop those
        mods.removeIf(mi -> mi.getModificationOp() == DirContext.REMOVE_ATTRIBUTE
            && e.attributes().getOrDefault(mi.getAttribute().getID().toLowerCase(Locale.ROOT), List.of()).isEmpty());
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("dn", e.dn());
        detail.put("settings", new ArrayList<>(changes.keySet()));
        String action = isServer ? "edir.ldap-server.change" : "edir.ldap-group.change";
        if (!mods.isEmpty()) {
            try {
                l.modify(e.dn(), mods);
            } catch (NamingException x) {
                audit(s, action, guid, detail, Ldap.Failure.of(x));
                throw x;
            }
        }
        audit(s, action, guid, detail, null);
        Map<String, Object> out = new LinkedHashMap<>(ldapObject(l, guid, objectClass));
        // what applies at a refresh and what needs the LDAP module reloaded
        out.put("needs", changes.keySet().stream().anyMatch(LdapObjects.NEED_RELOAD::contains) ? "reload" : "refresh");
        Http.json(ex, 200, out);
    }

    /**
     * {@code POST ldap/servers/{id}/refresh}: the LDAP server re-reads its LDAP Server and LDAP Group objects.
     * eDirectory's refresh operation acts on the server the request reaches, so it goes over a connection to
     * the LDAP server's host (signing in to it once, for a direct sign-in, as replica work does).
     */
    private void refreshLdap(HttpExchange ex, Sessions.Session s, String guid, boolean reload) throws IOException, NamingException {
        Ldap l = s.ldap();
        Ldap.Entry e = server.objects.byGuid(l, guid, "objectClass", "ldapHostServer");
        if (e == null || e.attributes().getOrDefault("objectclass", List.of()).stream().noneMatch(o -> String.valueOf(o).equalsIgnoreCase("ldapServer"))) {
            throw new Http.Problem(404, "not-found", "no LDAP Server object has GUID " + guid);
        }
        Map<String, Object> host = ref(l, String.valueOf(e.first("ldapHostServer")));
        Server.On on = server.on(s, (String) host.get("guid"));
        Map<String, Object> detail = Map.of("ldapServer", e.dn(), "server", on.serverDn());
        String action = reload ? "edir.ldap-reload" : "edir.ldap-refresh";
        try {
            if (reload) {
                Partitions.reloadLdapModule(on.ldap(), on.serverDn());
            } else {
                Partitions.refreshLdapServer(on.ldap());
            }
        } catch (NamingException x) {
            audit(s, action, guid, detail, Ldap.Failure.of(x));
            throw x;
        }
        audit(s, action, guid, detail, null);
        Http.json(ex, 204, Map.of());
    }

    /**
     * {@code POST servers/{id}/indexes/{name}/copy}: {servers: [GUID]}. The same index definition goes on each
     * server's object (online), and limber builds it there. A server that already has an index of that name
     * is left alone and reported.
     */
    private void copyIndex(HttpExchange ex, Ldap l, Sessions.Session s, String guid, String name) throws IOException, NamingException {
        List<String> targets = new ArrayList<>();
        if (Http.body(ex).get("servers") instanceof List<?> list) {
            list.forEach(x -> targets.add(String.valueOf(x)));
        }
        if (targets.isEmpty() || targets.stream().anyMatch(t -> !Names.guid(t))) {
            throw new Http.Problem(400, "bad-field", "servers is a list of server GUIDs");
        }
        Ldap.Entry from = server.objects.byGuid(l, guid, "indexDefinition");
        if (from == null) {
            throw new Http.Problem(404, "not-found", "no server has GUID " + guid);
        }
        Map<String, Object> ix = null;
        for (Object v : from.attributes().getOrDefault("indexdefinition", List.of())) {
            Map<String, Object> m = index(String.valueOf(v));
            if (m != null && String.valueOf(m.get("name")).equalsIgnoreCase(name)) {
                ix = m;
            }
        }
        if (ix == null) {
            throw new Http.Problem(404, "not-found", "this server has no index named " + name);
        }
        if (!"user".equals(ix.get("type"))) {
            throw new Http.Problem(409, "not-copyable", "only user-defined indexes are copied; eDirectory makes the others itself");
        }
        String[] f = String.valueOf(ix.get("raw")).split("\\$", -1);
        f[2] = "0";
        String value = String.join("$", f);
        List<Map<String, Object>> results = new ArrayList<>();
        for (String t : targets) {
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("server", t);
            Ldap.Entry to = server.objects.byGuid(l, t, "cn", "objectClass", "indexDefinition");
            if (to == null || to.attributes().getOrDefault("objectclass", List.of()).stream().noneMatch(o -> String.valueOf(o).equalsIgnoreCase("ncpServer"))) {
                r.put("status", "not-a-server");
                results.add(r);
                continue;
            }
            r.put("name", String.valueOf(to.first("cn")));
            boolean has = to.attributes().getOrDefault("indexdefinition", List.of()).stream()
                .map(v -> index(String.valueOf(v))).anyMatch(m -> m != null && String.valueOf(m.get("name")).equalsIgnoreCase(name));
            if (has) {
                r.put("status", "already-there");
                results.add(r);
                continue;
            }
            Map<String, Object> detail = Map.of("server", to.dn(), "index", value, "from", from.dn());
            try {
                l.modify(to.dn(), List.of(new ModificationItem(DirContext.ADD_ATTRIBUTE, new BasicAttribute("indexDefinition", value))));
                Partitions.trigger(l, "limber", to.dn());
                audit(s, "index.copy", t, detail, null);
                r.put("status", "copied");
            } catch (NamingException x) {
                audit(s, "index.copy", t, detail, Ldap.Failure.of(x));
                r.put("status", "failed");
                r.put("detail", Ldap.Failure.of(x).getMessage());
            }
            results.add(r);
        }
        Http.json(ex, 200, Map.of("results", results));
    }

    private void addIndex(HttpExchange ex, Ldap l, Sessions.Session s, String guid) throws IOException, NamingException {
        Map<String, Object> b = Http.body(ex);
        String name = Http.string(b, "name", true).trim();
        if (name.isEmpty() || name.contains("$") || name.length() > 64) {
            throw new Http.Problem(400, "bad-field", "an index name is up to 64 characters without $");
        }
        int rule = RULES.indexOf(String.valueOf(b.getOrDefault("rule", "value")));
        if (rule < 0) {
            throw new Http.Problem(400, "bad-field", "rule is value, presence or substring");
        }
        List<String> attrs = new ArrayList<>();
        if (b.get("attributes") instanceof List<?> list) {
            list.forEach(a -> attrs.add(String.valueOf(a)));
        }
        if (attrs.isEmpty() || attrs.stream().anyMatch(a -> a.contains("$") || a.isBlank())) {
            throw new Http.Problem(400, "bad-field", "an index needs one or more attributes");
        }
        com.pointblue.console.server.ldap.Schema schema = com.pointblue.console.server.ldap.Schema.load(l);
        for (String a : attrs) {
            if (schema.attribute(a) == null) {
                throw new Http.Problem(400, "undefined-attribute", "the directory has no attribute " + a);
            }
        }
        Ldap.Entry e = server.objects.byGuid(l, guid, "indexDefinition");
        for (Object v : e.attributes().getOrDefault("indexdefinition", List.of())) {
            Map<String, Object> ix = index(String.valueOf(v));
            if (ix != null && String.valueOf(ix.get("name")).equalsIgnoreCase(name)) {
                throw new Http.Problem(409, "already-exists", "this server already has an index named " + name);
            }
        }
        String value = "0$" + name + "$0$" + rule + "$0$1$" + String.join("$", attrs);
        Map<String, Object> detail = Map.of("server", e.dn(), "index", value);
        try {
            l.modify(e.dn(), List.of(new ModificationItem(DirContext.ADD_ATTRIBUTE, new BasicAttribute("indexDefinition", value))));
        } catch (NamingException x) {
            audit(s, "index.add", guid, detail, Ldap.Failure.of(x));
            throw x;
        }
        audit(s, "index.add", guid, detail, null);
        Http.json(ex, 201, serverDetail(l, guid));
    }

    private void deleteIndex(HttpExchange ex, Ldap l, Sessions.Session s, String guid, String name) throws IOException, NamingException {
        Ldap.Entry e = server.objects.byGuid(l, guid, "indexDefinition");
        String value = null;
        for (Object v : e.attributes().getOrDefault("indexdefinition", List.of())) {
            Map<String, Object> ix = index(String.valueOf(v));
            if (ix != null && String.valueOf(ix.get("name")).equals(name)) {
                if (!Boolean.TRUE.equals(ix.get("removable"))) {
                    throw new Http.Problem(409, "system-index", name + " is a " + ix.get("type") + " index; only user-defined indexes can be removed");
                }
                value = String.valueOf(v);
            }
        }
        if (value == null) {
            throw new Http.Problem(404, "not-found", "no index " + name + " on " + e.dn());
        }
        Map<String, Object> detail = Map.of("server", e.dn(), "index", value);
        try {
            l.modify(e.dn(), List.of(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute("indexDefinition", value))));
        } catch (NamingException x) {
            audit(s, "index.remove", guid, detail, Ldap.Failure.of(x));
            throw x;
        }
        audit(s, "index.remove", guid, detail, null);
        Http.json(ex, 200, serverDetail(l, guid));
    }

    // ---- partitions ---------------------------------------------------------------------------------

    /** Every partition any server holds, its entry count, and each server's replica as that server reports it. */
    private List<Map<String, Object>> partitions(Ldap l) throws NamingException {
        List<Ldap.Entry> servers = l.search("", "(objectClass=ncpServer)", null, SearchControls.SUBTREE_SCOPE, new String[] {"GUID", "cn"}, 200);
        Map<String, Map<String, Object>> parts = new LinkedHashMap<>();
        for (Ldap.Entry srv : servers) {
            List<String> held;
            try {
                held = Partitions.list(l, srv.dn());
            } catch (NamingException e) {
                continue;
            }
            for (String part : held) {
                Map<String, Object> p = parts.get(part.toLowerCase(Locale.ROOT));
                if (p == null) {
                    p = new LinkedHashMap<>(part.isEmpty() ? Map.of("dn", "", "name", "[Root]", "id", "root") : partitionRef(l, part));
                    p.put("replicas", new ArrayList<Map<String, Object>>());
                    parts.put(part.toLowerCase(Locale.ROOT), p);
                }
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("server", Map.of("dn", srv.dn(), "name", srv.first("cn"), "guid", Names.guidHex(srv.attributes().get("guid").get(0))));
                try {
                    r.putAll(infoJson(Partitions.info(l, srv.dn(), part)));
                } catch (NamingException x) {
                    r.put("error", Ldap.Failure.of(x).getMessage());
                }
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> rs = (List<Map<String, Object>>) p.get("replicas");
                rs.add(r);
            }
        }
        for (Map<String, Object> p : parts.values()) {
            try {
                p.put("entries", Partitions.entryCount(l, String.valueOf(p.get("dn"))));
            } catch (NamingException e) {
                p.put("entries", null);
            }
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> rs = (List<Map<String, Object>>) p.get("replicas");
            p.put("busy", rs.stream().anyMatch(r -> Boolean.TRUE.equals(r.get("busy")) || r.get("transition") != null || !"on".equals(r.get("state"))));
        }
        return new ArrayList<>(parts.values());
    }

    private interface PartitionWrite {
        void run(String partitionDn) throws NamingException;
    }

    private void partitionOp(HttpExchange ex, Ldap l, Sessions.Session s, String id, String action, PartitionWrite op) throws IOException, NamingException {
        String dn = id.equals("root") ? "" : dnOf(l, id);
        Map<String, Object> detail = Map.of("partition", dn.isEmpty() ? "[Root]" : dn);
        try {
            op.run(dn);
        } catch (NamingException x) {
            audit(s, action, id, detail, Ldap.Failure.of(x));
            throw busy(x);
        }
        audit(s, action, id, detail, null);
        // eDirectory finishes these in the background: the caller polls GET partitions (busy) to follow
        Http.json(ex, 202, Map.of("accepted", true));
    }

    private void split(HttpExchange ex, Ldap l, Sessions.Session s) throws IOException, NamingException {
        String guid = Http.string(Http.body(ex), "container", true);
        Ldap.Entry e = server.objects.byGuid(l, guid, "objectClass");
        Map<String, Object> detail = Map.of("container", e.dn());
        try {
            Partitions.split(l, e.dn());
        } catch (NamingException x) {
            audit(s, "partition.split", guid, detail, Ldap.Failure.of(x));
            throw busy(x);
        }
        audit(s, "partition.split", guid, detail, null);
        Http.json(ex, 202, Map.of("accepted", true));
    }

    /** -654 and LDAP 51 mean another partition operation is still running: say so. */
    private static NamingException busy(NamingException x) {
        Ldap.Failure f = Ldap.Failure.of(x);
        if (f.code == 51 || Integer.valueOf(-654).equals(f.ndsError)) {
            throw new Http.Problem(409, "partition-busy", "another partition operation is still in progress; wait for it to finish and try again");
        }
        return x;
    }

    // ---- schema -------------------------------------------------------------------------------------

    private String schemaDn(Ldap l) throws NamingException {
        Ldap.Entry root = l.read("", "subschemaSubentry");
        return root.first("subschemaSubentry");
    }

    /** An OID under 2.25 (a random 63-bit integer: eDirectory refused a full 128-bit UUID with -649 on a lab tree). */
    static String newOid() {
        return "2.25." + (RANDOM.nextLong() >>> 1);
    }

    private static String oid(Map<String, Object> b) {
        String o = Http.string(b, "oid", false);
        if (o == null || o.isBlank()) {
            return newOid();
        }
        if (!OID.matcher(o.trim()).matches()) {
            throw new Http.Problem(400, "bad-field", "oid is a dotted number such as 1.3.6.1.4.1.99999.1.1");
        }
        return o.trim();
    }

    private static String name(Map<String, Object> b, String field) {
        String n = Http.string(b, field, true).trim();
        if (!NAME.matcher(n).matches()) {
            throw new Http.Problem(400, "bad-field", field + " is a letter followed by letters, digits or hyphens");
        }
        return n;
    }

    private static List<String> names(Object o) {
        List<String> out = new ArrayList<>();
        if (o instanceof List<?> l) {
            for (Object x : l) {
                String n = String.valueOf(x).trim();
                if (!NAME.matcher(n).matches()) {
                    throw new Http.Problem(400, "bad-field", n + " is not a schema name");
                }
                out.add(n);
            }
        }
        return out;
    }

    private static String list(List<String> v) {
        return v.size() == 1 ? v.get(0) : "( " + String.join(" $ ", v) + " )";
    }

    private static String quoted(List<String> v) {
        return v.size() == 1 ? "'" + v.get(0) + "'" : "( " + String.join(" ", v.stream().map(x -> "'" + x + "'").toList()) + " )";
    }

    private void addAttribute(HttpExchange ex, Ldap l, Sessions.Session s) throws IOException, NamingException {
        Map<String, Object> b = Http.body(ex);
        String name = name(b, "name");
        String syntax = Http.string(b, "syntax", true).trim();
        if (!OID.matcher(syntax).matches()) {
            throw new Http.Problem(400, "bad-field", "syntax is a syntax OID, such as 1.3.6.1.4.1.1466.115.121.1.15 (directory string)");
        }
        Object bound = b.get("upperBound");
        StringBuilder def = new StringBuilder("( ").append(oid(b)).append(" NAME '").append(name).append("'");
        String desc = Http.string(b, "description", false);
        if (desc != null && !desc.isBlank()) {
            def.append(" DESC '").append(desc.replace("'", "").replace("\\", "")).append("'");
        }
        def.append(" SYNTAX ").append(syntax);
        if (bound instanceof Number n && n.intValue() > 0) {
            def.append("{").append(n.intValue()).append("}");
        }
        if (Boolean.TRUE.equals(b.get("singleValue"))) {
            def.append(" SINGLE-VALUE");
        }
        for (String flag : names(b.get("flags"))) {
            String x = ATTRIBUTE_FLAGS.get(flag);
            if (x == null) {
                throw new Http.Problem(400, "bad-field", "flags are " + String.join(", ", ATTRIBUTE_FLAGS.keySet()));
            }
            def.append(" ").append(x).append(" '1'");
        }
        def.append(" )");
        schemaWrite(ex, l, s, "schema.attribute.add", name, List.of(new ModificationItem(DirContext.ADD_ATTRIBUTE, new BasicAttribute("attributeTypes", def.toString()))));
    }

    private void addClass(HttpExchange ex, Ldap l, Sessions.Session s) throws IOException, NamingException {
        Map<String, Object> b = Http.body(ex);
        String name = name(b, "name");
        String kind = String.valueOf(b.getOrDefault("kind", "auxiliary"));
        if (!List.of("auxiliary", "structural", "abstract").contains(kind)) {
            throw new Http.Problem(400, "bad-field", "kind is auxiliary, structural or abstract");
        }
        List<String> sup = names(b.getOrDefault("superior", List.of("top")));
        List<String> must = names(b.get("must"));
        List<String> may = names(b.get("may"));
        List<String> naming = names(b.get("naming"));
        List<String> containment = names(b.get("containment"));
        StringBuilder def = new StringBuilder("( ").append(oid(b)).append(" NAME '").append(name).append("'");
        if (!sup.isEmpty()) {
            def.append(" SUP ").append(list(sup));
        }
        def.append(" ").append(kind.toUpperCase(Locale.ROOT));
        if (!must.isEmpty()) {
            def.append(" MUST ").append(list(must));
        }
        if (!may.isEmpty()) {
            def.append(" MAY ").append(list(may));
        }
        if (!kind.equals("auxiliary")) {
            if (!naming.isEmpty()) {
                def.append(" X-NDS_NAMING ").append(quoted(naming));
            }
            if (!containment.isEmpty()) {
                def.append(" X-NDS_CONTAINMENT ").append(quoted(containment));
            }
            if (!Boolean.TRUE.equals(b.get("container"))) {
                def.append(" X-NDS_NOT_CONTAINER '1'");
            }
        }
        def.append(" )");
        schemaWrite(ex, l, s, "schema.class.add", name, List.of(new ModificationItem(DirContext.ADD_ATTRIBUTE, new BasicAttribute("objectClasses", def.toString()))));
    }

    private static final Pattern MAY = Pattern.compile("\\sMAY\\s+(\\(\\s*([^)]*)\\)|(\\S+))");

    /** Add optional attributes to a class: the definition's old value removed and the extended one added, in one modify (lab). */
    private void addMay(HttpExchange ex, Ldap l, Sessions.Session s, String cls) throws IOException, NamingException {
        List<String> add = names(Http.body(ex).get("attributes"));
        if (add.isEmpty()) {
            throw new Http.Problem(400, "bad-field", "attributes lists the optional attributes to add");
        }
        String dn = schemaDn(l);
        String old = definition(l, dn, "objectClasses", cls);
        Set<String> may = new LinkedHashSet<>();
        Matcher m = MAY.matcher(old);
        String next;
        if (m.find()) {
            String current = m.group(2) != null ? m.group(2) : m.group(3);
            for (String a : current.split("\\$")) {
                if (!a.isBlank()) {
                    may.add(a.trim());
                }
            }
            may.addAll(add);
            next = old.substring(0, m.start()) + " MAY ( " + String.join(" $ ", may) + " )" + old.substring(m.end());
        } else {
            may.addAll(add);
            int at = old.indexOf(" X-NDS_");
            int cut = at > 0 ? at : old.lastIndexOf(')');
            next = old.substring(0, cut).replaceAll("\\s+$", "") + " MAY ( " + String.join(" $ ", may) + " )" + old.substring(cut);
        }
        schemaWrite(ex, l, s, "schema.class.may", cls, List.of(
            new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute("objectClasses", old)),
            new ModificationItem(DirContext.ADD_ATTRIBUTE, new BasicAttribute("objectClasses", next))));
    }

    private void deleteSchema(HttpExchange ex, Ldap l, Sessions.Session s, String kind, String name) throws IOException, NamingException {
        String old = definition(l, schemaDn(l), kind, name);
        schemaWrite(ex, l, s, kind.equals("objectClasses") ? "schema.class.remove" : "schema.attribute.remove", name,
            List.of(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute(kind, old))));
    }

    /** The subschema value that defines {@code name} (exactly as stored: a removal must match it). */
    private String definition(Ldap l, String schemaDn, String kind, String name) throws NamingException {
        Ldap.Entry e = l.read(schemaDn, kind);
        Pattern p = Pattern.compile("NAME\\s+(\\(\\s*)?'" + Pattern.quote(name) + "'", Pattern.CASE_INSENSITIVE);
        for (Object v : e.attributes().getOrDefault(kind.toLowerCase(Locale.ROOT), List.of())) {
            if (p.matcher(String.valueOf(v)).find()) {
                return String.valueOf(v);
            }
        }
        throw new Http.Problem(404, "not-found", "no " + (kind.equals("objectClasses") ? "class " : "attribute ") + name);
    }

    private void schemaWrite(HttpExchange ex, Ldap l, Sessions.Session s, String action, String name, List<ModificationItem> mods) throws IOException, NamingException {
        String dn = schemaDn(l);
        Map<String, Object> detail = Map.of("name", name);
        try {
            l.modify(dn, mods);
        } catch (NamingException x) {
            audit(s, action, null, detail, Ldap.Failure.of(x));
            throw x;
        }
        audit(s, action, null, detail, null);
        server.objects.forgetSchema(s.principal.directoryId());
        Http.json(ex, action.endsWith(".remove") ? 200 : 201, Map.of("name", name));
    }
}
