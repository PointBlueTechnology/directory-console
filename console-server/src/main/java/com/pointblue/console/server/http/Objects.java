package com.pointblue.console.server.http;

import com.pointblue.console.server.audit.AuditLog;
import com.pointblue.console.server.auth.Role;
import com.pointblue.console.server.auth.Sessions;
import com.pointblue.console.server.ldap.Filters;
import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.console.server.ldap.Names;
import com.pointblue.console.server.ldap.Schema;
import com.pointblue.console.server.ldap.Values;
import com.pointblue.dirxml.dev.json.Json;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;
import javax.naming.NamingException;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.Rdn;

/**
 * The directory object API (DESIGN-directory-console.md section 8; Design Proposal for Safe Object
 * Identity, section 5). Objects are addressed by GUID; DNs appear only in JSON. Every operation runs on
 * the signed-in person's own directory connection, so eDirectory applies their rights; the console's
 * roles gate what is offered (any role reads, {@code editor} writes).
 *
 * <pre>
 * GET    /api/v2/trees/{tree}/roots                         the top of the tree
 * GET    /api/v2/trees/{tree}/objects?dn=…                  resolve a DN
 * GET    /api/v2/trees/{tree}/objects/{guid}                read (ETag)
 * GET    /api/v2/trees/{tree}/objects/{guid}/children       ?offset=&count=&startAt=&kind=containers|leaves|all
 * GET    /api/v2/trees/{tree}/objects/{guid}/rights         the signed-in person's effective rights
 * POST   /api/v2/trees/{tree}/search                        structured search
 * PATCH  /api/v2/trees/{tree}/objects/{guid}                {"changes": [{"op", "attribute", "values"}]}, If-Match
 * POST   /api/v2/trees/{tree}/objects/{guid}/children       create
 * POST   /api/v2/trees/{tree}/objects/{guid}/rename         {"name"}, If-Match
 * POST   /api/v2/trees/{tree}/objects/{guid}/move           {"newParent": guid}, If-Match
 * DELETE /api/v2/trees/{tree}/objects/{guid}                If-Match
 * GET    /api/v2/trees/{tree}/schema/classes[/{name}]
 * GET    /api/v2/trees/{tree}/schema/attributes[/{name}]
 * </pre>
 */
final class Objects {

    static final int MAX_WINDOW = 500;
    static final int DEFAULT_WINDOW = 100;
    private static final Duration SCHEMA_TTL = Duration.ofHours(1);
    /** Operational attributes shown with every object. */
    private static final String[] OPERATIONAL = {"ACL", "GUID", "revision", "modifyTimestamp", "createTimestamp", "creatorsName", "modifiersName", "subordinateCount"};
    /** What a list row needs: the identity, the class, and the hints for whether it has children. */
    private static final String[] ROW = {"objectClass", "GUID", "subordinateCount"};
    /** Sort keys for a container's children: containers' naming attributes first, then cn. */
    private static final String SORT_DEFAULT = "cn";
    /** Sort segments for a container's children (eDirectory's sort leaves out entries without the sort attribute). */
    private static final List<String> NAMING = List.of("cn", "ou", "o", "l", "c", "dc", "uid");
    private static final List<String> CONTAINER_NAMING = List.of("ou", "o", "cn", "l", "c", "dc");

    private record CachedSchema(Schema schema, Instant loaded) {
    }

    private final Server server;
    private final Map<String, CachedSchema> schemas = new ConcurrentHashMap<>();
    private final Tasks tasks = new Tasks(this);
    private final Set<Ldap> prepared = Collections.synchronizedSet(Collections.newSetFromMap(new WeakHashMap<>()));

    Objects(Server server) {
        this.server = server;
    }

    void handle(HttpExchange ex, String path, String method) throws IOException {
        String[] p = path.substring("/api/v2/trees/".length()).split("/", -1);
        boolean write = !method.equals("GET");
        Sessions.Session s = server.session(ex, write ? Role.EDITOR : null);
        if (s.principal.roles().isEmpty()) {
            throw new Http.Problem(403, "forbidden", "you have no Directory Console role");
        }
        if (!p[0].equals(s.principal.directoryId())) {
            throw new Http.Problem(404, "unknown-tree", "you are signed in to " + s.principal.directoryId() + ", not " + p[0]);
        }
        Ldap l = s.ldap();
        if (l == null) {
            throw new Http.Problem(501, "not-available", "directory objects need a direct sign-in in this version");
        }
        try {
            Schema schema = schema(s.principal.directoryId(), l);
            String route = method + " " + String.join("/", java.util.Arrays.copyOfRange(p, 1, p.length)).replaceAll("^objects/[0-9a-f]{32}", "objects/{guid}")
                .replaceAll("^schema/(classes|attributes)/.+", "schema/$1/{name}");
            String guid = p.length > 2 && p[1].equals("objects") ? p[2] : null;
            switch (route) {
                case "GET roots" -> roots(ex, l, schema);
                case "GET objects" -> resolve(ex, l, schema);
                case "GET objects/{guid}" -> read(ex, l, schema, guid);
                case "GET objects/{guid}/children" -> children(ex, l, schema, guid);
                case "GET objects/{guid}/rights" -> rights(ex, l, s, guid);
                case "POST objects/{guid}/password" -> tasks.password(ex, l, s, guid);
                case "GET objects/{guid}/account" -> tasks.account(ex, l, guid);
                case "PATCH objects/{guid}/account" -> tasks.updateAccount(ex, l, s, guid);
                case "POST objects/{guid}/unlock" -> tasks.unlock(ex, l, s, guid);
                case "GET objects/{guid}/memberships" -> tasks.memberships(ex, l, guid);
                case "POST objects/{guid}/memberships" -> tasks.changeMemberships(ex, l, s, guid);
                case "GET objects/{guid}/members" -> tasks.members(ex, l, guid);
                case "POST objects/{guid}/members" -> tasks.changeMembers(ex, l, s, guid);
                case "GET objects/{guid}/subtree" -> tasks.subtree(ex, l, guid);
                case "POST search" -> search(ex, l, schema);
                case "PATCH objects/{guid}" -> modify(ex, l, schema, s, guid);
                case "POST objects/{guid}/children" -> create(ex, l, schema, s, guid);
                case "POST objects/{guid}/rename" -> rename(ex, l, schema, s, guid, false);
                case "POST objects/{guid}/move" -> rename(ex, l, schema, s, guid, true);
                case "DELETE objects/{guid}" -> delete(ex, l, schema, s, guid);
                case "GET schema/classes" -> Http.json(ex, 200, schema.objectClasses().stream().map(c -> classJson(c, schema)).toList());
                case "GET schema/attributes" -> Http.json(ex, 200, schema.attributeTypes().stream().map(Objects::attributeJson).toList());
                case "GET schema/classes/{name}" -> schemaClass(ex, schema, p[3]);
                case "GET schema/attributes/{name}" -> {
                    Schema.AttributeType a = schema.attribute(decode(p[3]));
                    if (a == null) {
                        throw new Http.Problem(404, "not-found", "no attribute type " + decode(p[3]));
                    }
                    Http.json(ex, 200, attributeJson(a));
                }
                default -> throw new Http.Problem(404, "not-found", method + " " + path);
            }
        } catch (NamingException e) {
            throw problem(s, Ldap.Failure.of(e));
        } catch (IllegalArgumentException e) {
            throw new Http.Problem(400, "bad-request", e.getMessage());
        }
    }

    private static String decode(String segment) {
        return java.net.URLDecoder.decode(segment, StandardCharsets.UTF_8);
    }

    /** A directory refusal as a problem document, with the LDAP result code and eDirectory error number. */
    private Http.Problem problem(Sessions.Session s, Ldap.Failure f) {
        Map<String, Object> extra = new LinkedHashMap<>();
        extra.put("ldapResultCode", f.code);
        if (f.ndsError != null) {
            extra.put("ndsError", f.ndsError);
        }
        if (f.getCause() instanceof javax.naming.CommunicationException || f.code == 52 || f.code == 81) {
            server.sessions.remove(s.id);
            return new Http.Problem(401, "directory-connection-lost", "the connection to the directory was lost; sign in again", extra);
        }
        int status;
        String type;
        switch (f.code) {
            case 32 -> { status = 404; type = "no-such-object"; }
            case 50 -> { status = 403; type = "insufficient-rights"; }
            case 16 -> { status = 409; type = "no-such-attribute"; }
            case 17 -> { status = 400; type = "undefined-attribute"; }
            case 19 -> { status = 409; type = "constraint-violation"; }
            case 20 -> { status = 409; type = "value-exists"; }
            case 21 -> { status = 400; type = "invalid-syntax"; }
            case 53 -> { status = 403; type = "unwilling-to-perform"; }
            case 64 -> { status = 400; type = "naming-violation"; }
            case 65 -> { status = 400; type = "object-class-violation"; }
            case 66 -> { status = 409; type = "not-a-leaf"; }
            case 67 -> { status = 400; type = "not-allowed-on-rdn"; }
            case 68 -> { status = 409; type = "already-exists"; }
            case 3, 4, 11 -> { status = 503; type = "limit-exceeded"; }
            case 51 -> { status = 503; type = "directory-busy"; }
            default -> { status = 502; type = "directory-error"; }
        }
        return new Http.Problem(status, type, f.getMessage(), extra);
    }

    // ---- schema ---------------------------------------------------------------------------------

    private Schema schema(String directoryId, Ldap l) throws NamingException {
        CachedSchema c = schemas.get(directoryId);
        if (c == null || c.loaded.plus(SCHEMA_TTL).isBefore(Instant.now())) {
            c = new CachedSchema(Schema.load(l), Instant.now());
            schemas.put(directoryId, c);
        }
        if (prepared.add(l)) {
            l.binaryAttributes(c.schema.binaryAttributes());
        }
        return c.schema;
    }

    /** A class; {@code naming} and {@code containment} are inherited from superiors when the class does not set them. */
    private static Map<String, Object> classJson(Schema.ObjectClass c, Schema schema) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", c.name());
        m.put("names", c.names());
        m.put("oid", c.oid());
        m.put("kind", c.kind());
        m.put("superiors", c.superiors());
        m.put("container", c.container());
        m.put("containment", schema.containment(c.name()));
        m.put("naming", schema.naming(c.name()));
        m.put("must", c.must());
        m.put("may", c.may());
        return m;
    }

    private static void schemaClass(HttpExchange ex, Schema schema, String segment) throws IOException {
        Schema.ObjectClass c = schema.objectClass(decode(segment));
        if (c == null) {
            throw new Http.Problem(404, "not-found", "no object class " + decode(segment));
        }
        Map<String, Object> m = classJson(c, schema);
        m.put("allMust", List.copyOf(schema.must(c.name())));
        m.put("allMay", List.copyOf(schema.may(c.name())));
        Http.json(ex, 200, m);
    }

    private static Map<String, Object> attributeJson(Schema.AttributeType a) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", a.name());
        m.put("names", a.names());
        m.put("oid", a.oid());
        m.put("syntax", a.syntax());
        m.put("singleValue", a.singleValue());
        m.put("readOnly", a.readOnly());
        m.put("operational", a.operational());
        m.put("binary", a.binary());
        if (a.ndsName() != null) {
            m.put("ndsName", a.ndsName());
        }
        return m;
    }

    // ---- reads ----------------------------------------------------------------------------------

    /** The entry with this GUID, with {@code attrs}; 404 when there is none (or the person cannot see it). */
    Ldap.Entry byGuid(Ldap l, String guid, String... attrs) throws NamingException {
        List<Ldap.Entry> r = l.search("", "(GUID={0})", new Object[] {Names.guidBytes(guid)}, SearchControls.SUBTREE_SCOPE, attrs, 2);
        if (r.isEmpty()) {
            throw new Http.Problem(404, "no-such-object", "no object with GUID " + guid);
        }
        return r.get(0);
    }

    String dnOf(Ldap l, String guid) throws NamingException {
        return byGuid(l, guid, "1.1").dn();
    }

    private static String[] fullRead() {
        String[] a = new String[OPERATIONAL.length + 1];
        a[0] = "*";
        System.arraycopy(OPERATIONAL, 0, a, 1, OPERATIONAL.length);
        return a;
    }

    /** {@code dn}, {@code revision} and {@code modifyTimestamp}: revision restarts at 1 on a move, so the DN is part of it. */
    static String etag(Ldap.Entry e) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            String basis = Names.canonical(e.dn()) + "|" + e.first("revision") + "|" + e.first("modifyTimestamp");
            return "\"" + HexFormat.of().formatHex(md.digest(basis.getBytes(StandardCharsets.UTF_8)), 0, 12) + "\"";
        } catch (NoSuchAlgorithmException x) {
            throw new IllegalStateException(x);
        }
    }

    private Map<String, Object> objectJson(Ldap.Entry e, Schema schema) {
        Map<String, Object> m = row(e, schema);
        Map<String, Object> attrs = new java.util.TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        Map<String, Object> operational = new LinkedHashMap<>();
        Set<String> op = Set.of("guid", "revision", "modifytimestamp", "createtimestamp", "creatorsname", "modifiersname", "subordinatecount");
        e.attributes().forEach((k, vs) -> {
            Schema.AttributeType t = schema.attribute(k);
            String name = t == null ? e.name(k) : t.name();
            if (k.equals("guid")) {
                return;
            }
            List<Object> json = Values.toJson(t, vs);
            if (op.contains(k)) {
                operational.put(name, t != null && t.singleValue() && json.size() == 1 ? json.get(0) : json);
            } else {
                attrs.put(name, json);
            }
        });
        m.put("attributes", attrs);
        m.put("operational", operational);
        return m;
    }

    /** The identity block plus the class and the children hint. */
    private Map<String, Object> row(Ldap.Entry e, Schema schema) {
        Map<String, Object> m = new LinkedHashMap<>();
        List<Object> guid = e.attributes().get("guid");
        m.put("guid", guid == null || guid.isEmpty() ? null : Names.guidHex(guid.get(0)));
        m.putAll(Names.identity(e.dn()));
        List<Object> classes = e.attributes().getOrDefault("objectclass", List.of());
        m.put("objectClass", schema.structural(classes));
        m.put("objectClasses", classes.stream().map(String::valueOf).toList());
        boolean container = schema.container(classes);
        int count = -1;
        try {
            count = e.first("subordinateCount") == null ? -1 : Integer.parseInt(e.first("subordinateCount").trim());
        } catch (NumberFormatException ignored) {
            // unknown
        }
        m.put("container", container || count > 0);
        // eDirectory's subordinateCount is believed only when positive: a partition root seen from its
        // parent partition reports 0 however many children it has (ArborJ's DirectoryTopology)
        m.put("children", count > 0 ? "yes" : container ? "maybe" : "no");
        if (count > 0) {
            m.put("childCount", count);
        }
        return m;
    }

    void read(HttpExchange ex, Ldap l, Schema schema, String guid) throws IOException, NamingException {
        Ldap.Entry e = byGuid(l, guid, fullRead());
        ex.getResponseHeaders().set("ETag", etag(e));
        Http.json(ex, 200, objectJson(e, schema));
    }

    private void resolve(HttpExchange ex, Ldap l, Schema schema) throws IOException, NamingException {
        Map<String, String> q = Http.query(ex);
        String dn = q.get("dn");
        if (dn == null || dn.isBlank()) {
            throw new Http.Problem(400, "missing-field", "?dn= is required");
        }
        Ldap.Entry e = l.read(Names.parse(dn).toString(), fullRead());
        if (e == null) {
            throw new Http.Problem(404, "no-such-object", "no object " + dn);
        }
        ex.getResponseHeaders().set("ETag", etag(e));
        Http.json(ex, 200, objectJson(e, schema));
    }

    private void roots(HttpExchange ex, Ldap l, Schema schema) throws IOException, NamingException {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Ldap.Entry e : l.search("", "(objectClass=*)", null, SearchControls.ONELEVEL_SCOPE, ROW, 1000)) {
            Map<String, Object> r = row(e, schema);
            if ("no".equals(r.get("children"))) {
                r.put("children", "maybe");   // the top of a tree opens; the listing settles it
            }
            out.add(r);
        }
        out.sort((a, b) -> String.valueOf(a.get("name")).compareToIgnoreCase(String.valueOf(b.get("name"))));
        Http.json(ex, 200, Map.of("items", out));
    }

    private void children(HttpExchange ex, Ldap l, Schema schema, String guid) throws IOException, NamingException {
        Map<String, String> q = Http.query(ex);
        String parent = dnOf(l, guid);
        String kind = q.getOrDefault("kind", "all");
        String filter = switch (kind) {
            case "all" -> "(objectClass=*)";
            case "containers", "leaves" -> {
                StringBuilder f = new StringBuilder("(|");
                for (String c : schema.containerClasses()) {
                    f.append("(objectClass=").append(c).append(')');
                }
                f.append(')');
                yield kind.equals("containers") ? f.toString() : "(!" + f + ")";
            }
            default -> throw new Http.Problem(400, "bad-field", "kind is containers, leaves or all");
        };
        List<String> sort = q.get("sort") != null ? List.of(q.get("sort")) : kind.equals("containers") ? CONTAINER_NAMING : NAMING;
        window(ex, l, schema, parent, filter, null, SearchControls.ONELEVEL_SCOPE, ROW, sort, q, Map.of("parent", Map.of("guid", guid, "dn", parent)));
    }

    private void window(HttpExchange ex, Ldap l, Schema schema, String base, String filter, Object[] args, int scope, String[] attrs,
                        List<String> sort, Map<String, String> page, Map<String, Object> extra) throws IOException, NamingException {
        for (String a : sort) {
            if (!Names.attributeName(a)) {
                throw new Http.Problem(400, "bad-field", "sort is an attribute name");
            }
        }
        int offset = parseInt(page.get("offset"), 1);
        int count = Math.min(MAX_WINDOW, Math.max(1, parseInt(page.get("count"), DEFAULT_WINDOW)));
        boolean descending = "desc".equalsIgnoreCase(page.get("order"));
        Ldap.Window w = l.sorted(base, filter, args, scope, attrs, sort, descending, offset, count, page.get("startAt"));
        List<Map<String, Object>> items = new ArrayList<>();
        boolean full = attrs != ROW;
        for (Ldap.Entry e : w.entries()) {
            items.add(full ? objectJson(e, schema) : row(e, schema));
        }
        Map<String, Object> out = new LinkedHashMap<>(extra);
        out.put("offset", w.offset());
        out.put("count", items.size());
        out.put("total", w.total());
        // false when the total may count an entry more than once (VLV over a multi-valued sort attribute) or is capped
        out.put("exact", w.exact());
        out.put("sort", Map.of("attributes", sort, "order", descending ? "desc" : "asc"));
        out.put("items", items);
        Http.json(ex, 200, out);
    }

    private static int parseInt(String s, int dflt) {
        try {
            return s == null || s.isBlank() ? dflt : Integer.parseInt(s.trim());
        } catch (NumberFormatException e) {
            throw new Http.Problem(400, "bad-field", "not a number: " + s);
        }
    }

    /**
     * Effective rights on the object: of the signed-in person, or of {@code ?trustee=} (a GUID or a DN);
     * {@code ?attribute=} adds the rights to that one attribute.
     */
    private void rights(HttpExchange ex, Ldap l, Sessions.Session s, String guid) throws IOException, NamingException {
        String dn = dnOf(l, guid);
        Map<String, String> q = Http.query(ex);
        String trustee = s.principal.dn();
        String t = q.get("trustee");
        if (t != null && !t.isBlank()) {
            trustee = Names.guid(t) ? dnOf(l, t) : Names.parse(t).toString();
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("trustee", Map.of("dn", trustee, "name", Names.identity(trustee).get("name")));
        out.put("entry", rightsJson(l.effectivePrivileges(dn, trustee, "[Entry Rights]"), true));
        out.put("allAttributes", rightsJson(l.effectivePrivileges(dn, trustee, "[All Attributes Rights]"), false));
        String attr = q.get("attribute");
        if (attr != null && !attr.isBlank()) {
            if (!Names.attributeName(attr)) {
                throw new Http.Problem(400, "bad-field", "not an attribute name: " + attr);
            }
            out.put("attribute", Map.of("name", attr, "rights", rightsJson(l.effectivePrivileges(dn, trustee, attr), false)));
        }
        Http.json(ex, 200, out);
    }

    private static List<String> rightsJson(int bits, boolean entry) {
        @SuppressWarnings("unchecked")
        List<String> p = (List<String>) Values.acl(bits + "#entry#[Self]#" + (entry ? "[Entry Rights]" : "[All Attributes Rights]")).get("privileges");
        return p;
    }

    private void search(HttpExchange ex, Ldap l, Schema schema) throws IOException, NamingException {
        Map<String, Object> b = Http.body(ex);
        String base = "";
        if (b.get("base") instanceof Map<?, ?> m) {
            if (m.get("guid") != null) {
                base = dnOf(l, String.valueOf(m.get("guid")));
            } else if (m.get("dn") != null) {
                base = Names.parse(String.valueOf(m.get("dn"))).toString();
            }
        }
        int scope = switch (String.valueOf(b.getOrDefault("scope", "subtree"))) {
            case "base" -> SearchControls.OBJECT_SCOPE;
            case "one" -> SearchControls.ONELEVEL_SCOPE;
            case "subtree" -> SearchControls.SUBTREE_SCOPE;
            default -> throw new Http.Problem(400, "bad-field", "scope is base, one or subtree");
        };
        String filter;
        Object[] args;
        if (b.get("ldapFilter") != null) {
            // advanced mode: sent as typed, parsed by the LDAP client (a bad filter is refused there), never combined
            filter = Http.string(b, "ldapFilter", true);
            if (!Filters.single(filter)) {
                throw new Http.Problem(400, "bad-filter", "ldapFilter must be one parenthesized LDAP filter, such as (&(objectClass=user)(cn=a*))");
            }
            args = null;
        } else if (b.get("filter") != null) {
            Filters.Built f = Filters.build(b.get("filter"));
            filter = f.filter();
            args = f.args();
        } else {
            filter = "(objectClass=*)";
            args = null;
        }
        String[] attrs = ROW;
        if (b.get("attributes") instanceof List<?> al && !al.isEmpty()) {
            List<String> a = new ArrayList<>(List.of(ROW));
            for (Object o : al) {
                if (!Names.attributeName(String.valueOf(o)) && !"*".equals(o)) {
                    throw new Http.Problem(400, "bad-field", "not an attribute name: " + o);
                }
                a.add(String.valueOf(o));
            }
            attrs = a.toArray(new String[0]);
        }
        Map<String, String> page = new LinkedHashMap<>();
        if (b.get("page") instanceof Map<?, ?> pm) {
            pm.forEach((k, v) -> page.put(String.valueOf(k), v == null ? null : String.valueOf(v instanceof Number n ? n.intValue() : v)));
        }
        String sort = SORT_DEFAULT;
        if (b.get("sort") instanceof Map<?, ?> sm) {
            sort = String.valueOf(sm.get("attribute") == null ? SORT_DEFAULT : sm.get("attribute"));
            if (sm.get("order") != null) {
                page.put("order", String.valueOf(sm.get("order")));
            }
        }
        window(ex, l, schema, base, filter, args, scope, attrs, List.of(sort), page, Map.of());
    }

    // ---- writes ---------------------------------------------------------------------------------

    /** The entry, after checking the request's If-Match against its current ETag. */
    Ldap.Entry current(HttpExchange ex, Ldap l, String guid) throws NamingException {
        String ifMatch = ex.getRequestHeaders().getFirst("If-Match");
        if (ifMatch == null || ifMatch.isBlank()) {
            throw new Http.Problem(428, "precondition-required", "send If-Match with the ETag from your last read of this object");
        }
        Ldap.Entry e = byGuid(l, guid, "revision", "modifyTimestamp", "objectClass", "GUID");
        String now = etag(e);
        if (!ifMatch.trim().equals("*") && !ifMatch.trim().replaceFirst("^W/", "").equals(now)) {
            throw new Http.Problem(412, "changed", "the object changed since you read it; read it again", Map.of("etag", now));
        }
        return e;
    }

    Values.GuidResolver guids(Ldap l) {
        return g -> {
            List<Ldap.Entry> r = l.search("", "(GUID={0})", new Object[] {Names.guidBytes(g)}, SearchControls.SUBTREE_SCOPE, new String[] {"1.1"}, 1);
            return r.isEmpty() ? null : r.get(0).dn();
        };
    }

    private void modify(HttpExchange ex, Ldap l, Schema schema, Sessions.Session s, String guid) throws IOException, NamingException {
        Map<String, Object> b = Http.body(ex);
        Ldap.Entry e = current(ex, l, guid);
        if (!(b.get("changes") instanceof List<?> changes) || changes.isEmpty()) {
            throw new Http.Problem(400, "missing-field", "changes is a non-empty list");
        }
        List<ModificationItem> mods = new ArrayList<>();
        List<String> summary = new ArrayList<>();
        for (Object o : changes) {
            Map<String, Object> c = Json.asMap(o);
            String op = String.valueOf(c.get("op"));
            String attr = String.valueOf(c.get("attribute"));
            if (!Names.attributeName(attr)) {
                throw new Http.Problem(400, "bad-field", "not an attribute name: " + attr);
            }
            Schema.AttributeType t = schema.attribute(attr);
            if (t != null && t.readOnly()) {
                throw new Http.Problem(400, "read-only-attribute", attr + " is maintained by the directory");
            }
            int code = switch (op) {
                case "add" -> DirContext.ADD_ATTRIBUTE;
                case "remove" -> DirContext.REMOVE_ATTRIBUTE;
                case "replace" -> DirContext.REPLACE_ATTRIBUTE;
                default -> throw new Http.Problem(400, "bad-field", "op is add, remove or replace");
            };
            BasicAttribute a = new BasicAttribute(t == null ? attr : t.name());
            if (c.get("values") instanceof List<?> vs) {
                for (Object v : vs) {
                    try {
                        a.add(Values.fromJson(t, v, guids(l)));
                    } catch (IllegalArgumentException | Http.Problem x) {
                        throw x;
                    } catch (Exception x) {
                        throw new Http.Problem(400, "bad-value", attr + ": " + x.getMessage());
                    }
                }
            } else if (!op.equals("remove")) {
                throw new Http.Problem(400, "missing-field", op + " needs values");
            }
            mods.add(new ModificationItem(code, a));
            summary.add(op + " " + a.getID());
        }
        tasks.guardInheritanceMask(l, e.dn(), mods);
        try {
            l.modify(e.dn(), mods);
        } catch (NamingException x) {
            audit(s, "object.modify", guid, Map.of("dn", e.dn(), "changes", summary), Ldap.Failure.of(x));
            throw x;
        }
        audit(s, "object.modify", guid, Map.of("dn", e.dn(), "changes", summary), null);
        read(ex, l, schema, guid);
    }

    private void create(HttpExchange ex, Ldap l, Schema schema, Sessions.Session s, String parentGuid) throws IOException, NamingException {
        Map<String, Object> b = Http.body(ex);
        String parent = dnOf(l, parentGuid);
        List<Object> classes = new ArrayList<>();
        Object oc = b.get("objectClass");
        if (oc instanceof String str) {
            classes.add(str);
        } else if (oc instanceof List<?> ol && !ol.isEmpty()) {
            classes.addAll(ol);
        } else {
            throw new Http.Problem(400, "missing-field", "objectClass is required");
        }
        for (Object c : classes) {
            if (schema.objectClass(String.valueOf(c)) == null) {
                throw new Http.Problem(400, "unknown-class", "no object class " + c);
            }
        }
        if (!(b.get("name") instanceof Map<?, ?> nm) || nm.get("type") == null || nm.get("value") == null) {
            throw new Http.Problem(400, "missing-field", "name is {\"type\": \"cn\", \"value\": \"…\"}");
        }
        String type = String.valueOf(nm.get("type"));
        String value = String.valueOf(nm.get("value"));
        String dn = Names.child(parent, type, value);
        Map<String, List<Object>> attrs = new LinkedHashMap<>();
        attrs.put("objectClass", classes);
        attrs.put(type, new ArrayList<>(List.of(value)));
        if (b.get("attributes") instanceof Map<?, ?> am) {
            for (Map.Entry<?, ?> a : am.entrySet()) {
                String name = String.valueOf(a.getKey());
                if (!Names.attributeName(name)) {
                    throw new Http.Problem(400, "bad-field", "not an attribute name: " + name);
                }
                Schema.AttributeType t = schema.attribute(name);
                List<Object> vals = new ArrayList<>();
                for (Object v : a.getValue() instanceof List<?> vl ? vl : List.of(a.getValue())) {
                    try {
                        vals.add(Values.fromJson(t, v, guids(l)));
                    } catch (IllegalArgumentException | Http.Problem x) {
                        throw x;
                    } catch (Exception x) {
                        throw new Http.Problem(400, "bad-value", name + ": " + x.getMessage());
                    }
                }
                attrs.merge(t == null ? name : t.name(), vals, (x, y) -> {
                    x.addAll(y);
                    return x;
                });
            }
        }
        Map<String, Object> detail = Map.of("dn", dn, "objectClass", classes.stream().map(String::valueOf).toList(), "attributes", List.copyOf(attrs.keySet()));
        try {
            l.create(dn, attrs);
        } catch (NamingException x) {
            audit(s, "object.create", parentGuid, detail, Ldap.Failure.of(x));
            throw x;
        }
        Ldap.Entry e = l.read(dn, fullRead());
        String guid = e == null ? null : Names.guidHex(e.attributes().getOrDefault("guid", List.of()).stream().findFirst().orElse(null));
        audit(s, "object.create", guid, detail, null);
        if (e == null) {
            Http.json(ex, 201, Map.of("dn", dn));
            return;
        }
        ex.getResponseHeaders().set("ETag", etag(e));
        ex.getResponseHeaders().set("Location", "/api/v2/trees/" + s.principal.directoryId() + "/objects/" + guid);
        Http.json(ex, 201, objectJson(e, schema));
    }

    private void rename(HttpExchange ex, Ldap l, Schema schema, Sessions.Session s, String guid, boolean move) throws IOException, NamingException {
        Map<String, Object> b = Http.body(ex);
        Ldap.Entry e = current(ex, l, guid);
        Rdn leaf = Names.leaf(e.dn());
        if (leaf.size() != 1) {
            throw new Http.Problem(409, "multi-valued-name", "renaming an object with a multi-valued name is not supported yet");
        }
        String newDn;
        String action;
        if (move) {
            String target = Http.string(b, "newParent", true);
            String parent = dnOf(l, target);
            if (Names.within(parent, e.dn())) {
                throw new Http.Problem(409, "move-into-itself", "an object cannot move under itself");
            }
            newDn = Names.child(parent, leaf.getType(), String.valueOf(leaf.getValue()));
            action = "object.move";
        } else {
            newDn = Names.child(Names.parent(e.dn()), leaf.getType(), Http.string(b, "name", true));
            action = "object.rename";
        }
        Map<String, Object> detail = new LinkedHashMap<>(Map.of("from", e.dn(), "to", newDn));
        try {
            l.rename(e.dn(), newDn);
        } catch (NamingException x) {
            audit(s, action, guid, detail, Ldap.Failure.of(x));
            throw x;
        }
        if (Boolean.TRUE.equals(b.get("leaveAlias"))) {
            String alias = tasks.leaveAlias(l, e.dn(), newDn);
            detail.put("alias", alias);
            ex.getResponseHeaders().set("X-Alias", alias);
        }
        audit(s, action, guid, detail, null);
        read(ex, l, schema, guid);
    }

    private void delete(HttpExchange ex, Ldap l, Schema schema, Sessions.Session s, String guid) throws IOException, NamingException {
        Ldap.Entry e = current(ex, l, guid);
        if ("true".equals(Http.query(ex).get("subtree"))) {
            tasks.deleteSubtree(ex, l, s, guid, e);
            return;
        }
        try {
            l.delete(e.dn());
        } catch (NamingException x) {
            audit(s, "object.delete", guid, Map.of("dn", e.dn()), Ldap.Failure.of(x));
            throw x;
        }
        audit(s, "object.delete", guid, Map.of("dn", e.dn(), "objectClasses", e.attributes().getOrDefault("objectclass", List.of()).stream().map(String::valueOf).toList()), null);
        Http.json(ex, 204, Map.of());
    }

    /** Writes are audited with attribute names only: values (a password among them) never reach the log. */
    void audit(Sessions.Session s, String action, String target, Map<String, Object> detail, Ldap.Failure failed) throws IOException {
        Map<String, Object> d = new LinkedHashMap<>(detail);
        d.put("directory", s.principal.directoryId());
        if (failed != null) {
            d.put("ldapResultCode", failed.code);
            if (failed.ndsError != null) {
                d.put("ndsError", failed.ndsError);
            }
        }
        server.audit.log(new AuditLog.Actor(s.principal.subject(), s.principal.dn(), s.principal.via()), action, target, d, failed == null ? "ok" : "refused");
    }
}
