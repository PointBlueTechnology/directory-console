package com.pointblue.console.server.http;

import com.pointblue.console.server.auth.Role;
import com.pointblue.console.server.auth.Sessions;
import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.console.server.ldap.Names;
import com.sun.net.httpserver.HttpExchange;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import javax.naming.NamingException;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Identity Manager mapping tables, read and changed over LDAP with the person's own rights: a
 * {@code DirXML-Resource} whose {@code DirXML-ContentType} is a mapping table and whose
 * {@code DirXML-Data} is {@code <mapping-table>} with a {@code <col-def name type/>} per column (written
 * among the rows by Designer) and a {@code <row>} of {@code <col>} values each (ig4, 2026-10-14).
 *
 * <pre>
 * GET    /api/v2/trees/{tree}/idm/mapping-tables?under={guid}   the tables under a driver set, driver or library
 * GET    /api/v2/trees/{tree}/idm/mapping-tables/{guid}         columns, rows, version, package
 * PUT    same   {"version", "columns": [{"name", "type"}], "rows": [[…]]}
 * POST   /api/v2/trees/{tree}/idm/mapping-tables                {"parent": guid, "name", "columns", "rows"}
 * DELETE /api/v2/trees/{tree}/idm/mapping-tables/{guid}         {"name"}: the table's name, typed
 * </pre>
 *
 * A save carries the version it was read at (a hash of {@code DirXML-Data}) and is refused (409) when the
 * table changed meanwhile. The table is written whole, in Designer's layout (column definitions first).
 */
final class MappingTables {

    static final String CONTENT_TYPE = "application/vnd.novell.dirxml.mapping-table+xml ;charset=UTF-8";
    /** Column types the engine compares by: case-sensitive and -insensitive text, numbers, and ranges. */
    static final Set<String> TYPES = Set.of("case", "nocase", "numeric", "interval-closed", "interval-open", "interval-rightopen", "interval-leftopen");
    private static final String[] ATTRS = {"objectClass", "cn", "DirXML-ContentType", "DirXML-Data", "DirXML-pkgGUID"};
    private static final List<String> PARENTS = List.of("DirXML-DriverSet", "DirXML-Driver", "DirXML-Library", "DirXML-Subscriber", "DirXML-Publisher");

    private final Server server;

    MappingTables(Server server) {
        this.server = server;
    }

    record Table(List<Map<String, String>> columns, List<List<String>> rows) {
    }

    void handle(HttpExchange ex, Sessions.Session s, String method, String guid) throws IOException {
        Ldap l = s.ldap();
        if (l == null) {
            throw new Http.Problem(503, "unavailable", "no directory connection");
        }
        try {
            if (guid == null) {
                switch (method) {
                    case "GET" -> list(ex, l);
                    case "POST" -> create(ex, l, s);
                    default -> throw new Http.Problem(405, "method-not-allowed", method);
                }
                return;
            }
            Ldap.Entry e = table(l, guid);
            if (!method.equals("GET") && !s.principal.may(Role.OPERATOR, e.dn())) {
                throw new Http.Problem(403, "out-of-scope", "changing a mapping table needs an operator role that reaches " + e.dn());
            }
            switch (method) {
                case "GET" -> Http.json(ex, 200, json(l, e));
                case "PUT" -> save(ex, l, s, guid, e);
                case "DELETE" -> delete(ex, l, s, guid, e);
                default -> throw new Http.Problem(405, "method-not-allowed", method);
            }
        } catch (NamingException x) {
            throw server.objects.problem(s, Ldap.Failure.of(x));
        } catch (IllegalArgumentException x) {
            throw new Http.Problem(400, "bad-request", x.getMessage());
        }
    }

    private Ldap.Entry table(Ldap l, String guid) throws NamingException {
        Ldap.Entry e = server.objects.byGuid(l, guid, ATTRS);
        String type = e == null ? null : e.first("DirXML-ContentType");
        if (type == null || !type.toLowerCase(Locale.ROOT).startsWith("application/vnd.novell.dirxml.mapping-table")) {
            throw new Http.Problem(404, "not-found", guid + " is not a mapping table");
        }
        return e;
    }

    private void list(HttpExchange ex, Ldap l) throws IOException, NamingException {
        String under = Http.query(ex).get("under");
        String base = under == null || under.isBlank() ? "" : server.objects.dnOf(l, under);
        List<Map<String, Object>> out = new ArrayList<>();
        for (Ldap.Entry e : l.search(base, "(DirXML-ContentType=application/vnd.novell.dirxml.mapping-table*)", null, SearchControls.SUBTREE_SCOPE,
                new String[] {"GUID", "cn", "DirXML-pkgGUID"}, 500)) {
            Map<String, Object> m = ref(e);
            m.put("owner", owner(l, e.dn()));
            m.put("package", packageName(e));
            out.add(m);
        }
        out.sort((a, b) -> String.valueOf(a.get("name")).compareToIgnoreCase(String.valueOf(b.get("name"))));
        Http.json(ex, 200, Map.of("items", out));
    }

    private static Map<String, Object> ref(Ldap.Entry e) {
        Map<String, Object> m = new LinkedHashMap<>(Names.identity(e.dn()));
        List<Object> g = e.attributes().get("guid");
        m.put("guid", g == null || g.isEmpty() ? null : Names.guidHex(g.get(0)));
        return m;
    }

    /** What the table belongs to: its parent, and the parent's kind. */
    private Map<String, Object> owner(Ldap l, String dn) throws NamingException {
        String parent = Names.parent(dn);
        Ldap.Entry p = l.read(parent, "objectClass");
        String kind = "container";
        if (p != null) {
            for (Object c : p.attributes().getOrDefault("objectclass", List.of())) {
                switch (String.valueOf(c).toLowerCase(Locale.ROOT)) {
                    case "dirxml-driverset" -> kind = "driver set";
                    case "dirxml-driver" -> kind = "driver";
                    case "dirxml-library" -> kind = "library";
                    case "dirxml-subscriber" -> kind = "subscriber";
                    case "dirxml-publisher" -> kind = "publisher";
                    default -> { }
                }
            }
        }
        return Map.of("dn", parent, "name", String.valueOf(Names.identity(parent).get("name")), "kind", kind);
    }

    /** The package a table came from ("…;package display name;PREFIX"), or null. */
    private static String packageName(Ldap.Entry e) {
        String g = e.first("DirXML-pkgGUID");
        if (g == null) {
            return null;
        }
        String[] parts = g.split(";");
        return parts.length >= 4 ? parts[3] : g;
    }

    private static byte[] data(Ldap.Entry e) {
        List<Object> v = e.attributes().get("dirxml-data");
        if (v == null || v.isEmpty()) {
            return null;
        }
        Object o = v.get(0);
        return o instanceof byte[] b ? b : String.valueOf(o).getBytes(StandardCharsets.UTF_8);
    }

    private Map<String, Object> json(Ldap l, Ldap.Entry e) throws NamingException {
        Map<String, Object> out = ref(e);
        out.put("owner", owner(l, e.dn()));
        out.put("package", packageName(e));
        byte[] data = data(e);
        out.put("version", Jobs.version(data));
        Table t = parse(data);
        out.put("columns", t.columns());
        out.put("rows", t.rows());
        return out;
    }

    /** {@code <mapping-table>} → columns (in document order) and rows; empty for no data. */
    static Table parse(byte[] xml) {
        List<Map<String, String>> columns = new ArrayList<>();
        List<List<String>> rows = new ArrayList<>();
        if (xml == null || xml.length == 0) {
            return new Table(columns, rows);
        }
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            f.setExpandEntityReferences(false);
            Document doc = f.newDocumentBuilder().parse(new ByteArrayInputStream(xml));
            Element root = doc.getDocumentElement();
            if (!root.getTagName().equals("mapping-table")) {
                throw new IllegalArgumentException("not a mapping table: <" + root.getTagName() + ">");
            }
            for (Node n = root.getFirstChild(); n != null; n = n.getNextSibling()) {
                if (!(n instanceof Element el)) {
                    continue;
                }
                if (el.getTagName().equals("col-def")) {
                    Map<String, String> c = new LinkedHashMap<>();
                    c.put("name", el.getAttribute("name"));
                    c.put("type", el.hasAttribute("type") ? el.getAttribute("type") : "nocase");
                    columns.add(c);
                } else if (el.getTagName().equals("row")) {
                    List<String> row = new ArrayList<>();
                    for (Node c = el.getFirstChild(); c != null; c = c.getNextSibling()) {
                        if (c instanceof Element ce && ce.getTagName().equals("col")) {
                            row.add(ce.getTextContent());
                        }
                    }
                    rows.add(row);
                }
            }
        } catch (IllegalArgumentException x) {
            throw x;
        } catch (Exception x) {
            throw new IllegalArgumentException("the table's data is not readable XML: " + x.getMessage());
        }
        return new Table(columns, rows);
    }

    /** The columns and rows from a request, checked: named, unique, typed, and each row as wide as the columns. */
    static Table fromRequest(Map<String, Object> b) {
        if (!(b.get("columns") instanceof List<?> cols) || cols.isEmpty()) {
            throw new IllegalArgumentException("columns is a list of at least one {name, type}");
        }
        List<Map<String, String>> columns = new ArrayList<>();
        Set<String> names = new HashSet<>();
        for (Object o : cols) {
            if (!(o instanceof Map<?, ?> c) || c.get("name") == null || String.valueOf(c.get("name")).isBlank()) {
                throw new IllegalArgumentException("every column has a name");
            }
            String name = String.valueOf(c.get("name")).trim();
            String type = c.get("type") == null ? "nocase" : String.valueOf(c.get("type"));
            if (!TYPES.contains(type)) {
                throw new IllegalArgumentException("a column type is one of " + String.join(", ", TYPES.stream().sorted().toList()));
            }
            if (!names.add(name.toLowerCase(Locale.ROOT))) {
                throw new IllegalArgumentException("two columns are named " + name);
            }
            columns.add(Map.of("name", name, "type", type));
        }
        List<List<String>> rows = new ArrayList<>();
        Object r = b.get("rows");
        if (r != null && !(r instanceof List)) {
            throw new IllegalArgumentException("rows is a list of lists");
        }
        for (Object o : r == null ? List.of() : (List<?>) r) {
            if (!(o instanceof List<?> cells) || cells.size() != columns.size()) {
                throw new IllegalArgumentException("every row has " + columns.size() + " values, one per column");
            }
            List<String> row = new ArrayList<>();
            for (Object v : cells) {
                row.add(v == null ? "" : String.valueOf(v));
            }
            rows.add(row);
        }
        return new Table(columns, rows);
    }

    /** The table as Designer writes it: column definitions, then the rows. */
    static byte[] write(Table t) {
        StringBuilder x = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\"?><mapping-table>\n");
        for (Map<String, String> c : t.columns()) {
            x.append("\t<col-def name=\"").append(escape(c.get("name"))).append("\" type=\"").append(escape(c.get("type"))).append("\"/>\n");
        }
        for (List<String> row : t.rows()) {
            x.append("\t<row>\n");
            for (String v : row) {
                x.append("\t\t<col>").append(escape(v)).append("</col>\n");
            }
            x.append("\t</row>\n");
        }
        return x.append("</mapping-table>").toString().getBytes(StandardCharsets.UTF_8);
    }

    private static String escape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private void save(HttpExchange ex, Ldap l, Sessions.Session s, String guid, Ldap.Entry e) throws IOException, NamingException {
        Map<String, Object> b = Http.body(ex);
        if (!Http.string(b, "version", true).equals(Jobs.version(data(e)))) {
            throw new Http.Problem(409, "changed", "the table changed meanwhile; reload it and try again");
        }
        Table t = fromRequest(b);
        Table before = parse(data(e));
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("dn", e.dn());
        detail.put("columns", t.columns().stream().map(c -> c.get("name")).toList());
        detail.put("rows", Map.of("from", before.rows().size(), "to", t.rows().size()));
        try {
            l.modify(e.dn(), List.of(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("DirXML-Data", write(t)))));
        } catch (NamingException x) {
            server.objects.audit(s, "idm.mapping-table.change", guid, detail, Ldap.Failure.of(x));
            throw x;
        }
        server.objects.audit(s, "idm.mapping-table.change", guid, detail, null);
        Http.json(ex, 200, json(l, table(l, guid)));
    }

    private void create(HttpExchange ex, Ldap l, Sessions.Session s) throws IOException, NamingException {
        Map<String, Object> b = Http.body(ex);
        Ldap.Entry parent = server.objects.byGuid(l, Http.string(b, "parent", true), "objectClass");
        if (parent == null || parent.attributes().getOrDefault("objectclass", List.of()).stream()
                .noneMatch(c -> PARENTS.stream().anyMatch(p -> p.equalsIgnoreCase(String.valueOf(c))))) {
            throw new Http.Problem(404, "not-found", "a mapping table goes in a driver set, driver, library or channel");
        }
        if (!s.principal.may(Role.OPERATOR, parent.dn())) {
            throw new Http.Problem(403, "out-of-scope", "creating a mapping table needs an operator role that reaches " + parent.dn());
        }
        String name = Http.string(b, "name", true).trim();
        if (name.isEmpty() || name.length() > 64) {
            throw new IllegalArgumentException("a table's name is 1 to 64 characters");
        }
        Table t = fromRequest(b);
        String dn = Names.child(parent.dn(), "cn", name);
        if (l.read(dn, "cn") != null) {
            throw new Http.Problem(409, "exists", "there is already an object named " + name + " there");
        }
        Map<String, List<Object>> attrs = new LinkedHashMap<>();
        attrs.put("objectClass", List.of("Top", "DirXML-Resource"));
        attrs.put("cn", List.of(name));
        attrs.put("DirXML-ContentType", List.of(CONTENT_TYPE));
        attrs.put("DirXML-Data", List.of(write(t)));
        Map<String, Object> detail = Map.of("dn", dn, "columns", t.columns().stream().map(c -> c.get("name")).toList(), "rows", t.rows().size());
        try {
            l.create(dn, attrs);
        } catch (NamingException x) {
            server.objects.audit(s, "idm.mapping-table.create", null, detail, Ldap.Failure.of(x));
            throw x;
        }
        Ldap.Entry made = l.read(dn, ATTRS);
        String guid = made == null ? null : String.valueOf(ref(made).get("guid"));
        server.objects.audit(s, "idm.mapping-table.create", guid, detail, null);
        Http.json(ex, 201, made == null ? Map.of("dn", dn) : json(l, made));
    }

    private void delete(HttpExchange ex, Ldap l, Sessions.Session s, String guid, Ldap.Entry e) throws IOException, NamingException {
        String typed = Http.string(Http.body(ex), "name", true);
        String name = String.valueOf(Names.identity(e.dn()).get("name"));
        if (!typed.equals(name)) {
            throw new Http.Problem(409, "confirm-name", "type the table's name, " + name + ", to delete it");
        }
        Map<String, Object> detail = Map.of("dn", e.dn());
        try {
            l.delete(e.dn());
        } catch (NamingException x) {
            server.objects.audit(s, "idm.mapping-table.delete", guid, detail, Ldap.Failure.of(x));
            throw x;
        }
        server.objects.audit(s, "idm.mapping-table.delete", guid, detail, null);
        Http.json(ex, 204, Map.of());
    }
}
