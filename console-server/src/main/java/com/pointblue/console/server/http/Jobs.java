package com.pointblue.console.server.http;

import com.pointblue.console.server.auth.Role;
import com.pointblue.console.server.auth.Sessions;
import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.console.server.ldap.Names;
import com.pointblue.dirxml.dev.json.Json;
import com.sun.net.httpserver.HttpExchange;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.naming.NamingException;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * A job's definition, read and changed over LDAP with the person's own rights (no engine needed): the
 * job object's {@code XmlData} ({@code <job-aggregation><job-definition disabled schedule …>}), its
 * servers ({@code DirXML-ServerList}) and scope ({@code DirXML-Scope}, {@code <dn>#<n>#<scope-def …/>}),
 * as on a lab tree (2026-10-14). Running and aborting a job stay with the engine (Idm).
 *
 * <pre>
 * GET    /api/v2/trees/{tree}/idm/jobs/{guid}/definition    summary, schedule, servers, scope, parameters, version
 * POST   /api/v2/trees/{tree}/idm/{drivers|driversets}/{guid}/jobs   a new job of a type the engine offers (see Idm, JobTypes)
 *        {"type", "name", "disabled"?, "schedule"? (cron, or null for none; the type's own when absent),
 *         "servers" [server DN…], "scope"? [{"dn", "scope": entry|subordinates|subtree|members}], "parameters"? {name: value}}
 * PATCH  same   {"version", "disabled"?, "schedule"? (cron, or null for none), "servers"? [server DN…],
 *                "parameters"? {name: value}, "scope"? [{"dn", "scope"}] ([] removes it, unless the type needs one)}
 * DELETE /api/v2/trees/{tree}/idm/jobs/{guid}               {"name"}: the job's name, typed
 * </pre>
 *
 * A change carries the version it was read at (a hash of {@code XmlData}) and is refused (409) when the
 * job changed meanwhile. The XML is edited in place (the job-definition start tag's attributes, and the
 * {@code <value>} of each parameter changed), so everything else in it is kept byte for byte. A job's named
 * passwords (its password-ref parameters name them) are set through the engine: see Idm.
 */
final class Jobs {

    private static final String[] ATTRS = {"objectClass", "cn", "XmlData", "DirXML-ServerList", "DirXML-Scope"};
    /** Five cron fields (minute hour day-of-month month day-of-week), as the engine's schedules are written. */
    static final Pattern CRON = Pattern.compile("^\\s*([0-9*,/-]+|\\?)(\\s+[0-9A-Za-z*,/?-]+){4}\\s*$");

    private final Server server;

    Jobs(Server server) {
        this.server = server;
    }

    void handle(HttpExchange ex, Sessions.Session s, String method, String guid, boolean definition) throws IOException {
        Ldap l = s.ldap();
        if (l == null) {
            throw new Http.Problem(503, "unavailable", "no directory connection");
        }
        try {
            Ldap.Entry e = server.objects.byGuid(l, guid, ATTRS);
            if (e == null || e.attributes().getOrDefault("objectclass", List.of()).stream().noneMatch(o -> String.valueOf(o).equalsIgnoreCase("DirXML-Job"))) {
                throw new Http.Problem(404, "not-found", guid + " is not a job");
            }
            if (!method.equals("GET") && !s.principal.may(Role.OPERATOR, e.dn())) {
                throw new Http.Problem(403, "out-of-scope", "changing a job needs an operator role that reaches " + e.dn());
            }
            switch ((definition ? "definition " : "job ") + method) {
                case "definition GET" -> Http.json(ex, 200, read(l, e));
                case "definition PATCH" -> {
                    change(l, s, guid, e, Http.body(ex));
                    Http.json(ex, 200, read(l, server.objects.byGuid(l, guid, ATTRS)));
                }
                case "job DELETE" -> delete(ex, l, s, guid, e);
                default -> throw new Http.Problem(405, "method-not-allowed", method);
            }
        } catch (NamingException x) {
            throw server.objects.problem(s, Ldap.Failure.of(x));
        } catch (IllegalArgumentException x) {
            throw new Http.Problem(400, "bad-request", x.getMessage());
        }
    }

    private static byte[] xml(Ldap.Entry e) {
        List<Object> v = e.attributes().get("xmldata");
        if (v == null || v.isEmpty()) {
            return null;
        }
        Object o = v.get(0);
        return o instanceof byte[] b ? b : String.valueOf(o).getBytes(StandardCharsets.UTF_8);
    }

    static String version(byte[] xml) {
        try {
            return xml == null ? "none" : HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(xml), 0, 12);
        } catch (NoSuchAlgorithmException x) {
            throw new IllegalStateException(x);
        }
    }

    private Map<String, Object> read(Ldap l, Ldap.Entry e) throws NamingException {
        Map<String, Object> out = new LinkedHashMap<>(Names.identity(e.dn()));
        String parent = Names.parent(e.dn());
        Ldap.Entry owner = l.read(parent, "objectClass");
        boolean underDriver = owner != null && owner.attributes().getOrDefault("objectclass", List.of()).stream().anyMatch(o -> String.valueOf(o).equalsIgnoreCase("DirXML-Driver"));
        out.put("owner", Map.of("dn", parent, "name", String.valueOf(Names.identity(parent).get("name")), "kind", underDriver ? "driver" : "driver set"));
        byte[] xml = xml(e);
        out.put("version", version(xml));
        Element def = definition(xml);
        if (def != null) {
            out.put("displayName", strip(def.getAttribute("display-name")));
            out.put("disabled", "true".equalsIgnoreCase(def.getAttribute("disabled")));
            out.put("schedule", def.hasAttribute("schedule") ? def.getAttribute("schedule") : null);
            out.put("scopeRequired", "true".equalsIgnoreCase(def.getAttribute("scope-required")));
            out.put("description", strip(text(def, "description")));
            out.put("javaClass", text(def, "java-class"));
            out.put("parameters", JobTypes.parameters(def));
        }
        List<Map<String, Object>> servers = new ArrayList<>();
        for (Object v : e.attributes().getOrDefault("dirxml-serverlist", List.of())) {
            String dn = String.valueOf(v);
            servers.add(Map.of("dn", dn, "name", String.valueOf(Names.identity(dn).get("name"))));
        }
        out.put("servers", servers);
        List<Map<String, Object>> scopes = new ArrayList<>();
        for (Object v : e.attributes().getOrDefault("dirxml-scope", List.of())) {
            String raw = String.valueOf(v);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("raw", raw);
            int a = raw.indexOf('#');
            int b = a < 0 ? -1 : raw.indexOf('#', a + 1);
            if (a > 0 && b > 0) {
                m.put("dn", raw.substring(0, a));
                Matcher sm = Pattern.compile("scope=\"([^\"]*)\"").matcher(raw.substring(b + 1));
                m.put("scope", sm.find() ? sm.group(1) : null);
            }
            scopes.add(m);
        }
        out.put("scope", scopes);
        return out;
    }

    /** "xlfid(job-description)This job…" → "This job…": the localization key is not for people. */
    private static String strip(String s) {
        return s == null ? null : s.replaceFirst("^xlfid\\([^)]*\\)", "");
    }

    private static String text(Element parent, String child) {
        NodeList n = parent.getElementsByTagName(child);
        return n.getLength() == 0 ? null : n.item(0).getTextContent().trim();
    }

    private static Element definition(byte[] xml) {
        if (xml == null) {
            return null;
        }
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            f.setExpandEntityReferences(false);
            Document doc = f.newDocumentBuilder().parse(new ByteArrayInputStream(xml));
            NodeList n = doc.getElementsByTagName("job-definition");
            return n.getLength() == 0 ? null : (Element) n.item(0);
        } catch (Exception x) {
            return null;
        }
    }

    /** The first {@code <job-definition …>} start tag. */
    private static final Pattern START = Pattern.compile("<job-definition\\b[^>]*>");

    /** {@code xml} with the job-definition start tag's {@code name} attribute set to {@code value} (null removes it). */
    static String withAttribute(String xml, String name, String value) {
        Matcher m = START.matcher(xml);
        if (!m.find()) {
            throw new IllegalArgumentException("the job's XmlData has no job-definition");
        }
        String tag = m.group();
        Pattern attr = Pattern.compile("\\s" + Pattern.quote(name) + "\\s*=\\s*(\"[^\"]*\"|'[^']*')");
        Matcher am = attr.matcher(tag);
        String changed;
        if (am.find()) {
            changed = value == null ? tag.substring(0, am.start()) + tag.substring(am.end())
                : tag.substring(0, am.start()) + " " + name + "=\"" + value + "\"" + tag.substring(am.end());
        } else if (value == null) {
            return xml;
        } else {
            int end = tag.endsWith("/>") ? tag.length() - 2 : tag.length() - 1;
            changed = tag.substring(0, end) + " " + name + "=\"" + value + "\"" + tag.substring(end);
        }
        return xml.substring(0, m.start()) + changed + xml.substring(m.end());
    }

    private void change(Ldap l, Sessions.Session s, String guid, Ldap.Entry e, Map<String, Object> b) throws IOException, NamingException {
        byte[] xml = xml(e);
        String expected = Http.string(b, "version", true);
        if (!expected.equals(version(xml))) {
            throw new Http.Problem(409, "changed", "the job changed meanwhile; reload it and try again");
        }
        List<ModificationItem> mods = new ArrayList<>();
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("dn", e.dn());
        if (b.containsKey("disabled") || b.containsKey("schedule") || b.containsKey("parameters")) {
            if (xml == null) {
                throw new IllegalArgumentException("the job has no definition (XmlData) to change");
            }
            String text = new String(xml, StandardCharsets.UTF_8);
            if (b.containsKey("disabled")) {
                if (!(b.get("disabled") instanceof Boolean on)) {
                    throw new IllegalArgumentException("disabled is true or false");
                }
                text = withAttribute(text, "disabled", on ? "true" : "false");
                detail.put("disabled", on);
            }
            if (b.containsKey("schedule")) {
                Object v = b.get("schedule");
                String cron = v == null || String.valueOf(v).isBlank() ? null : String.valueOf(v).trim().replaceAll("\\s+", " ");
                if (cron != null && !CRON.matcher(cron).matches()) {
                    throw new IllegalArgumentException("a schedule is five cron fields: minute hour day-of-month month day-of-week, such as 0 2 * * 6");
                }
                text = withAttribute(text, "schedule", cron);
                detail.put("schedule", cron);
            }
            if (b.get("parameters") != null) {
                Map<String, Object> values = Json.asMap(b.get("parameters"));
                Element def = definition(xml);
                if (def == null) {
                    throw new IllegalArgumentException("the job's definition could not be read");
                }
                text = JobTypes.withValues(text, def, values);
                // names only: a value can be a DN or other detail that does not belong in the audit log
                detail.put("parameters", new ArrayList<>(values.keySet()));
            }
            mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("XmlData", text.getBytes(StandardCharsets.UTF_8))));
        }
        if (b.containsKey("servers")) {
            if (!(b.get("servers") instanceof List<?> list) || list.isEmpty()) {
                throw new IllegalArgumentException("servers is a list of at least one server DN");
            }
            BasicAttribute a = new BasicAttribute("DirXML-ServerList");
            for (Object o : list) {
                String dn = String.valueOf(o);
                Ldap.Entry srv = l.read(dn, "objectClass");
                if (srv == null || srv.attributes().getOrDefault("objectclass", List.of()).stream().noneMatch(c -> String.valueOf(c).equalsIgnoreCase("ncpServer"))) {
                    throw new IllegalArgumentException("not a server: " + dn);
                }
                a.add(dn);
            }
            mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, a));
            detail.put("servers", list);
        }
        if (b.containsKey("scope")) {
            if (!(b.get("scope") instanceof List<?> list)) {
                throw new IllegalArgumentException("scope is a list of {dn, scope}");
            }
            List<Object> scope = scope(l, list);
            Element def = definition(xml);
            if (scope.isEmpty() && def != null && "true".equalsIgnoreCase(def.getAttribute("scope-required"))) {
                throw new IllegalArgumentException("this type of job needs a scope: the objects it works on");
            }
            BasicAttribute a = new BasicAttribute("DirXML-Scope");
            scope.forEach(a::add);
            mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, a));
            detail.put("scope", scope);
        }
        if (mods.isEmpty()) {
            return;
        }
        try {
            l.modify(e.dn(), mods);
        } catch (NamingException x) {
            server.objects.audit(s, "idm.job.change", guid, detail, Ldap.Failure.of(x));
            throw x;
        }
        server.objects.audit(s, "idm.job.change", guid, detail, null);
    }

    static final java.util.Set<String> SCOPES = java.util.Set.of("entry", "subordinates", "subtree", "members");

    /**
     * A new job under {@code owner} (a driver or driver set) from the type's aggregation as the engine gave
     * it: the object's XmlData is the aggregation with the chosen values, beside its servers and scope.
     */
    Map<String, Object> create(Ldap l, Sessions.Session s, Ldap.Entry owner, Element aggregation, boolean scopeRequired, Map<String, Object> b)
            throws IOException, NamingException {
        String name = Http.string(b, "name", true).trim();
        if (name.isEmpty() || name.length() > 64) {
            throw new IllegalArgumentException("a job's name is 1 to 64 characters");
        }
        String cron = null;
        boolean keepSchedule = !b.containsKey("schedule");
        if (!keepSchedule) {
            Object v = b.get("schedule");
            cron = v == null || String.valueOf(v).isBlank() ? null : String.valueOf(v).trim().replaceAll("\\s+", " ");
            if (cron != null && !CRON.matcher(cron).matches()) {
                throw new IllegalArgumentException("a schedule is five cron fields: minute hour day-of-month month day-of-week, such as 0 2 * * 6");
            }
        }
        boolean disabled = b.get("disabled") instanceof Boolean on && on;
        if (!(b.get("servers") instanceof List<?> serverList) || serverList.isEmpty()) {
            throw new IllegalArgumentException("servers is a list of at least one server DN");
        }
        List<Object> servers = new ArrayList<>();
        for (Object o : serverList) {
            String dn = String.valueOf(o);
            Ldap.Entry srv = l.read(dn, "objectClass");
            if (srv == null || srv.attributes().getOrDefault("objectclass", List.of()).stream().noneMatch(c -> String.valueOf(c).equalsIgnoreCase("ncpServer"))) {
                throw new IllegalArgumentException("not a server: " + dn);
            }
            servers.add(dn);
        }
        List<Object> scope = b.get("scope") instanceof List<?> list ? scope(l, list) : new ArrayList<>();
        if (scopeRequired && scope.isEmpty()) {
            throw new IllegalArgumentException("this type of job needs a scope: the objects it works on");
        }
        Map<String, Object> values = b.get("parameters") == null ? Map.of() : Json.asMap(b.get("parameters"));
        String schedule = keepSchedule ? (child(aggregation, "job-definition").hasAttribute("schedule") ? child(aggregation, "job-definition").getAttribute("schedule") : null) : cron;
        byte[] xml = JobTypes.build(aggregation, disabled, schedule, values);
        String dn = Names.child(owner.dn(), "cn", name);
        if (l.read(dn, "cn") != null) {
            throw new Http.Problem(409, "exists", "there is already an object named " + name + " there");
        }
        Map<String, List<Object>> attrs = new LinkedHashMap<>();
        attrs.put("objectClass", List.of("Top", "DirXML-Job"));
        attrs.put("cn", List.of(name));
        attrs.put("XmlData", List.of(xml));
        attrs.put("DirXML-ServerList", servers);
        if (!scope.isEmpty()) {
            attrs.put("DirXML-Scope", scope);
        }
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("dn", dn);
        detail.put("type", Http.string(b, "type", true));
        detail.put("disabled", disabled);
        detail.put("schedule", schedule);
        detail.put("servers", servers);
        detail.put("scope", scope);
        detail.put("parameters", values.keySet());
        try {
            l.create(dn, attrs);
        } catch (NamingException x) {
            server.objects.audit(s, "idm.job.create", null, detail, Ldap.Failure.of(x));
            throw x;
        }
        Ldap.Entry made = l.read(dn, "objectClass", "cn", "XmlData", "DirXML-ServerList", "DirXML-Scope", "GUID");
        Object guid = made == null ? null : made.attributes().get("guid") == null ? null : Names.guidHex(made.attributes().get("guid").get(0));
        server.objects.audit(s, "idm.job.create", guid == null ? null : String.valueOf(guid), detail, null);
        Map<String, Object> out = made == null ? new LinkedHashMap<>(Map.of("dn", dn)) : read(l, made);
        out.put("guid", guid);
        return out;
    }

    /** DirXML-Scope values ({@code <dn>#0#<scope-def scope="…"/>}) for {@code [{dn, scope}]}, each object checked. */
    private static List<Object> scope(Ldap l, List<?> list) throws NamingException {
        List<Object> scope = new ArrayList<>();
        for (Object o : list) {
            Map<String, Object> sc = Json.asMap(o);
            String dn = Http.string(sc, "dn", true).trim();
            String kind = Http.string(sc, "scope", true);
            if (!SCOPES.contains(kind)) {
                throw new IllegalArgumentException("a scope is entry, subordinates, subtree or members");
            }
            if (l.read(dn, "objectClass") == null) {
                throw new IllegalArgumentException("no object " + dn);
            }
            scope.add(dn + "#0#<scope-def scope=\"" + kind + "\"/>");
        }
        return scope;
    }

    private static Element child(Element parent, String tag) {
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element e && e.getTagName().equals(tag)) {
                return e;
            }
        }
        return null;
    }

    private void delete(HttpExchange ex, Ldap l, Sessions.Session s, String guid, Ldap.Entry e) throws IOException, NamingException {
        String typed = Http.string(Http.body(ex), "name", true);
        String name = String.valueOf(Names.identity(e.dn()).get("name"));
        if (!typed.equals(name)) {
            throw new Http.Problem(409, "confirm-name", "type the job's name, " + name + ", to delete it");
        }
        Map<String, Object> detail = Map.of("dn", e.dn());
        try {
            l.delete(e.dn());
        } catch (NamingException x) {
            server.objects.audit(s, "idm.job.delete", guid, detail, Ldap.Failure.of(x));
            throw x;
        }
        server.objects.audit(s, "idm.job.delete", guid, detail, null);
        Http.json(ex, 204, Map.of());
    }
}
