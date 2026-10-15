package com.pointblue.console.server.http;

import com.pointblue.console.server.auth.Sessions;
import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.console.server.ldap.Names;
import com.sun.net.httpserver.HttpExchange;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.naming.NamingException;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * A driver's properties, read-only (decided 2026-10-14: the console shows them; only the trace level is
 * changed here, on the Trace tab): what it runs, how it authenticates, its driver parameters, global
 * configuration values (its own and those of the GCV objects it links), engine control values, filter
 * and policies. Read over LDAP with the person's own rights; the shim's password is never read, only
 * whether one is set. Attributes and the policy-set numbers are as on ig4 (2026-10-14).
 *
 * <pre>
 * GET /api/v2/trees/{tree}/idm/drivers/{guid}/properties
 * </pre>
 */
final class DriverProperties {

    private static final String[] ATTRS = {"objectClass", "DirXML-JavaModule", "DirXML-NativeModule", "DirXML-ShimAuthID", "DirXML-ShimAuthServer",
        "DirXML-ShimAuthPassword", "DirXML-ShimConfigInfo", "DirXML-ConfigValues", "DirXML-EngineControlValues", "DirXML-DriverFilter", "DirXML-Policies",
        "DirXML-pkgGUID", "DirXML-DriverCacheLimit", "securityEquals"};

    /** The policy sets, by the number at the end of a DirXML-Policies value ({@code <policy DN>#<order>#<set>}). */
    static final List<String> SETS = List.of("Schema mapping", "Input transformation", "Output transformation", "ECMAScript",
        "Subscriber event transformation", "Publisher event transformation", "Subscriber matching", "Publisher matching",
        "Subscriber creation", "Publisher creation", "Subscriber command transformation", "Publisher command transformation",
        "Subscriber placement", "Publisher placement", "Global configuration values", "Startup", "Shutdown");

    private final Server server;

    DriverProperties(Server server) {
        this.server = server;
    }

    private static final String[] SET_ATTRS = {"objectClass", "DirXML-ConfigValues", "DirXML-Policies", "DirXML-JavaEnvironmentParameters", "DirXML-ServerList",
        "DirXML-LogLimit", "DirXML-pkgGUID", "nspmPasswordPolicyDN"};

    void handle(HttpExchange ex, Sessions.Session s, String guid, boolean driverSet) throws IOException {
        Ldap l = s.ldap();
        if (l == null) {
            throw new Http.Problem(503, "unavailable", "no directory connection");
        }
        String cls = driverSet ? "DirXML-DriverSet" : "DirXML-Driver";
        try {
            Ldap.Entry e = server.objects.byGuid(l, guid, driverSet ? SET_ATTRS : ATTRS);
            if (e == null || e.attributes().getOrDefault("objectclass", List.of()).stream().noneMatch(o -> String.valueOf(o).equalsIgnoreCase(cls))) {
                throw new Http.Problem(404, "not-found", guid + " is not a " + (driverSet ? "driver set" : "driver"));
            }
            Http.json(ex, 200, driverSet ? readSet(l, e) : read(l, e));
        } catch (NamingException x) {
            throw server.objects.problem(s, Ldap.Failure.of(x));
        }
    }

    /**
     * A driver set's properties, read-only: its global configuration values (its own and those of the GCV
     * objects it links), Java environment ({@code DirXML-JavaEnvironmentParameters}, NAME$value, ig4:
     * DHOST_JVM_INITIAL_HEAP$3G), servers, linked policies and libraries, log limit and password policy.
     * Its trace settings and activation have their own tabs.
     */
    private Map<String, Object> readSet(Ldap l, Ldap.Entry e) throws NamingException {
        Map<String, Object> out = new LinkedHashMap<>();
        List<Map<String, Object>> env = new ArrayList<>();
        for (Object v : e.attributes().getOrDefault("dirxml-javaenvironmentparameters", List.of())) {
            String raw = String.valueOf(v);
            int i = raw.indexOf('$');
            env.add(Map.of("name", i < 0 ? raw : raw.substring(0, i), "value", i < 0 ? "" : raw.substring(i + 1)));
        }
        out.put("javaEnvironment", env);
        out.put("servers", e.attributes().getOrDefault("dirxml-serverlist", List.of()).stream().map(String::valueOf).toList());
        out.put("logLimit", e.first("DirXML-LogLimit"));
        out.put("passwordPolicy", e.first("nspmPasswordPolicyDN"));
        out.put("package", packageName(e.first("DirXML-pkgGUID")));
        List<Map<String, Object>> gcvs = new ArrayList<>();
        Element own = root(bytes(e, "DirXML-ConfigValues"));
        if (own != null) {
            gcvs.add(Map.of("source", "the driver set", "items", values(own)));
        }
        List<Map<String, Object>> policies = policies(l, e, gcvs);
        out.put("gcvs", gcvs);
        out.put("policies", policies);
        return out;
    }

    private Map<String, Object> read(Ldap l, Ldap.Entry e) throws NamingException {
        Map<String, Object> out = new LinkedHashMap<>();
        Map<String, Object> general = new LinkedHashMap<>();
        general.put("javaModule", e.first("DirXML-JavaModule"));
        general.put("nativeModule", e.first("DirXML-NativeModule"));
        general.put("package", packageName(e.first("DirXML-pkgGUID")));
        general.put("cacheLimit", e.first("DirXML-DriverCacheLimit"));
        general.put("securityEquals", e.attributes().getOrDefault("securityequals", List.of()).stream().map(String::valueOf).toList());
        out.put("general", general);
        out.put("authentication", authentication(e));

        Element shim = root(bytes(e, "DirXML-ShimConfigInfo"));
        List<Map<String, Object>> parameters = new ArrayList<>();
        if (shim != null) {
            for (String[] section : new String[][] {{"driver-options", "Driver"}, {"subscriber-options", "Subscriber"}, {"publisher-options", "Publisher"}}) {
                Element opts = child(shim, section[0]);
                Element cv = opts == null ? null : child(opts, "configuration-values");
                if (cv != null) {
                    parameters.add(Map.of("section", section[1], "items", values(cv)));
                }
            }
        }
        out.put("parameters", parameters);

        List<Map<String, Object>> gcvs = new ArrayList<>();
        Element own = root(bytes(e, "DirXML-ConfigValues"));
        if (own != null) {
            gcvs.add(Map.of("source", "the driver", "items", values(own)));
        }
        List<Map<String, Object>> policies = policies(l, e, gcvs);
        out.put("gcvs", gcvs);
        Element ecv = root(bytes(e, "DirXML-EngineControlValues"));
        out.put("engineControlValues", ecv == null ? List.of() : values(ecv));
        out.put("filter", filter(root(bytes(e, "DirXML-DriverFilter"))));
        out.put("policies", policies);
        return out;
    }

    /** DirXML-Policies in order by policy set; a linked GCV object's values are added to {@code gcvs}. */
    private List<Map<String, Object>> policies(Ldap l, Ldap.Entry e, List<Map<String, Object>> gcvs) throws NamingException {
        List<Map<String, Object>> policies = new ArrayList<>();
        for (Object v : e.attributes().getOrDefault("dirxml-policies", List.of())) {
            String raw = String.valueOf(v);
            String[] parts = raw.split("#");
            if (parts.length < 3) {
                continue;
            }
            String dn = parts[0];
            int order = parseInt(parts[1]);
            int set = parseInt(parts[2]);
            Map<String, Object> p = new LinkedHashMap<>();
            p.put("dn", dn);
            p.put("name", String.valueOf(Names.identity(dn).get("name")));
            p.put("set", set >= 0 && set < SETS.size() ? SETS.get(set) : "Set " + set);
            p.put("setNumber", set);
            p.put("order", order);
            policies.add(p);
            // a package's GCV object: its values are the driver's too
            if (set == 14) {
                // a DirXML-GlobalConfigDef keeps them in DirXML-ConfigValues, as the driver does (ig4)
                Ldap.Entry g = l.read(dn, "DirXML-ConfigValues", "DirXML-Data");
                Element cv = g == null ? null : root(first(bytes(g, "DirXML-ConfigValues"), bytes(g, "DirXML-Data")));
                if (cv != null) {
                    gcvs.add(Map.of("source", p.get("name"), "items", values(cv)));
                }
            }
        }
        policies.sort((a, b) -> {
            int c = Integer.compare((int) a.get("setNumber"), (int) b.get("setNumber"));
            return c != 0 ? c : Integer.compare((int) a.get("order"), (int) b.get("order"));
        });
        return policies;
    }

    private static int parseInt(String s) {
        try {
            return Integer.parseInt(s.trim());
        } catch (NumberFormatException x) {
            return -1;
        }
    }

    private static byte[] first(byte[] a, byte[] b) {
        return a != null ? a : b;
    }

    private static String packageName(String g) {
        if (g == null) {
            return null;
        }
        String[] parts = g.split(";");
        return parts.length >= 4 ? parts[3] + (parts.length >= 3 ? " " + parts[2] : "") : g;
    }

    /** {@code REMOTE(hostname=h port=8090 kmo=idm)…}: through a Remote Loader at h:8090, else a server or URL. */
    static Map<String, Object> authentication(Ldap.Entry e) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", e.first("DirXML-ShimAuthID"));
        String server = e.first("DirXML-ShimAuthServer");
        Matcher r = server == null ? null : Pattern.compile("^REMOTE\\(([^)]*)\\)(.*)$").matcher(server.trim());
        if (r != null && r.matches()) {
            Map<String, String> opts = new LinkedHashMap<>();
            for (String kv : r.group(1).trim().split("\\s+")) {
                int eq = kv.indexOf('=');
                if (eq > 0) {
                    opts.put(kv.substring(0, eq).toLowerCase(), kv.substring(eq + 1));
                }
            }
            m.put("remoteLoader", opts);
            m.put("server", r.group(2).trim().isEmpty() ? null : r.group(2).trim());
        } else {
            m.put("server", server);
        }
        m.put("passwordSet", e.attributes().containsKey("dirxml-shimauthpassword"));
        return m;
    }

    private static byte[] bytes(Ldap.Entry e, String attr) {
        List<Object> v = e.attributes().get(attr.toLowerCase());
        if (v == null || v.isEmpty()) {
            return null;
        }
        Object o = v.get(0);
        return o instanceof byte[] b ? b : String.valueOf(o).getBytes(StandardCharsets.UTF_8);
    }

    private static Element root(byte[] xml) {
        if (xml == null || xml.length == 0) {
            return null;
        }
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            f.setExpandEntityReferences(false);
            return f.newDocumentBuilder().parse(new ByteArrayInputStream(xml)).getDocumentElement();
        } catch (Exception x) {
            return null;
        }
    }

    private static Element child(Element parent, String tag) {
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element el && el.getTagName().equals(tag)) {
                return el;
            }
        }
        return null;
    }

    private static List<Element> children(Element parent) {
        List<Element> out = new ArrayList<>();
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element el) {
                out.add(el);
            }
        }
        return out;
    }

    private static String strip(String s) {
        return s == null || s.isEmpty() ? null : s.replaceFirst("^xlfid\\([^)]*\\)", "");
    }

    /**
     * A {@code <configuration-values>} (GCVs, ECVs, driver parameters) as a flat list: headers and values,
     * each with its depth; a value under {@code <subordinates active-value>} that is not active is marked
     * inactive, as Designer greys it out.
     */
    static List<Map<String, Object>> values(Element cv) {
        List<Map<String, Object>> out = new ArrayList<>();
        Element defs = cv.getTagName().equals("definitions") ? cv : child(cv, "definitions");
        if (defs != null) {
            walk(defs, 0, false, out);
        }
        return out;
    }

    private static void walk(Element parent, int depth, boolean inactive, List<Map<String, Object>> out) {
        String last = null;
        for (Element el : children(parent)) {
            switch (el.getTagName()) {
                case "header" -> {
                    Map<String, Object> h = new LinkedHashMap<>();
                    h.put("kind", "header");
                    h.put("depth", depth);
                    h.put("label", strip(el.getAttribute("display-name")));
                    h.put("description", strip(text(child(el, "description"))));
                    h.put("inactive", inactive);
                    out.add(h);
                }
                case "definition" -> last = definition(el, depth, inactive, out);
                case "group" -> walk(el, depth, inactive, out);
                case "subordinates" -> {
                    boolean active = last != null && last.equals(el.getAttribute("active-value"));
                    walk(el, depth + 1, inactive || !active, out);
                }
                default -> { }
            }
        }
    }

    /** One definition: its label, type and value (an enum's choice by its label; a list's items joined); returns the value. */
    private static String definition(Element d, int depth, boolean inactive, List<Map<String, Object>> out) {
        Map<String, Object> m = new LinkedHashMap<>();
        String type = d.getAttribute("type");
        m.put("kind", "value");
        m.put("depth", depth);
        m.put("name", d.getAttribute("name"));
        m.put("label", strip(d.getAttribute("display-name")));
        m.put("type", type);
        m.put("description", strip(text(child(d, "description"))));
        m.put("inactive", inactive);
        Element value = child(d, "value");
        String raw = null;
        String shown;
        if (value == null) {
            shown = null;
        } else if (!children(value).isEmpty() && children(value).stream().allMatch(c -> c.getTagName().equals("item"))) {
            List<String> items = children(value).stream().map(Node::getTextContent).toList();
            raw = String.join(";", items);
            shown = String.join("; ", items);
        } else if (type.equals("structured")) {
            int n = (int) children(value).stream().filter(c -> c.getTagName().equals("instance")).count();
            raw = String.valueOf(n);
            shown = n + " entr" + (n == 1 ? "y" : "ies");
        } else {
            raw = value.getTextContent().trim();
            shown = raw;
        }
        if (type.equals("enum") && raw != null) {
            for (Element c : children(d)) {
                if (c.getTagName().equals("enum-choice") && c.getTextContent().trim().equals(raw)) {
                    String label = strip(c.getAttribute("display-name"));
                    shown = label == null || label.isEmpty() ? raw : label;
                }
            }
        }
        if (type.equals("password") && shown != null && !shown.isEmpty()) {
            shown = "(set)";
        }
        m.put("value", shown);
        out.add(m);
        return raw;
    }

    private static String text(Element e) {
        return e == null ? null : e.getTextContent().trim();
    }

    /** The filter: each class with its channels, and each attribute's. */
    static List<Map<String, Object>> filter(Element f) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (f == null) {
            return out;
        }
        for (Element c : children(f)) {
            if (!c.getTagName().equals("filter-class")) {
                continue;
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", c.getAttribute("class-name"));
            m.put("publisher", c.getAttribute("publisher"));
            m.put("subscriber", c.getAttribute("subscriber"));
            List<Map<String, Object>> attrs = new ArrayList<>();
            for (Element a : children(c)) {
                if (a.getTagName().equals("filter-attr")) {
                    attrs.add(Map.of("name", a.getAttribute("attr-name"), "publisher", a.getAttribute("publisher"), "subscriber", a.getAttribute("subscriber")));
                }
            }
            m.put("attributes", attrs);
            out.add(m);
        }
        return out;
    }
}
