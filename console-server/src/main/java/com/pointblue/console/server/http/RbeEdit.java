package com.pointblue.console.server.http;

import com.pointblue.console.server.auth.Role;
import com.pointblue.console.server.auth.Sessions;
import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.console.server.ldap.Names;
import com.pointblue.dirxml.dev.model.EntitlementPolicy;
import com.sun.net.httpserver.HttpExchange;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
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
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Creating and changing role-based entitlement policies (see {@link Rbe} for how they are stored). What is
 * written follows Designer and Identity Console, so either can still edit a policy saved here:
 * <ul>
 * <li>{@code memberQueryURL} {@code ldap:///<base>??<scope>?<filter>?x-sparse} (percent-encoded per RFC 4516);
 *     the editors' {@code DirXML-SPFilterXML} criteria, when the filter has their shape (groups of rows).</li>
 * <li>{@code dgIdentity}, the identity eDirectory computes the members as (the shim takes {@code member} as
 *     eDirectory computes it, so a query policy without one grants nobody): the set's Entitlements Service driver
 *     unless another, or none, is chosen.</li>
 * <li>{@code DirXML-EntitlementRef} {@code <entitlement dn>#0#<ref/>}, or one value per granted value
 *     {@code …#0#<ref><param>value</param></ref>}; and Designer's display copy, {@code DirXML-SPDisplayEntitlements}.</li>
 * <li>Every policy has a query: the Entitlements Service shim reads each policy's on every evaluation, and one
 *     without makes it fail for everyone (-603, a lab tree). A policy of static members only gets {@link #NOBODY},
 *     which matches nothing, and reads back as having no query.</li>
 * <li>{@code DirXML-SPPriority} is a typed name, so a value must name a policy that exists (a lab tree, -613):
 *     a new policy is written first, then the priorities, with it last.</li>
 * </ul>
 *
 * <pre>
 * GET  /api/v2/trees/{tree}/idm/driversets/{guid}/rbe/entitlements   the entitlements the set's drivers define, and their values
 * POST /api/v2/trees/{tree}/idm/driversets/{guid}/rbe/test           {"base", "scope", "filter"}: who the query finds now
 * POST /api/v2/trees/{tree}/idm/driversets/{guid}/rbe/policies       {"name", …a policy}: a new policy, lowest priority
 * PUT  /api/v2/trees/{tree}/idm/rbe/policies/{guid}                  {"version", …a policy}: the policy changed
 * POST /api/v2/trees/{tree}/idm/rbe/policies/{guid}/empty            everyone removed, its grants kept so the shim revokes them
 * </pre>
 * The shim ignores a policy's deletion (a lab tree: "unhandled command element: delete"), so what it granted would
 * stay: a policy is emptied first (the shim revokes as members leave, once it restarts), then deleted.
 * A policy: {@code {"description", "membership": {"base", "scope", "filter"} | null, "identity": dn | null,
 * "members": [dn], "excluded": [dn], "grants": [{"entitlement": dn, "values": [text]}], "criteria": xml | null}}.
 */
final class RbeEdit {

    static final String CONTAINER = "Entitlement Policies";
    /** The filter of a static-only policy's query: it matches nothing, searched on the container alone. */
    static final String NOBODY = "(!(objectClass=*))";
    static final Set<String> SCOPES = Set.of("base", "one", "sub");
    /** Every attribute a policy's editor writes, so a change can clear what is left out. */
    static final String[] EDITED = {"description", "memberQueryURL", "dgIdentity", "member", "excludedMember", "DirXML-EntitlementRef",
        "DirXML-SPFilterXML", "DirXML-SPDisplayEntitlements"};

    private final Server server;

    RbeEdit(Server server) {
        this.server = server;
    }

    record Grant(String entitlement, List<String> values) {
    }

    record Spec(String description, String base, String scope, String filter, String identity, boolean identityGiven,
        List<String> members, List<String> excluded, List<Grant> grants, String criteria) {
    }

    /** An entitlement a driver defines: what values it takes ("none", a static "list", "query" from the application, or "input"). */
    record Definition(String dn, String guid, String name, String driverDn, String driverName, String displayName, String description,
        String conflictResolution, boolean multiValued, String kind, List<String> values) {

        Map<String, Object> json() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("dn", dn);
            m.put("guid", guid);
            m.put("name", name);
            m.put("displayName", displayName);
            m.put("description", description);
            m.put("conflictResolution", conflictResolution);
            m.put("multiValued", multiValued);
            m.put("kind", kind);
            m.put("values", values);
            return m;
        }
    }

    // ---- requests ----------------------------------------------------------------------------------

    /** A policy from a request, checked for shape; the directory checks that the names exist. */
    static Spec spec(Map<String, Object> b) {
        String base = null;
        String scope = null;
        String filter = null;
        if (b.get("membership") instanceof Map<?, ?> m) {
            base = m.get("base") == null ? "" : String.valueOf(m.get("base")).trim();
            scope = m.get("scope") == null ? "sub" : String.valueOf(m.get("scope"));
            filter = m.get("filter") == null ? "" : String.valueOf(m.get("filter")).trim();
            if (!SCOPES.contains(scope)) {
                throw new IllegalArgumentException("scope is base, one or sub");
            }
            if (filter.isEmpty() || !filter.startsWith("(") || !filter.endsWith(")")) {
                throw new IllegalArgumentException("the membership filter is an LDAP filter in parentheses, as in (title=Clerk)");
            }
            if (!base.isEmpty()) {
                Names.parse(base);
            }
        } else if (b.get("membership") != null) {
            throw new IllegalArgumentException("membership is {base, scope, filter}, or null for static members only");
        }
        boolean identityGiven = b.containsKey("identity");
        String identity = b.get("identity") == null || String.valueOf(b.get("identity")).isBlank() ? null : String.valueOf(b.get("identity")).trim();
        List<String> members = dns(b.get("members"), "members");
        List<String> excluded = dns(b.get("excluded"), "excluded");
        List<Grant> grants = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        if (b.get("grants") != null && !(b.get("grants") instanceof List)) {
            throw new IllegalArgumentException("grants is a list of {entitlement, values}");
        }
        for (Object o : b.get("grants") == null ? List.of() : (List<?>) b.get("grants")) {
            if (!(o instanceof Map<?, ?> g) || g.get("entitlement") == null) {
                throw new IllegalArgumentException("each grant names an entitlement");
            }
            String dn = String.valueOf(g.get("entitlement")).trim();
            if (!seen.add(Names.canonical(dn))) {
                throw new IllegalArgumentException("an entitlement is granted twice: " + dn);
            }
            List<String> values = new ArrayList<>();
            for (Object v : g.get("values") instanceof List<?> vs ? vs : List.of()) {
                String text = String.valueOf(v);
                if (text.isBlank()) {
                    throw new IllegalArgumentException("a granted value is empty: " + dn);
                }
                if (!values.contains(text)) {
                    values.add(text);
                }
            }
            grants.add(new Grant(dn, values));
        }
        String criteria = b.get("criteria") == null || String.valueOf(b.get("criteria")).isBlank() ? null : String.valueOf(b.get("criteria"));
        if (criteria != null) {
            Element root = xml(criteria);
            if (root == null || !root.getTagName().equals("selection-criterion")) {
                throw new IllegalArgumentException("criteria is a <selection-criterion> document");
            }
        }
        String description = b.get("description") == null ? null : String.valueOf(b.get("description")).trim();
        return new Spec(description == null || description.isEmpty() ? null : description, base, scope, filter, identity, identityGiven,
            members, excluded, grants, filter == null ? null : criteria);
    }

    private static List<String> dns(Object o, String field) {
        if (o != null && !(o instanceof List)) {
            throw new IllegalArgumentException(field + " is a list of DNs");
        }
        List<String> out = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (Object v : o == null ? List.of() : (List<?>) o) {
            String dn = String.valueOf(v).trim();
            Names.parse(dn);
            if (seen.add(Names.canonical(dn))) {
                out.add(dn);
            }
        }
        return out;
    }

    // ---- what is written ---------------------------------------------------------------------------

    /** {@code ldap:///<base>??<scope>?<filter>?x-sparse}, percent-encoding what RFC 4516 reserves in a DN and a filter. */
    static String queryUrl(String base, String scope, String filter) {
        return "ldap:///" + urlPart(base) + "??" + scope + "?" + urlPart(filter) + "?x-sparse";
    }

    /**
     * "%" and "?" (which would end the part), control characters, and what is not ASCII (as UTF-8) are percent-encoded;
     * the rest, spaces included, stays as typed, as eDirectory keeps a query it is given and the editors read it.
     */
    static String urlPart(String s) {
        StringBuilder b = new StringBuilder();
        for (byte x : s.getBytes(StandardCharsets.UTF_8)) {
            int c = x & 0xff;
            if (c == '%' || c == '?' || c < 0x20 || c > 0x7e) {
                b.append('%').append(String.format("%02X", c));
            } else {
                b.append((char) c);
            }
        }
        return b.toString();
    }

    /** The {@code DirXML-EntitlementRef} values for the grants: one plain ref, or one per value. */
    static List<String> refs(List<Grant> grants) {
        List<String> out = new ArrayList<>();
        for (Grant g : grants) {
            if (g.values().isEmpty()) {
                out.add(g.entitlement() + "#0#<ref/>");
            }
            for (String v : g.values()) {
                out.add(g.entitlement() + "#0#<ref><param>" + escape(v) + "</param></ref>");
            }
        }
        return out;
    }

    /** Designer's display copy of the grants, by driver: what its editor (and Identity Console's) shows. */
    static String display(List<Grant> grants, Map<String, Definition> defs) {
        Map<String, List<Grant>> byDriver = new LinkedHashMap<>();
        for (Grant g : grants) {
            Definition d = defs.get(Names.canonical(g.entitlement()));
            byDriver.computeIfAbsent(d == null ? Names.parent(g.entitlement()) : d.driverDn(), k -> new ArrayList<>()).add(g);
        }
        StringBuilder x = new StringBuilder("<Drivers>");
        for (Map.Entry<String, List<Grant>> e : byDriver.entrySet()) {
            x.append("<Driver><name>").append(escape(String.valueOf(Names.identity(e.getKey()).get("name")))).append("</name><value>")
                .append(escape(e.getKey())).append("</value><description/>");
            for (Grant g : e.getValue()) {
                Definition d = defs.get(Names.canonical(g.entitlement()));
                boolean valued = !g.values().isEmpty();
                x.append("<Entitlement><name>").append(escape(d == null ? String.valueOf(Names.identity(g.entitlement()).get("name")) : d.name()))
                    .append("</name><value>").append(escape(g.entitlement())).append("</value><description/>")
                    .append("<type>").append(valued ? "InputValues" : "NoValues").append("</type>")
                    .append("<EntitlementMulti>").append(d != null && d.multiValued()).append("</EntitlementMulti>")
                    .append("<EntitlementPackedValues>PP</EntitlementPackedValues>")
                    .append("<EntitlementDN>").append(escape(g.entitlement())).append("</EntitlementDN>")
                    .append("<hasInterpretiveVariables>false</hasInterpretiveVariables>");
                if (valued) {
                    x.append("<InputValues>");
                    g.values().forEach(v -> x.append("<value>").append(escape(v)).append("</value>"));
                    x.append("</InputValues>");
                }
                x.append("<conflict-resolution>").append(escape(d == null || d.conflictResolution() == null ? "priority" : d.conflictResolution()))
                    .append("</conflict-resolution></Entitlement>");
            }
            x.append("</Driver>");
        }
        return x.append("</Drivers>").toString();
    }

    /** Every edited attribute's values for a policy (an empty list: the attribute is not there). */
    static Map<String, List<Object>> attributes(Spec p, Map<String, Definition> defs, String containerDn) {
        Map<String, List<Object>> m = new LinkedHashMap<>();
        m.put("description", p.description() == null ? List.of() : List.of(p.description()));
        m.put("memberQueryURL", List.of(p.filter() == null ? queryUrl(containerDn, "base", NOBODY) : queryUrl(p.base(), p.scope(), p.filter())));
        m.put("dgIdentity", p.identity() == null ? List.of() : List.of(p.identity()));
        m.put("member", new ArrayList<>(p.members()));
        m.put("excludedMember", new ArrayList<>(p.excluded()));
        m.put("DirXML-EntitlementRef", new ArrayList<>(refs(p.grants())));
        m.put("DirXML-SPFilterXML", p.criteria() == null ? List.of() : List.of(p.criteria()));
        m.put("DirXML-SPDisplayEntitlements", p.grants().isEmpty() ? List.of() : List.of(display(p.grants(), defs).getBytes(StandardCharsets.UTF_8)));
        return m;
    }

    // ---- the entitlements the set's drivers define -------------------------------------------------

    /** The entitlements under the set's drivers (the Entitlements Service driver's own left out), by canonical DN. */
    static Map<String, Definition> definitions(Ldap l, String setDn) throws NamingException {
        Map<String, Definition> out = new LinkedHashMap<>();
        List<Ldap.Entry> drivers = l.search(setDn, "(objectClass=DirXML-Driver)", null, SearchControls.ONELEVEL_SCOPE,
            new String[] {"cn", "DirXML-JavaModule"}, 500);
        drivers.sort(Comparator.comparing(Ldap.Entry::dn, String.CASE_INSENSITIVE_ORDER));
        for (Ldap.Entry d : drivers) {
            if (EntitlementPolicy.SERVICE_SHIM_CLASS.equals(d.first("DirXML-JavaModule"))) {
                continue;
            }
            List<Ldap.Entry> ents = l.search(d.dn(), "(objectClass=DirXML-Entitlement)", null, SearchControls.ONELEVEL_SCOPE,
                new String[] {"GUID", "cn", "XmlData"}, 500);
            ents.sort(Comparator.comparing(Ldap.Entry::dn, String.CASE_INSENSITIVE_ORDER));
            for (Ldap.Entry e : ents) {
                Definition def = definition(e, d.dn());
                out.put(Names.canonical(e.dn()), def);
            }
        }
        return out;
    }

    static Definition definition(Ldap.Entry e, String driverDn) {
        List<Object> g = e.attributes().get("guid");
        String guid = g == null || g.isEmpty() ? null : Names.guidHex(g.get(0));
        Object raw = e.attributes().getOrDefault("xmldata", List.of()).stream().findFirst().orElse(null);
        Element root = raw == null ? null : xml(raw instanceof byte[] bytes ? new String(bytes, StandardCharsets.UTF_8) : String.valueOf(raw));
        String name = String.valueOf(Names.identity(e.dn()).get("name"));
        String driverName = String.valueOf(Names.identity(driverDn).get("name"));
        if (root == null) {
            return new Definition(e.dn(), guid, name, driverDn, driverName, null, null, null, false, "none", List.of());
        }
        Element values = child(root, "values");
        String kind = "none";
        List<String> list = new ArrayList<>();
        boolean multi = false;
        if (values != null) {
            multi = "true".equalsIgnoreCase(values.getAttribute("multi-valued"));
            kind = "input";
            for (Node n = values.getFirstChild(); n != null; n = n.getNextSibling()) {
                if (n instanceof Element v && v.getTagName().equals("value")) {
                    kind = "list";
                    list.add(v.getTextContent().trim());
                } else if (n instanceof Element v && v.getTagName().equals("query-app")) {
                    kind = "query";
                }
            }
        }
        return new Definition(e.dn(), guid, name, driverDn, driverName, blank(root.getAttribute("display-name")), blank(root.getAttribute("description")),
            blank(root.getAttribute("conflict-resolution")), multi, kind, kind.equals("list") ? list : List.of());
    }

    void entitlements(HttpExchange ex, Ldap l, String setDn) throws IOException, NamingException {
        Map<String, List<Map<String, Object>>> byDriver = new LinkedHashMap<>();
        Map<String, String> names = new LinkedHashMap<>();
        for (Definition d : definitions(l, setDn).values()) {
            byDriver.computeIfAbsent(d.driverDn(), k -> new ArrayList<>()).add(d.json());
            names.put(d.driverDn(), d.driverName());
        }
        List<Map<String, Object>> out = new ArrayList<>();
        byDriver.forEach((dn, ents) -> out.add(Map.of("driver", Map.of("dn", dn, "name", names.get(dn)), "entitlements", ents)));
        Http.json(ex, 200, Map.of("drivers", out));
    }

    // ---- handlers ----------------------------------------------------------------------------------

    /** Who the query finds now, searched with the person's own rights. */
    void test(HttpExchange ex, Ldap l, Map<String, Object> b) throws IOException, NamingException {
        Spec p = spec(Map.of("membership", b));
        int scope = switch (p.scope()) {
            case "base" -> SearchControls.OBJECT_SCOPE;
            case "one" -> SearchControls.ONELEVEL_SCOPE;
            default -> SearchControls.SUBTREE_SCOPE;
        };
        List<Ldap.Entry> found = l.search(p.base(), p.filter(), null, scope, new String[] {"cn"}, 101);
        List<Map<String, Object>> items = new ArrayList<>();
        for (Ldap.Entry e : found.subList(0, Math.min(100, found.size()))) {
            items.add(Map.of("dn", e.dn(), "name", Names.identity(e.dn()).get("name")));
        }
        Http.json(ex, 200, Map.of("items", items, "more", found.size() > 100));
    }

    /** A new policy: the container made when there is none, the policy, then the priorities with it last. */
    void create(HttpExchange ex, Ldap l, Sessions.Session s, String setDn, List<Map<String, Object>> serviceDrivers) throws IOException, NamingException {
        Map<String, Object> b = Http.body(ex);
        String name = Http.string(b, "name", true).trim();
        if (name.isEmpty() || name.length() > 64) {
            throw new IllegalArgumentException("a policy's name is 1 to 64 characters");
        }
        Spec p = spec(b);
        if (!p.identityGiven() && p.filter() != null && !serviceDrivers.isEmpty()) {
            // the shim takes the members eDirectory computes, as this identity: default to the service driver
            p = new Spec(p.description(), p.base(), p.scope(), p.filter(), String.valueOf(serviceDrivers.get(0).get("dn")), true,
                p.members(), p.excluded(), p.grants(), p.criteria());
        }
        String containerDn = Names.child(setDn, "cn", CONTAINER);
        Ldap.Entry c = l.read(containerDn, "cn");
        if (!s.principal.may(Role.OPERATOR, containerDn)) {
            throw new Http.Problem(403, "out-of-scope", "creating an entitlement policy needs an operator role that reaches " + containerDn);
        }
        Map<String, Definition> defs = definitions(l, setDn);
        check(l, p, defs);
        String dn = Names.child(containerDn, "cn", name);
        if (c != null && l.read(dn, "cn") != null) {
            throw new Http.Problem(409, "exists", "there is already a policy named " + name);
        }
        Map<String, Object> detail = detail(dn, p);
        try {
            if (c == null) {
                l.create(containerDn, Map.of("objectClass", List.of("Top", Rbe.OC_SET), "cn", List.of(CONTAINER)));
            }
            Map<String, List<Object>> attrs = new LinkedHashMap<>();
            attrs.put("objectClass", List.of("Top", Rbe.OC_POLICY));
            attrs.put("cn", List.of(name));
            attributes(p, defs, containerDn).forEach((k, v) -> {
                if (!v.isEmpty()) {
                    attrs.put(k, v);
                }
            });
            l.create(dn, attrs);
            Ldap.Entry container = l.read(containerDn, "GUID", "cn", "DirXML-SPPriority");
            Map<String, Integer> levels = Rbe.levels(container.attributes().get("dirxml-sppriority"));
            List<String> order = new ArrayList<>();
            for (Ldap.Entry other : l.search(containerDn, "(objectClass=" + Rbe.OC_POLICY + ")", null, SearchControls.ONELEVEL_SCOPE, new String[] {"cn"}, 1000)) {
                if (!Names.same(other.dn(), dn)) {
                    order.add(other.dn());
                }
            }
            order.sort(Comparator.comparing((String d) -> levels.getOrDefault(Names.canonical(d), Integer.MAX_VALUE)).thenComparing(String.CASE_INSENSITIVE_ORDER));
            order.add(dn);
            List<Object> values = new ArrayList<>();
            for (int i = 0; i < order.size(); i++) {
                values.add(order.get(i) + "#" + i + "#0");
            }
            BasicAttribute a = new BasicAttribute("DirXML-SPPriority");
            values.forEach(a::add);
            l.modify(containerDn, List.of(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, a)));
        } catch (NamingException x) {
            server.objects.audit(s, "idm.rbe.create", null, detail, Ldap.Failure.of(x));
            throw x;
        }
        Ldap.Entry made = l.read(dn, "GUID");
        String guid = made == null || made.attributes().get("guid") == null ? null : Names.guidHex(made.attributes().get("guid").get(0));
        server.objects.audit(s, "idm.rbe.create", guid, detail, null);
        Http.json(ex, 201, Map.of("guid", guid == null ? "" : guid, "dn", dn));
    }

    /** A policy changed from the version read: each edited attribute replaced, or cleared when left out. */
    void change(HttpExchange ex, Ldap l, Sessions.Session s, String guid, Ldap.Entry policy) throws IOException, NamingException {
        if (!s.principal.may(Role.OPERATOR, policy.dn())) {
            throw new Http.Problem(403, "out-of-scope", "changing an entitlement policy needs an operator role that reaches " + policy.dn());
        }
        Map<String, Object> b = Http.body(ex);
        Ldap.Entry stored = l.read(policy.dn(), EDITED);
        if (!Http.string(b, "version", true).equals(version(stored))) {
            throw new Http.Problem(409, "changed", "the policy changed meanwhile; reload it and try again");
        }
        Spec p = spec(b);
        String setDn = Names.parent(Names.parent(policy.dn()));
        Map<String, Definition> defs = definitions(l, setDn);
        check(l, p, defs);
        List<ModificationItem> mods = new ArrayList<>();
        attributes(p, defs, Names.parent(policy.dn())).forEach((k, v) -> {
            boolean had = stored != null && !stored.attributes().getOrDefault(k.toLowerCase(Locale.ROOT), List.of()).isEmpty();
            if (!v.isEmpty()) {
                BasicAttribute a = new BasicAttribute(k);
                v.forEach(a::add);
                mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, a));
            } else if (had) {
                mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute(k)));
            }
        });
        Map<String, Object> detail = detail(policy.dn(), p);
        try {
            l.modify(policy.dn(), mods);
        } catch (NamingException x) {
            server.objects.audit(s, "idm.rbe.change", guid, detail, Ldap.Failure.of(x));
            throw x;
        }
        server.objects.audit(s, "idm.rbe.change", guid, detail, null);
        Http.json(ex, 200, Map.of("guid", guid, "dn", policy.dn()));
    }

    /** Everyone removed: no static members or exclusions, a query that matches nobody; the grants stay for the revocations. */
    void empty(HttpExchange ex, Ldap l, Sessions.Session s, String guid, Ldap.Entry policy) throws IOException, NamingException {
        if (!s.principal.may(Role.OPERATOR, policy.dn())) {
            throw new Http.Problem(403, "out-of-scope", "emptying an entitlement policy needs an operator role that reaches " + policy.dn());
        }
        Ldap.Entry stored = l.read(policy.dn(), EDITED);
        List<ModificationItem> mods = new ArrayList<>();
        for (String a : new String[] {"member", "excludedMember", "dgIdentity", "DirXML-SPFilterXML"}) {
            if (stored != null && !stored.attributes().getOrDefault(a.toLowerCase(Locale.ROOT), List.of()).isEmpty()) {
                mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute(a)));
            }
        }
        mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("memberQueryURL", queryUrl(Names.parent(policy.dn()), "base", NOBODY))));
        Map<String, Object> detail = Map.of("dn", policy.dn());
        try {
            l.modify(policy.dn(), mods);
        } catch (NamingException x) {
            server.objects.audit(s, "idm.rbe.empty", guid, detail, Ldap.Failure.of(x));
            throw x;
        }
        server.objects.audit(s, "idm.rbe.empty", guid, detail, null);
        Http.json(ex, 200, Map.of("guid", guid, "dn", policy.dn()));
    }

    /** Whether a policy has nobody left: no static members, and no query or the one that matches nobody. */
    static boolean emptied(Ldap.Entry stored) {
        if (stored == null) {
            return true;
        }
        boolean members = !stored.attributes().getOrDefault("member", List.of()).isEmpty();
        return !members && Rbe.query(stored.first("memberQueryURL")) == null;
    }

    /** What the editor needs beyond the policy's summary: the stored static members, the grants' values, and the version. */
    static Map<String, Object> editable(Ldap.Entry stored) {
        Map<String, Object> m = new LinkedHashMap<>();
        List<String> members = new ArrayList<>();
        for (Object o : stored == null ? List.<Object>of() : stored.attributes().getOrDefault("member", List.of())) {
            members.add(text(o));
        }
        m.put("staticMembers", members);
        m.put("emptied", emptied(stored));
        m.put("version", version(stored));
        return m;
    }

    /** Names that must exist, and grants that must fit their entitlement's definition. */
    private static void check(Ldap l, Spec p, Map<String, Definition> defs) throws NamingException {
        if (p.filter() != null && !p.base().isEmpty() && l.read(p.base(), "objectClass") == null) {
            throw new IllegalArgumentException("the membership's base " + p.base() + " was not found");
        }
        if (p.identity() != null && l.read(p.identity(), "objectClass") == null) {
            throw new IllegalArgumentException("the search identity " + p.identity() + " was not found");
        }
        for (String dn : p.members()) {
            if (l.read(dn, "objectClass") == null) {
                throw new IllegalArgumentException("the member " + dn + " was not found");
            }
        }
        for (String dn : p.excluded()) {
            if (l.read(dn, "objectClass") == null) {
                throw new IllegalArgumentException("the excluded " + dn + " was not found");
            }
        }
        for (Grant g : p.grants()) {
            Definition d = defs.get(Names.canonical(g.entitlement()));
            if (d == null) {
                throw new IllegalArgumentException(g.entitlement() + " is not an entitlement of this driver set's drivers");
            }
            if (d.kind().equals("none") && !g.values().isEmpty()) {
                throw new IllegalArgumentException(d.name() + " takes no values");
            }
            if (!d.kind().equals("none") && g.values().isEmpty()) {
                throw new IllegalArgumentException(d.name() + " needs a value");
            }
            if (d.kind().equals("list") && !d.values().containsAll(g.values())) {
                throw new IllegalArgumentException(d.name() + " takes only " + String.join(", ", d.values()));
            }
            if (!d.multiValued() && g.values().size() > 1) {
                throw new IllegalArgumentException(d.name() + " takes one value");
            }
        }
    }

    /** A version of the edited attributes as stored: a change made from an older read is refused. */
    static String version(Ldap.Entry stored) {
        StringBuilder b = new StringBuilder();
        for (String a : EDITED) {
            List<String> values = new ArrayList<>();
            for (Object o : stored == null ? List.<Object>of() : stored.attributes().getOrDefault(a.toLowerCase(Locale.ROOT), List.of())) {
                values.add(text(o));
            }
            values.sort(null);
            b.append(a).append('=').append(String.join("\u0000", values)).append('\n');
        }
        return Jobs.version(b.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static Map<String, Object> detail(String dn, Spec p) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("dn", dn);
        m.put("filter", p.filter());
        m.put("identity", p.identity());
        m.put("members", p.members().size());
        m.put("excluded", p.excluded().size());
        m.put("grants", p.grants().stream().map(g -> Names.identity(g.entitlement()).get("name") + (g.values().isEmpty() ? "" : " (" + g.values().size() + " values)")).toList());
        return m;
    }

    // ---- XML ---------------------------------------------------------------------------------------

    static Element xml(String text) {
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            f.setExpandEntityReferences(false);
            javax.xml.parsers.DocumentBuilder d = f.newDocumentBuilder();
            d.setErrorHandler(new org.xml.sax.helpers.DefaultHandler());
            return d.parse(new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8))).getDocumentElement();
        } catch (Exception x) {
            return null;
        }
    }

    private static Element child(Element parent, String tag) {
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element e && e.getTagName().equals(tag)) {
                return e;
            }
        }
        return null;
    }

    static String escape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private static String blank(String s) {
        return s == null || s.isEmpty() ? null : s;
    }

    private static String text(Object o) {
        return o instanceof byte[] b ? new String(b, StandardCharsets.UTF_8) : String.valueOf(o);
    }
}
