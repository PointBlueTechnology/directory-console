package com.pointblue.console.server.http;

import com.pointblue.console.server.auth.Role;
import com.pointblue.console.server.auth.Sessions;
import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.console.server.ldap.Names;
import com.pointblue.dirxml.dev.model.EntitlementPolicy;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
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
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Role-based entitlement (RBE) policies, read and changed over LDAP with the person's own rights. Grounded on
 * DirXMLDev's RBE work (docs/console-gaps.md §9: Designer's and the Entitlements Service shim's code, then a
 * policy deployed and cached on a lab tree):
 * <ul>
 * <li>A driver set holds one container, {@code cn=Entitlement Policies,<set>} ({@code DirXML-SharedProfileSet}),
 *     found by class. Its {@code DirXML-SPPriority} values {@code <policy dn>#<level>#0} order the policies; the
 *     levels must run 0, 1, 2 … with one per policy, or the Entitlements Service driver will not start.</li>
 * <li>Each policy is a {@code DirXML-SharedProfile}, a dynamic group: {@code description}; {@code memberQueryURL}
 *     ({@code ldap:///<base>??<one|sub>?<filter>?x-sparse}); {@code dgIdentity}; {@code member} and
 *     {@code excludedMember}; {@code DirXML-SPFilterXML} (the editors' criteria); {@code DirXML-EntitlementRef}
 *     {@code <entitlement dn>#0#<ref>…</ref>}, what it grants.</li>
 * <li>The Entitlements Service driver (shim {@link EntitlementPolicy#SERVICE_SHIM_CLASS}) reads the policies when it
 *     starts, so a change takes effect, and membership is evaluated again, when it restarts.</li>
 * </ul>
 *
 * <pre>
 * GET    /api/v2/trees/{tree}/idm/driversets/{guid}/rbe              container, service drivers, policies in priority order, version
 * PUT    /api/v2/trees/{tree}/idm/driversets/{guid}/rbe/priorities   {"version", "order": [policy guid…]}
 * GET    /api/v2/trees/{tree}/idm/rbe/policies/{guid}                one policy
 * GET    /api/v2/trees/{tree}/idm/rbe/policies/{guid}/members        its members, as the directory computes them
 * GET    /api/v2/trees/{tree}/idm/rbe/policies/{guid}/rights         ?under={guid or DN}: the objects whose ACL names it as trustee
 * DELETE /api/v2/trees/{tree}/idm/rbe/policies/{guid}                {"name", "force"?}: the policy's name, typed; refused (409)
 *                                                                    while it has members, unless forced (its grants then stay)
 * </pre>
 * Creating and changing policies, and the entitlements they can grant: {@link RbeEdit}.
 */
final class Rbe {

    static final String OC_SET = "DirXML-SharedProfileSet";
    static final String OC_POLICY = "DirXML-SharedProfile";
    private static final String[] POLICY_ATTRS = {"GUID", "cn", "description", "memberQueryURL", "dgIdentity", "excludedMember",
        "DirXML-EntitlementRef", "DirXML-SPEntitlementsXML"};

    private final Server server;
    private final RbeEdit edit;

    Rbe(Server server) {
        this.server = server;
        this.edit = new RbeEdit(server);
    }

    /** {@code rest}: what follows {@code driversets/{guid}/rbe} or {@code rbe/policies/{guid}}. */
    void handle(HttpExchange ex, Sessions.Session s, String method, String setGuid, String policyGuid, String rest) throws IOException {
        Ldap l = s.ldap();
        if (l == null) {
            throw new Http.Problem(503, "unavailable", "no directory connection");
        }
        try {
            if (setGuid != null) {
                String setDn = driverSet(l, setGuid);
                switch (method + " " + rest) {
                    case "GET " -> Http.json(ex, 200, list(l, setDn));
                    case "PUT priorities" -> priorities(ex, l, s, setDn);
                    case "GET entitlements" -> edit.entitlements(ex, l, setDn);
                    case "POST test" -> edit.test(ex, l, Http.body(ex));
                    case "POST policies" -> {
                        @SuppressWarnings("unchecked")
                        List<Map<String, Object>> drivers = (List<Map<String, Object>>) list(l, setDn).get("serviceDrivers");
                        edit.create(ex, l, s, setDn, drivers);
                    }
                    default -> throw new Http.Problem(404, "not-found", method + " rbe/" + rest);
                }
                return;
            }
            Ldap.Entry p = policy(l, policyGuid);
            switch (method + " " + rest) {
                case "GET " -> Http.json(ex, 200, detail(l, p));
                case "GET members" -> Http.json(ex, 200, members(l, p));
                case "GET rights" -> Http.json(ex, 200, rights(l, p, Http.query(ex).get("under")));
                case "PUT " -> edit.change(ex, l, s, policyGuid, p);
                case "POST empty" -> edit.empty(ex, l, s, policyGuid, p);
                case "DELETE " -> delete(ex, l, s, policyGuid, p);
                default -> throw new Http.Problem(404, "not-found", method + " rbe/policies/" + rest);
            }
        } catch (NamingException x) {
            throw server.objects.problem(s, Ldap.Failure.of(x));
        } catch (IllegalArgumentException x) {
            throw new Http.Problem(400, "bad-request", x.getMessage());
        }
    }

    private String driverSet(Ldap l, String guid) throws NamingException {
        Ldap.Entry e = server.objects.byGuid(l, guid, "objectClass");
        if (e == null || !classes(e).contains("dirxml-driverset")) {
            throw new Http.Problem(404, "not-found", guid + " is not a driver set");
        }
        return e.dn();
    }

    private Ldap.Entry policy(Ldap l, String guid) throws NamingException {
        Ldap.Entry e = server.objects.byGuid(l, guid, java.util.stream.Stream.concat(java.util.stream.Stream.of("objectClass"),
            java.util.Arrays.stream(POLICY_ATTRS)).toArray(String[]::new));
        if (e == null || !classes(e).contains(OC_POLICY.toLowerCase(Locale.ROOT))) {
            throw new Http.Problem(404, "not-found", guid + " is not an entitlement policy");
        }
        return e;
    }

    /** The set's policy container (the first, as the shim takes it), or null. */
    private static Ldap.Entry container(Ldap l, String setDn) throws NamingException {
        List<Ldap.Entry> sets = l.search(setDn, "(objectClass=" + OC_SET + ")", null, SearchControls.ONELEVEL_SCOPE,
            new String[] {"GUID", "cn", "DirXML-SPPriority"}, 10);
        sets.sort(Comparator.comparing(Ldap.Entry::dn, String.CASE_INSENSITIVE_ORDER));
        return sets.isEmpty() ? null : sets.get(0);
    }

    private static List<Ldap.Entry> policies(Ldap l, String containerDn) throws NamingException {
        return l.search(containerDn, "(objectClass=" + OC_POLICY + ")", null, SearchControls.ONELEVEL_SCOPE, POLICY_ATTRS, 1000);
    }

    /**
     * One {@code DirXML-SPPriority} typed name, {@code <dn>#<level>#<interval>}, as its DN and level; null when it does
     * not parse. Read from the right: the level and interval are the last two fields, and a DN may hold a {@code #}
     * ({@code cn=Team#1}), which a split from the left would take for the separator.
     */
    static Map.Entry<String, Integer> typedName(String v) {
        int last = v.lastIndexOf('#');
        int mid = last <= 0 ? -1 : v.lastIndexOf('#', last - 1);
        if (mid <= 0) {
            return null;
        }
        try {
            return Map.entry(v.substring(0, mid), Integer.parseInt(v.substring(mid + 1, last).trim()));
        } catch (NumberFormatException x) {
            return null;
        }
    }

    /** {@code DirXML-SPPriority} as policy DN (canonical) to level; values that do not parse are left out. */
    static Map<String, Integer> levels(List<Object> values) {
        Map<String, Integer> out = new LinkedHashMap<>();
        for (Object o : values == null ? List.<Object>of() : values) {
            Map.Entry<String, Integer> t = typedName(text(o));
            if (t != null) {
                try {
                    out.put(Names.canonical(t.getKey()), t.getValue());
                } catch (IllegalArgumentException x) {
                    // not a DN: the shim would refuse it too, and the list says so
                }
            }
        }
        return out;
    }

    /** Why the Entitlements Service driver would refuse these priorities, or empty: one each, levels 0, 1, 2 … */
    static List<String> priorityProblems(Map<String, Integer> levels, List<String> policyDns) {
        List<String> out = new ArrayList<>();
        Set<String> dns = new HashSet<>();
        for (String dn : policyDns) {
            dns.add(Names.canonical(dn));
            if (!levels.containsKey(Names.canonical(dn))) {
                out.add(Names.identity(dn).get("name") + " has no priority");
            }
        }
        for (String dn : levels.keySet()) {
            if (!dns.contains(dn)) {
                out.add("a priority names " + dn + ", which is not a policy here");
            }
        }
        List<Integer> sorted = levels.values().stream().sorted().toList();
        for (int i = 0; i < sorted.size(); i++) {
            if (sorted.get(i) != i) {
                out.add("the priorities are not 0, 1, 2 … without gaps or repeats");
                break;
            }
        }
        return out;
    }

    /** A version of the container's order and its policies: a reorder made from an older read is refused. */
    private static String version(Ldap.Entry container, List<Ldap.Entry> policies) {
        StringBuilder b = new StringBuilder();
        levels(container.attributes().get("dirxml-sppriority")).entrySet().stream().map(e -> e.getKey() + "#" + e.getValue()).sorted()
            .forEach(v -> b.append(v).append('\n'));
        policies.stream().map(p -> Names.canonical(p.dn())).sorted().forEach(d -> b.append(d).append('\n'));
        return Jobs.version(b.toString().getBytes(StandardCharsets.UTF_8));
    }

    private Map<String, Object> list(Ldap l, String setDn) throws NamingException {
        Map<String, Object> out = new LinkedHashMap<>();
        List<Map<String, Object>> drivers = new ArrayList<>();
        for (Ldap.Entry d : l.search(setDn, "(DirXML-JavaModule=" + EntitlementPolicy.SERVICE_SHIM_CLASS + ")", null, SearchControls.ONELEVEL_SCOPE,
                new String[] {"GUID", "cn"}, 20)) {
            drivers.add(ref(d));
        }
        out.put("serviceDrivers", drivers);
        Ldap.Entry c = container(l, setDn);
        if (c == null) {
            out.put("container", null);
            out.put("policies", List.of());
            out.put("problems", List.of());
            return out;
        }
        List<Ldap.Entry> found = policies(l, c.dn());
        Map<String, Integer> levels = levels(c.attributes().get("dirxml-sppriority"));
        found.sort(Comparator.comparing((Ldap.Entry e) -> levels.getOrDefault(Names.canonical(e.dn()), Integer.MAX_VALUE))
            .thenComparing(Ldap.Entry::dn, String.CASE_INSENSITIVE_ORDER));
        out.put("container", ref(c));
        out.put("version", version(c, found));
        List<Map<String, Object>> items = new ArrayList<>();
        for (Ldap.Entry p : found) {
            Map<String, Object> m = summary(p);
            m.put("priority", levels.get(Names.canonical(p.dn())));
            items.add(m);
        }
        out.put("policies", items);
        out.put("problems", priorityProblems(levels, found.stream().map(Ldap.Entry::dn).toList()));
        return out;
    }

    /** What a list row shows of a policy. */
    private static Map<String, Object> summary(Ldap.Entry p) {
        Map<String, Object> m = ref(p);
        m.put("description", p.first("description"));
        m.put("membership", query(p.first("memberQueryURL")));
        m.put("excluded", p.attributes().getOrDefault("excludedmember", List.of()).size());
        List<Map<String, Object>> grants = new ArrayList<>();
        for (Object o : p.attributes().getOrDefault("dirxml-entitlementref", List.of())) {
            grants.add(grant(text(o)));
        }
        m.put("grants", grants);
        String legacy = p.first("DirXML-SPEntitlementsXML");
        // the shim refuses a policy with a legacy entitlements document ("unconverted policy")
        m.put("legacy", legacy != null && !legacy.isBlank());
        return m;
    }

    private Map<String, Object> detail(Ldap l, Ldap.Entry p) throws NamingException {
        Map<String, Object> m = summary(p);
        m.put("identity", p.first("dgIdentity") == null ? null : Names.identity(p.first("dgIdentity")));
        List<Map<String, Object>> excluded = new ArrayList<>();
        for (Object o : p.attributes().getOrDefault("excludedmember", List.of())) {
            excluded.add(Names.identity(text(o)));
        }
        m.put("excludedMembers", excluded);
        // the grants with the entitlement's own name and its driver, read from the entitlement object
        for (Object o : (List<?>) m.get("grants")) {
            @SuppressWarnings("unchecked")
            Map<String, Object> g = (Map<String, Object>) o;
            Ldap.Entry e = l.read(String.valueOf(g.get("dn")), "GUID", "cn");
            g.put("exists", e != null);
            if (e != null) {
                g.put("guid", ref(e).get("guid"));
            }
        }
        Ldap.Entry stored = l.read(p.dn(), RbeEdit.EDITED);
        m.put("criteria", stored == null ? null : stored.first("DirXML-SPFilterXML"));
        m.putAll(RbeEdit.editable(stored));
        m.put("identityDn", p.first("dgIdentity"));
        // the grants as the editor holds them: each entitlement once, with the values its refs grant
        Map<String, Map<String, Object>> byEntitlement = new LinkedHashMap<>();
        for (Object o : (List<?>) m.get("grants")) {
            @SuppressWarnings("unchecked")
            Map<String, Object> g = (Map<String, Object>) o;
            Map<String, Object> e = byEntitlement.computeIfAbsent(Names.canonical(String.valueOf(g.get("dn"))), k -> {
                Map<String, Object> n = new LinkedHashMap<>();
                n.put("entitlement", g.get("dn"));
                n.put("values", new ArrayList<String>());
                return n;
            });
            Element ref = RbeEdit.xml(String.valueOf(g.get("ref")));
            if (ref != null) {
                for (Node n = ref.getFirstChild(); n != null; n = n.getNextSibling()) {
                    if (n instanceof Element param && param.getTagName().equals("param")) {
                        @SuppressWarnings("unchecked")
                        List<String> values = (List<String>) e.get("values");
                        values.add(param.getTextContent());
                    }
                }
            }
        }
        m.put("grantValues", new ArrayList<>(byEntitlement.values()));
        return m;
    }

    /** The policy's members as eDirectory computes them for the dynamic group (static and from the query, as its search identity). */
    private Map<String, Object> members(Ldap l, Ldap.Entry p) throws NamingException {
        Ldap.Entry e = l.readComputed(p.dn(), "member");
        List<Map<String, Object>> items = new ArrayList<>();
        for (Object o : e == null ? List.<Object>of() : e.attributes().getOrDefault("member", List.of())) {
            items.add(Names.identity(text(o)));
        }
        items.sort(Comparator.comparing(m -> String.valueOf(m.get("name")).toLowerCase(Locale.ROOT)));
        return Map.of("items", items, "total", items.size());
    }

    /** How many objects a rights scan reads at most: eDirectory matches an ACL value only whole, so no search finds a trustee. */
    static final int RIGHTS_SCAN_LIMIT = 50_000;

    /**
     * Rights to other objects: its members get them, being security-equivalent to the dynamic group. eDirectory matches
     * an ACL value only whole (privileges, scope, trustee and attribute alike, a lab tree), so the objects under
     * {@code under} (the whole tree by default) with an ACL are read a page at a time, and the values naming the policy kept.
     */
    private Map<String, Object> rights(Ldap l, Ldap.Entry p, String under) throws NamingException {
        String base = under == null || under.isBlank() ? "" : Names.guid(under) ? server.objects.dnOf(l, under) : Names.parse(under).toString();
        String policy = Names.canonical(p.dn());
        List<Map<String, Object>> items = new ArrayList<>();
        int scanned = 0;
        byte[] cookie = null;
        do {
            Ldap.Paged page = l.page(base, "(ACL=*)", null, SearchControls.SUBTREE_SCOPE, new String[] {"GUID", "ACL"}, 500, cookie);
            for (Ldap.Entry e : page.entries()) {
                scanned++;
                List<Map<String, Object>> acls = new ArrayList<>();
                for (Object o : e.attributes().getOrDefault("acl", List.of())) {
                    Map<String, Object> acl = com.pointblue.console.server.ldap.Values.acl(text(o));
                    if (acl != null && acl.get("trustee") instanceof Map<?, ?> t && t.get("dn") != null) {
                        try {
                            if (Names.canonical(String.valueOf(t.get("dn"))).equals(policy)) {
                                acls.add(acl);
                            }
                        } catch (IllegalArgumentException x) {
                            // not a DN: not this policy
                        }
                    }
                }
                if (!acls.isEmpty()) {
                    Map<String, Object> m = ref(e);
                    m.put("acls", acls);
                    items.add(m);
                }
            }
            cookie = page.cookie();
        } while (cookie != null && scanned < RIGHTS_SCAN_LIMIT);
        items.sort(Comparator.comparing(m -> String.valueOf(m.get("dn")).toLowerCase(Locale.ROOT)));
        return Map.of("items", items, "scanned", scanned, "complete", cookie == null, "under", base);
    }

    private void priorities(HttpExchange ex, Ldap l, Sessions.Session s, String setDn) throws IOException, NamingException {
        Map<String, Object> b = Http.body(ex);
        Ldap.Entry c = container(l, setDn);
        if (c == null) {
            throw new Http.Problem(404, "not-found", "this driver set has no entitlement policies");
        }
        if (!s.principal.may(Role.OPERATOR, c.dn())) {
            throw new Http.Problem(403, "out-of-scope", "reordering entitlement policies needs an operator role that reaches " + c.dn());
        }
        List<Ldap.Entry> found = policies(l, c.dn());
        if (!Http.string(b, "version", true).equals(version(c, found))) {
            throw new Http.Problem(409, "changed", "the policies or their order changed meanwhile; reload and try again");
        }
        if (!(b.get("order") instanceof List<?> order)) {
            throw new IllegalArgumentException("order is the list of every policy's guid, highest priority first");
        }
        Map<String, Ldap.Entry> byGuid = new LinkedHashMap<>();
        for (Ldap.Entry p : found) {
            byGuid.put(String.valueOf(ref(p).get("guid")), p);
        }
        List<String> dns = new ArrayList<>();
        for (Object g : order) {
            Ldap.Entry p = byGuid.get(String.valueOf(g).toLowerCase(Locale.ROOT));
            if (p == null || dns.contains(p.dn())) {
                throw new IllegalArgumentException("order names every policy once: " + g + " is not one, or is named twice");
            }
            dns.add(p.dn());
        }
        if (dns.size() != found.size()) {
            throw new IllegalArgumentException("order names every policy once: " + found.size() + " expected, " + dns.size() + " given");
        }
        write(l, s, c, dns, "idm.rbe.priorities", null);
        Http.json(ex, 200, list(l, setDn));
    }

    /** The container's priorities rewritten as 0, 1, 2 … in {@code dns}' order. */
    private void write(Ldap l, Sessions.Session s, Ldap.Entry c, List<String> dns, String action, String guid) throws NamingException, IOException {
        List<Object> values = new ArrayList<>();
        for (int i = 0; i < dns.size(); i++) {
            values.add(dns.get(i) + "#" + i + "#0");
        }
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("container", c.dn());
        detail.put("order", dns.stream().map(d -> Names.identity(d).get("name")).toList());
        BasicAttribute a = new BasicAttribute("DirXML-SPPriority");
        values.forEach(a::add);
        try {
            l.modify(c.dn(), List.of(new ModificationItem(values.isEmpty() ? DirContext.REMOVE_ATTRIBUTE : DirContext.REPLACE_ATTRIBUTE, a)));
        } catch (NamingException x) {
            if (!(values.isEmpty() && x instanceof javax.naming.directory.NoSuchAttributeException)) {
                server.objects.audit(s, action, guid, detail, Ldap.Failure.of(x));
                throw x;
            }
        }
        if (action.equals("idm.rbe.priorities")) {
            server.objects.audit(s, action, guid, detail, null);
        }
    }

    private void delete(HttpExchange ex, Ldap l, Sessions.Session s, String guid, Ldap.Entry p) throws IOException, NamingException {
        if (!s.principal.may(Role.OPERATOR, p.dn())) {
            throw new Http.Problem(403, "out-of-scope", "deleting an entitlement policy needs an operator role that reaches " + p.dn());
        }
        String name = String.valueOf(Names.identity(p.dn()).get("name"));
        Map<String, Object> body = Http.body(ex);
        if (!name.equals(Http.string(body, "name", true).trim())) {
            throw new Http.Problem(400, "confirm-name", "type the policy's name, " + name + ", to delete it");
        }
        boolean force = Boolean.TRUE.equals(body.get("force"));
        if (!force && !RbeEdit.emptied(l.read(p.dn(), "member", "memberQueryURL"))) {
            // the shim ignores a deleted policy: whatever it granted would stay
            throw new Http.Problem(409, "not-emptied", name + " still has members. Remove everyone first, and restart the Entitlements Service "
                + "driver so it revokes what the policy granted; deleting it now would leave those grants in place.");
        }
        Map<String, Object> detail = Map.of("dn", p.dn(), "forced", force);
        try {
            l.delete(p.dn());
        } catch (NamingException x) {
            server.objects.audit(s, "idm.rbe.delete", guid, detail, Ldap.Failure.of(x));
            throw x;
        }
        // the rest keep their order, renumbered without the gap the shim would refuse
        Ldap.Entry c = l.read(Names.parent(p.dn()), "GUID", "cn", "DirXML-SPPriority");
        if (c != null) {
            List<Ldap.Entry> rest = policies(l, c.dn());
            Map<String, Integer> levels = levels(c.attributes().get("dirxml-sppriority"));
            rest.sort(Comparator.comparing((Ldap.Entry e) -> levels.getOrDefault(Names.canonical(e.dn()), Integer.MAX_VALUE))
                .thenComparing(Ldap.Entry::dn, String.CASE_INSENSITIVE_ORDER));
            write(l, s, c, rest.stream().map(Ldap.Entry::dn).toList(), "idm.rbe.delete", guid);
        }
        server.objects.audit(s, "idm.rbe.delete", guid, detail, null);
        Http.json(ex, 200, Map.of("deleted", p.dn()));
    }

    /** {@code ldap:///<base>??<scope>?<filter>?x-sparse} as its parts, or null when there is no query (or {@link RbeEdit#NOBODY}'s). */
    static Map<String, Object> query(String url) {
        if (url == null || url.isBlank()) {
            return null;
        }
        Map<String, Object> parsed = parse(url);
        return "base".equals(parsed.get("scope")) && RbeEdit.NOBODY.equals(parsed.get("filter")) ? null : parsed;
    }

    private static Map<String, Object> parse(String url) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("url", url);
        String rest = url.replaceFirst("(?i)^ldap://[^/]*/", "");
        String[] parts = rest.split("\\?", -1);
        m.put("base", parts.length > 0 ? java.net.URLDecoder.decode(parts[0].replace("+", "%2B"), StandardCharsets.UTF_8) : "");
        m.put("scope", parts.length > 2 && !parts[2].isBlank() ? parts[2].toLowerCase(Locale.ROOT) : "base");
        m.put("filter", parts.length > 3 ? java.net.URLDecoder.decode(parts[3].replace("+", "%2B"), StandardCharsets.UTF_8) : "");
        return m;
    }

    /** A path value {@code <dn>#<level>#<xml>}: the XML starts with "<", which a DN never holds unescaped. */
    private static final java.util.regex.Pattern PATH = java.util.regex.Pattern.compile("^(.*?)#(\\d+)#(<.*)$", java.util.regex.Pattern.DOTALL);

    /**
     * One {@code DirXML-EntitlementRef} value: the entitlement, its driver, and the ref document (values granted).
     * Split where the XML starts, so a {@code #} in the entitlement's DN or in the values is kept.
     */
    static Map<String, Object> grant(String value) {
        Map<String, Object> m = new LinkedHashMap<>();
        java.util.regex.Matcher x = PATH.matcher(value);
        String dn = x.matches() ? x.group(1) : EntitlementPolicy.refDn(value);
        m.put("dn", dn);
        try {
            m.put("entitlement", Names.identity(dn).get("name"));
            m.put("driver", Names.identity(Names.parent(dn)).get("name"));
        } catch (IllegalArgumentException e) {
            m.put("entitlement", dn);
            m.put("driver", null);
        }
        m.put("ref", x.matches() ? x.group(3) : EntitlementPolicy.refXml(value));
        return m;
    }

    private static Map<String, Object> ref(Ldap.Entry e) {
        Map<String, Object> m = new LinkedHashMap<>(Names.identity(e.dn()));
        List<Object> g = e.attributes().get("guid");
        m.put("guid", g == null || g.isEmpty() ? null : Names.guidHex(g.get(0)));
        return m;
    }

    private static Set<String> classes(Ldap.Entry e) {
        Set<String> out = new HashSet<>();
        for (Object c : e.attributes().getOrDefault("objectclass", List.of())) {
            out.add(String.valueOf(c).toLowerCase(Locale.ROOT));
        }
        return out;
    }

    private static String text(Object o) {
        return o instanceof byte[] b ? new String(b, StandardCharsets.UTF_8) : String.valueOf(o);
    }
}
