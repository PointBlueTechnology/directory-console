package com.pointblue.console.server.ldap;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import javax.naming.NamingException;

/**
 * A directory's schema, read once from its subschema entry and parsed from the RFC 4512 descriptions,
 * including eDirectory's {@code X-NDS_*} extensions.
 *
 * <p><b>Containers.</b> eDirectory marks leaf classes with {@code X-NDS_NOT_CONTAINER '1'}; a structural
 * class without it is a container, except one with {@code X-NDS_AMBIGUOUS_CONTAINMENT} (such as
 * {@code Top}, which every entry carries). The rule is the one ArborJ and Arbor settled on.
 */
public final class Schema {

    /** RFC 4517 / eDirectory syntax OIDs the console treats specially. */
    public static final String DN_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.12";
    public static final String ACL_SYNTAX = "2.16.840.1.113719.1.1.5.1.17";
    /** Syntaxes whose values are bytes: octet string, binary, certificates, JPEG, audio, fax. */
    static final Set<String> BINARY_SYNTAXES = Set.of(
        "1.3.6.1.4.1.1466.115.121.1.40", "1.3.6.1.4.1.1466.115.121.1.5", "1.3.6.1.4.1.1466.115.121.1.8",
        "1.3.6.1.4.1.1466.115.121.1.9", "1.3.6.1.4.1.1466.115.121.1.10", "1.3.6.1.4.1.1466.115.121.1.28",
        "1.3.6.1.4.1.1466.115.121.1.4", "1.3.6.1.4.1.1466.115.121.1.23");

    public record ObjectClass(String oid, List<String> names, List<String> superiors, String kind,
                              List<String> must, List<String> may, boolean container, List<String> containment,
                              List<String> naming, List<String> ndsFlags, String ndsName) {
        public String name() {
            return names.isEmpty() ? oid : names.get(0);
        }

        /** Not part of eDirectory's base schema ({@code X-NDS_NONREMOVABLE}), so it may be deleted when unused. */
        public boolean removable() {
            return !ndsFlags.contains("X-NDS_NONREMOVABLE");
        }
    }

    /** {@code perReplica}: eDirectory never synchronizes it ({@code X-NDS_NEVER_SYNC}); each server keeps its own value. */
    public record AttributeType(String oid, List<String> names, String syntax, boolean singleValue,
                                boolean readOnly, boolean operational, String ndsName, boolean perReplica, List<String> ndsFlags) {
        public String name() {
            return names.isEmpty() ? oid : names.get(0);
        }

        /** Not part of eDirectory's base schema ({@code X-NDS_NONREMOVABLE}). */
        public boolean removable() {
            return !ndsFlags.contains("X-NDS_NONREMOVABLE");
        }

        public boolean binary() {
            return BINARY_SYNTAXES.contains(syntax);
        }

        public boolean dn() {
            return DN_SYNTAX.equals(syntax);
        }
    }

    private final Map<String, ObjectClass> classes = new LinkedHashMap<>();
    private final Map<String, AttributeType> attributes = new LinkedHashMap<>();
    private final Map<String, ObjectClass> classByName = new LinkedHashMap<>();
    private final Map<String, AttributeType> attributeByName = new LinkedHashMap<>();

    public Schema(Collection<String> classDefinitions, Collection<String> attributeDefinitions) {
        for (String d : attributeDefinitions) {
            Map<String, List<String>> p = parse(d);
            AttributeType a = new AttributeType(p.get("").get(0), p.getOrDefault("NAME", List.of()),
                first(p, "SYNTAX") == null ? null : first(p, "SYNTAX").replaceAll("\\{\\d+}$", ""),
                p.containsKey("SINGLE-VALUE"), p.containsKey("NO-USER-MODIFICATION"),
                first(p, "USAGE") != null && !first(p, "USAGE").equals("userApplications"), first(p, "X-NDS_NAME"), flag(p, "X-NDS_NEVER_SYNC"), flags(p));
            attributes.put(a.oid(), a);
            a.names().forEach(n -> attributeByName.put(n.toLowerCase(Locale.ROOT), a));
            attributeByName.put(a.oid(), a);
        }
        for (String d : classDefinitions) {
            Map<String, List<String>> p = parse(d);
            String kind = p.containsKey("AUXILIARY") ? "auxiliary" : p.containsKey("ABSTRACT") ? "abstract" : "structural";
            boolean container = kind.equals("structural") && !flag(p, "X-NDS_NOT_CONTAINER") && !p.containsKey("X-NDS_AMBIGUOUS_CONTAINMENT");
            ObjectClass c = new ObjectClass(p.get("").get(0), p.getOrDefault("NAME", List.of()), p.getOrDefault("SUP", List.of()), kind,
                p.getOrDefault("MUST", List.of()), p.getOrDefault("MAY", List.of()), container,
                p.getOrDefault("X-NDS_CONTAINMENT", List.of()), p.getOrDefault("X-NDS_NAMING", List.of()), flags(p), first(p, "X-NDS_NAME"));
            classes.put(c.oid(), c);
            c.names().forEach(n -> classByName.put(n.toLowerCase(Locale.ROOT), c));
            classByName.put(c.oid(), c);
        }
    }

    /** Read the schema named by the root DSE's {@code subschemaSubentry}. */
    public static Schema load(Ldap l) throws NamingException {
        Ldap.Entry root = l.read("", "subschemaSubentry");
        String dn = root == null || root.first("subschemaSubentry") == null ? "cn=schema" : root.first("subschemaSubentry");
        Ldap.Entry s = l.read(dn, "objectClasses", "attributeTypes");
        if (s == null) {
            throw new NamingException("the schema entry " + dn + " could not be read");
        }
        return new Schema(strings(s.attributes().get("objectclasses")), strings(s.attributes().get("attributetypes")));
    }

    private static List<String> strings(List<Object> v) {
        List<String> out = new ArrayList<>();
        if (v != null) {
            v.forEach(o -> out.add(String.valueOf(o)));
        }
        return out;
    }

    public ObjectClass objectClass(String name) {
        return name == null ? null : classByName.get(name.toLowerCase(Locale.ROOT));
    }

    public AttributeType attribute(String name) {
        return name == null ? null : attributeByName.get(name.toLowerCase(Locale.ROOT));
    }

    public Collection<ObjectClass> objectClasses() {
        return classes.values();
    }

    public Collection<AttributeType> attributeTypes() {
        return attributes.values();
    }

    /** Whether any of an entry's classes is a container class. */
    public boolean container(Collection<?> objectClasses) {
        for (Object o : objectClasses) {
            ObjectClass c = objectClass(String.valueOf(o));
            if (c != null && c.container()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether an entry is a container, by its base class (its most derived structural class) as eDirectory
     * decides containment: a user ({@code inetOrgPerson}, marked not a container) stays a leaf even when a
     * superclass in its chain carries no {@code X-NDS_NOT_CONTAINER}. When no base class is known, any of its
     * classes decides, as before.
     */
    public boolean entryIsContainer(Collection<?> objectClasses) {
        List<?> list = objectClasses instanceof List<?> l ? l : new ArrayList<>(objectClasses);
        String base = structural(list);
        ObjectClass c = base == null ? null : objectClass(base);
        return c != null ? c.container() : container(objectClasses);
    }

    /**
     * An LDAP filter for container entries: one of the container classes, and not a leaf class that inherits
     * from one (whose entries carry the container superclass in {@code objectClass} too).
     */
    public String containerFilter() {
        StringBuilder in = new StringBuilder("(|");
        containerClasses().forEach(n -> in.append("(objectClass=").append(n).append(')'));
        in.append(')');
        List<String> leaves = new ArrayList<>();
        for (ObjectClass c : classes.values()) {
            if (c.kind().equals("structural") && !c.container() && inheritsContainer(c, 0)) {
                leaves.add(c.name());
            }
        }
        if (leaves.isEmpty()) {
            return in.toString();
        }
        StringBuilder out = new StringBuilder("(&").append(in).append("(!(|");
        leaves.forEach(n -> out.append("(objectClass=").append(n).append(')'));
        return out.append(")))").toString();
    }

    private boolean inheritsContainer(ObjectClass c, int guard) {
        if (guard > 32) {
            return false;
        }
        for (String s : c.superiors()) {
            ObjectClass p = objectClass(s);
            if (p != null && (p.container() || inheritsContainer(p, guard + 1))) {
                return true;
            }
        }
        return false;
    }

    /** The names of every container class, for a containers-only children filter. */
    public List<String> containerClasses() {
        return classes.values().stream().filter(ObjectClass::container).map(ObjectClass::name).toList();
    }

    /** The structural class an entry was created as: its class that the others inherit from least. */
    public String structural(List<?> objectClasses) {
        String best = null;
        int depth = -1;
        for (Object o : objectClasses) {
            ObjectClass c = objectClass(String.valueOf(o));
            if (c != null && c.kind().equals("structural") && !c.names().contains("Top") && !c.names().contains("top")) {
                int d = depth(c, 0);
                if (d > depth) {
                    depth = d;
                    best = c.name();
                }
            }
        }
        return best != null ? best : objectClasses.isEmpty() ? null : String.valueOf(objectClasses.get(0));
    }

    private int depth(ObjectClass c, int guard) {
        int d = 0;
        if (guard > 32) {
            return d;
        }
        for (String s : c.superiors()) {
            ObjectClass p = objectClass(s);
            if (p != null) {
                d = Math.max(d, 1 + depth(p, guard + 1));
            }
        }
        return d;
    }

    /** The naming attributes of {@code className}, inherited from the nearest superior that names them. */
    public List<String> naming(String className) {
        return inherited(className, ObjectClass::naming, 0);
    }

    /** The classes {@code className} may be created under, inherited the same way. */
    public List<String> containment(String className) {
        return inherited(className, ObjectClass::containment, 0);
    }

    private List<String> inherited(String className, java.util.function.Function<ObjectClass, List<String>> f, int guard) {
        ObjectClass c = objectClass(className);
        if (c == null || guard > 32) {
            return List.of();
        }
        if (!f.apply(c).isEmpty()) {
            return f.apply(c);
        }
        for (String s : c.superiors()) {
            List<String> v = inherited(s, f, guard + 1);
            if (!v.isEmpty()) {
                return v;
            }
        }
        return List.of();
    }

    /** MUST and MAY of {@code className}, including its superiors'. */
    public Set<String> must(String className) {
        return collect(className, true, new LinkedHashSet<>(), 0);
    }

    public Set<String> may(String className) {
        return collect(className, false, new LinkedHashSet<>(), 0);
    }

    private Set<String> collect(String className, boolean must, Set<String> out, int guard) {
        ObjectClass c = objectClass(className);
        if (c == null || guard > 32) {
            return out;
        }
        out.addAll(must ? c.must() : c.may());
        for (String s : c.superiors()) {
            collect(s, must, out, guard + 1);
        }
        return out;
    }

    /** Attribute names whose values are bytes. */
    public List<String> binaryAttributes() {
        List<String> out = new ArrayList<>();
        for (AttributeType a : attributes.values()) {
            if (a.binary()) {
                out.addAll(a.names());
            }
        }
        return out;
    }

    // ---- RFC 4512 description parsing -------------------------------------------------------

    private static String first(Map<String, List<String>> p, String k) {
        List<String> v = p.get(k);
        return v == null || v.isEmpty() ? null : v.get(0);
    }

    /** The {@code X-NDS_*} extensions set to '1' (eDirectory's attribute and class flags). */
    private static List<String> flags(Map<String, List<String>> p) {
        List<String> out = new ArrayList<>();
        for (String k : p.keySet()) {
            if (k.startsWith("X-NDS_") && flag(p, k)) {
                out.add(k);
            }
        }
        return List.copyOf(out);
    }

    private static boolean flag(Map<String, List<String>> p, String k) {
        String v = first(p, k);
        return v != null && (v.equals("1") || v.equalsIgnoreCase("true"));
    }

    /**
     * {@code ( oid KEY value KEY ( a $ b ) FLAG ... )} into KEY → values; the OID is under "".
     * Quoted strings lose their quotes; {@code $} separators are dropped.
     */
    static Map<String, List<String>> parse(String def) {
        List<String> tokens = tokens(def);
        Map<String, List<String>> out = new LinkedHashMap<>();
        int i = 0;
        if (i < tokens.size() && tokens.get(i).equals("(")) {
            i++;
        }
        out.put("", List.of(i < tokens.size() ? tokens.get(i++) : ""));
        while (i < tokens.size()) {
            String key = tokens.get(i++);
            if (key.equals(")")) {
                break;
            }
            List<String> values = new ArrayList<>();
            if (i < tokens.size() && tokens.get(i).equals("(")) {
                i++;
                while (i < tokens.size() && !tokens.get(i).equals(")")) {
                    String t = tokens.get(i++);
                    if (!t.equals("$")) {
                        values.add(unquote(t));
                    }
                }
                i++;
            } else if (i < tokens.size() && !isKeyword(tokens.get(i))) {
                values.add(unquote(tokens.get(i++)));
            }
            out.put(key, values);
        }
        return out;
    }

    private static boolean isKeyword(String t) {
        return t.equals(")") || (!t.startsWith("'") && t.equals(t.toUpperCase(Locale.ROOT)) && t.matches("[A-Z][A-Z0-9_-]*"));
    }

    private static String unquote(String t) {
        return t.startsWith("'") && t.endsWith("'") && t.length() >= 2 ? t.substring(1, t.length() - 1) : t;
    }

    private static List<String> tokens(String s) {
        List<String> out = new ArrayList<>();
        int i = 0;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (Character.isWhitespace(c)) {
                i++;
            } else if (c == '(' || c == ')') {
                out.add(String.valueOf(c));
                i++;
            } else if (c == '\'') {
                int j = s.indexOf('\'', i + 1);
                j = j < 0 ? s.length() - 1 : j;
                out.add(s.substring(i, j + 1));
                i = j + 1;
            } else {
                int j = i;
                while (j < s.length() && !Character.isWhitespace(s.charAt(j)) && s.charAt(j) != '(' && s.charAt(j) != ')') {
                    j++;
                }
                out.add(s.substring(i, j));
                i = j;
            }
        }
        return out;
    }
}
