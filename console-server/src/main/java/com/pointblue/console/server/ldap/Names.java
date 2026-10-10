package com.pointblue.console.server.ldap;

import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

/**
 * Every DN operation the object API needs, in one place (Design Proposal for Safe Object Identity,
 * section 6.1): parse, build a child's DN from a type and a plain value, compare, and the identity block
 * (rdns, name, parent, dot and slash notation). Nothing else splits, joins or escapes DN text.
 *
 * <p>Built on the JDK's RFC 4514 {@link LdapName}. When DirXMLDev's DN library is released this class
 * becomes a thin adapter over it.
 */
public final class Names {

    private static final java.util.regex.Pattern ATTRIBUTE = java.util.regex.Pattern.compile("[A-Za-z][A-Za-z0-9-]*|\\d+(\\.\\d+)+");
    private static final java.util.regex.Pattern GUID = java.util.regex.Pattern.compile("[0-9a-f]{32}");

    private Names() {
    }

    public static LdapName parse(String dn) {
        try {
            return new LdapName(dn);
        } catch (InvalidNameException e) {
            throw new IllegalArgumentException("not a DN: " + e.getMessage());
        }
    }

    /** An attribute type name or OID, as it may appear in a filter or a DN. */
    public static boolean attributeName(String s) {
        return s != null && ATTRIBUTE.matcher(s).matches();
    }

    /** The DN of a new entry named {@code type=value} under {@code parent}; the value is escaped here. */
    public static String child(String parent, String type, String value) {
        if (!attributeName(type)) {
            throw new IllegalArgumentException("not an attribute name: " + type);
        }
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException("a name is required");
        }
        try {
            LdapName n = parse(parent);
            n.add(new Rdn(type, value));
            return n.toString();
        } catch (InvalidNameException e) {
            throw new IllegalArgumentException(e.getMessage());
        }
    }

    /**
     * One spelling per name: each RDN re-escaped from its parsed values, lowercased. Two spellings of the
     * same DN ({@code cn=a\\2cb} and {@code cn=a\\,b}) give the same string.
     */
    public static String canonical(String dn) {
        LdapName n = parse(dn);
        StringBuilder b = new StringBuilder();
        for (int i = n.size() - 1; i >= 0; i--) {
            if (b.length() > 0) {
                b.append(',');
            }
            b.append(n.getRdn(i).toString());
        }
        return b.toString().toLowerCase(Locale.ROOT);
    }

    /** The parent's DN ("" for a top-level entry). */
    public static String parent(String dn) {
        LdapName n = parse(dn);
        return n.size() <= 1 ? "" : n.getPrefix(n.size() - 1).toString();
    }

    /** The leftmost RDN. */
    public static Rdn leaf(String dn) {
        LdapName n = parse(dn);
        if (n.size() == 0) {
            throw new IllegalArgumentException("the root has no name");
        }
        return n.getRdn(n.size() - 1);
    }

    /** RFC 4514 equality: attribute types and (eDirectory's case-ignoring) values compared as names. */
    public static boolean same(String a, String b) {
        try {
            return new LdapName(a).equals(new LdapName(b));
        } catch (InvalidNameException e) {
            return a.trim().equalsIgnoreCase(b.trim());
        }
    }

    /** Whether {@code dn} is {@code ancestor} or underneath it. */
    public static boolean within(String dn, String ancestor) {
        LdapName d = parse(dn);
        LdapName a = parse(ancestor);
        return d.startsWith(a);
    }

    /**
     * The identity block for {@code dn}: {@code dn}, {@code rdns} (leaf to root, unescaped, each a list
     * so multi-valued names stay unambiguous), {@code name}, {@code parent} and {@code display}
     * ({@code dot} and {@code slash}, escaped here).
     */
    public static Map<String, Object> identity(String dn) {
        LdapName n = parse(dn);
        List<List<Map<String, String>>> rdns = new ArrayList<>();
        List<String> dot = new ArrayList<>();
        List<String> slash = new ArrayList<>();
        for (int i = n.size() - 1; i >= 0; i--) {
            List<Map<String, String>> avas = new ArrayList<>();
            List<String> dotParts = new ArrayList<>();
            List<String> slashParts = new ArrayList<>();
            for (Rdn r : avas(n.get(i))) {
                String v = String.valueOf(r.getValue());
                avas.add(Map.of("type", r.getType(), "value", v));
                dotParts.add(escape(v, ".=+\\"));
                slashParts.add(escape(v, "\\+"));
            }
            rdns.add(avas);
            dot.add(String.join("+", dotParts));
            slash.add(0, String.join("+", slashParts));
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("dn", n.toString());
        out.put("rdns", rdns);
        out.put("name", rdns.isEmpty() ? "" : rdns.get(0).get(0).get("value"));
        out.put("parentDn", n.size() <= 1 ? "" : n.getPrefix(n.size() - 1).toString());
        // the containers above, root first, for a breadcrumb (the client never splits a DN)
        List<Map<String, String>> ancestors = new ArrayList<>();
        for (int k = 1; k < n.size(); k++) {
            ancestors.add(Map.of("dn", n.getPrefix(k).toString(), "name", String.valueOf(avas(n.get(k - 1)).get(0).getValue())));
        }
        out.put("ancestors", ancestors);
        out.put("display", Map.of("dot", String.join(".", dot), "slash", "\\" + String.join("\\", slash)));
        return out;
    }

    /**
     * The parts of one RDN in the order they were written: split at each unescaped {@code +}.
     * ({@link Rdn} itself keeps them sorted by type, which would make {@code uid=js+cn=Smith} and
     * {@code cn=Smith+uid=js} name the entry differently.)
     */
    static List<Rdn> avas(String rdn) {
        List<Rdn> out = new ArrayList<>();
        int start = 0;
        for (int i = 0; i < rdn.length(); i++) {
            char c = rdn.charAt(i);
            if (c == '\\') {
                i++;
            } else if (c == '+') {
                out.add(rdn(rdn.substring(start, i)));
                start = i + 1;
            }
        }
        out.add(rdn(rdn.substring(start)));
        return out;
    }

    private static Rdn rdn(String s) {
        try {
            return new Rdn(s);
        } catch (InvalidNameException e) {
            throw new IllegalArgumentException(e.getMessage());
        }
    }

    private static String escape(String v, String special) {
        StringBuilder b = new StringBuilder();
        for (char c : v.toCharArray()) {
            if (special.indexOf(c) >= 0) {
                b.append('\\');
            }
            b.append(c);
        }
        return b.toString();
    }

    // ---- GUIDs ----------------------------------------------------------------------------------

    public static boolean guid(String s) {
        return s != null && GUID.matcher(s).matches();
    }

    public static byte[] guidBytes(String hex) {
        if (!guid(hex)) {
            throw new IllegalArgumentException("a GUID is 32 lowercase hex digits");
        }
        return HexFormat.of().parseHex(hex);
    }

    public static String guidHex(Object value) {
        if (value instanceof byte[] b) {
            return HexFormat.of().formatHex(b);
        }
        return value == null ? null : String.valueOf(value).toLowerCase(Locale.ROOT);
    }
}
