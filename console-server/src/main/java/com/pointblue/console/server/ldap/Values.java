package com.pointblue.console.server.ldap;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Attribute values between LDAP and JSON (Design Proposal for Safe Object Identity, sections 5.3 and
 * 5.6). Text stays a string; bytes become {@code {"base64": …}}; a DN-syntax value becomes
 * {@code {"dn", "name"}} (the client opens it with {@code ?dn=}, which answers with its GUID); an ACL
 * becomes {@code {privileges, scope, trustee, attribute}} instead of {@code privs#scope#trustee#attr}.
 * Writes accept the same shapes, and {@code {"guid": …}} for a reference.
 */
public final class Values {

    private Values() {
    }

    /** Resolves a GUID to a DN for reference writes. */
    public interface GuidResolver {
        String dn(String guid) throws Exception;
    }

    // eDirectory's entry and attribute rights bits (the GetEffectivePrivileges and ACL privilege values)
    private static final String[] ENTRY_RIGHTS = {"browse", "add", "delete", "rename", "supervisor"};
    private static final int[] ENTRY_BITS = {0x01, 0x02, 0x04, 0x08, 0x10};
    private static final String[] ATTRIBUTE_RIGHTS = {"compare", "read", "write", "self", "supervisor"};
    private static final int[] ATTRIBUTE_BITS = {0x01, 0x02, 0x04, 0x08, 0x20};

    public static List<Object> toJson(Schema.AttributeType type, List<Object> values) {
        List<Object> out = new ArrayList<>();
        for (Object v : values) {
            out.add(toJson(type, v));
        }
        return out;
    }

    static Object toJson(Schema.AttributeType type, Object v) {
        if (v instanceof byte[] b) {
            return Map.of("base64", Base64.getEncoder().encodeToString(b));
        }
        String s = String.valueOf(v);
        if (type != null && type.dn()) {
            return reference(s);
        }
        if (type != null && Schema.ACL_SYNTAX.equals(type.syntax())) {
            Map<String, Object> acl = acl(s);
            return acl == null ? s : acl;
        }
        return s;
    }

    private static Object reference(String dn) {
        try {
            Map<String, Object> id = Names.identity(dn);
            return Map.of("dn", id.get("dn"), "name", id.get("name"));
        } catch (IllegalArgumentException e) {
            return dn;
        }
    }

    /** {@code privs#scope#trustee#attr} as JSON; null when it does not have that shape. */
    public static Map<String, Object> acl(String s) {
        String[] p = s.split("#", 4);
        if (p.length != 4) {
            return null;
        }
        int bits;
        try {
            bits = Integer.parseInt(p[0]);
        } catch (NumberFormatException e) {
            return null;
        }
        boolean entry = p[3].equalsIgnoreCase("[Entry Rights]");
        String[] names = entry ? ENTRY_RIGHTS : ATTRIBUTE_RIGHTS;
        int[] masks = entry ? ENTRY_BITS : ATTRIBUTE_BITS;
        List<String> privileges = new ArrayList<>();
        int rest = bits;
        for (int i = 0; i < names.length; i++) {
            if ((bits & masks[i]) != 0) {
                privileges.add(names[i]);
                rest &= ~masks[i];
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("privileges", privileges);
        if (rest != 0) {
            out.put("otherBits", rest);
        }
        out.put("scope", p[1]);
        out.put("trustee", p[2].startsWith("[") ? Map.of("special", p[2]) : reference(p[2]));
        out.put("attribute", p[3]);
        return out;
    }

    /** The ACL string for a JSON ACL. */
    static String aclString(Map<?, ?> m, GuidResolver guids) throws Exception {
        String attr = String.valueOf(m.get("attribute") == null ? "[Entry Rights]" : m.get("attribute"));
        boolean entry = attr.equalsIgnoreCase("[Entry Rights]");
        String[] names = entry ? ENTRY_RIGHTS : ATTRIBUTE_RIGHTS;
        int[] masks = entry ? ENTRY_BITS : ATTRIBUTE_BITS;
        int bits = m.get("otherBits") instanceof Number n ? n.intValue() : 0;
        if (m.get("privileges") instanceof List<?> l) {
            for (Object o : l) {
                int i = List.of(names).indexOf(String.valueOf(o).toLowerCase(Locale.ROOT));
                if (i < 0) {
                    throw new IllegalArgumentException("unknown " + (entry ? "entry" : "attribute") + " right " + o + "; one of " + String.join(", ", names));
                }
                bits |= masks[i];
            }
        }
        String scope = String.valueOf(m.get("scope") == null ? "entry" : m.get("scope"));
        if (!scope.equals("entry") && !scope.equals("subtree")) {
            throw new IllegalArgumentException("an ACL scope is entry or subtree");
        }
        Object t = m.get("trustee");
        String trustee;
        if (t instanceof Map<?, ?> tm && tm.get("special") != null) {
            trustee = String.valueOf(tm.get("special"));
            if (!trustee.matches("\\[[A-Za-z ]+]")) {
                throw new IllegalArgumentException("a special trustee looks like [Root], [Public], [Self], [Creator]");
            }
        } else {
            trustee = referenceDn(t, guids);
        }
        if (attr.contains("#") || trustee.contains("#")) {
            throw new IllegalArgumentException("an ACL's trustee and attribute cannot contain #");
        }
        return bits + "#" + scope + "#" + trustee + "#" + attr;
    }

    /** A JSON value to write, given the attribute's type. */
    public static Object fromJson(Schema.AttributeType type, Object v, GuidResolver guids) throws Exception {
        if (v instanceof Map<?, ?> m) {
            if (m.containsKey("base64")) {
                return Base64.getDecoder().decode(String.valueOf(m.get("base64")));
            }
            if (type != null && Schema.ACL_SYNTAX.equals(type.syntax())) {
                return aclString(m, guids);
            }
            if (m.containsKey("guid") || m.containsKey("dn")) {
                return referenceDn(m, guids);
            }
            throw new IllegalArgumentException("an object value is {\"base64\"}, {\"guid\"}, {\"dn\"} or an ACL");
        }
        if (v instanceof String s) {
            if (type != null && type.binary()) {
                return s.getBytes(StandardCharsets.UTF_8);
            }
            if (type != null && type.dn()) {
                Names.parse(s);
            }
            return s;
        }
        if (v instanceof Number || v instanceof Boolean) {
            return v instanceof Boolean b ? (b ? "TRUE" : "FALSE") : String.valueOf(v);
        }
        throw new IllegalArgumentException("unsupported value " + v);
    }

    private static String referenceDn(Object t, GuidResolver guids) throws Exception {
        if (t instanceof Map<?, ?> tm) {
            if (tm.get("guid") != null) {
                String dn = guids.dn(String.valueOf(tm.get("guid")));
                if (dn == null) {
                    throw new IllegalArgumentException("no object has GUID " + tm.get("guid"));
                }
                return dn;
            }
            if (tm.get("dn") != null) {
                return Names.parse(String.valueOf(tm.get("dn"))).toString();
            }
        }
        if (t instanceof String s) {
            return Names.parse(s).toString();
        }
        throw new IllegalArgumentException("a reference is {\"guid\": …} or {\"dn\": …}");
    }
}
