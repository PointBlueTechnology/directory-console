package com.pointblue.console.server.http;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * eDirectory's CEF audit configuration (cefConfiguration on an NCP Server: {@code key=value} strings) and
 * SNMP trap configuration (an SNMP Group's snmpTrapConfig: 36-byte records). Both are read and written as
 * Identity Console stores them; values and bytes the console does not understand are kept as they were.
 * Where the audit events go (syslog, files, caching) is in auditlogconfig.properties on each server, and
 * trap destinations in its SNMP agent's configuration, not in the directory.
 */
final class Monitoring {

    private Monitoring() {
    }

    // ---- CEF auditing -------------------------------------------------------------------------------

    static final Map<String, List<String>> EVENTS = new LinkedHashMap<>();

    static {
        EVENTS.put("security", List.of("ACL_CHANGED", "ADD_MEMBER", "DELETE_MEMBER", "INTRUDER_DETECTED", "LOGIN_DISABLED", "LOGIN_ENABLED", "LOGIN",
            "CHANGE_SECURITY_EQUALS", "AUDIT_CONFIG", "CHANGE_PASSWORD", "ACCOUNT_UNLOCK", "LOGOUT", "CONNECTION", "IMPERSONATE", "AUTHENTICATE",
            "VERIFY_PASSWORD", "CHANGE_LOGIN_CONFIG", "QUERY_CREDENTIALS"));
        EVENTS.put("object", List.of("CREATE_OBJECT", "DELETE_OBJECT", "RENAME_OBJECT", "MOVE_OBJECT", "DSA_READ", "SEARCH"));
        EVENTS.put("attribute", List.of("READ_ATTRIBUTE", "DELETE_ATTRIBUTE", "ADD_VALUE", "DELETE_VALUE", "COMPARE_ATTRIBUTE_VALUE"));
        EVENTS.put("ldap", List.of("LDAP_BIND", "LDAP_BIND_RESPONSE", "LDAP_UNBIND", "LDAP_CONNECTION", "LDAP_SEARCH", "LDAP_SEARCH_RESPONSE",
            "LDAP_SEARCH_ENTRY_RESPONSE", "LDAP_ADD", "LDAP_ADD_RESPONSE", "LDAP_COMPARE", "LDAP_COMPARE_RESPONSE", "LDAP_MODIFY", "LDAP_MODIFY_RESPONSE",
            "LDAP_DELETE", "LDAP_DELETE_RESPONSE", "LDAP_MODDN", "LDAP_MODDN_RESPONSE", "LDAP_ABANDON", "LDAP_EXTENDED_OP", "LDAP_SYSTEM_EXTENDED_OP",
            "LDAP_EXTENDED_OP_RESPONSE", "LDAP_MODIFY_SERVER", "LDAP_UNKNOWN_OPERATION", "LDAP_PASSWORD_MODIFY"));
    }

    /** CEF needs a server whose dsRevision is above this (Identity Console's check). */
    static final long CEF_REVISION = 4000803;

    /** What eDirectory audits when a server has no configuration: Identity Console's "Default Settings". */
    static Map<String, Object> cefDefaults() {
        List<String> events = new ArrayList<>(EVENTS.get("security"));
        events.addAll(List.of("CREATE_OBJECT", "DELETE_OBJECT", "RENAME_OBJECT", "MOVE_OBJECT", "DELETE_ATTRIBUTE", "ADD_VALUE", "DELETE_VALUE"));
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("noReplicatedEvents", true);
        m.put("logLargeValues", false);
        m.put("logAttributeValues", false);
        m.put("logEncryptedAttributeValues", false);
        m.put("events", events);
        m.put("objectClasses", List.of());
        m.put("attributeFilter", Map.of("classes", List.of(), "attributes", List.of()));
        m.put("exclude", Map.of("classes", List.of(), "attributes", List.of()));
        return m;
    }

    /** cefConfiguration values → settings; values it does not recognise are returned under "unknown". */
    static Map<String, Object> parseCef(List<String> values) {
        Map<String, Object> m = cefDefaults();
        m.put("events", new ArrayList<>());
        List<String> unknown = new ArrayList<>();
        for (String v : values) {
            int eq = v.indexOf('=');
            String key = eq < 0 ? v : v.substring(0, eq);
            String val = eq < 0 ? "" : v.substring(eq + 1);
            switch (key) {
                case "DSNoReplicatedEvents" -> m.put("noReplicatedEvents", "1".equals(val.trim()));
                case "loglargevalues" -> m.put("logLargeValues", "true".equalsIgnoreCase(val.trim()));
                case "logattributevalues" -> m.put("logAttributeValues", "true".equalsIgnoreCase(val.trim()));
                case "logencryptedattributevalues" -> m.put("logEncryptedAttributeValues", "true".equalsIgnoreCase(val.trim()));
                case "cefEvents" -> m.put("events", val.isEmpty() ? List.of() : List.of(val.split("\\$\\$")));
                case "dsobject" -> m.put("objectClasses", val.isEmpty() ? List.of() : List.of(val.split("\\$")));
                case "dsattribute" -> m.put("attributeFilter", classesAndAttributes(val));
                case "dsExcludeList" -> m.put("exclude", classesAndAttributes(val));
                default -> unknown.add(v);
            }
        }
        m.put("unknown", unknown);
        return m;
    }

    /** {@code Class1$Class2$$attr1$attr2} → {classes, attributes}. */
    private static Map<String, Object> classesAndAttributes(String v) {
        int split = v.indexOf("$$");
        String classes = split < 0 ? v : v.substring(0, split);
        String attrs = split < 0 ? "" : v.substring(split + 2);
        return Map.of("classes", classes.isEmpty() ? List.of() : List.of(classes.split("\\$")), "attributes", attrs.isEmpty() ? List.of() : List.of(attrs.split("\\$")));
    }

    /** Settings → cefConfiguration values, checked; {@code keep} (values not understood) are written back as they were. */
    static List<String> cefValues(Map<String, Object> b, List<String> keep) {
        Set<String> known = new LinkedHashSet<>();
        EVENTS.values().forEach(known::addAll);
        List<String> events = strings(b.get("events"), "events");
        for (String e : events) {
            if (!known.contains(e)) {
                throw new Http.Problem(400, "bad-field", e + " is not a CEF event");
            }
        }
        List<String> out = new ArrayList<>();
        out.add("DSNoReplicatedEvents=" + (Boolean.FALSE.equals(b.get("noReplicatedEvents")) ? "0" : "1"));
        out.add("loglargevalues=" + Boolean.TRUE.equals(b.get("logLargeValues")));
        out.add("logattributevalues=" + Boolean.TRUE.equals(b.get("logAttributeValues")));
        out.add("logencryptedattributevalues=" + Boolean.TRUE.equals(b.get("logEncryptedAttributeValues")));
        out.add("cefEvents=" + String.join("$$", events));
        List<String> objects = names(b.get("objectClasses"), "objectClasses");
        if (!objects.isEmpty()) {
            out.add("dsobject=" + String.join("$", objects));
        }
        String attr = filter(b.get("attributeFilter"), "attributeFilter");
        if (attr != null) {
            out.add("dsattribute=" + attr);
        }
        String exclude = filter(b.get("exclude"), "exclude");
        if (exclude != null) {
            out.add("dsExcludeList=" + exclude);
        }
        out.addAll(keep);
        return out;
    }

    private static String filter(Object o, String field) {
        if (o == null) {
            return null;
        }
        Map<String, Object> m = com.pointblue.dirxml.dev.json.Json.asMap(o);
        List<String> classes = names(m.get("classes"), field + ".classes");
        List<String> attrs = names(m.get("attributes"), field + ".attributes");
        return classes.isEmpty() && attrs.isEmpty() ? null : String.join("$", classes) + "$$" + String.join("$", attrs);
    }

    private static List<String> strings(Object o, String field) {
        List<String> out = new ArrayList<>();
        if (o == null) {
            return out;
        }
        if (!(o instanceof List<?> l)) {
            throw new Http.Problem(400, "bad-field", field + " is a list");
        }
        l.forEach(x -> out.add(String.valueOf(x).trim()));
        return out;
    }

    /** eDirectory class or attribute names: no $ (the separator), no =. */
    private static List<String> names(Object o, String field) {
        List<String> out = strings(o, field);
        for (String n : out) {
            if (n.isEmpty() || n.contains("$") || n.contains("=") || n.length() > 128) {
                throw new Http.Problem(400, "bad-field", field + " holds eDirectory names without $ or =");
            }
        }
        return out;
    }

    // ---- SNMP traps ---------------------------------------------------------------------------------

    static final int RECORD = 36;
    private static final int OID_LENGTH = 20;

    /** One trap: its number, whether it is sent, whether failure traps are, and its interval (seconds; 0 uses the group's). */
    record Trap(int number, String name, boolean active, boolean failure, long interval) {
    }

    /** snmpTrapConfig's records, named from snmpTrapDescription (NUL-separated, in the same order). */
    static List<Trap> traps(byte[] config, byte[] descriptions) {
        List<String> names = new ArrayList<>();
        if (descriptions != null) {
            for (String n : new String(descriptions, StandardCharsets.ISO_8859_1).split("\0")) {
                if (!n.isEmpty()) {
                    names.add(n);
                }
            }
        }
        List<Trap> out = new ArrayList<>();
        if (config == null) {
            return out;
        }
        ByteBuffer b = ByteBuffer.wrap(config).order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0, k = 0; i + RECORD <= config.length; i += RECORD, k++) {
            int number = b.getInt(i + OID_LENGTH);
            out.add(new Trap(number, k < names.size() ? names.get(k) : "trap " + number, b.getInt(i + OID_LENGTH + 4) != 0,
                b.getInt(i + OID_LENGTH + 8) != 0, Integer.toUnsignedLong(b.getInt(i + OID_LENGTH + 12))));
        }
        return out;
    }

    /**
     * The same snmpTrapConfig with {@code changes} (trap number → {active, failure, interval}) applied: only
     * those fields of those records change; every other byte stays as it was.
     */
    static byte[] withTraps(byte[] config, Map<Integer, Map<String, Object>> changes) {
        byte[] out = config.clone();
        ByteBuffer b = ByteBuffer.wrap(out).order(ByteOrder.LITTLE_ENDIAN);
        Set<Integer> seen = new LinkedHashSet<>();
        for (int i = 0; i + RECORD <= out.length; i += RECORD) {
            int number = b.getInt(i + OID_LENGTH);
            Map<String, Object> c = changes.get(number);
            if (c == null) {
                continue;
            }
            seen.add(number);
            if (c.get("active") instanceof Boolean a) {
                b.putInt(i + OID_LENGTH + 4, a ? 1 : 0);
            }
            if (c.get("failure") instanceof Boolean f) {
                b.putInt(i + OID_LENGTH + 8, f ? 1 : 0);
            }
            if (c.get("interval") != null) {
                long iv = c.get("interval") instanceof Number n ? n.longValue() : -1;
                if (iv < 0 || iv > 2_592_000) {
                    throw new Http.Problem(400, "bad-field", "a trap interval is 0 to 2592000 seconds");
                }
                b.putInt(i + OID_LENGTH + 12, (int) iv);
            }
        }
        for (Integer n : changes.keySet()) {
            if (!seen.contains(n)) {
                throw new Http.Problem(400, "bad-field", "this group has no trap " + n);
            }
        }
        return out;
    }
}
