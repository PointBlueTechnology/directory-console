package com.pointblue.console.server.http;

import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.console.server.ldap.Names;
import com.pointblue.dirxml.dev.json.Json;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import javax.naming.NamingException;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;

/**
 * The settings on eDirectory's LDAP Server and LDAP Group objects that the console reads and writes, each
 * with its kind and allowed values, so a request is checked before it reaches eDirectory. The LDAP server
 * applies a change when it is refreshed ({@code POST ldap/servers/{id}/refresh}).
 */
final class LdapObjects {

    enum Kind { BOOLEAN, INTEGER, CHOICE, FLAGS, BIND_RESTRICTIONS, STRINGS, MAPPINGS, DN, SSL_CONFIG }

    /** One setting: its attribute, kind, and for an integer its range or for a choice its values. */
    record Field(String attribute, Kind kind, long min, long max, Set<Long> choices, Pattern pattern) {
        static Field bool(String a) {
            return new Field(a, Kind.BOOLEAN, 0, 0, null, null);
        }

        static Field integer(String a, long min, long max) {
            return new Field(a, Kind.INTEGER, min, max, null, null);
        }

        static Field choice(String a, Long... values) {
            return new Field(a, Kind.CHOICE, 0, 0, Set.of(values), null);
        }

        static Field strings(String a, Pattern p) {
            return new Field(a, Kind.STRINGS, 0, 0, null, p);
        }

        /** An integer of bit flags, any combination of those in {@code mask}. */
        static Field flags(String a, long mask) {
            return new Field(a, Kind.FLAGS, 0, mask, null, null);
        }

        static Field of(String a, Kind k) {
            return new Field(a, k, 0, 0, null, null);
        }
    }

    private static final Pattern INTERFACE = Pattern.compile("ldaps?://[A-Za-z0-9.:\\[\\]-]*:\\d{1,5}");
    private static final long MAX = Integer.MAX_VALUE;
    /** ldapTraceLevel: informational 1, connection 8, packet dump 16, configuration 64, extended operations 128, non-critical errors 4096, critical errors 8192, connection detail 16384. */
    static final long TRACE_FLAGS = 1 | 8 | 16 | 64 | 128 | 4096 | 8192 | 16384;
    /** Settings the LDAP server applies only when its LDAP module is reloaded, not refreshed (Identity Console's reload path). */
    static final Set<String> NEED_RELOAD = Set.of("ldapTLSRequired", "sslEnableMutualAuthentication", "ldapBindRestrictions", "ldapSSLConfig",
        "ldapInterfaces", "ldapKeyMaterialName");

    /** LDAP Server object settings, by attribute (case as eDirectory spells it). */
    static final Map<String, Field> SERVER = fields(
        Field.strings("ldapInterfaces", INTERFACE),
        Field.bool("ldapTLSRequired"),
        Field.bool("sslEnableMutualAuthentication"),
        Field.choice("ldapTLSVerifyClientCertificate", 0L, 1L, 2L),
        Field.of("ldapBindRestrictions", Kind.BIND_RESTRICTIONS),
        Field.of("ldapSSLConfig", Kind.SSL_CONFIG),
        Field.integer("ldapServerBindLimit", 0, MAX),
        Field.integer("ldapServerIdleTimeout", 0, MAX),
        Field.integer("searchSizeLimit", 0, MAX),
        Field.integer("searchTimeLimit", 0, MAX),
        Field.choice("filteredReplicaUsage", 0L, 1L),
        Field.bool("ldapEnablePSearch"),
        Field.integer("ldapMaximumPSearchOperations", 0, MAX),
        Field.bool("ldapIgnorePSearchLimitsForEvents"),
        Field.bool("ldapEnableMonitorEvents"),
        Field.integer("ldapMaximumMonitorEventsLoad", 0, MAX),
        Field.bool("ldapNonStdAllUserAttrsMode"),
        Field.bool("nonStdClientSchemaCompatMode"),
        Field.bool("ldapDerefAlias"),
        Field.bool("ldapDerefAliasOnAuth"),
        Field.bool("ldapGeneralizedTime"),
        Field.bool("ldapPermissiveModify"),
        Field.choice("ldapSearchReferralUsage", 0L, 1L, 2L, 3L),
        Field.choice("lDAPOtherReferralUsage", 0L, 1L, 2L, 3L),
        Field.flags("ldapDefaultReferralBehavior", 0x7),
        Field.flags("ldapTraceLevel", TRACE_FLAGS),
        Field.integer("ldapLBURPNumWriterThreads", 1, 64));

    /** LDAP Group object settings. */
    static final Map<String, Field> GROUP = fields(
        Field.bool("ldapAllowClearTextPassword"),
        Field.flags("ldapDefaultReferralBehavior", 0x7),
        Field.choice("ldapSearchReferralUsage", 0L, 1L, 2L, 3L),
        Field.choice("lDAPOtherReferralUsage", 0L, 1L, 2L, 3L),
        Field.of("ldapSSLConfig", Kind.SSL_CONFIG),
        Field.of("ldapAnonymousIdentity", Kind.DN),
        Field.of("ldapClassList", Kind.MAPPINGS),
        Field.of("ldapAttributeList", Kind.MAPPINGS));

    private static Map<String, Field> fields(Field... fs) {
        Map<String, Field> m = new LinkedHashMap<>();
        for (Field f : fs) {
            m.put(f.attribute(), f);
        }
        return m;
    }

    private LdapObjects() {
    }

    /** Each setting's value as JSON: booleans, numbers, lists, mappings as {eDirectory, ldap: [...]}. */
    static Map<String, Object> read(Ldap.Entry e, Map<String, Field> fields) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Field f : fields.values()) {
            List<Object> vs = e.attributes().getOrDefault(f.attribute().toLowerCase(Locale.ROOT), List.of());
            Object first = vs.isEmpty() ? null : vs.get(0);
            out.put(f.attribute(), switch (f.kind()) {
                case BOOLEAN -> first == null ? null : "TRUE".equalsIgnoreCase(String.valueOf(first));
                case INTEGER, CHOICE, FLAGS, BIND_RESTRICTIONS -> first == null ? null : parseLong(String.valueOf(first));
                case STRINGS -> vs.stream().map(String::valueOf).toList();
                case MAPPINGS -> vs.stream().map(v -> mapping(String.valueOf(v))).toList();
                case DN -> first == null ? null : String.valueOf(first);
                case SSL_CONFIG -> first == null ? null : sslConfig(first);
            });
        }
        return out;
    }

    /** The modifications for {@code changes} (setting → new value; null removes it), each checked first. */
    static List<ModificationItem> modifications(Map<String, Object> changes, Map<String, Field> fields) {
        List<ModificationItem> mods = new ArrayList<>();
        for (Map.Entry<String, Object> c : changes.entrySet()) {
            Field f = fields.get(c.getKey());
            if (f == null) {
                throw new Http.Problem(400, "bad-field", c.getKey() + " is not a setting here; settings are " + String.join(", ", fields.keySet()));
            }
            Object v = c.getValue();
            if (v == null || v instanceof List<?> l && l.isEmpty() && f.kind() != Kind.STRINGS) {
                mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute(f.attribute())));
                continue;
            }
            BasicAttribute a = new BasicAttribute(f.attribute());
            switch (f.kind()) {
                case BOOLEAN -> {
                    if (!(v instanceof Boolean b)) {
                        throw bad(f, "true or false");
                    }
                    a.add(b ? "TRUE" : "FALSE");
                }
                case INTEGER -> {
                    long n = number(f, v);
                    if (n < f.min() || n > f.max()) {
                        throw bad(f, "a number from " + f.min() + " to " + f.max());
                    }
                    a.add(String.valueOf(n));
                }
                case CHOICE -> {
                    long n = number(f, v);
                    if (!f.choices().contains(n)) {
                        throw bad(f, "one of " + new java.util.TreeSet<>(f.choices()));
                    }
                    a.add(String.valueOf(n));
                }
                case FLAGS -> {
                    long n = number(f, v);
                    if (n < 0 || (n & ~f.max()) != 0) {
                        throw bad(f, "a combination of the flags " + f.max());
                    }
                    a.add(String.valueOf(n));
                }
                case BIND_RESTRICTIONS -> {
                    // binds (0-7) + 16 x cipher level (0-6) + 256 x cipher suite level (0-3), as Identity Console packs them
                    long n = number(f, v);
                    if (n < 0 || n > 0x3ff || ((n >> 4) & 0xf) > 6 || (n & 0x8) != 0) {
                        throw bad(f, "binds (0-7) plus 16 x the cipher level (0-6) plus 256 x the cipher suite level (0-3)");
                    }
                    a.add(String.valueOf(n));
                }
                case STRINGS -> {
                    if (!(v instanceof List<?> list)) {
                        throw bad(f, "a list");
                    }
                    for (Object o : list) {
                        String sv = String.valueOf(o).trim();
                        if (f.pattern() != null && !f.pattern().matcher(sv).matches()) {
                            throw bad(f, "values such as ldap://:389 or ldaps://:636 (" + sv + " is not)");
                        }
                        a.add(sv);
                    }
                }
                case MAPPINGS -> {
                    if (!(v instanceof List<?> list)) {
                        throw bad(f, "a list of {eDirectory, ldap: [names]}");
                    }
                    for (Object o : list) {
                        a.add(mappingValue(f, Json.asMap(o)));
                    }
                }
                case DN -> {
                    String dn = String.valueOf(v).trim();
                    Names.parse(dn);
                    a.add(dn);
                }
                case SSL_CONFIG -> a.add(sslConfigValue(f, Json.asMap(v)));
            }
            mods.add(new ModificationItem(a.size() == 0 ? DirContext.REMOVE_ATTRIBUTE : DirContext.REPLACE_ATTRIBUTE, a));
        }
        return mods;
    }

    private static Http.Problem bad(Field f, String what) {
        return new Http.Problem(400, "bad-field", f.attribute() + " is " + what);
    }

    private static long number(Field f, Object v) {
        if (v instanceof Number n) {
            return n.longValue();
        }
        Long n = parseLong(String.valueOf(v));
        if (n == null) {
            throw bad(f, "a number");
        }
        return n;
    }

    private static Long parseLong(String s) {
        try {
            return Long.parseLong(s.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * {@code NDSName=Group$LDAPNames=groupOfNames\24group[$Obselete=false$Description=…]} → {eDirectory: Group,
     * ldap: [groupOfNames, group], obsolete, description}. Identity Console writes the last two fields (with that
     * spelling) and reads them by position; they are kept as they are.
     */
    static Map<String, Object> mapping(String v) {
        Map<String, Object> m = new LinkedHashMap<>();
        String[] f = v.split("\\$", -1);
        String nds = f[0].startsWith("NDSName=") ? f[0].substring("NDSName=".length()) : f[0];
        String ldap = f.length > 1 && f[1].startsWith("LDAPNames=") ? f[1].substring("LDAPNames=".length()) : "";
        m.put("eDirectory", nds);
        m.put("ldap", ldap.isEmpty() ? List.of() : List.of(ldap.split("\\\\24")));
        if (f.length > 2) {
            m.put("obsolete", "true".equalsIgnoreCase(after(f[2])));
        }
        if (f.length > 3) {
            m.put("description", after(String.join("$", java.util.Arrays.copyOfRange(f, 3, f.length))));
        }
        return m;
    }

    private static String after(String field) {
        int eq = field.indexOf('=');
        return eq < 0 ? field : field.substring(eq + 1);
    }

    static String mappingValue(Field f, Map<String, Object> m) {
        String nds = m.get("eDirectory") == null ? "" : String.valueOf(m.get("eDirectory")).trim();
        List<String> ldap = new ArrayList<>();
        if (m.get("ldap") instanceof List<?> l) {
            l.forEach(x -> ldap.add(String.valueOf(x).trim()));
        }
        if (nds.isEmpty() || nds.contains("$") || ldap.isEmpty() || ldap.stream().anyMatch(x -> !x.matches("[A-Za-z][A-Za-z0-9-]*"))) {
            throw bad(f, "a list of mappings, each an eDirectory name and one or more LDAP names (letters, digits, hyphens)");
        }
        String v = "NDSName=" + nds + "$LDAPNames=" + String.join("\\24", ldap);
        if (m.containsKey("obsolete") || m.get("description") != null) {
            String desc = m.get("description") == null ? "" : String.valueOf(m.get("description"));
            if (desc.contains("$")) {
                throw bad(f, "a mapping whose description has no $");
            }
            v += "$Obselete=" + Boolean.TRUE.equals(m.get("obsolete")) + "$Description=" + desc;
        }
        return v;
    }

    /**
     * ldapSSLConfig: {"Version":1,"Info":{"Protocol":"+TLSv1.2+TLSv1.3","Ciphers":"…","Ciphersuites":"…"}} → {protocol,
     * ciphers, ciphersuites}. Empty means none is configured and the ldapBindRestrictions cipher level applies.
     */
    static Map<String, Object> sslConfig(Object raw) {
        String s = raw instanceof byte[] b ? new String(b, java.nio.charset.StandardCharsets.UTF_8) : String.valueOf(raw);
        Map<String, Object> out = new LinkedHashMap<>();
        try {
            Map<String, Object> info = Json.asMap(Json.asMap(Json.parse(s)).get("Info"));
            out.put("protocol", info.get("Protocol") == null ? "" : String.valueOf(info.get("Protocol")));
            out.put("ciphers", info.get("Ciphers") == null ? "" : String.valueOf(info.get("Ciphers")));
            out.put("ciphersuites", info.get("Ciphersuites") == null ? "" : String.valueOf(info.get("Ciphersuites")));
        } catch (RuntimeException e) {
            out.put("raw", s);
        }
        return out;
    }

    static String sslConfigValue(Field f, Map<String, Object> m) {
        String protocol = m.get("protocol") == null ? "" : String.valueOf(m.get("protocol")).trim();
        String ciphers = m.get("ciphers") == null ? "" : String.valueOf(m.get("ciphers")).trim();
        String suites = m.get("ciphersuites") == null ? "" : String.valueOf(m.get("ciphersuites")).trim();
        if (!protocol.matches("((\\+|-)(ALL|TLSv1\\.[23]))*") || !ciphers.matches("[A-Za-z0-9._:,+!@=-]*") || !suites.matches("[A-Za-z0-9_:]*")) {
            throw bad(f, "{protocol, ciphers, ciphersuites}: a protocol such as +TLSv1.2+TLSv1.3 or +ALL-TLSv1.2, an OpenSSL cipher string, and TLS 1.3 suites separated by colons");
        }
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("Protocol", protocol);
        info.put("Ciphers", ciphers);
        info.put("Ciphersuites", suites);
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("Version", 1);
        doc.put("Info", info);
        return Json.compact(doc);
    }
}
