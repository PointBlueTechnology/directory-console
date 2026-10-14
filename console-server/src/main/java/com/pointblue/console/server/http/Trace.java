package com.pointblue.console.server.http;

import com.pointblue.console.server.auth.Role;
import com.pointblue.console.server.auth.Sessions;
import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.console.server.ldap.Names;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.naming.NamingException;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;

/**
 * Trace settings of a driver or a driver set, read and written over LDAP with the person's own rights
 * (no engine connection needed). A driver setting that is not set means "use the driver set's", as
 * Identity Console and iManager show it; removing it here is how that is chosen.
 *
 * <pre>
 * GET /api/v2/trees/{tree}/idm/drivers/{guid}/trace       level, file, name, encoding, sizeLimitKb, and the driver set's
 * PUT same   {"level": 3 | null, …}                       each named field: a value, or null to use the driver set's
 * GET /api/v2/trees/{tree}/idm/driversets/{guid}/trace    level, xslLevel, javaDebugPort, file, encoding, sizeLimitKb
 * PUT same
 * </pre>
 *
 * Attributes (ig4 schema, 2026-10-14): a driver's DirXML-TraceLevel, -TraceFile, -TraceName,
 * -TraceFileEncoding and -TraceSizeLimit; a driver set's DirXML-DriverTraceLevel, -XSLTraceLevel,
 * -JavaDebugPort, -JavaTraceFile, -TraceFileEncoding and -TraceSizeLimit. The size limit is in KB
 * (ig4's drivers have 100000 and 200000); 0 is unlimited.
 */
final class Trace {

    /** JSON field → attribute, and whether it is a number. */
    private record Field(String attribute, boolean number, int min, int max) {
    }

    private static final Map<String, Field> DRIVER = new LinkedHashMap<>();
    private static final Map<String, Field> DRIVER_SET = new LinkedHashMap<>();

    static {
        DRIVER.put("level", new Field("DirXML-TraceLevel", true, 0, 10));
        DRIVER.put("file", new Field("DirXML-TraceFile", false, 0, 0));
        DRIVER.put("name", new Field("DirXML-TraceName", false, 0, 0));
        DRIVER.put("encoding", new Field("DirXML-TraceFileEncoding", false, 0, 0));
        DRIVER.put("sizeLimitKb", new Field("DirXML-TraceSizeLimit", true, 0, Integer.MAX_VALUE));
        DRIVER_SET.put("level", new Field("DirXML-DriverTraceLevel", true, 0, 10));
        DRIVER_SET.put("xslLevel", new Field("DirXML-XSLTraceLevel", true, 0, 10));
        DRIVER_SET.put("javaDebugPort", new Field("DirXML-JavaDebugPort", true, 1, 65535));
        DRIVER_SET.put("file", new Field("DirXML-JavaTraceFile", false, 0, 0));
        DRIVER_SET.put("encoding", new Field("DirXML-TraceFileEncoding", false, 0, 0));
        DRIVER_SET.put("sizeLimitKb", new Field("DirXML-TraceSizeLimit", true, 0, Integer.MAX_VALUE));
    }

    private final Server server;

    Trace(Server server) {
        this.server = server;
    }

    void handle(HttpExchange ex, Sessions.Session s, String method, String guid, boolean driverSet) throws IOException {
        Ldap l = s.ldap();
        if (l == null) {
            throw new Http.Problem(503, "unavailable", "no directory connection");
        }
        Map<String, Field> fields = driverSet ? DRIVER_SET : DRIVER;
        String cls = driverSet ? "DirXML-DriverSet" : "DirXML-Driver";
        try {
            Ldap.Entry e = server.objects.byGuid(l, guid, attributes(fields, "objectClass"));
            if (e == null || e.attributes().getOrDefault("objectclass", List.of()).stream().noneMatch(o -> String.valueOf(o).equalsIgnoreCase(cls))) {
                throw new Http.Problem(404, "not-found", guid + " is not a " + cls);
            }
            if (method.equals("PUT")) {
                if (!s.principal.may(Role.OPERATOR, e.dn())) {
                    throw new Http.Problem(403, "out-of-scope", "changing trace settings needs an operator role that reaches " + e.dn());
                }
                update(l, s, guid, e, fields, Http.body(ex));
                e = server.objects.byGuid(l, guid, attributes(fields, "objectClass"));
            } else if (!method.equals("GET")) {
                throw new Http.Problem(405, "method-not-allowed", method);
            }
            Map<String, Object> out = values(e, fields);
            if (!driverSet) {
                // what "use the driver set's" means for this driver
                Ldap.Entry set = l.read(Names.parent(e.dn()), attributes(DRIVER_SET));
                out.put("driverSet", set == null ? null : values(set, DRIVER_SET));
            }
            Http.json(ex, 200, out);
        } catch (NamingException x) {
            throw server.objects.problem(s, Ldap.Failure.of(x));
        } catch (IllegalArgumentException x) {
            throw new Http.Problem(400, "bad-request", x.getMessage());
        }
    }

    private static String[] attributes(Map<String, Field> fields, String... more) {
        List<String> a = new ArrayList<>(List.of(more));
        fields.values().forEach(f -> a.add(f.attribute()));
        return a.toArray(new String[0]);
    }

    private static Map<String, Object> values(Ldap.Entry e, Map<String, Field> fields) {
        Map<String, Object> out = new LinkedHashMap<>();
        fields.forEach((k, f) -> {
            String v = e.first(f.attribute());
            out.put(k, v == null ? null : f.number() && v.trim().matches("-?\\d+") ? (Object) Integer.parseInt(v.trim()) : v);
        });
        return out;
    }

    private void update(Ldap l, Sessions.Session s, String guid, Ldap.Entry e, Map<String, Field> fields, Map<String, Object> b)
            throws IOException, NamingException {
        List<ModificationItem> mods = new ArrayList<>();
        Map<String, Object> changes = new LinkedHashMap<>();
        for (String k : b.keySet()) {
            if (!fields.containsKey(k)) {
                throw new IllegalArgumentException("not a trace setting: " + k + " (one of " + String.join(", ", fields.keySet()) + ")");
            }
        }
        for (Map.Entry<String, Field> en : fields.entrySet()) {
            if (!b.containsKey(en.getKey())) {
                continue;
            }
            Field f = en.getValue();
            Object v = b.get(en.getKey());
            String before = e.first(f.attribute());
            String after;
            if (v == null || (v instanceof String str && str.isBlank())) {
                after = null;
            } else if (f.number()) {
                long n;
                try {
                    n = v instanceof Number num ? num.longValue() : Long.parseLong(String.valueOf(v).trim());
                } catch (NumberFormatException x) {
                    throw new IllegalArgumentException(en.getKey() + " is a number");
                }
                if (n < f.min() || n > f.max()) {
                    throw new IllegalArgumentException(en.getKey() + " is " + f.min() + " to " + f.max());
                }
                after = String.valueOf(n);
            } else {
                after = String.valueOf(v).trim();
                if (after.contains("\n") || after.length() > 1024) {
                    throw new IllegalArgumentException(en.getKey() + " is one line of at most 1024 characters");
                }
            }
            if (java.util.Objects.equals(before, after)) {
                continue;
            }
            if (after == null) {
                mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute(f.attribute())));
            } else {
                mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(f.attribute(), after)));
            }
            Map<String, Object> c = new LinkedHashMap<>();
            c.put("from", before);
            c.put("to", after);
            changes.put(en.getKey(), c);
        }
        if (mods.isEmpty()) {
            return;
        }
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("dn", e.dn());
        detail.put("changes", changes);
        String action = "idm.trace." + (fields == DRIVER ? "driver" : "driver-set");
        try {
            l.modify(e.dn(), mods);
        } catch (NamingException x) {
            server.objects.audit(s, action, guid, detail, Ldap.Failure.of(x));
            throw x;
        }
        server.objects.audit(s, action, guid, detail, null);
    }
}
