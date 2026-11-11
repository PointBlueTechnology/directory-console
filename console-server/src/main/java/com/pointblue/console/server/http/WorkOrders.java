package com.pointblue.console.server.http;

import com.pointblue.console.server.auth.Role;
import com.pointblue.console.server.auth.Sessions;
import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.console.server.ldap.Names;
import com.pointblue.dirxml.dev.deploy.Vault;
import com.pointblue.dirxml.dev.operate.Operate;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
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

/**
 * The Work Order driver's {@code DirXML-WorkOrder} objects, read and changed over LDAP with the person's own rights,
 * as DirXMLDev's {@code workorder.*} commands do. They live in the container the {@code idv.workorder.container} GCV
 * names (a slash DN, NOVLWOBASE 2.1.1), which the shim polls on its publisher channel; when it runs one it adds a
 * {@code DirXML-WorkToDo} (NOVLWOBASE names it {@code DO-<work order>}), sets the status to {@code configured} or
 * {@code error}, logs, and writes the time it ran as the due date. Seen on a lab with a live driver, 2026-11-02.
 *
 * <pre>
 * GET    /api/v2/trees/{tree}/idm/driversets/{guid}/work-orders   the set's Work Order drivers, their containers, the work orders
 * POST   /api/v2/trees/{tree}/idm/driversets/{guid}/work-orders   {"container": dn, "name", …fields}: a new one, pending and run once by default
 * GET    /api/v2/trees/{tree}/idm/work-orders/{guid}              every field, the driver's log, its WorkToDo objects, version
 * PUT    same   {"version", …fields}: what is given is set; null or "" clears it
 * DELETE same
 * </pre>
 *
 * Fields: {@code description, status} (a person sets {@code pending} or {@code onhold}), {@code now} (true: run at the
 * next poll; clears the due date), {@code due} and {@code deleteDate} (ISO times; a due date clears "now"),
 * {@code repeatMinutes}, {@code deleteOnError}, {@code dependents} (work order DNs), {@code type, number, contact, content}.
 */
final class WorkOrders {

    static final String OC = "DirXML-WorkOrder";
    static final List<String> SETTABLE_STATUSES = List.of("pending", "onhold");
    private static final DateTimeFormatter GENERALIZED = DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);

    /** {request field, attribute, kind}. */
    static final String[][] FIELDS = {
        {"description", "description", "text"}, {"status", "DirXML-nwoStatus", "status"}, {"due", "DirXML-DueDate", "time"},
        {"repeatMinutes", "DirXML-nwoRepeatInterval", "minutes"}, {"deleteDate", "DirXML-nwoDeleteDueDate", "time"},
        {"deleteOnError", "DirXML-nwoDeleteOnError", "bool"}, {"dependents", "DirXML-nwoDependentWorkOrder", "dns"},
        {"type", "DirXML-woType", "text"}, {"number", "DirXML-nwoWorkOrderNumber", "text"}, {"contact", "DirXML-nwoContactName", "text"},
        {"content", "DirXML-nwoContent", "text"}, {"now", "DirXML-nwoDoItNowFlag", "bool"},
    };
    private static final String[] ATTRS;

    static {
        List<String> a = new ArrayList<>(List.of("objectClass", "GUID", "cn", "DirXML-nwoProcessLog", "DirXML-nwoCreationDate", "DirXML-CreatorName"));
        for (String[] f : FIELDS) {
            a.add(f[1]);
        }
        ATTRS = a.toArray(new String[0]);
    }

    private final Server server;

    WorkOrders(Server server) {
        this.server = server;
    }

    /** {@code setGuid} for the set's routes, else {@code guid} for one work order's. */
    void handle(HttpExchange ex, Sessions.Session s, String method, String setGuid, String guid) throws IOException {
        Ldap l = s.ldap();
        if (l == null) {
            throw new Http.Problem(503, "unavailable", "no directory connection");
        }
        try {
            if (setGuid != null) {
                String setDn = driverSet(l, setGuid);
                switch (method) {
                    case "GET" -> Http.json(ex, 200, list(l, setDn));
                    case "POST" -> create(ex, l, s, setDn);
                    default -> throw new Http.Problem(405, "method-not-allowed", method);
                }
                return;
            }
            Ldap.Entry e = workOrder(l, guid);
            if (!method.equals("GET") && !s.principal.may(Role.OPERATOR, e.dn())) {
                throw new Http.Problem(403, "out-of-scope", "changing a work order needs an operator role that reaches " + e.dn());
            }
            switch (method) {
                case "GET" -> Http.json(ex, 200, json(l, e, true));
                case "PUT" -> change(ex, l, s, guid, e);
                case "DELETE" -> delete(ex, l, s, guid, e);
                default -> throw new Http.Problem(405, "method-not-allowed", method);
            }
        } catch (NamingException x) {
            throw server.objects.problem(s, Ldap.Failure.of(x));
        } catch (IllegalArgumentException x) {
            throw new Http.Problem(400, "bad-request", x.getMessage());
        }
    }

    private String driverSet(Ldap l, String guid) throws NamingException {
        Ldap.Entry e = server.objects.byGuid(l, guid, "objectClass");
        if (!classes(e).contains("dirxml-driverset")) {
            throw new Http.Problem(404, "not-found", guid + " is not a driver set");
        }
        return e.dn();
    }

    private Ldap.Entry workOrder(Ldap l, String guid) throws NamingException {
        Ldap.Entry e = server.objects.byGuid(l, guid, ATTRS);
        if (!classes(e).contains(OC.toLowerCase(Locale.ROOT))) {
            throw new Http.Problem(404, "not-found", guid + " is not a work order");
        }
        return e;
    }

    private static Set<String> classes(Ldap.Entry e) {
        Set<String> out = new LinkedHashSet<>();
        for (Object c : e.attributes().getOrDefault("objectclass", List.of())) {
            out.add(String.valueOf(c).toLowerCase(Locale.ROOT));
        }
        return out;
    }

    /**
     * The set's Work Order drivers and the container each uses, as DirXMLDev finds them ({@code Operate.workOrderDrivers}):
     * a driver with the Work Order shim or a {@code workorder-dn} shim parameter (one behind a Remote Loader); the GCV from
     * the driver (its own values, then the GCV objects linked to it), else from the set; failing that, the driver object,
     * NetIQ's suggestion. It reads through {@code l}, so with the person's rights and their session's controls.
     */
    List<Map<String, Object>> drivers(Ldap l, String setDn) throws NamingException {
        List<Map<String, Object>> out = new ArrayList<>();
        try {
            for (Operate.WorkOrderDriver d : Operate.workOrderDrivers(Operate.readOnly(directory(l)), setDn)) {
                Map<String, Object> m = new LinkedHashMap<>(Names.identity(d.driver().dn));
                List<byte[]> g = d.driver().attrs.get("GUID");
                m.put("guid", g == null || g.isEmpty() ? null : Names.guidHex(g.get(0)));
                m.put("gcv", d.gcv());
                m.put("container", d.container());
                m.put("containerFrom", d.from());
                out.add(m);
            }
        } catch (Failed f) {
            throw f.cause;
        }
        return out;
    }

    /** A directory failure carried out of DirXMLDev's reads, which take no checked exceptions. */
    private static final class Failed extends RuntimeException {
        final NamingException cause;

        Failed(NamingException cause) {
            super(cause);
            this.cause = cause;
        }
    }

    /** DirXMLDev's reads and searches, done through the person's connection {@code l}. */
    private static Operate.Directory directory(Ldap l) {
        String[] attrs = {"*", "GUID"};
        return new Operate.Directory() {
            @Override
            public Vault.Entry read(String dn) {
                try {
                    Ldap.Entry e = l.read(dn, attrs);
                    return e == null ? null : vaultEntry(e);
                } catch (NamingException e) {
                    throw new Failed(e);
                }
            }

            @Override
            public List<Vault.Entry> search(String base, String filter, int scope) {
                try {
                    return l.search(base, filter, null, scope, attrs, 1000).stream().map(WorkOrders::vaultEntry).toList();
                } catch (NamingException e) {
                    throw new Failed(e);
                }
            }
        };
    }

    private static Vault.Entry vaultEntry(Ldap.Entry e) {
        Vault.Entry v = new Vault.Entry(e.dn());
        e.attributes().forEach((name, values) -> v.attrs.put(name, values.stream()
            .map(o -> o instanceof byte[] b ? b : String.valueOf(o).getBytes(StandardCharsets.UTF_8)).toList()));
        return v;
    }

    private Map<String, Object> list(Ldap l, String setDn) throws NamingException {
        List<Map<String, Object>> drivers = drivers(l, setDn);
        List<Map<String, Object>> items = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (Map<String, Object> d : drivers) {
            String c = String.valueOf(d.get("container"));
            if (!seen.add(Names.canonical(c))) {
                continue;
            }
            for (Ldap.Entry e : l.search(c, "(objectClass=" + OC + ")", null, SearchControls.ONELEVEL_SCOPE, ATTRS, 1000)) {
                Map<String, Object> m = json(l, e, false);
                m.put("container", c);
                items.add(m);
            }
        }
        // newest due date first, as workorder.list shows them; those to run now at the top
        items.sort((a, b) -> {
            int n = Boolean.compare(Boolean.TRUE.equals(b.get("now")) && b.get("due") == null, Boolean.TRUE.equals(a.get("now")) && a.get("due") == null);
            if (n != 0) {
                return n;
            }
            String da = (String) a.get("due"), db = (String) b.get("due");
            return da == null ? (db == null ? 0 : 1) : db == null ? -1 : db.compareTo(da);
        });
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("drivers", drivers);
        out.put("items", items);
        return out;
    }

    private static Map<String, Object> ref(Ldap.Entry e) {
        Map<String, Object> m = new LinkedHashMap<>(Names.identity(e.dn()));
        List<Object> g = e.attributes().get("guid");
        m.put("guid", g == null || g.isEmpty() ? null : Names.guidHex(g.get(0)));
        return m;
    }

    private static String text(Ldap.Entry e, String attr) {
        List<Object> v = e.attributes().get(attr.toLowerCase(Locale.ROOT));
        if (v == null || v.isEmpty()) {
            return null;
        }
        Object o = v.get(0);
        return o instanceof byte[] b ? new String(b, StandardCharsets.UTF_8) : String.valueOf(o);
    }

    private static List<String> all(Ldap.Entry e, String attr) {
        return e.attributes().getOrDefault(attr.toLowerCase(Locale.ROOT), List.of()).stream()
            .map(o -> o instanceof byte[] b ? new String(b, StandardCharsets.UTF_8) : String.valueOf(o)).toList();
    }

    /** A work order as JSON; {@code full} adds the dependents' names, its WorkToDo objects and the version. */
    private Map<String, Object> json(Ldap l, Ldap.Entry e, boolean full) throws NamingException {
        Map<String, Object> m = ref(e);
        for (String[] f : FIELDS) {
            String v = text(e, f[1]);
            switch (f[2]) {
                case "time" -> m.put(f[0], iso(v));
                case "bool" -> m.put(f[0], v == null ? null : v.equalsIgnoreCase("TRUE"));
                case "dns" -> {
                    List<Map<String, Object>> deps = new ArrayList<>();
                    for (String dn : all(e, f[1])) {
                        deps.add(Map.of("dn", dn, "name", String.valueOf(Names.identity(dn).get("name"))));
                    }
                    m.put(f[0], deps);
                }
                default -> m.put(f[0], v);
            }
        }
        m.put("log", all(e, "DirXML-nwoProcessLog"));
        m.put("created", iso(text(e, "DirXML-nwoCreationDate")));
        m.put("creator", text(e, "DirXML-CreatorName"));
        if (full) {
            m.put("container", Names.parent(e.dn()));
            m.put("version", version(e));
            m.put("todos", todos(l, e.dn()));
        }
        return m;
    }

    /** The WorkToDo objects the driver made for this work order, in its container. */
    private static List<Map<String, Object>> todos(Ldap l, String dn) throws NamingException {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Ldap.Entry t : l.search(Names.parent(dn), "(objectClass=DirXML-WorkToDo)", null, SearchControls.ONELEVEL_SCOPE,
                new String[] {"GUID", "cn", "DirXML-nwoDN", "DirXML-woType", "description"}, 500)) {
            String of = t.first("DirXML-nwoDN");
            // the engine writes it as it reads a DN: an LDAP DN, or the slash form with the tree first
            if (of == null || !(Names.same(of, dn) || slashEnds(of, dn))) {
                continue;
            }
            Map<String, Object> m = ref(t);
            m.put("type", t.first("DirXML-woType"));
            out.add(m);
        }
        return out;
    }

    private static boolean slashEnds(String slash, String dn) {
        if (!slash.contains("\\") || slash.contains("=")) {
            return false;
        }
        List<String> names = new ArrayList<>();
        // the most significant RDN first, as the slash form writes it
        for (javax.naming.ldap.Rdn r : Names.parse(dn).getRdns()) {
            names.add(String.valueOf(r.getValue()));
        }
        String tail = "\\" + String.join("\\", names);
        return slash.toLowerCase(Locale.ROOT).endsWith(tail.toLowerCase(Locale.ROOT));
    }

    /** A hash of every field the console changes: a change carries it back. */
    private static String version(Ldap.Entry e) {
        StringBuilder b = new StringBuilder();
        for (String[] f : FIELDS) {
            b.append(f[1]).append('=').append(String.join("\u0001", all(e, f[1]))).append('\n');
        }
        return Jobs.version(b.toString().getBytes(StandardCharsets.UTF_8));
    }

    /** A generalized time as ISO, or null. */
    static String iso(String generalized) {
        if (generalized == null || generalized.isBlank()) {
            return null;
        }
        try {
            String g = generalized.trim();
            String digits = g.endsWith("Z") ? g.substring(0, g.length() - 1) : g;
            if (digits.contains(".")) {
                digits = digits.substring(0, digits.indexOf('.'));
            }
            return java.time.LocalDateTime.parse(digits, DateTimeFormatter.ofPattern("yyyyMMddHHmmss")).toInstant(ZoneOffset.UTC).toString();
        } catch (DateTimeParseException x) {
            return generalized;
        }
    }

    /** An ISO time (an instant, an offset time or a date) as a generalized time. */
    static String generalized(String iso) {
        String v = iso.trim();
        Instant t;
        try {
            t = Instant.parse(v);
        } catch (DateTimeParseException a) {
            try {
                t = OffsetDateTime.parse(v).toInstant();
            } catch (DateTimeParseException b) {
                try {
                    t = LocalDate.parse(v).atStartOfDay(ZoneOffset.UTC).toInstant();
                } catch (DateTimeParseException c) {
                    throw new IllegalArgumentException("a time is ISO 8601, such as 2026-12-31T23:59:00Z: " + v);
                }
            }
        }
        return GENERALIZED.format(t);
    }

    /**
     * The modifications that bring {@code current} (null for a new one) to what {@code b} gives, checked: a status a
     * person sets, ISO times, whole minutes, dependents that are work orders. A field left out stays; null or "" clears.
     */
    List<ModificationItem> changes(Ldap l, Map<String, Object> b, Ldap.Entry current) throws NamingException {
        Map<String, List<String>> want = new LinkedHashMap<>();
        for (String[] f : FIELDS) {
            if (!b.containsKey(f[0])) {
                continue;
            }
            Object raw = b.get(f[0]);
            List<String> values = new ArrayList<>();
            switch (f[2]) {
                case "dns" -> {
                    if (raw != null && !(raw instanceof List)) {
                        throw new IllegalArgumentException(f[0] + " is a list of work order DNs");
                    }
                    for (Object o : raw == null ? List.of() : (List<?>) raw) {
                        String dn = String.valueOf(o instanceof Map<?, ?> m ? m.get("dn") : o).trim();
                        Ldap.Entry dep = l.read(dn, "objectClass");
                        if (dep == null || !classes(dep).contains(OC.toLowerCase(Locale.ROOT))) {
                            throw new IllegalArgumentException("a dependent is a work order; " + dn + " is not");
                        }
                        values.add(dn);
                    }
                }
                case "bool" -> {
                    if (raw != null && !(raw instanceof Boolean)) {
                        throw new IllegalArgumentException(f[0] + " is true, false or null");
                    }
                    if (Boolean.TRUE.equals(raw)) {
                        values.add("TRUE");
                    } else if (Boolean.FALSE.equals(raw) && !f[0].equals("now")) {
                        values.add("FALSE");
                    }
                }
                default -> {
                    String v = raw == null ? "" : String.valueOf(raw).trim();
                    if (!v.isEmpty()) {
                        switch (f[2]) {
                            case "time" -> v = generalized(v);
                            case "minutes" -> {
                                if (!v.matches("\\d{1,9}")) {
                                    throw new IllegalArgumentException("repeatMinutes is a whole number of minutes; 0 runs it once");
                                }
                            }
                            case "status" -> {
                                String was = current == null ? null : text(current, f[1]);
                                if (!SETTABLE_STATUSES.contains(v) && !v.equals(was)) {
                                    throw new IllegalArgumentException("a person sets the status to pending or onhold; the driver sets configured or error");
                                }
                            }
                            default -> { }
                        }
                        values.add(v);
                    }
                }
            }
            want.put(f[1], values);
        }
        // "now" runs it at the next poll with no due date; a due date replaces "now"
        if (Boolean.TRUE.equals(b.get("now"))) {
            want.put("DirXML-DueDate", List.of());
        } else if (want.containsKey("DirXML-DueDate") && !want.get("DirXML-DueDate").isEmpty()) {
            want.put("DirXML-nwoDoItNowFlag", List.of());
        }
        List<ModificationItem> mods = new ArrayList<>();
        for (Map.Entry<String, List<String>> w : want.entrySet()) {
            List<String> before = current == null ? List.of() : all(current, w.getKey());
            if (before.equals(w.getValue())) {
                continue;
            }
            BasicAttribute a = new BasicAttribute(w.getKey());
            w.getValue().forEach(a::add);
            if (w.getValue().isEmpty()) {
                if (!before.isEmpty()) {
                    mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, a));
                }
            } else {
                mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, a));
            }
        }
        return mods;
    }

    private static Map<String, Object> summary(List<ModificationItem> mods) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (ModificationItem i : mods) {
            m.put(i.getAttribute().getID(), i.getModificationOp() == DirContext.REMOVE_ATTRIBUTE ? "cleared" : "set");
        }
        return m;
    }

    private void create(HttpExchange ex, Ldap l, Sessions.Session s, String setDn) throws IOException, NamingException {
        Map<String, Object> b = new LinkedHashMap<>(Http.body(ex));
        String name = Http.string(b, "name", true).trim();
        if (name.isEmpty() || name.length() > 64) {
            throw new IllegalArgumentException("a work order's name is 1 to 64 characters");
        }
        String container = Http.string(b, "container", false);
        List<String> containers = drivers(l, setDn).stream().map(d -> String.valueOf(d.get("container"))).distinct().toList();
        if (containers.isEmpty()) {
            throw new Http.Problem(409, "no-work-order-driver", "this driver set has no Work Order driver to run a work order");
        }
        if (container == null) {
            if (containers.size() > 1) {
                throw new IllegalArgumentException("the set's Work Order drivers use several containers; say which");
            }
            container = containers.get(0);
        } else if (containers.stream().noneMatch(c -> Names.same(c, Http.string(b, "container", true)))) {
            throw new IllegalArgumentException("a work order goes in a Work Order driver's container: " + String.join("; ", containers));
        }
        if (!s.principal.may(Role.OPERATOR, container)) {
            throw new Http.Problem(403, "out-of-scope", "creating a work order needs an operator role that reaches " + container);
        }
        String dn = Names.child(container, "cn", name);
        if (l.read(dn, "1.1") != null) {
            throw new Http.Problem(409, "exists", "there is already an object named " + name + " there");
        }
        // as Identity Console makes one: pending, run once
        b.putIfAbsent("status", "pending");
        b.putIfAbsent("repeatMinutes", "0");
        Map<String, List<Object>> attrs = new LinkedHashMap<>();
        attrs.put("objectClass", List.of("Top", OC));
        attrs.put("cn", List.of(name));
        List<ModificationItem> mods = changes(l, b, null);
        for (ModificationItem m : mods) {
            List<Object> values = new ArrayList<>();
            for (int i = 0; i < m.getAttribute().size(); i++) {
                values.add(m.getAttribute().get(i));
            }
            attrs.put(m.getAttribute().getID(), values);
        }
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("dn", dn);
        detail.put("fields", summary(mods));
        try {
            l.create(dn, attrs);
        } catch (NamingException x) {
            server.objects.audit(s, "idm.work-order.create", null, detail, Ldap.Failure.of(x));
            throw x;
        }
        Ldap.Entry made = l.read(dn, ATTRS);
        String guid = made == null ? null : String.valueOf(ref(made).get("guid"));
        server.objects.audit(s, "idm.work-order.create", guid, detail, null);
        Http.json(ex, 201, made == null ? Map.of("dn", dn) : json(l, made, true));
    }

    private void change(HttpExchange ex, Ldap l, Sessions.Session s, String guid, Ldap.Entry e) throws IOException, NamingException {
        Map<String, Object> b = Http.body(ex);
        if (!Http.string(b, "version", true).equals(version(e))) {
            throw new Http.Problem(409, "changed", "the work order changed meanwhile (the driver may have run it); reload it and try again");
        }
        List<ModificationItem> mods = changes(l, b, e);
        if (!mods.isEmpty()) {
            Map<String, Object> detail = Map.of("dn", e.dn(), "fields", summary(mods));
            try {
                l.modify(e.dn(), mods);
            } catch (NamingException x) {
                server.objects.audit(s, "idm.work-order.change", guid, detail, Ldap.Failure.of(x));
                throw x;
            }
            server.objects.audit(s, "idm.work-order.change", guid, detail, null);
        }
        Http.json(ex, 200, json(l, workOrder(l, guid), true));
    }

    private void delete(HttpExchange ex, Ldap l, Sessions.Session s, String guid, Ldap.Entry e) throws IOException, NamingException {
        Map<String, Object> detail = Map.of("dn", e.dn());
        try {
            l.delete(e.dn());
        } catch (NamingException x) {
            server.objects.audit(s, "idm.work-order.delete", guid, detail, Ldap.Failure.of(x));
            throw x;
        }
        server.objects.audit(s, "idm.work-order.delete", guid, detail, null);
        Http.json(ex, 204, Map.of());
    }
}
