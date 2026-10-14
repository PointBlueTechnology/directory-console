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
import java.util.Locale;
import java.util.Map;
import javax.naming.NamingException;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;

/**
 * The Object Inspector: an object's Identity Manager associations ({@code DirXML-Associations}), read
 * and changed over LDAP with the person's own rights, so it needs no engine connection. A value is
 * {@code <driver DN>#<state>#<association>} (ig4); the states are 0 disabled, 1 processed, 2 pending,
 * 3 manual and 4 migrate, as DirXMLDev and the engine name them.
 *
 * <pre>
 * GET    /api/v2/trees/{tree}/idm/objects/{guid}/associations   the object, its associations, and the tree's drivers
 * POST   same   {"driver": guid, "state", "value"}               add one
 * PATCH  same   {"raw", "state"?, "value"?}                      change one (its state, or its value)
 * DELETE same   {"raw"}                                          remove one
 * </pre>
 *
 * A change names the value it changes as read ({@code raw}); when that value is no longer there, the
 * change is refused (409) rather than applied to whatever is there now. Writes need an operator role
 * that reaches the object.
 */
final class Associations {

    static final List<String> STATES = List.of("disabled", "processed", "pending", "manual", "migrate");

    private final Server server;

    Associations(Server server) {
        this.server = server;
    }

    record Value(String driverDn, int state, String value, String raw) {
    }

    /** {@code cn=d,cn=set,o=system#1#abc} → its parts; null when it is not in that form. */
    static Value parse(String raw) {
        int a = raw.indexOf('#');
        int b = a < 0 ? -1 : raw.indexOf('#', a + 1);
        if (a <= 0 || b < 0) {
            return null;
        }
        try {
            return new Value(raw.substring(0, a), Integer.parseInt(raw.substring(a + 1, b).trim()), raw.substring(b + 1), raw);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    static int stateOf(Object name) {
        int i = STATES.indexOf(String.valueOf(name).toLowerCase(Locale.ROOT));
        if (i < 0) {
            throw new IllegalArgumentException("state is one of " + String.join(", ", STATES));
        }
        return i;
    }

    void handle(HttpExchange ex, Sessions.Session s, String method, String guid) throws IOException {
        Ldap l = s.ldap();
        if (l == null) {
            throw new Http.Problem(503, "unavailable", "no directory connection");
        }
        try {
            String dn = server.objects.dnOf(l, guid);
            if (!method.equals("GET") && !s.principal.may(Role.OPERATOR, dn)) {
                throw new Http.Problem(403, "out-of-scope", "changing associations needs an operator role that reaches " + dn);
            }
            switch (method) {
                case "GET" -> Http.json(ex, 200, read(l, guid));
                case "POST" -> add(ex, l, s, guid);
                case "PATCH" -> change(ex, l, s, guid);
                case "DELETE" -> remove(ex, l, s, guid);
                default -> throw new Http.Problem(405, "method-not-allowed", method);
            }
        } catch (NamingException e) {
            throw server.objects.problem(s, Ldap.Failure.of(e));
        } catch (IllegalArgumentException e) {
            throw new Http.Problem(400, "bad-request", e.getMessage());
        }
    }

    private List<String> values(Ldap.Entry e) {
        List<String> out = new ArrayList<>();
        for (Object v : e.attributes().getOrDefault("dirxml-associations", List.of())) {
            out.add(String.valueOf(v));
        }
        return out;
    }

    private Map<String, Object> read(Ldap l, String guid) throws NamingException {
        Ldap.Entry e = server.objects.byGuid(l, guid, "objectClass", "DirXML-Associations", "GUID");
        if (e == null) {
            throw new Http.Problem(404, "not-found", "no object has GUID " + guid);
        }
        Map<String, Map<String, Object>> drivers = drivers(l);
        Map<String, Object> out = new LinkedHashMap<>();
        Map<String, Object> object = new LinkedHashMap<>(Names.identity(e.dn()));
        object.put("guid", guid);
        object.put("objectClasses", e.attributes().getOrDefault("objectclass", List.of()).stream().map(String::valueOf).toList());
        out.put("object", object);
        List<Map<String, Object>> list = new ArrayList<>();
        for (String raw : values(e)) {
            Value v = parse(raw);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("raw", raw);
            if (v != null) {
                m.put("driver", drivers.get(Names.canonical(v.driverDn())));
                m.put("driverDn", v.driverDn());
                m.put("state", v.state() >= 0 && v.state() < STATES.size() ? STATES.get(v.state()) : String.valueOf(v.state()));
                m.put("value", v.value());
            }
            list.add(m);
        }
        out.put("associations", list);
        out.put("drivers", new ArrayList<>(drivers.values()));
        return out;
    }

    /** The tree's drivers, by canonical DN: GUID, name and driver set. */
    private Map<String, Map<String, Object>> drivers(Ldap l) throws NamingException {
        Map<String, Map<String, Object>> out = new LinkedHashMap<>();
        for (Ldap.Entry d : l.search("", "(objectClass=DirXML-Driver)", null, SearchControls.SUBTREE_SCOPE, new String[] {"GUID"}, 1000)) {
            Map<String, Object> m = new LinkedHashMap<>();
            List<Object> g = d.attributes().get("guid");
            m.put("guid", g == null || g.isEmpty() ? null : Names.guidHex(g.get(0)));
            m.put("dn", d.dn());
            m.put("name", Names.identity(d.dn()).get("name"));
            String set = Names.parent(d.dn());
            m.put("driverSet", Map.of("dn", set, "name", String.valueOf(Names.identity(set).get("name"))));
            out.put(Names.canonical(d.dn()), m);
        }
        return out;
    }

    private Ldap.Entry object(Ldap l, String guid) throws NamingException {
        Ldap.Entry e = server.objects.byGuid(l, guid, "DirXML-Associations");
        if (e == null) {
            throw new Http.Problem(404, "not-found", "no object has GUID " + guid);
        }
        return e;
    }

    /** The value named by {@code raw}, as it is on the object now; 409 when it is not there any more. */
    private Value current(Ldap.Entry e, Map<String, Object> b) {
        String raw = Http.string(b, "raw", true);
        if (!values(e).contains(raw)) {
            throw new Http.Problem(409, "changed", "that association is no longer on the object; reload it and try again");
        }
        Value v = parse(raw);
        if (v == null) {
            throw new IllegalArgumentException("not an association value: " + raw);
        }
        return v;
    }

    private void add(HttpExchange ex, Ldap l, Sessions.Session s, String guid) throws IOException, NamingException {
        Map<String, Object> b = Http.body(ex);
        int state = stateOf(b.getOrDefault("state", "processed"));
        Ldap.Entry e = object(l, guid);
        Ldap.Entry driver = server.objects.byGuid(l, Http.string(b, "driver", true), "objectClass");
        if (driver == null || driver.attributes().getOrDefault("objectclass", List.of()).stream().noneMatch(o -> String.valueOf(o).equalsIgnoreCase("DirXML-Driver"))) {
            throw new Http.Problem(404, "not-found", "no driver has that GUID");
        }
        for (String raw : values(e)) {
            Value v = parse(raw);
            if (v != null && Names.same(v.driverDn(), driver.dn())) {
                throw new Http.Problem(409, "exists", "the object already has an association with " + Names.identity(driver.dn()).get("name") + "; change that one instead");
            }
        }
        String value = b.get("value") == null ? "" : String.valueOf(b.get("value"));
        if (value.contains("\n")) {
            throw new IllegalArgumentException("an association value is one line");
        }
        String raw = driver.dn() + "#" + state + "#" + value;
        write(s, l, e, guid, "idm.association.add", List.of(new ModificationItem(DirContext.ADD_ATTRIBUTE, new BasicAttribute("DirXML-Associations", raw))),
            Map.of("driver", driver.dn(), "state", STATES.get(state), "value", value));
        Http.json(ex, 200, read(l, guid));
    }

    private void change(HttpExchange ex, Ldap l, Sessions.Session s, String guid) throws IOException, NamingException {
        Map<String, Object> b = Http.body(ex);
        Ldap.Entry e = object(l, guid);
        Value v = current(e, b);
        int state = b.get("state") == null ? v.state() : stateOf(b.get("state"));
        String value = b.get("value") == null ? v.value() : String.valueOf(b.get("value"));
        if (value.contains("\n")) {
            throw new IllegalArgumentException("an association value is one line");
        }
        String raw = v.driverDn() + "#" + state + "#" + value;
        if (raw.equals(v.raw())) {
            Http.json(ex, 200, read(l, guid));
            return;
        }
        // one modify: the old value goes and the new one comes, or neither
        write(s, l, e, guid, "idm.association.change", List.of(
                new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute("DirXML-Associations", v.raw())),
                new ModificationItem(DirContext.ADD_ATTRIBUTE, new BasicAttribute("DirXML-Associations", raw))),
            Map.of("driver", v.driverDn(), "from", Map.of("state", name(v.state()), "value", v.value()), "to", Map.of("state", STATES.get(state), "value", value)));
        Http.json(ex, 200, read(l, guid));
    }

    private void remove(HttpExchange ex, Ldap l, Sessions.Session s, String guid) throws IOException, NamingException {
        Map<String, Object> b = Http.body(ex);
        Ldap.Entry e = object(l, guid);
        Value v = current(e, b);
        write(s, l, e, guid, "idm.association.remove", List.of(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute("DirXML-Associations", v.raw()))),
            Map.of("driver", v.driverDn(), "state", name(v.state()), "value", v.value()));
        Http.json(ex, 200, read(l, guid));
    }

    private static String name(int state) {
        return state >= 0 && state < STATES.size() ? STATES.get(state) : String.valueOf(state);
    }

    private void write(Sessions.Session s, Ldap l, Ldap.Entry e, String guid, String action, List<ModificationItem> mods, Map<String, Object> what)
            throws IOException, NamingException {
        Map<String, Object> detail = new LinkedHashMap<>(what);
        detail.put("dn", e.dn());
        try {
            l.modify(e.dn(), mods);
        } catch (NamingException x) {
            server.objects.audit(s, action, guid, detail, Ldap.Failure.of(x));
            throw x;
        }
        server.objects.audit(s, action, guid, detail, null);
    }
}
