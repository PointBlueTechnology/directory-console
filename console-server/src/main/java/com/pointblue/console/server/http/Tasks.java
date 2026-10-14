package com.pointblue.console.server.http;

import com.pointblue.console.server.auth.Role;
import com.pointblue.console.server.auth.Sessions;
import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.console.server.ldap.Names;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.Rdn;

/**
 * Object tasks (Phase 2b): password, account, intruder lockout, group membership kept on both sides,
 * aliases after a move or rename, subtree delete, and the guard against an Inherited Rights Filter that
 * would lock the editor out. What eDirectory does for each was measured on ig4 (spikes/Phase2bProbe).
 */
final class Tasks {

    /** Account attributes on a user, read for {@link #account}. */
    private static final String[] ACCOUNT = {
        "loginDisabled", "lockedByIntruder", "loginIntruderAttempts", "loginIntruderResetTime", "loginIntruderAddress", "loginExpirationTime",
        "loginMaximumSimultaneous", "loginTime", "passwordRequired", "passwordAllowChange", "passwordMinimumLength",
        "passwordExpirationInterval", "passwordExpirationTime", "passwordUniqueRequired", "loginGraceLimit",
        "loginGraceRemaining", "loginAllowedTimeMap", "revision", "modifyTimestamp", "objectClass", "GUID"};
    private static final DateTimeFormatter GENERALIZED = DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
    /** The login time map: 7 days of 48 half-hours, one bit each. */
    static final int TIME_MAP_BYTES = 42;
    /** A subtree delete refuses more than this many objects. */
    static final int SUBTREE_LIMIT = 10_000;

    private final Objects objects;

    Tasks(Objects objects) {
        this.objects = objects;
    }

    // ---- password -------------------------------------------------------------------------------

    /**
     * {@code {"password", "mustChange"}}. The password is never logged or returned; {@code mustChange}
     * expires it at once so the person must change it at the next login.
     */
    void password(HttpExchange ex, Ldap l, Sessions.Session s, String guid) throws IOException, NamingException {
        Map<String, Object> b = Http.body(ex);
        String pw = Http.string(b, "password", true);
        boolean mustChange = Boolean.TRUE.equals(b.get("mustChange"));
        String dn = objects.dnOf(l, guid);
        List<ModificationItem> mods = new ArrayList<>(List.of(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("userPassword", pw))));
        if (mustChange) {
            mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("passwordExpirationTime", GENERALIZED.format(Instant.now().minusSeconds(60)))));
        }
        Map<String, Object> detail = Map.of("dn", dn, "mustChange", mustChange);
        try {
            l.modify(dn, mods);
        } catch (NamingException x) {
            objects.audit(s, "object.password", guid, detail, Ldap.Failure.of(x));
            throw x;
        }
        objects.audit(s, "object.password", guid, detail, null);
        Http.json(ex, 204, Map.of());
    }

    // ---- account --------------------------------------------------------------------------------

    void account(HttpExchange ex, Ldap l, String guid) throws IOException, NamingException {
        Ldap.Entry e = objects.byGuid(l, guid, ACCOUNT);
        ex.getResponseHeaders().set("ETag", Objects.etag(e));
        Http.json(ex, 200, accountJson(e));
    }

    static Map<String, Object> accountJson(Ldap.Entry e) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("disabled", bool(e.first("loginDisabled")));
        m.put("lockedByIntruder", bool(e.first("lockedByIntruder")));
        m.put("intruderAttempts", integer(e.first("loginIntruderAttempts")));
        m.put("intruderResetTime", iso(e.first("loginIntruderResetTime")));
        Object from = e.attributes().getOrDefault("loginintruderaddress", List.of()).stream().findFirst().orElse(null);
        m.put("intruderAddress", from instanceof byte[] b ? NetAddress.ip(b) : from == null ? null : String.valueOf(from));
        m.put("loginExpires", iso(e.first("loginExpirationTime")));
        m.put("maxConnections", integer(e.first("loginMaximumSimultaneous")));
        m.put("lastLogin", iso(e.first("loginTime")));
        m.put("passwordRequired", bool(e.first("passwordRequired")));
        m.put("passwordAllowChange", bool(e.first("passwordAllowChange")));
        m.put("passwordMinimumLength", integer(e.first("passwordMinimumLength")));
        Integer interval = integer(e.first("passwordExpirationInterval"));
        m.put("passwordExpirationDays", interval == null ? null : interval / 86400);
        m.put("passwordExpires", iso(e.first("passwordExpirationTime")));
        m.put("passwordUnique", bool(e.first("passwordUniqueRequired")));
        m.put("graceLimit", integer(e.first("loginGraceLimit")));
        m.put("graceRemaining", integer(e.first("loginGraceRemaining")));
        List<Object> map = e.attributes().get("loginallowedtimemap");
        m.put("timeMap", map == null || map.isEmpty() || !(map.get(0) instanceof byte[] bytes) ? null : HexFormat.of().formatHex(bytes));
        return m;
    }

    /**
     * Change the fields present in the body; {@code null} removes the attribute. Booleans, ISO-8601
     * times, whole days for the expiration interval, and the time map as 84 hex digits.
     */
    void updateAccount(HttpExchange ex, Ldap l, Sessions.Session s, String guid) throws IOException, NamingException {
        Map<String, Object> b = Http.body(ex);
        Ldap.Entry e = objects.current(ex, l, guid);
        Ldap.Entry now = objects.byGuid(l, guid, ACCOUNT);
        List<ModificationItem> mods = new ArrayList<>();
        List<String> changed = new ArrayList<>();
        set(b, "disabled", "loginDisabled", now, mods, changed, v -> booleanValue(v));
        set(b, "loginExpires", "loginExpirationTime", now, mods, changed, Tasks::generalized);
        set(b, "maxConnections", "loginMaximumSimultaneous", now, mods, changed, v -> number(v, 0, 100_000));
        set(b, "passwordRequired", "passwordRequired", now, mods, changed, v -> booleanValue(v));
        set(b, "passwordAllowChange", "passwordAllowChange", now, mods, changed, v -> booleanValue(v));
        set(b, "passwordMinimumLength", "passwordMinimumLength", now, mods, changed, v -> number(v, 0, 512));
        set(b, "passwordExpirationDays", "passwordExpirationInterval", now, mods, changed, v -> String.valueOf(Long.parseLong(number(v, 1, 3650)) * 86400));
        set(b, "passwordExpires", "passwordExpirationTime", now, mods, changed, Tasks::generalized);
        set(b, "passwordUnique", "passwordUniqueRequired", now, mods, changed, v -> booleanValue(v));
        set(b, "graceLimit", "loginGraceLimit", now, mods, changed, v -> number(v, 0, 1000));
        set(b, "graceRemaining", "loginGraceRemaining", now, mods, changed, v -> number(v, 0, 1000));
        if (b.containsKey("timeMap")) {
            Object v = b.get("timeMap");
            if (v == null) {
                if (now.attributes().containsKey("loginallowedtimemap")) {
                    mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute("loginAllowedTimeMap")));
                }
            } else {
                String hex = String.valueOf(v);
                if (!hex.matches("[0-9a-fA-F]{" + (TIME_MAP_BYTES * 2) + "}")) {
                    throw new Http.Problem(400, "bad-field", "timeMap is " + (TIME_MAP_BYTES * 2) + " hex digits (7 days x 48 half-hours)");
                }
                mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("loginAllowedTimeMap", HexFormat.of().parseHex(hex))));
            }
            changed.add("loginAllowedTimeMap");
        }
        if (mods.isEmpty()) {
            account(ex, l, guid);
            return;
        }
        Map<String, Object> detail = Map.of("dn", e.dn(), "attributes", changed);
        try {
            l.modify(e.dn(), mods);
        } catch (NamingException x) {
            objects.audit(s, "object.account", guid, detail, Ldap.Failure.of(x));
            throw x;
        }
        objects.audit(s, "object.account", guid, detail, null);
        account(ex, l, guid);
    }

    private interface Convert {
        String apply(Object v);
    }

    private static void set(Map<String, Object> body, String field, String attr, Ldap.Entry now, List<ModificationItem> mods,
                            List<String> changed, Convert convert) {
        if (!body.containsKey(field)) {
            return;
        }
        Object v = body.get(field);
        if (v == null) {
            if (now.attributes().containsKey(attr.toLowerCase(Locale.ROOT))) {
                mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute(attr)));
                changed.add(attr);
            }
            return;
        }
        try {
            mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(attr, convert.apply(v))));
        } catch (RuntimeException x) {
            throw new Http.Problem(400, "bad-field", field + ": " + x.getMessage());
        }
        changed.add(attr);
    }

    /** Clear an intruder lockout: {@code lockedByIntruder} FALSE and the attempt counter and reset time removed. */
    void unlock(HttpExchange ex, Ldap l, Sessions.Session s, String guid) throws IOException, NamingException {
        Ldap.Entry e = objects.byGuid(l, guid, ACCOUNT);
        List<ModificationItem> mods = new ArrayList<>(List.of(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("lockedByIntruder", "FALSE"))));
        for (String a : new String[] {"loginIntruderAttempts", "loginIntruderResetTime"}) {
            if (e.attributes().containsKey(a.toLowerCase(Locale.ROOT))) {
                mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute(a)));
            }
        }
        try {
            l.modify(e.dn(), mods);
        } catch (NamingException x) {
            objects.audit(s, "object.unlock", guid, Map.of("dn", e.dn()), Ldap.Failure.of(x));
            throw x;
        }
        objects.audit(s, "object.unlock", guid, Map.of("dn", e.dn()), null);
        account(ex, l, guid);
    }

    // ---- membership -----------------------------------------------------------------------------

    /** A user's groups, from {@code groupMembership}, and whether each also grants security equivalence. */
    void memberships(HttpExchange ex, Ldap l, String guid) throws IOException, NamingException {
        Ldap.Entry e = objects.byGuid(l, guid, "groupMembership", "securityEquals");
        Set<String> equals = canonical(e.attributes().getOrDefault("securityequals", List.of()));
        List<Map<String, Object>> groups = new ArrayList<>();
        for (Object g : e.attributes().getOrDefault("groupmembership", List.of())) {
            String dn = String.valueOf(g);
            Map<String, Object> m = reference(dn);
            m.put("securityEquivalent", equals.contains(Names.canonical(dn)));
            groups.add(m);
        }
        groups.sort(Comparator.comparing(m -> String.valueOf(m.get("name")).toLowerCase(Locale.ROOT)));
        Http.json(ex, 200, Map.of("items", groups, "total", groups.size()));
    }

    /** {@code {"add": [group…], "remove": [group…]}} for a user (each a GUID or {"dn"}). */
    void changeMemberships(HttpExchange ex, Ldap l, Sessions.Session s, String guid) throws IOException, NamingException {
        Map<String, Object> b = Http.body(ex);
        String member = objects.dnOf(l, guid);
        List<Map<String, Object>> results = new ArrayList<>();
        for (String g : targets(l, b.get("add"))) {
            results.add(membership(l, s, g, member, true));
        }
        for (String g : targets(l, b.get("remove"))) {
            results.add(membership(l, s, g, member, false));
        }
        respond(ex, results);
    }

    /** A group's members (stored, or computed for a dynamic group), as a window sorted by name. */
    void members(HttpExchange ex, Ldap l, String guid) throws IOException, NamingException {
        Ldap.Entry e = objects.byGuid(l, guid, "member", "objectClass", "memberQueryURL");
        Map<String, String> q = Http.query(ex);
        List<Map<String, Object>> all = new ArrayList<>();
        for (Object m : e.attributes().getOrDefault("member", List.of())) {
            all.add(reference(String.valueOf(m)));
        }
        all.sort(Comparator.comparing(m -> String.valueOf(m.get("name")).toLowerCase(Locale.ROOT)));
        int offset = Math.max(1, parse(q.get("offset"), 1));
        int count = Math.min(500, Math.max(1, parse(q.get("count"), 100)));
        int from = Math.min(all.size(), offset - 1);
        Map<String, Object> out = new LinkedHashMap<>();
        Set<String> classes = lower(e.attributes().getOrDefault("objectclass", List.of()));
        out.put("dynamic", classes.contains("dynamicgroup") || classes.contains("dynamicgroupaux"));
        out.put("nested", classes.contains("nestedgroupaux"));
        out.put("memberQueryURL", e.first("memberQueryURL"));
        out.put("offset", offset);
        out.put("total", all.size());
        out.put("items", all.subList(from, Math.min(all.size(), from + count)));
        Http.json(ex, 200, out);
    }

    /** {@code {"add": [member…], "remove": [member…]}} for a group. A dynamic group's members come from its query. */
    void changeMembers(HttpExchange ex, Ldap l, Sessions.Session s, String guid) throws IOException, NamingException {
        Map<String, Object> b = Http.body(ex);
        Ldap.Entry group = objects.byGuid(l, guid, "objectClass");
        Set<String> classes = lower(group.attributes().getOrDefault("objectclass", List.of()));
        if (classes.contains("dynamicgroup") || classes.contains("dynamicgroupaux")) {
            throw new Http.Problem(409, "dynamic-group", "a dynamic group's members come from its query (memberQueryURL); change the query instead");
        }
        List<Map<String, Object>> results = new ArrayList<>();
        for (String m : targets(l, b.get("add"))) {
            results.add(membership(l, s, group.dn(), m, true));
        }
        for (String m : targets(l, b.get("remove"))) {
            results.add(membership(l, s, group.dn(), m, false));
        }
        respond(ex, results);
    }

    private void respond(HttpExchange ex, List<Map<String, Object>> results) throws IOException {
        boolean failed = results.stream().anyMatch(r -> !"ok".equals(r.get("status")) && !"unchanged".equals(r.get("status")));
        Http.json(ex, failed ? 207 : 200, Map.of("results", results));
    }

    /**
     * Add or remove one membership on both sides: the group's {@code member} and {@code equivalentToMe},
     * the member's {@code groupMembership} and {@code securityEquals}. Measured on ig4: eDirectory does not
     * link {@code member} and {@code groupMembership}, but does add or remove {@code securityEquals} when
     * {@code equivalentToMe} changes. Only missing (or present) values are written. When the member side
     * fails after the group side succeeded, the group side is put back.
     */
    Map<String, Object> membership(Ldap l, Sessions.Session s, String groupDn, String memberDn, boolean add) throws IOException, NamingException {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("group", reference(groupDn));
        result.put("member", reference(memberDn));
        String action = add ? "membership.add" : "membership.remove";
        Map<String, Object> detail = Map.of("group", groupDn, "member", memberDn);
        if (!s.principal.may(Role.EDITOR, groupDn) || !s.principal.may(Role.EDITOR, memberDn)) {
            // both sides are written, so both must be within the person's editor scope
            result.put("status", "refused");
            result.put("detail", "outside your editor scope: " + (s.principal.may(Role.EDITOR, groupDn) ? memberDn : groupDn));
            return result;
        }
        Ldap.Entry g = l.read(groupDn, "member", "equivalentToMe");
        Ldap.Entry m = l.read(memberDn, "groupMembership", "securityEquals");
        if (g == null || m == null) {
            result.put("status", "failed");
            result.put("detail", (g == null ? groupDn : memberDn) + " was not found");
            return result;
        }
        List<ModificationItem> groupSide = sideChanges(g, add, memberDn, "member", "equivalentToMe");
        List<ModificationItem> memberSide = sideChanges(m, add, groupDn, "groupMembership", "securityEquals");
        if (groupSide.isEmpty() && memberSide.isEmpty()) {
            result.put("status", "unchanged");
            return result;
        }
        try {
            if (!groupSide.isEmpty()) {
                l.modify(groupDn, groupSide);
            }
        } catch (NamingException x) {
            Ldap.Failure f = Ldap.Failure.of(x);
            objects.audit(s, action, null, detail, f);
            result.put("status", "failed");
            result.put("detail", "the group could not be changed: " + f.getMessage());
            return result;
        }
        try {
            // eDirectory keeps securityEquals in step with the group's equivalentToMe (ig4), so the
            // member side is worked out again after the group side is written
            Ldap.Entry after = groupSide.isEmpty() ? m : l.read(memberDn, "groupMembership", "securityEquals");
            memberSide = after == null ? memberSide : sideChanges(after, add, groupDn, "groupMembership", "securityEquals");
            if (!memberSide.isEmpty()) {
                l.modify(memberDn, memberSide);
            }
        } catch (NamingException x) {
            Ldap.Failure f = Ldap.Failure.of(x);
            String undo = "the group was put back";
            try {
                if (!groupSide.isEmpty()) {
                    l.modify(groupDn, inverse(groupSide));
                }
            } catch (NamingException y) {
                undo = "the group could NOT be put back (" + Ldap.Failure.of(y).getMessage() + "); it lists the member on one side only";
            }
            objects.audit(s, action, null, Map.of("group", groupDn, "member", memberDn, "rollback", undo), f);
            result.put("status", "failed");
            result.put("detail", "the member could not be changed: " + f.getMessage() + "; " + undo);
            return result;
        }
        objects.audit(s, action, null, detail, null);
        result.put("status", "ok");
        return result;
    }

    private static List<ModificationItem> sideChanges(Ldap.Entry e, boolean add, String otherDn, String... attrs) {
        List<ModificationItem> out = new ArrayList<>();
        String other = Names.canonical(otherDn);
        for (String a : attrs) {
            boolean present = canonical(e.attributes().getOrDefault(a.toLowerCase(Locale.ROOT), List.of())).contains(other);
            if (add && !present) {
                out.add(new ModificationItem(DirContext.ADD_ATTRIBUTE, new BasicAttribute(a, otherDn)));
            } else if (!add && present) {
                out.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute(a, otherDn)));
            }
        }
        return out;
    }

    private static List<ModificationItem> inverse(List<ModificationItem> mods) {
        List<ModificationItem> out = new ArrayList<>();
        for (ModificationItem m : mods) {
            out.add(new ModificationItem(m.getModificationOp() == DirContext.ADD_ATTRIBUTE ? DirContext.REMOVE_ATTRIBUTE : DirContext.ADD_ATTRIBUTE, m.getAttribute()));
        }
        return out;
    }

    /** GUIDs or {"dn": …} references, as DNs. */
    private List<String> targets(Ldap l, Object list) throws NamingException {
        List<String> out = new ArrayList<>();
        if (list == null) {
            return out;
        }
        if (!(list instanceof List<?> items)) {
            throw new Http.Problem(400, "bad-field", "add and remove are lists of GUIDs or {\"dn\": …}");
        }
        for (Object o : items) {
            if (o instanceof String g && Names.guid(g)) {
                out.add(objects.dnOf(l, g));
            } else if (o instanceof Map<?, ?> m && m.get("dn") != null) {
                out.add(Names.parse(String.valueOf(m.get("dn"))).toString());
            } else if (o instanceof Map<?, ?> m && m.get("guid") != null) {
                out.add(objects.dnOf(l, String.valueOf(m.get("guid"))));
            } else {
                throw new Http.Problem(400, "bad-field", "not a GUID or {\"dn\": …}: " + o);
            }
        }
        return out;
    }

    // ---- alias, subtree -------------------------------------------------------------------------

    /**
     * An alias at {@code oldDn} pointing to {@code newDn}, created as soon as eDirectory allows (ig4 took
     * one attempt, 52 ms after a move); retried briefly while the move settles. Returns "created" or why not.
     */
    String leaveAlias(Ldap l, String oldDn, String newDn) {
        Rdn leaf = Names.leaf(oldDn);
        Map<String, List<Object>> attrs = new LinkedHashMap<>();
        attrs.put("objectClass", new ArrayList<>(List.of("aliasObject")));
        attrs.put(leaf.getType(), new ArrayList<>(List.of(String.valueOf(leaf.getValue()))));
        attrs.put("aliasedObjectName", new ArrayList<>(List.of(newDn)));
        String last = "";
        for (int attempt = 0; attempt < 10; attempt++) {
            try {
                l.create(oldDn, attrs);
                return "created";
            } catch (NamingException e) {
                Ldap.Failure f = Ldap.Failure.of(e);
                last = f.getMessage();
                boolean settling = f.code == 68 || (f.ndsError != null && f.ndsError == -637);
                if (!settling) {
                    break;
                }
                try {
                    Thread.sleep(500);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        return "not created: " + last;
    }

    /** How many objects a subtree delete would remove (the object included); {@code capped} past the limit. */
    void subtree(HttpExchange ex, Ldap l, String guid) throws IOException, NamingException {
        String dn = objects.dnOf(l, guid);
        List<Ldap.Entry> all = l.search(dn, "(objectClass=*)", null, SearchControls.SUBTREE_SCOPE, new String[] {"1.1"}, SUBTREE_LIMIT + 1);
        Http.json(ex, 200, Map.of("count", Math.min(all.size(), SUBTREE_LIMIT), "capped", all.size() > SUBTREE_LIMIT));
    }

    /**
     * Delete the object and everything under it, deepest first, one at a time. The request carries
     * {@code X-Confirm-Count}: the count the person was shown. A different count now means the subtree
     * changed, and nothing is deleted. A failure stops the delete and reports what was removed.
     */
    void deleteSubtree(HttpExchange ex, Ldap l, Sessions.Session s, String guid, Ldap.Entry e) throws IOException, NamingException {
        String confirm = ex.getRequestHeaders().getFirst("X-Confirm-Count");
        List<Ldap.Entry> all = l.search(e.dn(), "(objectClass=*)", null, SearchControls.SUBTREE_SCOPE, new String[] {"1.1"}, SUBTREE_LIMIT + 1);
        if (all.size() > SUBTREE_LIMIT) {
            throw new Http.Problem(409, "subtree-too-large", "more than " + SUBTREE_LIMIT + " objects; delete smaller parts first");
        }
        if (confirm == null || !confirm.trim().equals(String.valueOf(all.size()))) {
            throw new Http.Problem(409, "confirm-count", "send X-Confirm-Count with the number of objects to delete (" + all.size() + " now)",
                Map.of("count", all.size()));
        }
        List<String> dns = new ArrayList<>(all.stream().map(Ldap.Entry::dn).toList());
        dns.sort(Comparator.comparingInt((String d) -> Names.parse(d).size()).reversed());
        int deleted = 0;
        for (String d : dns) {
            NamingException failure = null;
            for (int attempt = 0; attempt < 10; attempt++) {
                try {
                    l.delete(d);
                    failure = null;
                    break;
                } catch (NamingException x) {
                    failure = x;
                    Ldap.Failure f = Ldap.Failure.of(x);
                    if (f.ndsError == null || f.ndsError != -637) {
                        break;
                    }
                    try {
                        Thread.sleep(1000);   // a recent move is still settling
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
            if (failure != null) {
                Ldap.Failure f = Ldap.Failure.of(failure);
                objects.audit(s, "object.delete-subtree", guid, Map.of("dn", e.dn(), "deleted", deleted, "of", dns.size(), "stoppedAt", d), f);
                Map<String, Object> extra = new LinkedHashMap<>();
                extra.put("deleted", deleted);
                extra.put("of", dns.size());
                extra.put("stoppedAt", d);
                extra.put("ldapResultCode", f.code);
                if (f.ndsError != null) {
                    extra.put("ndsError", f.ndsError);
                }
                throw new Http.Problem(409, "subtree-partly-deleted", deleted + " of " + dns.size() + " objects were deleted; " + d + ": " + f.getMessage(), extra);
            }
            deleted++;
        }
        objects.audit(s, "object.delete-subtree", guid, Map.of("dn", e.dn(), "deleted", deleted), null);
        Http.json(ex, 200, Map.of("deleted", deleted));
    }

    // ---- the Inherited Rights Filter guard ------------------------------------------------------

    /**
     * Refuse ACL changes that leave an Inherited Rights Filter blocking Supervisor (entry rights), or
     * write or Supervisor on all attributes, while no trustee holds explicit Supervisor on the object:
     * nobody could then manage it (an ig4 test container was lost this way on 2026-10-09). Explicit
     * rights are not filtered, so an explicit Supervisor trustee keeps the object manageable.
     */
    void guardInheritanceMask(Ldap l, String dn, List<ModificationItem> mods) throws NamingException {
        List<ModificationItem> acl = mods.stream().filter(m -> m.getAttribute().getID().equalsIgnoreCase("ACL")).toList();
        if (acl.isEmpty()) {
            return;
        }
        Ldap.Entry e = l.read(dn, "ACL");
        Set<String> values = new LinkedHashSet<>();
        for (Object v : e == null ? List.of() : e.attributes().getOrDefault("acl", List.of())) {
            values.add(String.valueOf(v));
        }
        for (ModificationItem m : acl) {
            List<String> vs = strings(m.getAttribute());
            switch (m.getModificationOp()) {
                case DirContext.ADD_ATTRIBUTE -> values.addAll(vs);
                case DirContext.REPLACE_ATTRIBUTE -> {
                    values.clear();
                    values.addAll(vs);
                }
                default -> {
                    if (vs.isEmpty()) {
                        values.clear();
                    } else {
                        values.removeIf(v -> vs.stream().anyMatch(r -> sameAcl(r, v)));
                    }
                }
            }
        }
        boolean blocking = false;
        boolean explicitSupervisor = false;
        for (String v : values) {
            String[] p = v.split("#", 4);
            if (p.length != 4) {
                continue;
            }
            int bits;
            try {
                bits = Integer.parseInt(p[0]);
            } catch (NumberFormatException x) {
                continue;
            }
            boolean entry = p[3].equalsIgnoreCase("[Entry Rights]");
            if (p[2].equalsIgnoreCase("[Inheritance Mask]")) {
                if (entry && (bits & 0x10) == 0) {
                    blocking = true;
                } else if ((p[3].equalsIgnoreCase("[All Attributes Rights]") || p[3].equalsIgnoreCase("ACL")) && (bits & 0x20) == 0 && (bits & 0x04) == 0) {
                    blocking = true;
                }
            } else if (!p[2].startsWith("[") && entry && (bits & 0x10) != 0) {
                explicitSupervisor = true;
            }
        }
        if (blocking && !explicitSupervisor) {
            throw new Http.Problem(409, "would-lock-out",
                "this Inherited Rights Filter blocks Supervisor (or write to all attributes) and no trustee has explicit Supervisor on the object, "
                    + "so nobody, including you, could manage it afterwards; first give a trustee explicit Supervisor on this object");
        }
    }

    private static boolean sameAcl(String a, String b) {
        String[] x = a.split("#", 4);
        String[] y = b.split("#", 4);
        if (x.length != 4 || y.length != 4) {
            return a.equalsIgnoreCase(b);
        }
        boolean trustee = x[2].startsWith("[") || y[2].startsWith("[") ? x[2].equalsIgnoreCase(y[2]) : Names.same(x[2], y[2]);
        return x[0].equals(y[0]) && x[1].equalsIgnoreCase(y[1]) && trustee && x[3].equalsIgnoreCase(y[3]);
    }

    private static List<String> strings(javax.naming.directory.Attribute a) throws NamingException {
        List<String> out = new ArrayList<>();
        NamingEnumeration<?> all = a.getAll();
        while (all.hasMore()) {
            out.add(String.valueOf(all.next()));
        }
        return out;
    }

    // ---- small helpers --------------------------------------------------------------------------

    private static Map<String, Object> reference(String dn) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("dn", dn);
        try {
            m.put("name", Names.identity(dn).get("name"));
        } catch (IllegalArgumentException e) {
            m.put("name", dn);
        }
        return m;
    }

    private static Set<String> canonical(List<Object> dns) {
        Set<String> out = new LinkedHashSet<>();
        for (Object d : dns) {
            try {
                out.add(Names.canonical(String.valueOf(d)));
            } catch (IllegalArgumentException e) {
                out.add(String.valueOf(d).toLowerCase(Locale.ROOT));
            }
        }
        return out;
    }

    private static Set<String> lower(List<Object> values) {
        Set<String> out = new LinkedHashSet<>();
        values.forEach(v -> out.add(String.valueOf(v).toLowerCase(Locale.ROOT)));
        return out;
    }

    private static Boolean bool(String v) {
        return v == null ? null : v.equalsIgnoreCase("TRUE");
    }

    private static Integer integer(String v) {
        try {
            return v == null ? null : Integer.valueOf(v.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static int parse(String v, int dflt) {
        Integer i = integer(v);
        return i == null ? dflt : i;
    }

    /** 20301231230000Z → 2030-12-31T23:00:00Z. */
    static String iso(String generalized) {
        if (generalized == null) {
            return null;
        }
        try {
            String g = generalized.replaceFirst("[.,]\\d+Z$", "Z");
            return Instant.from(GENERALIZED.parse(g)).toString();
        } catch (RuntimeException e) {
            return generalized;
        }
    }

    static String generalized(Object iso) {
        return GENERALIZED.format(Instant.parse(String.valueOf(iso)));
    }

    private static String booleanValue(Object v) {
        if (!(v instanceof Boolean b)) {
            throw new IllegalArgumentException("true or false");
        }
        return b ? "TRUE" : "FALSE";
    }

    private static String number(Object v, long min, long max) {
        if (!(v instanceof Number n) || n.doubleValue() != Math.floor(n.doubleValue()) || n.longValue() < min || n.longValue() > max) {
            throw new IllegalArgumentException("a whole number from " + min + " to " + max);
        }
        return String.valueOf(n.longValue());
    }
}
