package com.pointblue.console.server.http;

import com.pointblue.console.server.auth.DirectoryConfig;
import com.pointblue.console.server.auth.Grant;
import com.pointblue.console.server.auth.Sessions;
import com.pointblue.console.server.auth.TaskPreset;
import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.console.server.ldap.Schema;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
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

/**
 * Task presets: the presets a person may run, and running
 * one on an object. A run is checked against the preset (its class, actions and field rules) and the
 * grants that give it (their containers), then written as one modification, so it applies entirely
 * or not at all. eDirectory's own rights still decide whether that modification is allowed.
 *
 * <pre>
 * GET  /api/v2/trees/{tree}/presets                         the presets granted to the caller, with where
 * POST /api/v2/trees/{tree}/objects/{guid}/presets/{id}     {"password", "mustChange", "unlock", "enabled", "attributes": {name: value|null}}
 * </pre>
 */
final class Presets {

    private static final DateTimeFormatter GENERALIZED = DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);

    private final Server server;
    private final Objects objects;

    Presets(Server server, Objects objects) {
        this.server = server;
        this.objects = objects;
    }

    private DirectoryConfig directory(Sessions.Session s) {
        DirectoryConfig d = server.directoryOf(s);
        if (d == null) {
            throw new Http.Problem(404, "unknown-directory", "no directory " + s.principal.directoryId());
        }
        return d;
    }

    void list(HttpExchange ex, Sessions.Session s) throws IOException {
        DirectoryConfig d = directory(s);
        List<Map<String, Object>> out = new ArrayList<>();
        for (TaskPreset p : d.presets().values()) {
            Set<String> scopes = new LinkedHashSet<>();
            boolean anywhere = false;
            boolean granted = false;
            for (Grant g : s.principal.grants()) {
                if (g.presets().contains(p.id())) {
                    granted = true;
                    anywhere |= g.scopes().isEmpty();
                    scopes.addAll(g.scopes());
                }
            }
            if (granted) {
                Map<String, Object> m = p.json();
                m.put("scopes", anywhere ? List.of() : List.copyOf(scopes));
                out.add(m);
            }
        }
        Http.json(ex, 200, out);
    }

    void run(HttpExchange ex, Ldap l, Schema schema, Sessions.Session s, String guid, String id) throws IOException, NamingException {
        TaskPreset p = directory(s).presets().get(id);
        if (p == null) {
            throw new Http.Problem(404, "no-such-preset", "no task preset " + id);
        }
        Ldap.Entry e = objects.byGuid(l, guid, presetAttributes(p));
        if (!s.principal.presetsAt(e.dn()).contains(id)) {
            throw new Http.Problem(403, "out-of-scope", "you may not run " + p.name() + " on " + e.dn());
        }
        List<Object> classes = e.attributes().getOrDefault("objectclass", List.of());
        if (classes.stream().noneMatch(c -> String.valueOf(c).equalsIgnoreCase(p.objectClass()))) {
            throw new Http.Problem(409, "wrong-class", p.name() + " applies to " + p.objectClass() + " objects");
        }
        Map<String, Object> b = Http.body(ex);
        List<ModificationItem> mods = new ArrayList<>();
        List<String> changed = new ArrayList<>();
        List<String> problems = new ArrayList<>();

        String pw = Http.string(b, "password", false);
        if (pw != null) {
            need(p, "password");
            mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("userPassword", pw)));
            changed.add("userPassword");
            if (Boolean.TRUE.equals(b.get("mustChange"))) {
                mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("passwordExpirationTime", GENERALIZED.format(Instant.now().minusSeconds(60)))));
                changed.add("passwordExpirationTime");
            }
        }
        if (Boolean.TRUE.equals(b.get("unlock"))) {
            need(p, "unlock");
            mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("lockedByIntruder", "FALSE")));
            changed.add("lockedByIntruder");
            for (String a : new String[] {"loginIntruderAttempts", "loginIntruderResetTime"}) {
                if (e.attributes().containsKey(a.toLowerCase(Locale.ROOT))) {
                    mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute(a)));
                }
            }
        }
        if (b.get("enabled") instanceof Boolean enabled) {
            need(p, enabled ? "enable" : "disable");
            mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("loginDisabled", enabled ? "FALSE" : "TRUE")));
            changed.add("loginDisabled");
        }
        if (b.get("attributes") instanceof Map<?, ?> attrs && !attrs.isEmpty()) {
            need(p, "attributes");
            for (Map.Entry<?, ?> a : attrs.entrySet()) {
                String name = String.valueOf(a.getKey());
                TaskPreset.Field f = p.field(name);
                if (f == null) {
                    throw new Http.Problem(403, "not-in-preset", p.name() + " does not change " + name);
                }
                if (f.readOnly() || f.value() != null) {
                    throw new Http.Problem(403, "read-only", (f.label() == null ? name : f.label()) + " cannot be changed here");
                }
                if (schema.attribute(f.name()) == null) {
                    throw new Http.Problem(400, "undefined-attribute", "the directory has no attribute " + f.name());
                }
                String v = a.getValue() == null ? null : String.valueOf(a.getValue()).trim();
                String why = f.check(v);
                if (why != null) {
                    problems.add(why);
                    continue;
                }
                if (v == null || v.isEmpty()) {
                    if (e.attributes().containsKey(f.name().toLowerCase(Locale.ROOT))) {
                        mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute(f.name())));
                        changed.add(f.name());
                    }
                } else if (!v.equals(e.first(f.name()))) {
                    mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(f.name(), v)));
                    changed.add(f.name());
                }
            }
        }
        if (!problems.isEmpty()) {
            throw new Http.Problem(400, "invalid-fields", String.join("; ", problems), Map.of("problems", problems));
        }
        if (mods.isEmpty()) {
            Http.json(ex, 200, Map.of("changed", List.of()));
            return;
        }
        for (TaskPreset.Field f : p.attributes()) {
            // preset values ride along with every change the preset makes
            if (f.value() != null && !f.value().equals(e.first(f.name()))) {
                mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(f.name(), f.value())));
                changed.add(f.name());
            }
        }
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("dn", e.dn());
        detail.put("preset", id);
        detail.put("attributes", changed);
        try {
            l.modify(e.dn(), mods);
        } catch (NamingException x) {
            objects.audit(s, "preset.run", guid, detail, Ldap.Failure.of(x));
            Exception why = objects.explainRefusal(s, l, e.dn(), mods.stream().map(mi -> mi.getAttribute().getID()).distinct().toList(), x);
            if (why instanceof Http.Problem p2) {
                throw p2;
            }
            throw x;
        }
        objects.audit(s, "preset.run", guid, detail, null);
        Http.json(ex, 200, Map.of("changed", changed));
    }

    private static void need(TaskPreset p, String action) {
        if (!p.actions().contains(action)) {
            throw new Http.Problem(403, "not-in-preset", p.name() + " does not " + switch (action) {
                case "password" -> "set passwords";
                case "unlock" -> "unlock accounts";
                case "enable" -> "enable accounts";
                case "disable" -> "disable accounts";
                default -> "change attributes";
            });
        }
    }

    private static String[] presetAttributes(TaskPreset p) {
        List<String> a = new ArrayList<>(List.of("objectClass", "loginIntruderAttempts", "loginIntruderResetTime"));
        p.attributes().forEach(f -> a.add(f.name()));
        return a.toArray(new String[0]);
    }
}
