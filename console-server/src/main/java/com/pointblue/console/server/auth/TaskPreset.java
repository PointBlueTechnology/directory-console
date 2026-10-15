package com.pointblue.console.server.auth;

import com.pointblue.dirxml.dev.json.Json;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * A named, restricted task, such as "reset password and
 * unlock" for a help desk or "edit phone and title" for HR. It applies to objects of one class and
 * allows only its {@link #ACTIONS} and its attributes, each with field rules. Who may run it, and
 * where, comes from role mappings that grant it.
 *
 * <pre>
 * { "name": "Edit phone and title", "description": "…", "objectClass": "inetOrgPerson",
 *   "actions": ["attributes"],
 *   "attributes": [ { "name": "telephoneNumber", "label": "Phone", "pattern": "\\+?[0-9 ()-]{4,20}" },
 *                   { "name": "title", "required": true },
 *                   { "name": "departmentNumber", "readOnly": true },
 *                   { "name": "description", "value": "Changed by HR" } ] }
 * </pre>
 *
 * A field with {@code value} is set to that value whenever the preset changes the object.
 */
public record TaskPreset(String id, String name, String description, String objectClass, Set<String> actions, List<Field> attributes) {

    /** {@code password}: set a password; {@code unlock}: clear intruder lockout; {@code enable}/{@code disable}; {@code attributes}: edit the fields. */
    public static final List<String> ACTIONS = List.of("password", "unlock", "enable", "disable", "attributes");

    public record Field(String name, String label, boolean required, boolean readOnly, String pattern, String value) {

        public Map<String, Object> json() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", name);
            m.put("label", label == null ? name : label);
            m.put("required", required);
            m.put("readOnly", readOnly);
            if (pattern != null) {
                m.put("pattern", pattern);
            }
            if (value != null) {
                m.put("value", value);
            }
            return m;
        }

        /** Why {@code v} breaks this field's rules, or null. */
        public String check(String v) {
            if (v == null || v.isEmpty()) {
                return required ? (label == null ? name : label) + " is required" : null;
            }
            if (pattern != null && !Pattern.compile(pattern).matcher(v).matches()) {
                return (label == null ? name : label) + " does not have the expected form";
            }
            return null;
        }
    }

    public static TaskPreset of(String id, Map<String, Object> m) {
        if (!id.matches("[a-z0-9][a-z0-9-]{0,62}")) {
            throw new IllegalArgumentException("a preset id is lowercase letters, digits and hyphens: " + id);
        }
        List<String> actions = new ArrayList<>();
        if (m.get("actions") instanceof List<?> l) {
            for (Object o : l) {
                String a = String.valueOf(o);
                if (!ACTIONS.contains(a)) {
                    throw new IllegalArgumentException("preset " + id + ": unknown action " + a + " (one of " + ACTIONS + ")");
                }
                actions.add(a);
            }
        }
        List<Field> fields = new ArrayList<>();
        if (m.get("attributes") instanceof List<?> l) {
            for (Object o : l) {
                Map<String, Object> f = Json.asMap(o);
                String name = Json.asString(f.get("name"));
                if (name == null || !name.matches("[A-Za-z][A-Za-z0-9-]*")) {
                    throw new IllegalArgumentException("preset " + id + ": an attribute needs a valid name");
                }
                String pattern = Json.asString(f.get("pattern"));
                if (pattern != null) {
                    try {
                        Pattern.compile(pattern);
                    } catch (PatternSyntaxException e) {
                        throw new IllegalArgumentException("preset " + id + ": the pattern for " + name + " is not a valid regular expression");
                    }
                }
                fields.add(new Field(name, Json.asString(f.get("label")), Json.asBool(f.get("required")), Json.asBool(f.get("readOnly")),
                    pattern, Json.asString(f.get("value"))));
            }
        }
        if (fields.isEmpty() && actions.contains("attributes")) {
            throw new IllegalArgumentException("preset " + id + ": the attributes action needs attributes");
        }
        if (actions.isEmpty()) {
            throw new IllegalArgumentException("preset " + id + " has no actions");
        }
        String cls = Json.asString(m.get("objectClass"));
        String name = Json.asString(m.get("name"));
        return new TaskPreset(id, name == null || name.isBlank() ? id : name, Json.asString(m.get("description")),
            cls == null || cls.isBlank() ? "inetOrgPerson" : cls, Set.copyOf(actions), List.copyOf(fields));
    }

    public Field field(String attribute) {
        return attributes.stream().filter(f -> f.name.equalsIgnoreCase(attribute)).findFirst().orElse(null);
    }

    public Map<String, Object> json() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("name", name);
        if (description != null) {
            m.put("description", description);
        }
        m.put("objectClass", objectClass);
        m.put("actions", ACTIONS.stream().filter(actions::contains).toList());
        m.put("attributes", attributes.stream().map(Field::json).toList());
        return m;
    }
}
