package com.pointblue.console.server.auth;

import java.util.Locale;

/**
 * What the console offers a person (DESIGN-directory-console.md section 7.4). eDirectory's own rights
 * still decide what an operation can do: both must allow it.
 */
public enum Role {
    /** Read objects, schema and IDM status. */
    VIEWER,
    /** Directory object writes. */
    EDITOR,
    /** IDM operations. */
    OPERATOR,
    /** Configuration, trust, sign-in methods, roles, audit export. */
    ADMIN;

    public static Role parse(String s) {
        try {
            return valueOf(s.trim().toUpperCase(Locale.ROOT));
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("a role is viewer, editor, operator or admin, not " + s);
        }
    }

    public String id() {
        return name().toLowerCase(Locale.ROOT);
    }
}
