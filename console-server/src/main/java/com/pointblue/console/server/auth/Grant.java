package com.pointblue.console.server.auth;

import com.pointblue.console.server.ldap.Names;
import java.util.List;

/**
 * What one role mapping gives a person (DESIGN-directory-console.md section 7.4): a role, task presets,
 * or both, limited to {@code scopes} (containers) when there are any. A scoped grant applies to objects
 * at or under one of its containers; eDirectory's own rights still apply on top. {@code admin} is
 * console-wide and ignores scopes.
 *
 * @param role    the role, or null when the mapping only grants presets
 * @param scopes  container DNs; empty means the whole tree
 * @param presets task preset ids
 */
public record Grant(Role role, List<String> scopes, List<String> presets) {

    public Grant {
        scopes = scopes == null ? List.of() : List.copyOf(scopes);
        presets = presets == null ? List.of() : List.copyOf(presets);
    }

    public static Grant everywhere(Role role) {
        return new Grant(role, List.of(), List.of());
    }

    /** Whether this grant reaches {@code dn} (always, without scopes). */
    public boolean covers(String dn) {
        if (scopes.isEmpty() || role == Role.ADMIN) {
            return true;
        }
        if (dn == null) {
            return false;
        }
        for (String s : scopes) {
            try {
                if (Names.within(dn, s)) {
                    return true;
                }
            } catch (IllegalArgumentException e) {
                // a malformed scope reaches nothing
            }
        }
        return false;
    }
}
