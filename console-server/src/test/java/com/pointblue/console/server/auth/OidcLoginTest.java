package com.pointblue.console.server.auth;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.pointblue.console.server.ldap.Ldap;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.Test;

public class OidcLoginTest {

    private static final Instant NOW = Instant.parse("2026-10-30T12:00:00Z");

    private static Ldap.Entry person(String locked, String reset) {
        Map<String, List<Object>> a = new LinkedHashMap<>();
        if (locked != null) {
            a.put("lockedbyintruder", List.of(locked));
        }
        if (reset != null) {
            a.put("loginintruderresettime", List.of(reset));
        }
        return new Ldap.Entry("cn=pat,ou=users,o=acme", a);
    }

    @Test
    public void intruderLockout() {
        assertFalse("never locked", OidcLogin.locked(person(null, null), NOW));
        assertFalse("unlocked", OidcLogin.locked(person("FALSE", "20261030130000Z"), NOW));
        assertTrue("locked, no reset time", OidcLogin.locked(person("TRUE", null), NOW));
        assertTrue("locked until later", OidcLogin.locked(person("TRUE", "20261030120001Z"), NOW));
        assertFalse("the reset time has passed", OidcLogin.locked(person("TRUE", "20261030115959Z"), NOW));
        assertFalse("at the reset time", OidcLogin.locked(person("TRUE", "20261030120000Z"), NOW));
        assertTrue("an unreadable reset time counts as locked", OidcLogin.locked(person("TRUE", "soon"), NOW));
    }
}
