package com.pointblue.console.server.auth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;
import org.junit.Test;

public class SessionsAndThrottleTest {

    /** A clock the test moves. */
    static final class Moving extends Clock {
        Instant now = Instant.parse("2026-10-09T12:00:00Z");

        void advance(Duration d) {
            now = now.plus(d);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    private static final Sessions.Principal PAT = new Sessions.Principal("cn=pat,o=acme", "cn=pat,o=acme", "Pat", "prod", Set.of(Role.OPERATOR), "direct");

    @Test
    public void aTreeCanHaveItsOwnLimitsAndAChangeAppliesAtOnce() {
        Moving clock = new Moving();
        Sessions s = new Sessions(Duration.ofMinutes(30), Duration.ofHours(12), clock);
        java.util.Map<String, Sessions.Limits> byTree = new java.util.concurrent.ConcurrentHashMap<>();
        s.limits(byTree::get);
        Sessions.Session prod = s.create(PAT, null);
        Sessions.Session dev = s.create(new Sessions.Principal("cn=pat,o=acme", "cn=pat,o=acme", "Pat", "dev", Set.of(Role.OPERATOR), "direct"), null);
        byTree.put("prod", new Sessions.Limits(Duration.ofMinutes(10), Duration.ofHours(2)));
        assertEquals("prod's own idle limit", Duration.ofMinutes(10), s.limitsOf(prod).idle());
        assertEquals("dev keeps the defaults", Duration.ofMinutes(30), s.limitsOf(dev).idle());
        assertEquals(clock.now.plus(Duration.ofHours(2)), s.expiresAt(prod));
        clock.advance(Duration.ofMinutes(11));
        assertNull("prod's 10 minutes apply to a session already open", s.get(prod.id));
        assertSame(dev, s.get(dev.id));
        byTree.put("dev", new Sessions.Limits(Duration.ofMinutes(5), Duration.ofHours(1)));
        clock.advance(Duration.ofMinutes(6));
        assertNull("dev's new limit applies at once", s.get(dev.id));
    }

    @Test
    public void idleAndAbsoluteLimitsEndASession() {
        Moving clock = new Moving();
        Sessions s = new Sessions(Duration.ofMinutes(30), Duration.ofHours(12), clock);
        Sessions.Session a = s.create(PAT, null);
        assertNotEquals(a.id, a.csrf);
        assertTrue(a.id.length() >= 43);
        clock.advance(Duration.ofMinutes(29));
        assertSame(a, s.get(a.id));
        clock.advance(Duration.ofMinutes(31));
        assertNull("idle for 31 minutes", s.get(a.id));
        Sessions.Session b = s.create(PAT, null);
        for (int i = 0; i < 25; i++) {
            clock.advance(Duration.ofMinutes(29));
            s.get(b.id);
        }
        assertNull("over 12 hours however active", s.get(b.id));
        assertEquals(0, s.size());
    }

    @Test
    public void stepUpNeedsARecentSignIn() {
        Moving clock = new Moving();
        Sessions s = new Sessions(Duration.ofMinutes(30), Duration.ofHours(12), clock);
        Sessions.Session a = s.create(PAT, null);
        assertTrue(s.recentlyAuthenticated(a, Duration.ofMinutes(10)));
        clock.advance(Duration.ofMinutes(11));
        s.get(a.id);
        assertFalse(s.recentlyAuthenticated(a, Duration.ofMinutes(10)));
        s.reauthenticated(a);
        assertTrue(s.recentlyAuthenticated(a, Duration.ofMinutes(10)));
    }

    @Test
    public void rolesAreCheckedWithAdminCoveringAll() {
        assertTrue(PAT.has(Role.OPERATOR));
        assertFalse(PAT.has(Role.ADMIN));
        Sessions.Principal admin = new Sessions.Principal("a", "a", "a", "prod", Set.of(Role.ADMIN), "break-glass");
        assertTrue(admin.has(Role.EDITOR));
    }

    @Test
    public void throttleAllowsLimitPerWindow() {
        Moving clock = new Moving();
        Throttle t = new Throttle(3, Duration.ofMinutes(1), clock);
        for (int i = 0; i < 3; i++) {
            assertTrue(t.allowed("10.0.0.1"));
            t.record("10.0.0.1");
        }
        assertFalse(t.allowed("10.0.0.1"));
        assertTrue("other keys are separate", t.allowed("10.0.0.2"));
        clock.advance(Duration.ofSeconds(61));
        assertTrue(t.allowed("10.0.0.1"));
        t.record("10.0.0.1");
        t.clear("10.0.0.1");
        assertTrue(t.allowed("10.0.0.1"));
    }
}
