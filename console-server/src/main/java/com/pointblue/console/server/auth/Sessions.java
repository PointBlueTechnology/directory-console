package com.pointblue.console.server.auth;

import com.pointblue.console.server.ldap.Ldap;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Server-side sessions (DESIGN-directory-console.md section 7.1): a 256-bit id in a {@code __Host-}
 * cookie, a CSRF token, an idle and an absolute limit. A direct-login session owns the person's bound
 * LDAP connection; the password itself is never kept, so a lost connection means signing in again.
 */
public final class Sessions {

    /** Who is signed in. {@code via} is {@code direct}, {@code break-glass} or {@code oidc}. */
    public record Principal(String subject, String dn, String name, String directoryId, Set<Role> roles, String via) {
        public boolean has(Role r) {
            return roles.contains(r) || roles.contains(Role.ADMIN);
        }
    }

    public static final class Session {
        public final String id;
        public final String csrf;
        public final Principal principal;
        public final Instant created;
        final Ldap ldap;
        volatile Instant lastSeen;
        volatile Instant authenticatedAt;

        Session(String id, String csrf, Principal principal, Ldap ldap, Instant now) {
            this.id = id;
            this.csrf = csrf;
            this.principal = principal;
            this.ldap = ldap;
            this.created = now;
            this.lastSeen = now;
            this.authenticatedAt = now;
        }

        /** The person's own directory connection (direct login); null for others. */
        public Ldap ldap() {
            return ldap;
        }
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    private final Duration idle;
    private final Duration absolute;
    private final Clock clock;
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    public Sessions(Duration idle, Duration absolute) {
        this(idle, absolute, Clock.systemUTC());
    }

    Sessions(Duration idle, Duration absolute, Clock clock) {
        this.idle = idle;
        this.absolute = absolute;
        this.clock = clock;
    }

    public Session create(Principal p, Ldap ldap) {
        Session s = new Session(token(), token(), p, ldap, clock.instant());
        sessions.put(s.id, s);
        return s;
    }

    /** The live session for {@code id}, refreshing its idle timer; null (and closed) when expired or unknown. */
    public Session get(String id) {
        Session s = id == null ? null : sessions.get(id);
        if (s == null) {
            return null;
        }
        Instant now = clock.instant();
        if (s.lastSeen.plus(idle).isBefore(now) || s.created.plus(absolute).isBefore(now)) {
            remove(s.id);
            return null;
        }
        s.lastSeen = now;
        return s;
    }

    public void remove(String id) {
        Session s = sessions.remove(id);
        if (s != null && s.ldap != null) {
            s.ldap.close();
        }
    }

    /** Whether the person authenticated within {@code window} (step-up for sensitive changes). */
    public boolean recentlyAuthenticated(Session s, Duration window) {
        return s.authenticatedAt.plus(window).isAfter(clock.instant());
    }

    /** Record a fresh authentication on an existing session (a step-up sign-in). */
    public void reauthenticated(Session s) {
        s.authenticatedAt = clock.instant();
    }

    /** Close and drop expired sessions. */
    public void sweep() {
        sessions.keySet().forEach(this::get);
    }

    public int size() {
        return sessions.size();
    }

    static String token() {
        byte[] b = new byte[32];
        RANDOM.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }
}
