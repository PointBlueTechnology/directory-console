package com.pointblue.console.server.auth;

import com.pointblue.console.server.ldap.Ldap;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Server-side sessions: a 256-bit id in a {@code __Host-}
 * cookie, a CSRF token, an idle and an absolute limit. A direct-login session owns the person's bound
 * LDAP connection; the password itself is never kept, so a lost connection means signing in again.
 */
public final class Sessions {

    /**
     * Who is signed in. {@code via} is {@code direct}, {@code break-glass} or {@code oidc}. {@code roles}
     * are every role any grant gives, scoped or not, for what the UI offers; {@link #may} decides for
     * an object.
     */
    public record Principal(String subject, String dn, String name, String directoryId, Set<Role> roles, String via, List<Grant> grants) {

        public Principal {
            grants = List.copyOf(grants);
        }

        /** Unscoped grants of {@code roles}. */
        public Principal(String subject, String dn, String name, String directoryId, Set<Role> roles, String via) {
            this(subject, dn, name, directoryId, roles, via, roles.stream().map(Grant::everywhere).toList());
        }

        /** Whether some grant gives {@code r} (or admin), anywhere. */
        public boolean has(Role r) {
            return roles.contains(r) || roles.contains(Role.ADMIN);
        }

        /** Whether a grant of {@code r} (or admin) reaches {@code dn}. */
        public boolean may(Role r, String dn) {
            return grants.stream().anyMatch(g -> g.role() != null && (g.role() == r || g.role() == Role.ADMIN) && g.covers(dn));
        }

        /** The task presets a grant gives at {@code dn}. */
        public Set<String> presetsAt(String dn) {
            Set<String> out = new java.util.TreeSet<>();
            grants.stream().filter(g -> g.covers(dn)).forEach(g -> out.addAll(g.presets()));
            return out;
        }

        /** Whether any grant gives a task preset, anywhere. */
        public boolean hasPresets() {
            return grants.stream().anyMatch(g -> !g.presets().isEmpty());
        }
    }

    public static final class Session {
        public final String id;
        public final String csrf;
        public final Principal principal;
        public final Instant created;
        final Ldap ldap;
        /** Identity Manager's engine, bound as the person at sign-in; null when unavailable (see {@link #engineProblem}). */
        public final com.pointblue.dirxml.dev.operate.Operate.Engine engine;
        public final String engineProblem;
        final AutoCloseable engineHandle;
        volatile Instant lastSeen;
        volatile Instant authenticatedAt;

        Session(String id, String csrf, Principal principal, Ldap ldap, com.pointblue.console.server.idm.Engines.Opened engine, String engineProblem, Instant now) {
            this.id = id;
            this.csrf = csrf;
            this.principal = principal;
            this.ldap = ldap;
            this.engine = engine == null ? null : engine.engine();
            this.engineHandle = engine == null ? null : engine.handle();
            this.engineProblem = engineProblem;
            this.created = now;
            this.lastSeen = now;
            this.authenticatedAt = now;
        }

        /** The person's own directory connection (direct login); null for others. */
        public Ldap ldap() {
            return ldap;
        }

        /** Connections to other servers of the tree (server GUID → connection), opened when first needed. */
        public final Map<String, ServerConnection> servers = new ConcurrentHashMap<>();
    }

    /** A session's connection to one more server: as the person, and its Identity Manager engine when one could be opened. */
    public record ServerConnection(String dn, String name, Ldap ldap, com.pointblue.console.server.idm.Engines.Opened engine, String engineProblem) {
        public void close() {
            if (engine != null && engine.handle() != null) {
                try {
                    engine.handle().close();
                } catch (Exception ignored) {
                    // already gone
                }
            }
            ldap.close();
        }
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    private final Duration idle;
    private final Duration absolute;
    private final Clock clock;
    /** A tree's own limits (Settings > Directory), looked up at every check so a change applies at once; null keeps the defaults. */
    private volatile java.util.function.Function<String, Limits> limits = id -> null;

    /** How long a session may sit idle, and how long it may last at most. */
    public record Limits(Duration idle, Duration absolute) {
    }
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
        return create(p, ldap, null, "no engine connection was opened");
    }

    public Session create(Principal p, Ldap ldap, com.pointblue.console.server.idm.Engines.Opened engine, String engineProblem) {
        Session s = new Session(token(), token(), p, ldap, engine, engineProblem, clock.instant());
        sessions.put(s.id, s);
        return s;
    }

    /** Where each tree's own limits come from. */
    public void limits(java.util.function.Function<String, Limits> byDirectory) {
        this.limits = byDirectory;
    }

    /** The limits that apply to {@code s}: its tree's, or the defaults. */
    public Limits limitsOf(Session s) {
        Limits l = limits.apply(s.principal.directoryId());
        return l == null ? new Limits(idle, absolute) : l;
    }

    /** When {@code s} ends at the latest, however active it is. */
    public Instant expiresAt(Session s) {
        return s.created.plus(limitsOf(s).absolute());
    }

    /** The live session for {@code id}, refreshing its idle timer; null (and closed) when expired or unknown. */
    public Session get(String id) {
        Session s = id == null ? null : sessions.get(id);
        if (s == null) {
            return null;
        }
        Instant now = clock.instant();
        Limits l = limitsOf(s);
        if (s.lastSeen.plus(l.idle()).isBefore(now) || s.created.plus(l.absolute()).isBefore(now)) {
            remove(s.id);
            return null;
        }
        s.lastSeen = now;
        return s;
    }

    public void remove(String id) {
        Session s = sessions.remove(id);
        if (s != null && s.engineHandle != null) {
            try {
                s.engineHandle.close();
            } catch (Exception ignored) {
                // already gone
            }
        }
        if (s != null && s.ldap != null) {
            s.ldap.close();
        }
        if (s != null) {
            s.servers.values().forEach(ServerConnection::close);
            s.servers.clear();
        }
    }

    /** End every session on the directory {@code directoryId} (it was removed); how many ended. */
    public int removeDirectory(String directoryId) {
        List<String> ids = sessions.values().stream().filter(s -> s.principal.directoryId().equals(directoryId)).map(s -> s.id).toList();
        ids.forEach(this::remove);
        return ids.size();
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
