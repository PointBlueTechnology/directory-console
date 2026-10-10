package com.pointblue.console.server.auth;

import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.console.server.tls.TrustStore;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.naming.InvalidNameException;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.LdapName;

/**
 * Direct login (DESIGN-directory-console.md section 7.2): the person's name and password, an LDAPS bind
 * as them, and console roles from their eDirectory group membership.
 *
 * <p>A full DN is used as given. A bare name is resolved contextlessly, as the directory's console
 * service account: a tree-wide search of the configured match attributes (every value, since {@code cn}
 * is multi-valued), excluding disabled and expired accounts. No match is answered exactly like a wrong
 * password. Several matches follow the directory's policy: {@code error} asks for the full name and
 * reveals nothing; {@code choose} returns each account's context with a single-use, two-minute choice
 * token, and the browser sends the password again with the chosen token. The password is only ever
 * tried against the one account the person chose: trying it against every candidate would count wrong
 * passwords toward intruder lockout on other people's accounts.
 */
public final class DirectLogin {

    public sealed interface Outcome permits SignedIn, Choose, Refused {
    }

    /** {@code engine} is null when Identity Manager's engine could not be opened; {@code engineProblem} says why. */
    public record SignedIn(Sessions.Principal principal, Ldap connection, com.pointblue.console.server.idm.Engines.Opened engine, String engineProblem) implements Outcome {
        public SignedIn(Sessions.Principal principal, Ldap connection) {
            this(principal, connection, null, "no engine connection was opened");
        }
    }

    public record Candidate(String token, String context, String label) {
    }

    public record Choose(List<Candidate> candidates) implements Outcome {
    }

    /**
     * A refusal. {@code code}: {@code bad-credentials}, {@code ambiguous}, {@code choice-expired},
     * {@code full-name-required}, {@code untrusted-certificate}, {@code no-role}, {@code not-allowed},
     * {@code unavailable}. {@code untrusted} is set for {@code untrusted-certificate}.
     */
    public record Refused(String code, String message, TrustStore.Untrusted untrusted) implements Outcome {
        Refused(String code, String message) {
            this(code, message, null);
        }
    }

    static final String BAD_CREDENTIALS = "The name or password is incorrect, or the account may not log in.";
    private static final Duration CHOICE = Duration.ofMinutes(2);
    private static final Duration TIMEOUT = Duration.ofSeconds(10);
    private static final DateTimeFormatter GENERALIZED = DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
    private static final SecureRandom RANDOM = new SecureRandom();

    private record Choice(String directoryId, String dn, Instant expires) {
    }

    private final TrustStore trust;
    private final Clock clock;
    private final Map<String, Choice> choices = new ConcurrentHashMap<>();

    private volatile com.pointblue.console.server.idm.Engines engines = com.pointblue.console.server.idm.Engines.none("not configured");

    /** Where Identity Manager engine connections come from (detected at start; a fake in tests). */
    public void engines(com.pointblue.console.server.idm.Engines e) {
        this.engines = e;
    }

    public DirectLogin(TrustStore trust) {
        this(trust, Clock.systemUTC());
    }

    DirectLogin(TrustStore trust, Clock clock) {
        this.trust = trust;
        this.clock = clock;
    }

    /**
     * Sign in to {@code d}. {@code serviceAccountPassword} (null when none is configured) is needed only
     * to resolve a bare name. {@code choiceToken} is set on the second step of a {@code choose}.
     */
    public Outcome login(DirectoryConfig d, String serviceAccountPassword, String name, char[] password, String choiceToken) {
        String dn;
        if (choiceToken != null && !choiceToken.isBlank()) {
            Choice c = choices.remove(choiceToken);
            if (c == null || c.expires.isBefore(clock.instant()) || !c.directoryId.equals(d.id())) {
                return new Refused("choice-expired", "That choice expired or was already used. Sign in again.");
            }
            dn = c.dn;
        } else if (name == null || name.isBlank()) {
            return new Refused("bad-credentials", BAD_CREDENTIALS);
        } else if (looksLikeDn(name)) {
            dn = name.trim();
        } else {
            boolean breakGlassOnly = !d.directLogin();
            if (d.serviceAccountDn() == null || serviceAccountPassword == null || breakGlassOnly) {
                return new Refused("full-name-required", "Sign in with your full name (for example cn=jsmith,ou=users,o=acme).");
            }
            List<Ldap.Entry> found;
            try (Ldap svc = Ldap.connect(trust, d.target(), null, d.serviceAccountDn(), serviceAccountPassword.toCharArray(), TIMEOUT)) {
                found = resolve(svc, d, name.trim());
            } catch (Ldap.Untrusted u) {
                return new Refused("untrusted-certificate", u.getMessage(), u.cause);
            } catch (Ldap.BadCredentials | NamingException e) {
                return new Refused("unavailable", "Contextless sign-in is unavailable: the console's service account could not search the directory. Sign in with your full name.");
            }
            if (found.isEmpty()) {
                // the same answer as a wrong password, after a bind that takes about as long
                equalize(d, password);
                return new Refused("bad-credentials", BAD_CREDENTIALS);
            }
            if (found.size() > d.maxCandidates() || (found.size() > 1 && d.duplicates() == DirectoryConfig.Duplicates.ERROR)) {
                return new Refused("ambiguous", "More than one account has this name. Sign in with your full name.");
            }
            if (found.size() > 1) {
                List<Candidate> out = new ArrayList<>();
                for (Ldap.Entry e : found) {
                    String token = token();
                    choices.put(token, new Choice(d.id(), e.dn(), clock.instant().plus(CHOICE)));
                    out.add(new Candidate(token, context(e.dn()), d.labelAttribute() == null ? null : e.first(d.labelAttribute())));
                }
                choices.values().removeIf(c -> c.expires.isBefore(clock.instant()));
                return new Choose(out);
            }
            dn = found.get(0).dn();
        }
        boolean breakGlass = d.breakGlass().stream().anyMatch(b -> sameDn(b, dn));
        if (!d.directLogin() && !breakGlass) {
            return new Refused("not-allowed", "Direct sign-in is turned off for this directory.");
        }
        Ldap conn;
        try {
            conn = Ldap.connect(trust, d.target(), null, dn, password, TIMEOUT);
        } catch (Ldap.Untrusted u) {
            return new Refused("untrusted-certificate", u.getMessage(), u.cause);
        } catch (Ldap.BadCredentials e) {
            return new Refused("bad-credentials", BAD_CREDENTIALS);
        } catch (NamingException e) {
            return new Refused("unavailable", "The directory did not answer: " + e.getMessage());
        }
        try {
            Ldap.Entry me = conn.read(dn, "groupMembership", "cn", "fullName");
            Set<Role> roles = EnumSet.noneOf(Role.class);
            if (breakGlass) {
                roles.add(Role.ADMIN);
            }
            List<Object> groups = me == null ? List.of() : me.attributes().getOrDefault("groupmembership", List.of());
            for (DirectoryConfig.RoleMapping m : d.roles()) {
                if (groups.stream().anyMatch(g -> sameDn(String.valueOf(g), m.group()))) {
                    roles.add(m.role());
                }
            }
            if (roles.isEmpty()) {
                conn.close();
                return new Refused("no-role", "Your account has no Directory Console role. Ask an administrator to map one of your groups to a role.");
            }
            String display = me == null ? null : me.first("fullName");
            if (display == null && me != null) {
                display = me.first("cn");
            }
            com.pointblue.console.server.idm.Engines.Opened engine = null;
            String engineProblem = engines.unavailable();
            if (engineProblem == null) {
                // the engine connection is bound now, while the password is in hand; it is not kept
                try {
                    engine = engines.open(conn, trust, d.target(), dn, password);
                } catch (Exception e) {
                    engineProblem = "the Identity Manager engine connection could not be opened: " + e.getMessage();
                }
            }
            return new SignedIn(new Sessions.Principal(dn, dn, display == null ? dn : display, d.id(), Set.copyOf(roles),
                breakGlass && roles.size() == 1 ? "break-glass" : "direct"), conn, engine, engineProblem);
        } catch (NamingException e) {
            conn.close();
            return new Refused("unavailable", "Your account could not be read after sign-in: " + e.getMessage());
        }
    }

    /** Accounts whose match attributes equal {@code name}, in the configured bases, up to maxCandidates + 1. */
    List<Ldap.Entry> resolve(Ldap svc, DirectoryConfig d, String name) throws NamingException {
        List<Object> args = new ArrayList<>();
        StringBuilder f = new StringBuilder("(&(|");
        for (String oc : d.objectClasses()) {
            f.append("(objectClass={").append(args.size()).append("})");
            args.add(oc);
        }
        f.append(")(|");
        for (String a : d.matchAttributes()) {
            if (!a.matches("[A-Za-z][A-Za-z0-9-]*")) {
                throw new NamingException("invalid match attribute " + a);
            }
            f.append('(').append(a).append("={").append(args.size()).append("})");
            args.add(name);
        }
        f.append(')');
        if (d.excludeInactive()) {
            f.append("(!(loginDisabled=TRUE))(|(!(loginExpirationTime=*))(loginExpirationTime>={").append(args.size()).append("}))");
            args.add(GENERALIZED.format(clock.instant()));
        }
        f.append(')');
        List<String> attrs = new ArrayList<>(List.of("cn"));
        if (d.labelAttribute() != null) {
            attrs.add(d.labelAttribute());
        }
        List<Ldap.Entry> out = new ArrayList<>();
        List<String> bases = d.searchBases().isEmpty() ? List.of("") : d.searchBases();
        for (String base : bases) {
            for (Ldap.Entry e : svc.search(base, f.toString(), args.toArray(), SearchControls.SUBTREE_SCOPE, attrs.toArray(new String[0]), d.maxCandidates() + 1)) {
                if (out.stream().noneMatch(x -> sameDn(x.dn(), e.dn()))) {
                    out.add(e);
                }
            }
        }
        return out;
    }

    private void equalize(DirectoryConfig d, char[] password) {
        try (Ldap ignored = Ldap.connect(trust, d.target(), null, "cn=" + token() + ",o=directory-console-no-such-account", password, TIMEOUT)) {
            // never succeeds
        } catch (Exception expected) {
            // the point is the time it took
        }
    }

    /** A name with an {@code attr=value} component is a DN; a bare name is resolved. */
    static boolean looksLikeDn(String name) {
        if (!name.contains("=")) {
            return false;
        }
        try {
            return new LdapName(name.trim()).size() > 0;
        } catch (InvalidNameException e) {
            return false;
        }
    }

    /** The container of {@code dn}, for the choose list. */
    static String context(String dn) {
        try {
            LdapName n = new LdapName(dn);
            return n.size() <= 1 ? "" : n.getPrefix(n.size() - 1).toString();
        } catch (InvalidNameException e) {
            return "";
        }
    }

    /** RFC 4514 comparison (case-ignored values, as eDirectory's naming attributes). */
    static boolean sameDn(String a, String b) {
        try {
            return new LdapName(a).equals(new LdapName(b));
        } catch (InvalidNameException e) {
            return a.trim().equalsIgnoreCase(b.trim());
        }
    }

    private static String token() {
        byte[] b = new byte[24];
        RANDOM.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }
}
