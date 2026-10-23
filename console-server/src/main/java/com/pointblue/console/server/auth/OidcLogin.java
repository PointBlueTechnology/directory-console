package com.pointblue.console.server.auth;

import com.pointblue.console.auth.OidcClient;
import com.pointblue.console.auth.OidcConfig;
import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.console.server.tls.TrustStore;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.net.ssl.SSLContext;

/**
 * OpenID Connect sign-in. The provider proves who the person
 * is; the directory's console service account then finds their eDirectory object from a claim
 * (exactly one, active), and the session acts as them: every operation on the service account's
 * connection carries the RFC 4370 proxied-authorization control, so eDirectory applies the person's
 * own rights. Before a session is made, the person's own entry is read under the control: eDirectory
 * refuses the control for disabled and expired accounts, and when the service account lacks
 * Supervisor over the person, so a sign-in that could not act is refused here rather than later.
 *
 * <p>The service account itself, the break-glass accounts and the directory's {@code neverProxy} list
 * are never acted as; they sign in directly. Console grants come from the provider's groups.
 */
public final class OidcLogin {

    /** {@code code}: {@code not-configured}, {@code provider}, {@code claim-missing}, {@code no-account}, {@code ambiguous-account}, {@code never-proxy}, {@code no-role}, {@code proxy-refused}, {@code unavailable}. */
    public record Refused(String code, String message) {
    }

    public record SignedIn(Sessions.Principal principal, Ldap connection, String next) {
    }

    private static final Duration TIMEOUT = Duration.ofSeconds(10);
    private static final DateTimeFormatter GENERALIZED = DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);

    private record Client(DirectoryConfig.Oidc settings, String secret, OidcClient client) {
    }

    private final TrustStore trust;
    private final String redirectUri;
    private final Clock clock;
    private final Map<String, Client> clients = new ConcurrentHashMap<>();
    private final Map<String, String> started = new ConcurrentHashMap<>();   // state -> directory id
    private volatile SSLContext tls;

    public OidcLogin(TrustStore trust, String publicUrl) {
        this(trust, publicUrl, Clock.systemUTC());
    }

    OidcLogin(TrustStore trust, String publicUrl, Clock clock) {
        this.trust = trust;
        this.redirectUri = publicUrl + "/api/v2/oidc/callback";
        this.clock = clock;
    }

    public String redirectUri() {
        return redirectUri;
    }

    /** TLS for talking to providers, for tests; null (the default) trusts Java's public roots and the console's trusted CAs. */
    public void tls(SSLContext tls) {
        this.tls = tls;
        clients.clear();
    }

    private OidcClient client(DirectoryConfig d, String secret) {
        Client c = clients.get(d.id());
        if (c == null || !c.settings.equals(d.oidc()) || !Objects.equals(c.secret, secret)) {
            DirectoryConfig.Oidc o = d.oidc();
            SSLContext ctx = tls;
            if (ctx == null) {
                try {
                    ctx = trust.withPublicRoots(d.id());
                } catch (java.security.GeneralSecurityException e) {
                    throw new IllegalStateException("TLS for the provider could not be set up: " + e.getMessage(), e);
                }
            }
            c = new Client(o, secret, new OidcClient(new OidcConfig(o.issuer(), o.clientId(), secret, o.scopes(), o.groupsClaim(), redirectUri, ctx)));
            clients.put(d.id(), c);
        }
        return c.client;
    }

    /** Where to send the browser, and the state to bind to it (a cookie). */
    public OidcClient.Start start(DirectoryConfig d, String secret, String next) throws IOException {
        if (d.oidc() == null) {
            throw new IllegalStateException("single sign-on is not configured for " + d.id());
        }
        OidcClient.Start s = client(d, secret).start(next);
        started.put(s.state(), d.id());
        return s;
    }

    /** The directory a callback's {@code state} belongs to; null when it was not started here (or was used). */
    public String directoryOf(String state) {
        return state == null ? null : started.remove(state);
    }

    /** Finish the provider's callback for {@code d} and map the person to their eDirectory object. */
    public Object finish(DirectoryConfig d, String secret, String serviceAccountPassword, Map<String, String> query) {
        if (d.oidc() == null || d.serviceAccountDn() == null || serviceAccountPassword == null) {
            return new Refused("not-configured", "Single sign-on is not set up for this directory (it needs the console's service account).");
        }
        OidcClient.SignIn si;
        try {
            si = client(d, secret).finish(query);
        } catch (IOException e) {
            return new Refused("provider", e.getMessage());
        }
        DirectoryConfig.Oidc o = d.oidc();
        Object claim = si.claims().get(o.claim());
        String value = claim instanceof String str ? str.trim() : claim instanceof List<?> l && l.size() == 1 ? String.valueOf(l.get(0)) : null;
        if (value == null || value.isEmpty()) {
            return new Refused("claim-missing", "The identity provider did not send " + o.claim() + ", which this console uses to find your account.");
        }
        List<Grant> grants = new ArrayList<>();
        for (DirectoryConfig.RoleMapping m : o.roles()) {
            if (si.groups().stream().anyMatch(g -> g.equalsIgnoreCase(m.group()))) {
                grants.add(m.grant());
            }
        }
        Ldap svc;
        try {
            svc = Ldap.connect(trust, d.target(), null, d.serviceAccountDn(), serviceAccountPassword.toCharArray(), TIMEOUT);
        } catch (Ldap.Untrusted | Ldap.BadCredentials | NamingException e) {
            return new Refused("unavailable", "The console's service account could not reach the directory: " + e.getMessage());
        }
        boolean keep = false;
        try {
            List<Ldap.Entry> found = find(svc, d, o, value);
            if (found.isEmpty()) {
                return new Refused("no-account", "No active account in this directory has " + o.attribute() + " = " + value + ".");
            }
            if (found.size() > 1) {
                return new Refused("ambiguous-account", "More than one account has " + o.attribute() + " = " + value + "; ask an administrator to fix the mapping.");
            }
            String dn = found.get(0).dn();
            if (neverProxy(d).stream().anyMatch(n -> DirectLogin.sameDn(n, dn))) {
                return new Refused("never-proxy", "This account signs in directly, not through single sign-on.");
            }
            if (grants.isEmpty()) {
                return new Refused("no-role", "Your account has no Directory Console role. Ask an administrator to map one of your groups to a role.");
            }
            svc.actAs(dn);
            Ldap.Entry me;
            try {
                me = svc.read(dn, "cn", "fullName");
            } catch (NamingException e) {
                return new Refused("proxy-refused", "The directory would not let the console act for you ("
                    + Ldap.Failure.of(e).getMessage() + "). Your account may be disabled or expired, or the console's service account lacks Supervisor over it.");
            }
            if (me == null) {
                return new Refused("proxy-refused", "The directory would not let the console act for you. Your account may be disabled or expired, or the console's service account lacks Supervisor over it.");
            }
            String name = si.name() != null && !si.name().equals(si.subject()) ? si.name() : me.first("fullName");
            if (name == null) {
                name = me.first("cn");
            }
            keep = true;
            return new SignedIn(new Sessions.Principal(si.subject(), dn, name == null ? dn : name, d.id(), DirectLogin.roles(grants), "oidc", grants), svc, si.next());
        } catch (NamingException e) {
            return new Refused("unavailable", "Your account could not be looked up: " + e.getMessage());
        } finally {
            if (!keep) {
                svc.close();
            }
        }
    }

    /** Accounts of the configured classes whose mapping attribute equals {@code value}, active only. */
    List<Ldap.Entry> find(Ldap svc, DirectoryConfig d, DirectoryConfig.Oidc o, String value) throws NamingException {
        if (!o.attribute().matches("[A-Za-z][A-Za-z0-9-]*")) {
            throw new NamingException("invalid mapping attribute " + o.attribute());
        }
        List<Object> args = new ArrayList<>();
        StringBuilder f = new StringBuilder("(&(|");
        for (String oc : o.objectClasses()) {
            f.append("(objectClass={").append(args.size()).append("})");
            args.add(oc);
        }
        f.append(")(").append(o.attribute()).append("={").append(args.size()).append("})");
        args.add(value);
        f.append("(!(loginDisabled=TRUE))(|(!(loginExpirationTime=*))(loginExpirationTime>={").append(args.size()).append("})))");
        args.add(GENERALIZED.format(clock.instant()));
        List<String> bases = !o.searchBases().isEmpty() ? o.searchBases() : d.searchBases().isEmpty() ? List.of("") : d.searchBases();
        List<Ldap.Entry> out = new ArrayList<>();
        for (String base : bases) {
            for (Ldap.Entry e : svc.search(base, f.toString(), args.toArray(), SearchControls.SUBTREE_SCOPE, new String[] {"1.1"}, 2)) {
                if (out.stream().noneMatch(x -> DirectLogin.sameDn(x.dn(), e.dn()))) {
                    out.add(e);
                }
            }
        }
        return out;
    }

    /** The DNs a claim value maps to (none, one, or the first two of several), for testing a mapping. */
    public List<String> mapped(Ldap svc, DirectoryConfig d, String value) throws NamingException {
        return find(svc, d, d.oidc(), value).stream().map(Ldap.Entry::dn).toList();
    }

    public boolean isNeverProxy(DirectoryConfig d, String dn) {
        return neverProxy(d).stream().anyMatch(n -> DirectLogin.sameDn(n, dn));
    }

    /** The service account, the break-glass accounts and the configured list. */
    static List<String> neverProxy(DirectoryConfig d) {
        List<String> out = new ArrayList<>();
        if (d.serviceAccountDn() != null) {
            out.add(d.serviceAccountDn());
        }
        out.addAll(d.breakGlass());
        if (d.oidc() != null) {
            out.addAll(d.oidc().neverProxy());
        }
        return out;
    }
}
