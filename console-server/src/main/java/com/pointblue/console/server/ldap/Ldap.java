package com.pointblue.console.server.ldap;

import com.pointblue.console.server.tls.TrustStore;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.naming.AuthenticationException;
import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.BasicControl;
import javax.naming.ldap.Control;
import javax.naming.ldap.ExtendedRequest;
import javax.naming.ldap.ExtendedResponse;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

/**
 * One bound LDAPS connection to a directory, opened through the console's {@link TrustStore}: the
 * JDK's own LDAP client (no engine jars), with JNDI's pool off and a per-connection trust manager.
 *
 * <p>Search filters take their values as arguments ({@code "(cn={0})"}), which JNDI escapes per
 * RFC 4515, so a value never changes a filter's structure. DNs come back as the server wrote them.
 */
public final class Ldap implements AutoCloseable {

    /** RFC 4370 proxied authorization (v2): eDirectory applies the named user's rights. */
    public static final String PROXIED_AUTHZ = "2.16.840.1.113730.3.4.18";
    /** eDirectory's GetEffectivePrivileges request and response. */
    static final String EFFECTIVE_PRIVILEGES = "2.16.840.1.113719.1.27.100.33";

    /** Which configured directory, and where it listens. */
    public record Target(String directoryId, String host, int port) {
    }

    /** The server's certificate is not trusted; carries the trust store's reason and the chain for a probe. */
    public static final class Untrusted extends Exception {
        public final TrustStore.Untrusted cause;

        Untrusted(TrustStore.Untrusted cause) {
            super(cause.getMessage(), cause);
            this.cause = cause;
        }
    }

    /** Wrong name or password, or an account that may not log in (eDirectory reports these alike). */
    public static final class BadCredentials extends Exception {
        BadCredentials(String m) {
            super(m);
        }
    }

    public record Entry(String dn, Map<String, List<Object>> attributes) {
        public String first(String attr) {
            List<Object> v = attributes.get(attr.toLowerCase(java.util.Locale.ROOT));
            return v == null || v.isEmpty() ? null : String.valueOf(v.get(0));
        }
    }

    private final LdapContext ctx;
    private final String boundDn;

    private Ldap(LdapContext ctx, String boundDn) {
        this.ctx = ctx;
        this.boundDn = boundDn;
    }

    /** Open and bind. {@code subject} scopes personal trust entries (null for none). */
    public static Ldap connect(TrustStore trust, Target t, String subject, String dn, char[] password, Duration timeout)
            throws Untrusted, BadCredentials, NamingException {
        if (dn == null || dn.isBlank() || password == null || password.length == 0) {
            // an empty password would be an anonymous bind that "succeeds": never allowed
            throw new BadCredentials("a name and a password are required");
        }
        SSLContext ssl;
        try {
            ssl = SSLContext.getInstance("TLS");
            ssl.init(null, new TrustManager[] {trust.trustManager(t.host(), t.port(), t.directoryId(), subject)}, null);
        } catch (GeneralSecurityException | java.io.IOException e) {
            throw new NamingException("TLS for " + t.host() + ": " + e.getMessage());
        }
        Hashtable<String, Object> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldaps://" + bracket(t.host()) + ":" + t.port());
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, dn);
        env.put(Context.SECURITY_CREDENTIALS, new String(password));
        env.put(Context.REFERRAL, "ignore");
        env.put("java.naming.ldap.factory.socket", DirectorySocketFactory.class.getName());
        env.put("com.sun.jndi.ldap.connect.pool", "false");
        env.put("com.sun.jndi.ldap.connect.timeout", String.valueOf(timeout.toMillis()));
        env.put("com.sun.jndi.ldap.read.timeout", String.valueOf(timeout.toMillis() * 6));
        env.put("java.naming.ldap.attributes.binary", "GUID");
        DirectorySocketFactory.set(ssl.getSocketFactory());
        try {
            return new Ldap(new InitialLdapContext(env, null), dn);
        } catch (AuthenticationException e) {
            throw new BadCredentials("the name or password is incorrect, or the account may not log in");
        } catch (CommunicationException e) {
            TrustStore.Untrusted u = untrusted(e);
            if (u != null) {
                throw new Untrusted(u);
            }
            throw e;
        } finally {
            DirectorySocketFactory.clear();
        }
    }

    private static String bracket(String host) {
        return host.contains(":") && !host.startsWith("[") ? "[" + host + "]" : host;
    }

    private static TrustStore.Untrusted untrusted(Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause() == c ? null : c.getCause()) {
            if (c instanceof TrustStore.Untrusted u) {
                return u;
            }
            if (c instanceof NamingException ne && ne.getRootCause() != null && ne.getRootCause() != c) {
                TrustStore.Untrusted u = untrusted(ne.getRootCause());
                if (u != null) {
                    return u;
                }
            }
        }
        return null;
    }

    public String boundDn() {
        return boundDn;
    }

    /**
     * Search with {@code filter} taking {@code args} as {@code {0}}, {@code {1}}… (escaped by JNDI).
     * At most {@code limit} entries (0: no limit).
     */
    public List<Entry> search(String base, String filter, Object[] args, int scope, String[] attrs, int limit) throws NamingException {
        SearchControls sc = new SearchControls();
        sc.setSearchScope(scope);
        sc.setReturningAttributes(attrs);
        sc.setCountLimit(limit);
        sc.setReturningObjFlag(false);
        List<Entry> out = new ArrayList<>();
        NamingEnumeration<SearchResult> r = ctx.search(base, filter, args == null ? new Object[0] : args, sc);
        try {
            while (r.hasMore()) {
                SearchResult e = r.next();
                out.add(new Entry(e.getNameInNamespace(), attributes(e.getAttributes())));
            }
        } catch (javax.naming.SizeLimitExceededException e) {
            // limit reached: the caller asked for at most `limit`
        } finally {
            r.close();
        }
        return out;
    }

    /** One entry's attributes; null when it does not exist. */
    public Entry read(String dn, String... attrs) throws NamingException {
        try {
            return new Entry(dn, attributes(ctx.getAttributes(dn, attrs.length == 0 ? null : attrs)));
        } catch (javax.naming.NameNotFoundException e) {
            return null;
        }
    }

    /**
     * eDirectory's effective privileges of {@code trustee} on {@code target} for {@code attr}
     * ({@code [Entry Rights]}, {@code [All Attributes Rights]} or an attribute name).
     */
    public int effectivePrivileges(String target, String trustee, String attr) throws NamingException {
        ExtendedResponse r = ctx.extendedOperation(new EffectivePrivileges(target, trustee, attr));
        byte[] v = r.getEncodedValue();
        if (v == null || v.length < 3 || v[0] != 0x02) {
            throw new NamingException("unexpected effective-privileges response");
        }
        int len = v[1] & 0xff;
        int n = 0;
        for (int i = 0; i < len; i++) {
            n = (n << 8) | (v[2 + i] & 0xff);
        }
        return n;
    }

    /** Send the following operations with the RFC 4370 control naming {@code dn}; null stops it. */
    public void actAs(String dn) throws NamingException {
        ctx.setRequestControls(dn == null ? null
            : new Control[] {new BasicControl(PROXIED_AUTHZ, true, ("dn:" + dn).getBytes(StandardCharsets.UTF_8))});
    }

    @Override
    public void close() {
        try {
            ctx.close();
        } catch (NamingException e) {
            // already gone
        }
    }

    private static Map<String, List<Object>> attributes(Attributes as) throws NamingException {
        Map<String, List<Object>> out = new LinkedHashMap<>();
        if (as == null) {
            return out;
        }
        NamingEnumeration<? extends Attribute> all = as.getAll();
        while (all.hasMore()) {
            Attribute a = all.next();
            List<Object> values = new ArrayList<>();
            NamingEnumeration<?> vs = a.getAll();
            while (vs.hasMore()) {
                values.add(vs.next());
            }
            out.put(a.getID().toLowerCase(java.util.Locale.ROOT), values);
        }
        return out;
    }

    /** Three BER OCTET STRINGs, back to back: target DN, trustee DN, attribute (as eDirectory's own client sends). */
    static final class EffectivePrivileges implements ExtendedRequest {
        private final byte[] value;

        EffectivePrivileges(String target, String trustee, String attr) {
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            for (String s : new String[] {target, trustee, attr}) {
                octetString(b, s.getBytes(StandardCharsets.UTF_8));
            }
            this.value = b.toByteArray();
        }

        @Override
        public String getID() {
            return EFFECTIVE_PRIVILEGES;
        }

        @Override
        public byte[] getEncodedValue() {
            return value.clone();
        }

        @Override
        public ExtendedResponse createExtendedResponse(String id, byte[] berValue, int offset, int length) {
            byte[] v = berValue == null ? null : java.util.Arrays.copyOfRange(berValue, offset, offset + length);
            return new ExtendedResponse() {
                @Override
                public String getID() {
                    return id;
                }

                @Override
                public byte[] getEncodedValue() {
                    return v;
                }
            };
        }

        static void octetString(ByteArrayOutputStream b, byte[] v) {
            b.write(0x04);
            if (v.length < 128) {
                b.write(v.length);
            } else if (v.length < 256) {
                b.write(0x81);
                b.write(v.length);
            } else {
                b.write(0x82);
                b.write(v.length >> 8);
                b.write(v.length & 0xff);
            }
            b.write(v, 0, v.length);
        }
    }
}
