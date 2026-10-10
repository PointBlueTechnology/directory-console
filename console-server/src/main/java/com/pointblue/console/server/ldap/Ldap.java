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
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.ModificationItem;
import javax.naming.ldap.BasicControl;
import javax.naming.ldap.Control;
import javax.naming.ldap.SortControl;
import javax.naming.ldap.SortKey;
import javax.naming.ldap.SortResponseControl;
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
    /** Virtual list view request and response. eDirectory honours them without listing them in the root DSE. */
    /** Attributes always read as bytes, whatever the schema says (the login time map is a bit map). */
    static final String BINARY = "GUID loginAllowedTimeMap";
    static final String VLV_REQUEST = "2.16.840.1.113730.3.4.9";
    static final String VLV_RESPONSE = "2.16.840.1.113730.3.4.10";

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

    /**
     * An entry: {@code attributes} keyed by lowercased name (for lookups), {@code names} giving each
     * key's spelling as the server sent it.
     */
    public record Entry(String dn, Map<String, List<Object>> attributes, Map<String, String> names) {
        public Entry(String dn, Map<String, List<Object>> attributes) {
            this(dn, attributes, Map.of());
        }

        /** The attribute's name as the server spelled it. */
        public String name(String key) {
            return names.getOrDefault(key, key);
        }

        public String first(String attr) {
            List<Object> v = attributes.get(attr.toLowerCase(java.util.Locale.ROOT));
            return v == null || v.isEmpty() ? null : String.valueOf(v.get(0));
        }
    }

    /**
     * A directory refusal, with the LDAP result code and, when the server gave one, eDirectory's own
     * error number (for example -606 for "entry already exists").
     */
    public static final class Failure extends Exception {
        public final int code;
        public final Integer ndsError;

        Failure(int code, Integer ndsError, String message, Throwable cause) {
            super(message, cause);
            this.code = code;
            this.ndsError = ndsError;
        }

        private static final java.util.regex.Pattern CODE = java.util.regex.Pattern.compile("error code (\\d+)");
        private static final java.util.regex.Pattern NDS = java.util.regex.Pattern.compile("\\((-\\d+)\\)");

        /** The result code JNDI folds into its message ("[LDAP: error code 68 - NDS error: … (-606)]"). */
        public static Failure of(NamingException e) {
            String m = String.valueOf(e.getMessage());
            java.util.regex.Matcher c = CODE.matcher(m);
            int code = c.find() ? Integer.parseInt(c.group(1))
                : e instanceof javax.naming.NameNotFoundException ? 32
                : e instanceof javax.naming.NoPermissionException ? 50
                : e instanceof javax.naming.CommunicationException || e instanceof javax.naming.ServiceUnavailableException ? 52
                : 80;
            java.util.regex.Matcher n = NDS.matcher(m);
            Integer nds = n.find() ? Integer.valueOf(n.group(1)) : null;
            String text = m.replaceFirst("^\\[LDAP: error code \\d+ - ", "").replaceFirst("]$", "");
            return new Failure(code, nds, text, e);
        }
    }

    /**
     * One window of a sorted list: {@code entries} starting at {@code offset} (1-based) of {@code total}.
     * {@code total} is -1 when the server could not say (the unsorted fallback).
     */
    public record Window(List<Entry> entries, int offset, int total, boolean exact) {
        Window(List<Entry> entries, int offset, int total) {
            this(entries, offset, total, total >= 0);
        }
    }

    private final LdapContext ctx;
    private final String boundDn;
    private Control proxied;

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
        env.put("java.naming.ldap.attributes.binary", BINARY);
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
     * The underlying JNDI context, lent to DirXMLDev's {@code Vault} for Identity Manager operations.
     * Callers hold this object's monitor while using it ({@code synchronized (ldap) {…}}), as every
     * method here does, so the context is never used from two threads at once.
     */
    public LdapContext context() {
        return ctx;
    }

    /** TLS sockets that trust what the console's trust store trusts for {@code t} (and {@code subject}'s own entries). */
    public static javax.net.ssl.SSLSocketFactory socketFactory(TrustStore trust, Target t, String subject) throws GeneralSecurityException, java.io.IOException {
        SSLContext ssl = SSLContext.getInstance("TLS");
        ssl.init(null, new TrustManager[] {trust.trustManager(t.host(), t.port(), t.directoryId(), subject)}, null);
        return ssl.getSocketFactory();
    }

    /**
     * Search with {@code filter} taking {@code args} as {@code {0}}, {@code {1}}… (escaped by JNDI).
     * At most {@code limit} entries (0: no limit).
     */
    public synchronized List<Entry> search(String base, String filter, Object[] args, int scope, String[] attrs, int limit) throws NamingException {
        controls();
        SearchControls sc = new SearchControls();
        sc.setSearchScope(scope);
        sc.setReturningAttributes(attrs);
        sc.setCountLimit(limit);
        sc.setReturningObjFlag(false);
        List<Entry> out = new ArrayList<>();
        NamingEnumeration<SearchResult> r = args == null ? ctx.search(base, filter, sc) : ctx.search(base, filter, args, sc);
        try {
            while (r.hasMore()) {
                SearchResult e = r.next();
                out.add(entry(e.getNameInNamespace(), e.getAttributes()));
            }
        } catch (javax.naming.SizeLimitExceededException e) {
            // limit reached: the caller asked for at most `limit`
        } finally {
            r.close();
        }
        return out;
    }

    /** One entry's attributes; null when it does not exist. */
    public synchronized Entry read(String dn, String... attrs) throws NamingException {
        controls();
        try {
            return entry(dn, ctx.getAttributes(dn, attrs.length == 0 ? null : attrs));
        } catch (javax.naming.NameNotFoundException e) {
            return null;
        }
    }

    /**
     * eDirectory's effective privileges of {@code trustee} on {@code target} for {@code attr}
     * ({@code [Entry Rights]}, {@code [All Attributes Rights]} or an attribute name).
     */
    public synchronized int effectivePrivileges(String target, String trustee, String attr) throws NamingException {
        controls();
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
    public synchronized void actAs(String dn) {
        proxied = dn == null ? null : new BasicControl(PROXIED_AUTHZ, true, ("dn:" + dn).getBytes(StandardCharsets.UTF_8));
    }

    /** The next operation's request controls: the proxied-authorization control, if any, and {@code extra}. */
    private void controls(Control... extra) throws NamingException {
        List<Control> all = new ArrayList<>();
        if (proxied != null) {
            all.add(proxied);
        }
        all.addAll(List.of(extra));
        ctx.setRequestControls(all.isEmpty() ? null : all.toArray(new Control[0]));
    }

    /**
     * A window of a search sorted on {@code sortAttr}: server-side sort plus virtual list view, so a
     * container of any size pages by position without server-side state between requests.
     * {@code startAt}, when set, jumps to the first entry whose sort value is at least it (and
     * {@code offset} is ignored). Servers that refuse the controls get an unsorted search, cut to the
     * window here, with an unknown total.
     */
    public synchronized Window window(String base, String filter, Object[] args, int scope, String[] attrs,
                                      String sortAttr, boolean descending, int offset, int count, String startAt) throws NamingException {
        int first = Math.max(1, offset);
        int size = Math.max(1, count);
        byte[] target = startAt != null
            ? Ber.tlv(0x81, startAt.getBytes(StandardCharsets.UTF_8))
            : Ber.tlv(0xa0, Ber.concat(Ber.integer(0x02, first), Ber.integer(0x02, 0)));
        byte[] vlv = Ber.tlv(0x30, Ber.concat(Ber.integer(0x02, 0), Ber.integer(0x02, size - 1), target));
        try {
            controls(new SortControl(new SortKey[] {new SortKey(sortAttr, !descending, null)}, Control.CRITICAL),
                new BasicControl(VLV_REQUEST, true, vlv));
        } catch (java.io.IOException e) {
            throw new NamingException("sort control: " + e.getMessage());
        }
        SearchControls sc = new SearchControls();
        sc.setSearchScope(scope);
        sc.setReturningAttributes(attrs);
        sc.setReturningObjFlag(false);
        List<Entry> out = new ArrayList<>();
        try {
            NamingEnumeration<SearchResult> r = args == null ? ctx.search(base, filter, sc) : ctx.search(base, filter, args, sc);
            try {
                while (r.hasMore()) {
                    SearchResult e = r.next();
                    out.add(entry(e.getNameInNamespace(), e.getAttributes()));
                }
            } finally {
                r.close();
            }
        } catch (NamingException e) {
            Failure f = Failure.of(e);
            if (f.code == 12) {   // unavailableCriticalExtension: no sort or VLV here
                controls();
                List<Entry> all = search(base, filter, args, scope, attrs, first - 1 + size);
                return new Window(all.subList(Math.min(first - 1, all.size()), all.size()), first, -1);
            }
            throw e;
        }
        int position = first;
        int total = -1;
        Control[] rc = ctx.getResponseControls();
        if (rc != null) {
            for (Control c : rc) {
                if (c instanceof SortResponseControl s && !s.isSorted()) {
                    throw new NamingException("[LDAP: error code " + s.getResultCode() + " - the server could not sort on " + sortAttr + "]");
                }
                if (c.getID().equals(VLV_RESPONSE)) {
                    List<Ber.Element> seq = Ber.read(c.getEncodedValue()).get(0).children();
                    position = (int) seq.get(0).integer();
                    total = (int) seq.get(1).integer();
                    int result = (int) seq.get(2).integer();
                    if (result != 0) {
                        throw new NamingException("[LDAP: error code " + result + " - virtual list view refused the window]");
                    }
                }
            }
        }
        controls();
        return new Window(out, position, total);
    }

    /** A segment eDirectory cannot sort (or the remainder) is listed with an ordinary search: at most this many. */
    static final int UNSORTED_LIMIT = 5000;
    /** Up to this many matches are listed with one ordinary search and sorted here; more use VLV. */
    static final int SMALL = 1000;

    /**
     * A sorted window over every matching entry, not only those that have the sort attribute.
     *
     * <p>eDirectory's server-side sort depends on its indexes (ig4, 2026-10-09): sorting on some
     * attributes leaves out entries without a value ({@code cn}, {@code sn}), on others keeps them
     * ({@code ou}, {@code l}), and on unindexed ones fails with "dib error (-785)" ({@code o},
     * {@code c}, {@code description}). So the list is split into segments: entries with
     * {@code sortAttrs[0]}; those without it but with {@code sortAttrs[1]}; and so on; and last, those
     * with none of them. A segment the server sorts is a VLV window sized by its content count; one it
     * refuses, and the remainder, are an ordinary search sorted here (up to {@link #UNSORTED_LIMIT}).
     * {@code startAt} jumps within the first segment. {@code total} is -1 when a capped search may have
     * left entries out.
     *
     * @param filter an LDAP filter, possibly with {@code {n}} placeholders for {@code args}
     */
    public Window sorted(String base, String filter, Object[] args, int scope, String[] attrs,
                         List<String> sortAttrs, boolean descending, int offset, int count, String startAt) throws NamingException {
        // eDirectory's sort walks its whole index for the attribute and tests the filter on each entry
        // (seconds for a large OR filter, against milliseconds unsorted), so a small result is listed
        // with one ordinary search and sorted here, and VLV is kept for large ones
        String[] withSort = attrs;
        for (String a : sortAttrs) {
            withSort = withAttr(withSort, a);
        }
        List<Entry> small = search(base, filter, args, scope, withSort, SMALL + 1);
        if (small.size() <= SMALL) {
            small.sort((x, y) -> {
                int c = sortValue(x, sortAttrs).compareToIgnoreCase(sortValue(y, sortAttrs));
                return descending ? -c : c;
            });
            int first = Math.max(1, offset);
            if (startAt != null) {
                first = 1;
                while (first <= small.size() && sortValue(small.get(first - 1), sortAttrs).compareToIgnoreCase(startAt) < 0) {
                    first++;
                }
            }
            int from = Math.min(first - 1, small.size());
            return new Window(List.copyOf(small.subList(from, Math.min(small.size(), from + count))), first, small.size());
        }
        return segmented(base, filter, args, scope, attrs, sortAttrs, descending, offset, count, startAt);
    }

    private Window segmented(String base, String filter, Object[] args, int scope, String[] attrs,
                             List<String> sortAttrs, boolean descending, int offset, int count, String startAt) throws NamingException {
        record Segment(String filter, String attr, int total, List<Entry> listed) {
        }
        List<Segment> segments = new ArrayList<>();
        StringBuilder without = new StringBuilder();
        int first = Math.max(1, offset);
        boolean capped = false;
        for (int i = 0; i <= sortAttrs.size(); i++) {
            String a = i < sortAttrs.size() ? sortAttrs.get(i) : null;
            String f = "(&" + filter + (a == null ? "" : "(" + a + "=*)") + without + ")";
            Segment seg = null;
            if (a != null) {
                try {
                    Window probe = window(base, f, args, scope, new String[] {"1.1"}, a, descending, 1, 1, i == 0 ? startAt : null);
                    if (probe.total() >= 0) {
                        seg = new Segment(f, a, probe.total(), null);
                        if (i == 0 && startAt != null) {
                            first = probe.total() == 0 ? 1 : probe.offset();
                        }
                    }
                } catch (NamingException e) {
                    if (Failure.of(e).code != 80) {
                        throw e;
                    }
                    // this tree cannot sort on `a`: list the segment unsorted below
                }
            }
            if (seg == null) {
                List<Entry> all = search(base, f, args, scope, withAttr(attrs, a), UNSORTED_LIMIT);
                capped |= all.size() >= UNSORTED_LIMIT;
                List<String> key = a == null ? List.of() : List.of(a);
                all.sort((x, y) -> {
                    int c = sortValue(x, key).compareToIgnoreCase(sortValue(y, key));
                    return descending ? -c : c;
                });
                if (i == 0 && startAt != null) {
                    int at = 0;
                    while (at < all.size() && sortValue(all.get(at), key).compareToIgnoreCase(startAt) < 0) {
                        at++;
                    }
                    first = at + 1;
                }
                seg = new Segment(f, a, all.size(), all);
            }
            segments.add(seg);
            if (a != null) {
                without.append("(!(").append(a).append("=*))");
            }
        }
        int total = 0;
        for (Segment g : segments) {
            total += g.total();
        }
        List<Entry> out = new ArrayList<>();
        java.util.Set<String> seen = new java.util.HashSet<>();
        boolean repeats = false;
        int consumed = 0;
        int next = first;
        for (Segment g : segments) {
            if (out.size() >= count) {
                break;
            }
            if (next <= consumed + g.total()) {
                int local = next - consumed;
                int want = Math.min(count - out.size(), g.total() - local + 1);
                List<Entry> got = g.listed() != null
                    ? g.listed().subList(local - 1, local - 1 + want)
                    : window(base, g.filter(), args, scope, attrs, g.attr(), descending, local, want, null).entries();
                got = got.subList(0, Math.min(want, got.size()));
                for (Entry e : got) {
                    // the sort lists an entry once per value of a multi-valued sort attribute
                    if (seen.add(e.dn().toLowerCase(java.util.Locale.ROOT))) {
                        out.add(e);
                    } else {
                        repeats = true;
                    }
                }
                next += got.size();
            }
            consumed += g.total();
        }
        return new Window(out, first, capped ? -1 : total, !capped && !repeats && sortAttrs.size() <= 1);
    }

    private static String[] withAttr(String[] attrs, String a) {
        if (a == null || attrs == null || List.of(attrs).contains("*") || List.of(attrs).stream().anyMatch(a::equalsIgnoreCase)) {
            return attrs;
        }
        String[] out = java.util.Arrays.copyOf(attrs, attrs.length + 1);
        out[attrs.length] = a;
        return out;
    }

    /** What an entry sorts by here: the first of {@code attrs} it has a value for, else its name. */
    private static String sortValue(Entry e, List<String> attrs) {
        for (String a : attrs) {
            String v = e.first(a);
            if (v != null) {
                return v;
            }
        }
        return leafValue(e.dn());
    }

    private static String leafValue(String dn) {
        try {
            javax.naming.ldap.LdapName n = new javax.naming.ldap.LdapName(dn);
            return n.size() == 0 ? "" : String.valueOf(n.getRdn(n.size() - 1).getValue());
        } catch (javax.naming.InvalidNameException e) {
            return dn;
        }
    }

    /** Add, remove or replace attribute values. */
    public synchronized void modify(String dn, List<ModificationItem> changes) throws NamingException {
        controls();
        ctx.modifyAttributes(dn, changes.toArray(new ModificationItem[0]));
    }

    /** Create an entry. */
    public synchronized void create(String dn, Map<String, List<Object>> attributes) throws NamingException {
        controls();
        BasicAttributes as = new BasicAttributes(true);
        attributes.forEach((k, vs) -> {
            javax.naming.directory.BasicAttribute a = new javax.naming.directory.BasicAttribute(k);
            vs.forEach(a::add);
            as.put(a);
        });
        ctx.createSubcontext(dn, as).close();
    }

    /** Rename and/or move: the old naming value is removed (deleteOldRDN). */
    public synchronized void rename(String dn, String newDn) throws NamingException {
        controls();
        ctx.addToEnvironment("java.naming.ldap.deleteRDN", "true");
        ctx.rename(dn, newDn);
    }

    public synchronized void delete(String dn) throws NamingException {
        controls();
        ctx.destroySubcontext(dn);
    }

    /** Attributes whose values come back as bytes, not text (added to what the connection already treats so). */
    public synchronized void binaryAttributes(java.util.Collection<String> names) throws NamingException {
        if (!names.isEmpty()) {
            ctx.addToEnvironment("java.naming.ldap.attributes.binary", BINARY + " " + String.join(" ", names));
        }
    }

    @Override
    public synchronized void close() {
        try {
            ctx.close();
        } catch (NamingException e) {
            // already gone
        }
    }

    private static Entry entry(String dn, Attributes as) throws NamingException {
        Map<String, String> names = new LinkedHashMap<>();
        if (as != null) {
            NamingEnumeration<String> ids = as.getIDs();
            while (ids.hasMore()) {
                String id = ids.next();
                names.put(id.toLowerCase(java.util.Locale.ROOT), id);
            }
        }
        return new Entry(dn, attributes(as), names);
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
