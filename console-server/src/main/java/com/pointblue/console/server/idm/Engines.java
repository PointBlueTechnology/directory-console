package com.pointblue.console.server.idm;

import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.console.server.tls.TrustStore;
import com.pointblue.dirxml.dev.deploy.Vault;
import com.pointblue.dirxml.dev.operate.Operate;

/**
 * Identity Manager's engine operations (DirXML extended operations) for a signed-in person, through
 * DirXMLDev's {@code Vault} and {@code Operate}, which encode them with the open-source JLDAP library
 * (since DirXMLDev 0.37.0): no engine jars are needed, and none of OpenText's code is in the image.
 */
public interface Engines {

    /** An engine connection bound as the person; {@code close} ends it. */
    record Opened(Operate.Engine engine, AutoCloseable handle) {
    }

    /** Why engine operations are unavailable, or null when they are. */
    String unavailable();

    /**
     * Bind the engine connection as the person, at sign-in, while the password is in hand; the
     * password is used for that bind only. {@code ldap} is the person's directory connection.
     */
    Opened open(Ldap ldap, TrustStore trust, Ldap.Target target, String dn, char[] password) throws Exception;

    /**
     * For a single sign-on session: the engine connection bound as the console's service account, every
     * engine request carrying the RFC 4370 proxied-authorization control for {@code personDn}, so the
     * engine decides with the person's rights. {@code ldap} is the session's own (proxied) connection.
     * The connection belongs to this one person: eDirectory's engine keeps the last identity it was given
     * on a connection (seen on ig4, 2026-10-23), so it is never shared.
     */
    Opened openAs(Ldap ldap, TrustStore trust, Ldap.Target target, String serviceDn, char[] servicePassword, String personDn) throws Exception;

    /** The job types the engine on {@code ldap}'s server offers, as its DiscoverJobs answers, for the driver or driver set {@code dn}. */
    default byte[] discoverJobs(Ldap ldap, String dn) throws javax.naming.NamingException {
        return JobCatalog.discover(ldap.context(), dn);
    }

    /** Tell the engine on {@code ldap}'s server that a job was added or changed; false when that failed. */
    default boolean notifyJob(Ldap ldap, String jobDn) {
        return JobCatalog.notify(ldap.context(), jobDn);
    }

    /** The real engine: DirXMLDev's Vault over JLDAP, a dependency of the console like any other. */
    static Engines detect() {
        return new Engines() {
            @Override
            public String unavailable() {
                return null;
            }

            @Override
            public Opened open(Ldap ldap, TrustStore trust, Ldap.Target target, String dn, char[] password) throws Exception {
                Vault v = Vault.open(ldap.context(), target.host(), target.port(), Ldap.socketFactory(trust, target, null), dn, password);
                return new Opened(Operate.vaultEngine(v), v);
            }

            @Override
            public Opened openAs(Ldap ldap, TrustStore trust, Ldap.Target target, String serviceDn, char[] servicePassword, String personDn) throws Exception {
                Vault v = Vault.open(ldap.context(), target.host(), target.port(), Ldap.socketFactory(trust, target, null), serviceDn, servicePassword);
                try {
                    actAs(v, personDn);
                } catch (Exception | LinkageError e) {
                    v.close();
                    throw e;
                }
                return new Opened(Operate.vaultEngine(v), v);
            }
        };
    }

    /**
     * Make every request on {@code v}'s extended-operation connection carry the proxied-authorization
     * control for {@code personDn}, as the connection's default constraints. DirXMLDev's Vault has no
     * public way to reach that connection yet, so its {@code ops} field is read here; a test checks the
     * field is still there, and a missing one fails the sign-in's engine (never runs unproxied).
     */
    static void actAs(Vault v, String personDn) throws ReflectiveOperationException, com.novell.ldap.LDAPException {
        java.lang.reflect.Field f = Vault.class.getDeclaredField("ops");
        f.setAccessible(true);
        com.novell.ldap.LDAPConnection ops = (com.novell.ldap.LDAPConnection) f.get(v);
        if (ops == null) {
            throw new IllegalStateException("the engine connection is not open");
        }
        com.novell.ldap.LDAPSearchConstraints c = ops.getSearchConstraints();
        c.setControls(new com.novell.ldap.LDAPControl(Ldap.PROXIED_AUTHZ, true, ("dn:" + personDn).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        ops.setConstraints(c);
    }

    static Engines none(String why) {
        return new Engines() {
            @Override
            public String unavailable() {
                return why;
            }

            @Override
            public Opened open(Ldap ldap, TrustStore trust, Ldap.Target target, String dn, char[] password) {
                throw new IllegalStateException(why);
            }

            @Override
            public Opened openAs(Ldap ldap, TrustStore trust, Ldap.Target target, String serviceDn, char[] servicePassword, String personDn) {
                throw new IllegalStateException(why);
            }
        };
    }
}
