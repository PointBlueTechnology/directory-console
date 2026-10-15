package com.pointblue.console.server.idm;

import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.console.server.tls.TrustStore;
import com.pointblue.dirxml.dev.deploy.Vault;
import com.pointblue.dirxml.dev.operate.Operate;

/**
 * Identity Manager's engine operations (DirXML extended operations) for a signed-in person, through
 * DirXMLDev's {@code Vault} and {@code Operate}. They need the customer's engine jars
 * ({@code dirxml_misc.jar}, {@code ldap.jar}) on the class path, mounted at {@code /engine} in the
 * container: OpenText's code never ships in the image. Without them the console works and says why
 * Identity Manager is unavailable.
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

    /** The job types the engine on {@code ldap}'s server offers, as its DiscoverJobs answers, for the driver or driver set {@code dn}. */
    default byte[] discoverJobs(Ldap ldap, String dn) throws javax.naming.NamingException {
        return JobCatalog.discover(ldap.context(), dn);
    }

    /** Tell the engine on {@code ldap}'s server that a job was added or changed; false when that failed. */
    default boolean notifyJob(Ldap ldap, String jobDn) {
        return JobCatalog.notify(ldap.context(), jobDn);
    }

    /** The real engine when its classes are on the class path; otherwise one that says they are not. */
    static Engines detect() {
        try {
            Class.forName("com.novell.nds.dirxml.ldap.GetDriverStateRequest", false, Engines.class.getClassLoader());
            Class.forName("com.novell.ldap.LDAPConnection", false, Engines.class.getClassLoader());
        } catch (ClassNotFoundException | LinkageError e) {
            return none("the Identity Manager engine jars (dirxml_misc.jar, ldap.jar) are not mounted at /engine");
        }
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
        };
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
        };
    }
}
