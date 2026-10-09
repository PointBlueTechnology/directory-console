package com.pointblue.console.server.ldap;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;

import com.pointblue.console.server.data.DataDir;
import com.pointblue.console.server.tls.TrustStore;
import java.time.Duration;
import java.util.List;
import javax.naming.directory.SearchControls;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class LdapTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private static final Duration T = Duration.ofSeconds(5);

    static final String ADMIN = "dn: cn=admin,o=system\nobjectClass: inetOrgPerson\ncn: admin\nsn: admin\nuserPassword: admin-pw";

    @Test
    public void anUntrustedServerIsReportedAsSuchAndTrustingTheTreeCaLetsTheBindThrough() throws Exception {
        try (FakeEdir edir = new FakeEdir(ADMIN)) {
            TrustStore ts = new TrustStore(new DataDir(tmp.newFolder().toPath()));
            Ldap.Target t = new Ldap.Target("prod", "127.0.0.1", edir.port());
            Ldap.Untrusted u = assertThrows(Ldap.Untrusted.class, () -> Ldap.connect(ts, t, null, "cn=admin,o=system", "admin-pw".toCharArray(), T));
            assertEquals(TrustStore.Reason.UNTRUSTED, u.cause.reason);
            assertEquals("the chain is carried for a probe", 2, u.cause.chain.size());

            ts.add(edir.pki.ca, TrustStore.Kind.CA, "directory:prod", "test", "upload");
            try (Ldap l = Ldap.connect(ts, t, null, "cn=admin,o=system", "admin-pw".toCharArray(), T)) {
                assertEquals("admin", l.read("cn=admin,o=system", "cn").first("cn"));
                assertNull(l.read("cn=nobody,o=system"));
            }
            assertThrows(Ldap.BadCredentials.class, () -> Ldap.connect(ts, t, null, "cn=admin,o=system", "wrong".toCharArray(), T));
            assertThrows("never an anonymous bind", Ldap.BadCredentials.class, () -> Ldap.connect(ts, t, null, "cn=admin,o=system", new char[0], T));
        }
    }

    @Test
    public void searchArgumentsAreEscapedSoAValueCannotChangeTheFilter() throws Exception {
        try (FakeEdir edir = new FakeEdir(ADMIN,
                "dn: cn=Smith\\, John,o=acme\nobjectClass: inetOrgPerson\ncn: Smith, John\nsn: Smith",
                "dn: cn=Smith (Admin),o=acme\nobjectClass: inetOrgPerson\ncn: Smith (Admin)\nsn: Smith",
                "dn: cn=Other,o=acme\nobjectClass: inetOrgPerson\ncn: Other\nsn: Other")) {
            TrustStore ts = new TrustStore(new DataDir(tmp.newFolder().toPath()));
            ts.add(edir.pki.ca, TrustStore.Kind.CA, "global", "test", "upload");
            try (Ldap l = Ldap.connect(ts, new Ldap.Target("prod", "127.0.0.1", edir.port()), null, "cn=admin,o=system", "admin-pw".toCharArray(), T)) {
                List<Ldap.Entry> r = l.search("o=acme", "(cn={0})", new Object[] {"Smith (Admin)"}, SearchControls.SUBTREE_SCOPE, new String[] {"cn"}, 0);
                assertEquals(1, r.size());
                assertEquals("Smith (Admin)", r.get(0).first("cn"));
                assertEquals(1, l.search("o=acme", "(cn={0})", new Object[] {"Smith, John"}, SearchControls.SUBTREE_SCOPE, new String[] {"cn"}, 0).size());
                assertEquals("a literal star is not a wildcard", 0,
                    l.search("o=acme", "(cn={0})", new Object[] {"*"}, SearchControls.SUBTREE_SCOPE, new String[] {"cn"}, 0).size());
                assertEquals(0, l.search("o=acme", "(cn={0})", new Object[] {"x)(objectClass=*"}, SearchControls.SUBTREE_SCOPE, new String[] {"cn"}, 0).size());
                assertEquals("limit", 2, l.search("o=acme", "(objectClass=inetOrgPerson)", null, SearchControls.SUBTREE_SCOPE, new String[] {"cn"}, 2).size());
            }
        }
    }

    @Test
    public void effectivePrivilegesSendsThreeOctetStringsAndReadsTheInteger() throws Exception {
        try (FakeEdir edir = new FakeEdir(ADMIN)) {
            TrustStore ts = new TrustStore(new DataDir(tmp.newFolder().toPath()));
            ts.add(edir.pki.ca, TrustStore.Kind.CA, "global", "test", "upload");
            edir.privileges = 0x1f;
            String longDn = "cn=" + "x".repeat(200) + ",o=acme";
            try (Ldap l = Ldap.connect(ts, new Ldap.Target("prod", "127.0.0.1", edir.port()), null, "cn=admin,o=system", "admin-pw".toCharArray(), T)) {
                assertEquals(0x1f, l.effectivePrivileges("o=acme", "cn=admin,o=system", "[Entry Rights]"));
                edir.privileges = 0;
                assertEquals(0, l.effectivePrivileges(longDn, "cn=admin,o=system", "[All Attributes Rights]"));
            }
            assertArrayEquals(new String[] {"o=acme", "cn=admin,o=system", "[Entry Rights]"}, edir.privilegeRequests.get(0));
            assertEquals("long values use the long BER length form", longDn, edir.privilegeRequests.get(1)[0]);
        }
    }
}
