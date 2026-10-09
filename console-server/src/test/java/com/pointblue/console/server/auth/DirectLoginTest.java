package com.pointblue.console.server.auth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.pointblue.console.server.data.DataDir;
import com.pointblue.console.server.ldap.FakeEdir;
import com.pointblue.console.server.tls.TrustStore;
import java.util.List;
import java.util.Set;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/** Direct and contextless sign-in against an eDirectory stand-in. */
public class DirectLoginTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private FakeEdir edir;
    private TrustStore trust;
    private DirectLogin login;

    private static String user(String dn, String cn, String extra) {
        return "dn: " + dn + "\nobjectClass: inetOrgPerson\ncn: " + cn + "\nsn: x\nuserPassword: pw-" + cn.replaceAll("[^A-Za-z0-9]", "") + (extra == null ? "" : "\n" + extra);
    }

    @Before
    public void tree() throws Exception {
        edir = new FakeEdir(
            "dn: ou=sales,o=acme\nobjectClass: organizationalUnit\nou: sales",
            "dn: ou=it,o=acme\nobjectClass: organizationalUnit\nou: it",
            "dn: ou=users,o=acme\nobjectClass: organizationalUnit\nou: users",
            "dn: cn=Console Admins,o=acme\nobjectClass: groupOfNames\ncn: Console Admins",
            "dn: cn=Operators,o=acme\nobjectClass: groupOfNames\ncn: Operators",
            user("cn=admin,o=system", "admin", null),
            user("cn=console,o=system", "console", null),
            user("cn=pat,ou=users,o=acme", "pat", "groupMembership: cn=Console Admins,o=acme\ngroupMembership: cn=Operators,o=acme\nfullName: Pat Smith"),
            user("cn=jsmith,ou=sales,o=acme", "jsmith", "groupMembership: CN=OPERATORS,O=ACME\ntitle: Sales"),
            user("cn=jsmith,ou=it,o=acme", "jsmith", "groupMembership: cn=Operators,o=acme\ntitle: IT"),
            user("cn=gone,ou=users,o=acme", "gone", "loginDisabled: TRUE\ngroupMembership: cn=Operators,o=acme"),
            user("cn=old,ou=users,o=acme", "old", "loginExpirationTime: 20200101000000Z\ngroupMembership: cn=Operators,o=acme"),
            user("cn=norole,ou=users,o=acme", "norole", null),
            user("cn=Smith\\, John,ou=users,o=acme", "Smith, John", "groupMembership: cn=Operators,o=acme"));
        trust = new TrustStore(new DataDir(tmp.newFolder().toPath()));
        trust.add(edir.pki.ca, TrustStore.Kind.CA, "directory:prod", "test", "upload");
        login = new DirectLogin(trust);
    }

    @After
    public void stop() {
        edir.close();
    }

    private DirectoryConfig dir(DirectoryConfig.Duplicates dup, boolean direct) {
        return new DirectoryConfig("prod", "Production", "127.0.0.1", edir.port(), "production", direct, List.of("o=acme"),
            List.of("inetOrgPerson"), List.of("cn"), true, 10, dup, "title", "cn=console,o=system",
            List.of(new DirectoryConfig.RoleMapping("cn=Console Admins,o=acme", Role.ADMIN), new DirectoryConfig.RoleMapping("cn=Operators,o=acme", Role.OPERATOR)),
            List.of("cn=admin,o=system"));
    }

    private DirectLogin.Outcome as(DirectoryConfig d, String name, String pw) {
        return login.login(d, "pw-console", name, pw.toCharArray(), null);
    }

    @Test
    public void aFullDnSignsInWithRolesFromGroupMembership() {
        DirectLogin.SignedIn s = (DirectLogin.SignedIn) as(dir(DirectoryConfig.Duplicates.CHOOSE, true), "cn=pat,ou=users,o=acme", "pw-pat");
        assertEquals(Set.of(Role.ADMIN, Role.OPERATOR), s.principal().roles());
        assertEquals("Pat Smith", s.principal().name());
        assertEquals("direct", s.principal().via());
        s.connection().close();
    }

    @Test
    public void aUniqueBareNameResolvesWithoutTheContext() {
        DirectLogin.SignedIn s = (DirectLogin.SignedIn) as(dir(DirectoryConfig.Duplicates.CHOOSE, true), "pat", "pw-pat");
        assertEquals("cn=pat,ou=users,o=acme", s.principal().dn());
        s.connection().close();
        DirectLogin.SignedIn comma = (DirectLogin.SignedIn) as(dir(DirectoryConfig.Duplicates.CHOOSE, true), "Smith, John", "pw-SmithJohn");
        assertEquals(Set.of(Role.OPERATOR), comma.principal().roles());
        comma.connection().close();
    }

    @Test
    public void duplicatesOfferAChoiceAndThePasswordGoesOnlyToTheChosenAccount() {
        DirectoryConfig d = dir(DirectoryConfig.Duplicates.CHOOSE, true);
        DirectLogin.Choose c = (DirectLogin.Choose) as(d, "jsmith", "pw-jsmith");
        assertEquals(2, c.candidates().size());
        assertEquals(Set.of("ou=sales,o=acme", "ou=it,o=acme"), Set.of(c.candidates().get(0).context(), c.candidates().get(1).context()));
        assertTrue(c.candidates().stream().anyMatch(x -> "Sales".equals(x.label())));
        assertNotEquals(c.candidates().get(0).token(), c.candidates().get(1).token());
        DirectLogin.Candidate it = c.candidates().stream().filter(x -> x.context().equals("ou=it,o=acme")).findFirst().orElseThrow();
        DirectLogin.SignedIn s = (DirectLogin.SignedIn) login.login(d, "pw-console", null, "pw-jsmith".toCharArray(), it.token());
        assertEquals("cn=jsmith,ou=it,o=acme", s.principal().dn());
        s.connection().close();
        DirectLogin.Refused again = (DirectLogin.Refused) login.login(d, "pw-console", null, "pw-jsmith".toCharArray(), it.token());
        assertEquals("a choice token is single-use", "choice-expired", again.code());
    }

    @Test
    public void theErrorPolicyRevealsNothingAboutTheAccounts() {
        DirectLogin.Refused r = (DirectLogin.Refused) as(dir(DirectoryConfig.Duplicates.ERROR, true), "jsmith", "pw-jsmith");
        assertEquals("ambiguous", r.code());
        assertFalse(r.message().contains("sales") || r.message().contains("ou="));
    }

    @Test
    public void anUnknownNameLooksExactlyLikeAWrongPassword() {
        DirectoryConfig d = dir(DirectoryConfig.Duplicates.CHOOSE, true);
        DirectLogin.Refused unknown = (DirectLogin.Refused) as(d, "nobody", "whatever");
        DirectLogin.Refused wrong = (DirectLogin.Refused) as(d, "pat", "wrong");
        assertEquals("bad-credentials", unknown.code());
        assertEquals(wrong.code(), unknown.code());
        assertEquals(wrong.message(), unknown.message());
        assertEquals("a star is a name, not a wildcard", "bad-credentials", ((DirectLogin.Refused) as(d, "*", "x")).code());
    }

    @Test
    public void disabledAndExpiredAccountsAreNotCandidates() {
        DirectoryConfig d = dir(DirectoryConfig.Duplicates.CHOOSE, true);
        assertEquals("bad-credentials", ((DirectLogin.Refused) as(d, "gone", "pw-gone")).code());
        assertEquals("bad-credentials", ((DirectLogin.Refused) as(d, "old", "pw-old")).code());
    }

    @Test
    public void noMappedRoleIsRefusedAndBreakGlassIsAlwaysAdmin() {
        DirectoryConfig d = dir(DirectoryConfig.Duplicates.CHOOSE, true);
        assertEquals("no-role", ((DirectLogin.Refused) as(d, "cn=norole,ou=users,o=acme", "pw-norole")).code());
        DirectLogin.SignedIn bg = (DirectLogin.SignedIn) as(d, "cn=admin,o=system", "pw-admin");
        assertEquals(Set.of(Role.ADMIN), bg.principal().roles());
        assertEquals("break-glass", bg.principal().via());
        bg.connection().close();
    }

    @Test
    public void withDirectLoginOffOnlyBreakGlassSignsIn() {
        DirectoryConfig off = dir(DirectoryConfig.Duplicates.CHOOSE, false);
        assertEquals("not-allowed", ((DirectLogin.Refused) as(off, "cn=pat,ou=users,o=acme", "pw-pat")).code());
        DirectLogin.SignedIn bg = (DirectLogin.SignedIn) as(off, "cn=admin,o=system", "pw-admin");
        bg.connection().close();
    }

    @Test
    public void anUntrustedServerIsReportedForAProbe() throws Exception {
        TrustStore empty = new TrustStore(new DataDir(tmp.newFolder().toPath()));
        DirectLogin.Refused r = (DirectLogin.Refused) new DirectLogin(empty).login(dir(DirectoryConfig.Duplicates.CHOOSE, true), "pw-console",
            "cn=pat,ou=users,o=acme", "pw-pat".toCharArray(), null);
        assertEquals("untrusted-certificate", r.code());
        assertEquals(TrustStore.Reason.UNTRUSTED, r.untrusted().reason);
    }

    @Test
    public void withoutAServiceAccountABareNameNeedsTheFullName() {
        DirectoryConfig d = dir(DirectoryConfig.Duplicates.CHOOSE, true);
        assertEquals("full-name-required", ((DirectLogin.Refused) login.login(d, null, "pat", "pw-pat".toCharArray(), null)).code());
        assertNull(null);
    }
}
