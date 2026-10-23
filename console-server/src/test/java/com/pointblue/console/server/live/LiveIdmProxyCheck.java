package com.pointblue.console.server.live;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPControl;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPExtendedResponse;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPSearchResults;
import com.pointblue.dirxml.dev.LegacyTls;
import com.pointblue.dirxml.dev.deploy.Environments;
import com.pointblue.dirxml.dev.deploy.IdmOps;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Live check: does eDirectory apply RFC 4370 proxied authorization to Identity Manager's engine
 * operations? Bound as the environment's account, it sends read-only engine requests for one driver
 * with no control, acting as that account, and acting as a test user made for the run with no rights
 * (and no password); then a start-option "change" to the value it already has. If the test user's
 * requests are refused, the control is honoured and a single sign-on session can use the engine on the
 * service account's connection.
 *
 * <p>Found on ig4 (eDirectory 9.2.8, IDM 4.8.7, 2026-10-23): the control is honoured, and the engine
 * keeps the last identity it was given on that connection: after any request under the control, requests
 * without it are decided as that person too (plain LDAP operations are not affected). So an engine
 * connection used this way must belong to one person and carry the control on every request. The test
 * container is deleted at the end, on a fresh connection. Not a JUnit test.
 *
 *   java -cp … LiveIdmProxyCheck <environments.properties> <env> <parent DN>
 */
public final class LiveIdmProxyCheck {

    private static final String PROXIED_AUTHZ = "2.16.840.1.113730.3.4.18";

    public static void main(String[] args) throws Exception {
        LegacyTls.enable();
        Environments.Environment env = Environments.load(Path.of(args[0])).get(args[1]);
        if (env.tier != null && env.tier.name().equalsIgnoreCase("prd")) {
            throw new IllegalStateException("refusing a prd-tier environment");
        }
        URI u = URI.create(env.url);
        SSLContext tls = SSLContext.getInstance("TLS");
        tls.init(null, new TrustManager[] {new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) { }
            public void checkServerTrusted(X509Certificate[] c, String a) { }
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, null);
        LDAPConnection conn = connect(tls, u, env);

        LDAPSearchResults drivers = conn.search(env.driverSetDn, LDAPConnection.SCOPE_ONE, "(objectClass=DirXML-Driver)", new String[] {"cn"}, false);
        String driver = drivers.next().getDN();
        System.out.println("# driver " + driver);

        String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
        String ou = "ou=dc-idmproxy-" + ts + "," + args[2];
        String user = "cn=nobody," + ou;
        conn.add(new LDAPEntry(ou, new LDAPAttributeSet() {{
            add(new LDAPAttribute("objectClass", "organizationalUnit"));
            add(new LDAPAttribute("ou", "dc-idmproxy-" + ts));
        }}));
        try {
            conn.add(new LDAPEntry(user, new LDAPAttributeSet() {{
                add(new LDAPAttribute("objectClass", "inetOrgPerson"));
                add(new LDAPAttribute("cn", "nobody"));
                add(new LDAPAttribute("sn", "Nobody"));
            }}));
            System.out.println("# test user " + user + " (no rights, no password)");

            for (String as : new String[] {null, env.bindDn}) {
                String who = as == null ? "no control" : "as the bound account";
                probe(conn, as, who + ": GetDriverState", IdmOps.Op.GET_DRIVER_STATE, driver);
                probe(conn, as, who + ": ListNamedPasswords", IdmOps.Op.LIST_NAMED_PASSWORDS, driver);
            }
            // as the test user: one the engine answers, then the same connection without the control
            probe(conn, user, "as the test user: GetVersion", IdmOps.Op.GET_VERSION);
            probe(conn, null, "then no control: GetDriverState", IdmOps.Op.GET_DRIVER_STATE, driver);
            probe(conn, user, "as the test user: GetDriverState", IdmOps.Op.GET_DRIVER_STATE, driver);
            probe(conn, null, "then no control: GetDriverState", IdmOps.Op.GET_DRIVER_STATE, driver);
            probe(conn, env.bindDn, "then as the bound account: GetDriverState", IdmOps.Op.GET_DRIVER_STATE, driver);
            try {
                conn.read(driver, new String[] {"cn"});
                System.out.println("then no control: LDAP read of the driver: read");
            } catch (LDAPException e) {
                System.out.println("then no control: LDAP read of the driver: refused " + e.getResultCode() + " " + e.getLDAPErrorMessage());
            }
            // a fresh connection, as the same account, is not affected
            LDAPConnection fresh = connect(tls, u, env);
            probe(fresh, null, "fresh connection, no control: GetDriverState", IdmOps.Op.GET_DRIVER_STATE, driver);
            int option = IdmOps.decode(fresh.extendedOperation(IdmOps.request(IdmOps.Op.GET_DRIVER_START_OPTION, driver)).getValue()).integer(0);
            probe(fresh, user, "fresh connection, as the test user: ListNamedPasswords", IdmOps.Op.LIST_NAMED_PASSWORDS, driver);
            probe(fresh, user, "fresh connection, as the test user: SetDriverStartOption to its current " + option,
                IdmOps.Op.SET_DRIVER_START_OPTION, driver, option, 0);
            fresh.disconnect();
        } finally {
            // on a fresh connection: a refusal under the control can leave this one refusing everything
            conn.disconnect();
            LDAPConnection clean = connect(tls, u, env);
            try {
                clean.delete(user);
            } catch (LDAPException ignored) {
                // not made
            }
            clean.delete(ou);
            System.out.println("# removed " + ou);
            clean.disconnect();
        }
    }

    private static LDAPConnection connect(SSLContext tls, URI u, Environments.Environment env) throws LDAPException {
        LDAPConnection c = new LDAPConnection(new LDAPJSSESecureSocketFactory(tls.getSocketFactory()));
        c.connect(u.getHost(), u.getPort() > 0 ? u.getPort() : 636);
        c.bind(LDAPConnection.LDAP_V3, env.bindDn, env.password.getBytes(StandardCharsets.UTF_8));
        return c;
    }

    private static LDAPControl control(String dn) {
        return new LDAPControl(PROXIED_AUTHZ, true, ("dn:" + dn).getBytes(StandardCharsets.UTF_8));
    }

    private static void probe(LDAPConnection conn, String as, String what, IdmOps.Op op, Object... items) {
        try {
            LDAPConstraints c = new LDAPConstraints();
            if (as != null) {
                c.setControls(control(as));
            }
            LDAPExtendedResponse r = conn.extendedOperation(IdmOps.request(op, items), c);
            IdmOps.Reply reply = IdmOps.decode(r == null ? null : r.getValue());
            System.out.println(what + ": answered " + (r == null ? "-" : r.getResultCode()) + " " + reply);
        } catch (LDAPException e) {
            System.out.println(what + ": refused " + e.getResultCode() + " " + e.getLDAPErrorMessage());
        } catch (Exception e) {
            System.out.println(what + ": failed " + e);
        }
    }
}
