package com.pointblue.console.server.idm;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPControl;
import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.dirxml.dev.deploy.Vault;
import java.nio.charset.StandardCharsets;
import org.junit.Test;

public class EnginesTest {

    @Test
    public void actingAsSomeoneMarksEveryEngineRequestOnThatConnection() throws Exception {
        // a Vault with an engine connection that never connected: only its default constraints are looked at
        java.lang.reflect.Constructor<Vault> make = Vault.class.getDeclaredConstructor(Vault.Config.class, javax.naming.directory.DirContext.class);
        make.setAccessible(true);
        Vault v = make.newInstance(new Vault.Config(), null);
        java.lang.reflect.Field ops = Vault.class.getDeclaredField("ops");
        ops.setAccessible(true);
        LDAPConnection conn = new LDAPConnection();
        ops.set(v, conn);

        Engines.actAs(v, "cn=alice,ou=Sales,o=acme");

        LDAPControl[] controls = conn.getSearchConstraints().getControls();
        assertEquals(1, controls.length);
        assertEquals(Ldap.PROXIED_AUTHZ, controls[0].getID());
        assertTrue(controls[0].isCritical());
        assertEquals("dn:cn=alice,ou=Sales,o=acme", new String(controls[0].getValue(), StandardCharsets.UTF_8));
        assertEquals("plain requests carry it too", 1, conn.getConstraints().getControls().length);
    }
}
