package com.pointblue.console.server.http;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.novell.ldap.LDAPException;
import com.pointblue.dirxml.dev.deploy.Vault;
import org.junit.Test;

public class IdmRefusalTest {

    @Test
    public void anEngineRefusalForRightsIsTheCallersRightsNotAnEngineFault() {
        Exception denied = new Vault.VaultException("GetDriverState cn=AD: Insufficient Access Rights",
            new LDAPException("Insufficient Access Rights", LDAPException.INSUFFICIENT_ACCESS_RIGHTS, "no access (-672)"));
        assertTrue(Idm.refused(denied));
        assertFalse(Idm.refused(new Vault.VaultException("StartDriver cn=AD: busy",
            new LDAPException("Other", LDAPException.OTHER, "-9010"))));
        assertFalse(Idm.refused(new UnsupportedOperationException("no")));
    }
}
