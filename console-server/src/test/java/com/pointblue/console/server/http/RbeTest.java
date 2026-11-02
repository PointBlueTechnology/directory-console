package com.pointblue.console.server.http;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.List;
import java.util.Map;
import org.junit.Test;

/** Reading role-based entitlement values whose names hold the separator. */
public class RbeTest {

    @Test
    public void aPriorityIsReadFromTheRight() {
        Map.Entry<String, Integer> t = Rbe.typedName("cn=Team#1,cn=Entitlement Policies,cn=Set,o=system#2#0");
        assertEquals("cn=Team#1,cn=Entitlement Policies,cn=Set,o=system", t.getKey());
        assertEquals(2, (int) t.getValue());
        assertNull(Rbe.typedName("cn=x,o=system"));
        assertNull(Rbe.typedName("cn=x,o=system#a#0"));
        assertEquals("keyed by the canonical DN", Map.of(com.pointblue.console.server.ldap.Names.canonical("cn=Team#1,o=system"), 0), Rbe.levels(List.of("cn=Team#1,o=system#0#0")));
    }

    @Test
    public void aGrantIsSplitWhereItsXmlStarts() {
        Map<String, Object> g = Rbe.grant("cn=Group#2,cn=AD,cn=Set,o=system#0#<ref><param>CN=R#D,OU=G</param></ref>");
        assertEquals("cn=Group#2,cn=AD,cn=Set,o=system", g.get("dn"));
        assertEquals("Group#2", g.get("entitlement"));
        assertEquals("AD", g.get("driver"));
        assertEquals("<ref><param>CN=R#D,OU=G</param></ref>", g.get("ref"));
    }
}
