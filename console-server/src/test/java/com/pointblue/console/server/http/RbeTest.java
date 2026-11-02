package com.pointblue.console.server.http;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

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

    @Test
    public void theQueryUrlEncodesWhatRfc4516Reserves() {
        assertEquals("ldap:///ou=Users,o=acme??sub?(title=clerk)?x-sparse", RbeEdit.queryUrl("ou=Users,o=acme", "sub", "(title=clerk)"));
        assertEquals("a ? and % are encoded, as is what is not ASCII; spaces stay",
            "ldap:///ou=R%3FD,o=acme??one?(cn=100%25 %C3%A9*)?x-sparse", RbeEdit.queryUrl("ou=R?D,o=acme", "one", "(cn=100% é*)"));
        Map<String, Object> back = Rbe.query(RbeEdit.queryUrl("ou=R?D,o=acme", "one", "(cn=100% é+*)"));
        assertEquals("ou=R?D,o=acme", back.get("base"));
        assertEquals("(cn=100% é+*)", back.get("filter"));
    }

    @Test
    public void grantsAreOneRefOrOnePerValue() {
        List<RbeEdit.Grant> grants = List.of(new RbeEdit.Grant("cn=Account,cn=AD,cn=S,o=x", List.of()),
            new RbeEdit.Grant("cn=Group,cn=AD,cn=S,o=x", List.of("CN=R&D", "CN=<b>")));
        assertEquals(List.of("cn=Account,cn=AD,cn=S,o=x#0#<ref/>", "cn=Group,cn=AD,cn=S,o=x#0#<ref><param>CN=R&amp;D</param></ref>",
            "cn=Group,cn=AD,cn=S,o=x#0#<ref><param>CN=&lt;b&gt;</param></ref>"), RbeEdit.refs(grants));
        String display = RbeEdit.display(grants, Map.of());
        assertTrue(display.startsWith("<Drivers><Driver><name>AD</name><value>cn=AD,cn=S,o=x</value>"));
        assertTrue(display.contains("<type>NoValues</type>"));
        assertTrue(display.contains("<type>InputValues</type>"));
        assertTrue(display.contains("<InputValues><value>CN=R&amp;D</value><value>CN=&lt;b&gt;</value></InputValues>"));
        assertTrue("well-formed", RbeEdit.xml(display) != null);
    }

    @Test
    public void anEntitlementsDefinitionSaysWhatValuesItTakes() {
        RbeEdit.Definition d = RbeEdit.definition(entry("cn=Group,cn=AD,cn=S,o=x",
            "<entitlement conflict-resolution=\"union\" display-name=\"Group\"><values multi-valued=\"true\"><value>g1</value><value>g2</value></values></entitlement>"), "cn=AD,cn=S,o=x");
        assertEquals("list", d.kind());
        assertEquals(List.of("g1", "g2"), d.values());
        assertTrue(d.multiValued());
        assertEquals("union", d.conflictResolution());
        assertEquals("query", RbeEdit.definition(entry("cn=G,cn=AD,cn=S,o=x",
            "<entitlement><values multi-valued=\"true\"><query-app><query-xml/></query-app></values></entitlement>"), "cn=AD,cn=S,o=x").kind());
        assertEquals("input", RbeEdit.definition(entry("cn=G,cn=AD,cn=S,o=x", "<entitlement><values/></entitlement>"), "cn=AD,cn=S,o=x").kind());
        assertEquals("none", RbeEdit.definition(entry("cn=G,cn=AD,cn=S,o=x", "<entitlement/>"), "cn=AD,cn=S,o=x").kind());
        assertEquals("none", RbeEdit.definition(entry("cn=G,cn=AD,cn=S,o=x", null), "cn=AD,cn=S,o=x").kind());
    }

    @Test
    public void aRequestIsCheckedForShape() {
        assertThrows(IllegalArgumentException.class, () -> RbeEdit.spec(Map.of("membership", Map.of("base", "o=x", "scope", "deep", "filter", "(a=b)"))));
        assertThrows(IllegalArgumentException.class, () -> RbeEdit.spec(Map.of("membership", Map.of("base", "o=x", "filter", "a=b"))));
        assertThrows(IllegalArgumentException.class, () -> RbeEdit.spec(Map.of("grants", List.of(Map.of("entitlement", "cn=a,o=x"), Map.of("entitlement", "CN=A,O=X")))));
        assertThrows(IllegalArgumentException.class, () -> RbeEdit.spec(Map.of("membership", Map.of("filter", "(a=b)"), "criteria", "<other/>")));
        RbeEdit.Spec p = RbeEdit.spec(Map.of("members", List.of("cn=a,o=x", "CN=A,O=X")));
        assertEquals("the same DN once", 1, p.members().size());
        assertNull("no membership query: criteria are dropped", RbeEdit.spec(Map.of("criteria", "<selection-criterion/>")).criteria());
        assertFalse(p.identityGiven());
    }

    private static com.pointblue.console.server.ldap.Ldap.Entry entry(String dn, String xml) {
        Map<String, List<Object>> attrs = new java.util.HashMap<>();
        if (xml != null) {
            attrs.put("xmldata", List.of(xml.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        }
        return new com.pointblue.console.server.ldap.Ldap.Entry(dn, attrs, Map.of());
    }
}
