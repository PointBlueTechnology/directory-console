package com.pointblue.console.server.ldap;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.Test;

/** Names, schema parsing, structured filters and value conversion: the pieces under the object API. */
public class ObjectModelTest {

    private static Schema schema() {
        List<String> classes = Arrays.stream(FakeEdir.SCHEMA).filter(l -> l.startsWith("objectClasses: ")).map(l -> l.substring(15)).toList();
        List<String> attrs = Arrays.stream(FakeEdir.SCHEMA).filter(l -> l.startsWith("attributeTypes: ")).map(l -> l.substring(16)).toList();
        return new Schema(classes, attrs);
    }

    // ---- names ----

    @Test
    public void identityBlockKeepsEscapesInTheDnAndNowhereElse() {
        Map<String, Object> id = Names.identity("cn=Smith\\, John+uid=js,ou=Users\\+Admins,o=Acme");
        assertEquals("cn=Smith\\, John+uid=js,ou=Users\\+Admins,o=Acme", id.get("dn"));
        assertEquals("Smith, John", id.get("name"));
        assertEquals("ou=Users\\+Admins,o=Acme", id.get("parentDn"));
        assertEquals(List.of(Map.of("dn", "o=Acme", "name", "Acme"), Map.of("dn", "ou=Users\\+Admins,o=Acme", "name", "Users+Admins")), id.get("ancestors"));
        List<?> rdns = (List<?>) id.get("rdns");
        assertEquals("leaf to root", 3, rdns.size());
        assertEquals("a multi-valued name keeps both parts", 2, ((List<?>) rdns.get(0)).size());
        assertEquals(Map.of("type", "ou", "value", "Users+Admins"), ((List<?>) rdns.get(1)).get(0));
        Map<?, ?> display = (Map<?, ?>) id.get("display");
        assertEquals("Smith, John+js.Users\\+Admins.Acme", display.get("dot"));
        assertEquals("\\Acme\\Users\\+Admins\\Smith, John+js", display.get("slash"));
        assertEquals("a period in a name is escaped in dot notation", "a.b\\.c", ((Map<?, ?>) Names.identity("ou=a,ou=b.c").get("display")).get("dot"));
    }

    @Test
    public void childNamesAreEscapedHereNotByTheCaller() {
        String dn = Names.child("ou=a\\, b,o=acme", "cn", "Team #1, (x)+y=z\\");
        assertEquals("Team #1, (x)+y=z\\", Names.leaf(dn).getValue());
        assertEquals("ou=a\\, b,o=acme", Names.parent(dn));
        assertThrows(IllegalArgumentException.class, () -> Names.child("o=acme", "cn=x,ou", "y"));
        assertThrows(IllegalArgumentException.class, () -> Names.child("o=acme", "cn", ""));
    }

    @Test
    public void canonicalFormIgnoresSpellingAndCase() {
        assertEquals(Names.canonical("CN=a\\2cb,O=Acme"), Names.canonical("cn=A\\,B, o=acme"));
        assertTrue(Names.same("cn=a\\2cb,o=acme", "CN=A\\,B,O=ACME"));
        assertTrue(Names.within("cn=x,ou=a,o=acme", "ou=a,o=acme"));
        assertFalse(Names.within("ou=a,o=acme", "cn=x,ou=a,o=acme"));
    }

    @Test
    public void guidsAreLowercaseHex() {
        byte[] b = Names.guidBytes("00112233445566778899aabbccddeeff");
        assertEquals(16, b.length);
        assertEquals("00112233445566778899aabbccddeeff", Names.guidHex(b));
        assertThrows(IllegalArgumentException.class, () -> Names.guidBytes("00112233445566778899AABBCCDDEEFF"));
        assertThrows(IllegalArgumentException.class, () -> Names.guidBytes("../../etc"));
    }

    // ---- schema ----

    @Test
    public void containersFollowEdirectoryFlags() {
        Schema s = schema();
        assertTrue(s.objectClass("organizationalUnit").container());
        assertTrue(s.objectClass("DirXML-DriverSet").container());
        assertFalse("X-NDS_NOT_CONTAINER", s.objectClass("inetOrgPerson").container());
        assertFalse("X-NDS_NOT_CONTAINER", s.objectClass("group").container());
        assertFalse("Top: X-NDS_AMBIGUOUS_CONTAINMENT", s.objectClass("Top").container());
        assertFalse("abstract", s.objectClass("ndsLoginProperties").container());
        assertTrue(s.container(List.of("organizationalUnit", "ndsLoginProperties", "Top")));
        assertFalse("every entry has Top; that alone is not a container", s.container(List.of("inetOrgPerson", "Top")));
        assertEquals("inetOrgPerson", s.structural(List.of("Top", "Person", "inetOrgPerson", "organizationalPerson", "ndsLoginProperties")));
    }

    @Test
    public void attributesAndInheritance() {
        Schema s = schema();
        assertEquals("member", s.attribute("uniqueMember").name());
        assertTrue(s.attribute("member").dn());
        assertTrue(s.attribute("GUID").binary() && s.attribute("GUID").readOnly() && s.attribute("GUID").operational());
        assertEquals("the {n} bound is not part of the syntax", "1.3.6.1.4.1.1466.115.121.1.15", s.attribute("cn").syntax());
        assertEquals("Login Disabled", s.attribute("loginDisabled").ndsName());
        assertTrue(s.must("inetOrgPerson").containsAll(List.of("cn", "sn", "objectClass")));
        assertTrue(s.may("inetOrgPerson").containsAll(List.of("mail", "title", "telephoneNumber", "loginDisabled", "ACL")));
        assertTrue(s.binaryAttributes().containsAll(List.of("GUID", "jpegPhoto")));
        assertNull(s.objectClass("noSuchClass"));
        assertEquals("inherited from Person", List.of("cn", "ou", "uid"), s.naming("inetOrgPerson"));
        assertEquals(List.of("Organization", "organizationalUnit", "domain"), s.containment("inetOrgPerson"));
        assertEquals(List.of("ou"), s.naming("organizationalUnit"));
    }

    // ---- filters ----

    @Test
    public void structuredFiltersPutEveryValueInAnArgument() {
        Filters.Built f = Filters.build(Map.of("and", List.of(
            Map.of("eq", Map.of("objectClass", "inetOrgPerson")),
            Map.of("prefix", Map.of("cn", "Smith (Admin")),
            Map.of("not", Map.of("present", "loginDisabled")),
            Map.of("or", List.of(Map.of("contains", Map.of("mail", "*")), Map.of("gte", Map.of("revision", 3)))))));
        assertEquals("(&(objectClass={0})(cn={1}*)(!(loginDisabled=*))(|(mail=*{2}*)(revision>={3})))", f.filter());
        assertArrayEquals(new Object[] {"inetOrgPerson", "Smith (Admin", "*", "3"}, f.args());
        Filters.Built g = Filters.build(Map.of("eq", Map.of("GUID", "00112233445566778899aabbccddeeff")));
        assertTrue("a GUID is compared as bytes", g.args()[0] instanceof byte[]);
        assertThrows(IllegalArgumentException.class, () -> Filters.build(Map.of("eq", Map.of("cn)(x", "y"))));
        assertThrows(IllegalArgumentException.class, () -> Filters.build(Map.of("like", Map.of("cn", "y"))));
        assertThrows(IllegalArgumentException.class, () -> Filters.build(Map.of("and", List.of())));
    }

    @Test
    public void anAdvancedFilterMustBeOneExpression() {
        assertTrue(Filters.single("(&(objectClass=user)(cn=a*))"));
        assertTrue("escaped parentheses are value text", Filters.single("(cn=a\\29b)"));
        assertFalse(Filters.single("(cn=a)(cn=b)"));
        assertFalse(Filters.single("cn=a"));
        assertFalse(Filters.single("(cn=a))(|(cn=*"));
        assertFalse(Filters.single("((cn=a)"));
    }

    // ---- values ----

    @Test
    public void aclValuesRoundTrip() throws Exception {
        Map<String, Object> acl = Values.acl("2#entry#ou=a,o=system#loginScript");
        assertEquals(List.of("read"), acl.get("privileges"));
        assertEquals("entry", acl.get("scope"));
        assertEquals(Map.of("dn", "ou=a,o=system", "name", "a"), acl.get("trustee"));
        assertEquals("2#entry#ou=a,o=system#loginScript", Values.aclString(acl, g -> null));
        Map<String, Object> sup = Values.acl("16#subtree#[Creator]#[Entry Rights]");
        assertEquals(List.of("supervisor"), sup.get("privileges"));
        assertEquals(Map.of("special", "[Creator]"), sup.get("trustee"));
        assertEquals("16#subtree#[Creator]#[Entry Rights]", Values.aclString(sup, g -> null));
        assertEquals("attribute supervisor is 0x20", "35#subtree#cn=x,o=y#[All Attributes Rights]",
            Values.aclString(Map.of("privileges", List.of("compare", "read", "supervisor"), "scope", "subtree",
                "trustee", Map.of("guid", "00112233445566778899aabbccddeeff"), "attribute", "[All Attributes Rights]"), g -> "cn=x,o=y"));
        assertThrows(IllegalArgumentException.class, () -> Values.aclString(Map.of("privileges", List.of("fly")), g -> null));
        assertNull(Values.acl("not an acl"));
    }

    @Test
    public void valuesByType() throws Exception {
        Schema s = schema();
        assertEquals(Map.of("base64", "AQI="), Values.toJson(s.attribute("jpegPhoto"), new byte[] {1, 2}));
        assertEquals(Map.of("dn", "cn=Team\\, A,o=acme", "name", "Team, A"), Values.toJson(s.attribute("member"), "cn=Team\\, A,o=acme"));
        assertEquals("plain", Values.toJson(s.attribute("description"), "plain"));
        assertEquals("cn=resolved,o=acme", Values.fromJson(s.attribute("member"), Map.of("guid", "00112233445566778899aabbccddeeff"), g -> "cn=resolved,o=acme"));
        assertArrayEquals(new byte[] {1, 2}, (byte[]) Values.fromJson(s.attribute("jpegPhoto"), Map.of("base64", "AQI="), g -> null));
        assertEquals("TRUE", Values.fromJson(s.attribute("loginDisabled"), true, g -> null));
        assertThrows(IllegalArgumentException.class, () -> Values.fromJson(s.attribute("member"), "not a dn", g -> null));
        assertThrows(IllegalArgumentException.class, () -> Values.fromJson(s.attribute("member"), Map.of("guid", "00112233445566778899aabbccddeeff"), g -> null));
    }
}
