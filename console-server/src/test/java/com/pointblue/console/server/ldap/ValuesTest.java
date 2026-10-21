package com.pointblue.console.server.ldap;

import static org.junit.Assert.assertEquals;

import java.util.List;
import java.util.Map;
import org.junit.Test;

public class ValuesTest {

    private static final Schema.AttributeType PATH = new Schema.AttributeType("2.16.840.1.113719.1.33.4.46", List.of("nrfAssignedRoles"),
        Schema.PATH_SYNTAX, false, false, false, "nrfAssignedRoles", false, List.of());

    @Test
    @SuppressWarnings("unchecked")
    public void aPathNamesItsObjectAndKeepsItsRawFormForWriting() throws Exception {
        String raw = "cn=secAdmin,cn=System,cn=RoleDefs,o=system#0#<assignment><req>cn=admin,ou=sa,o=system</req></assignment>";
        Map<String, Object> v = (Map<String, Object>) Values.toJson(PATH, raw);
        assertEquals(raw, v.get("raw"));
        assertEquals("secAdmin", ((Map<String, Object>) v.get("path")).get("name"));
        assertEquals("cn=secAdmin,cn=System,cn=RoleDefs,o=system", ((Map<String, Object>) v.get("path")).get("dn"));
        assertEquals(0, v.get("space"));
        assertEquals("<assignment><req>cn=admin,ou=sa,o=system</req></assignment>", v.get("text"));
        assertEquals("written back as it was", raw, Values.fromJson(PATH, v, null));
        assertEquals("a value of another shape stays text", "not a path", Values.toJson(PATH, "not a path"));
    }
}
