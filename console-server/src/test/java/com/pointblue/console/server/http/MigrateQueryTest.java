package com.pointblue.console.server.http;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import com.pointblue.console.server.ldap.FakeEdir;
import com.pointblue.console.server.ldap.Schema;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.Test;

/** The query a migration from the application sends: eDirectory's own class and attribute names, escaped. */
public class MigrateQueryTest {

    private static Schema schema() {
        return new Schema(Arrays.stream(FakeEdir.SCHEMA).filter(l -> l.startsWith("objectClasses: ")).map(l -> l.substring(15)).toList(),
            Arrays.stream(FakeEdir.SCHEMA).filter(l -> l.startsWith("attributeTypes: ")).map(l -> l.substring(16)).toList());
    }

    @Test
    public void usesEdirectoryNames() {
        byte[] q = Idm.migrateQuery(schema(), Map.of("class", "inetOrgPerson", "search", List.of(Map.of("attribute", "sn", "value", "O'Brien & <Co>"))));
        assertEquals("<nds dtdversion=\"4.0\"><input><query class-name=\"User\" scope=\"subtree\"><search-class class-name=\"User\"/>"
            + "<search-attr attr-name=\"Surname\"><value>O'Brien &amp; &lt;Co&gt;</value></search-attr><read-attr/></query></input></nds>",
            new String(q, StandardCharsets.UTF_8));
    }

    @Test
    public void refusesUnknownNames() {
        assertThrows(Http.Problem.class, () -> Idm.migrateQuery(schema(), Map.of("class", "nosuchClass")));
        assertThrows(Http.Problem.class, () -> Idm.migrateQuery(schema(), Map.of("class", "inetOrgPerson", "search", List.of(Map.of("attribute", "nope", "value", "x")))));
    }
}
