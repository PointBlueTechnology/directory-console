package com.pointblue.console.server.audit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.pointblue.console.server.data.DataDir;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class AuditLogTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private static final AuditLog.Actor ADMIN = new AuditLog.Actor("u-1", "cn=admin,o=system", "direct");

    private Path only(DataDir d) throws Exception {
        try (var s = Files.list(d.audit())) {
            return s.findFirst().orElseThrow();
        }
    }

    @Test
    public void anUntouchedLogVerifiesAndSurvivesARestart() throws Exception {
        DataDir d = new DataDir(tmp.newFolder().toPath());
        AuditLog a = new AuditLog(d);
        a.log(ADMIN, "sign-in", null, Map.of(), "ok");
        a.log(ADMIN, "config.update", "oidc", Map.of("version", 2), "ok");
        AuditLog reopened = new AuditLog(d);   // picks up the chain where it ended
        assertEquals(3, reopened.log(AuditLog.Actor.SYSTEM, "startup", null, null, "ok"));
        AuditLog.Verification v = reopened.verify();
        assertTrue(v.problem(), v.intact());
        assertEquals(3, v.lines());
    }

    @Test
    public void editingRemovingOrInsertingALineBreaksTheChain() throws Exception {
        for (String attack : List.of("edit", "remove", "insert")) {
            DataDir d = new DataDir(tmp.newFolder(attack).toPath());
            AuditLog a = new AuditLog(d);
            for (int i = 0; i < 4; i++) {
                a.log(ADMIN, "trust.add", "cert-" + i, Map.of("i", i), "ok");
            }
            Path f = only(d);
            List<String> lines = new ArrayList<>(Files.readAllLines(f, StandardCharsets.UTF_8));
            switch (attack) {
                case "edit" -> lines.set(1, lines.get(1).replace("cert-1", "cert-X"));
                case "remove" -> lines.remove(1);
                default -> lines.add(2, lines.get(1));
            }
            Files.write(f, lines, StandardCharsets.UTF_8);
            AuditLog.Verification v = a.verify();
            assertFalse(attack, v.intact());
            assertTrue(attack + ": " + v.problem(), v.problem().contains("line"));
        }
    }

    @Test
    public void secretLookingDetailsAreRedacted() throws Exception {
        DataDir d = new DataDir(tmp.newFolder().toPath());
        new AuditLog(d).log(ADMIN, "directory.add", "prod", Map.of("host", "edir1:636",
            "serviceAccount", Map.of("dn", "cn=svc,o=system", "password", "hunter2"), "clientSecret", "abc", "apiKey", "k", "tokenId", "t"), "ok");
        String text = Files.readString(only(d), StandardCharsets.UTF_8);
        for (String leaked : List.of("hunter2", "\"abc\"", "\"k\"", "\"t\"")) {
            assertFalse(leaked + " leaked: " + text, text.contains(leaked));
        }
        assertTrue(text.contains("edir1:636") && text.contains("cn=svc,o=system"));
    }
}
