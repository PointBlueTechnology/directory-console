package com.pointblue.console.server;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.pointblue.console.server.audit.AuditLog;
import com.pointblue.console.server.data.ConfigStore;
import com.pointblue.console.server.data.DataDir;
import com.pointblue.console.server.data.SecretBox;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class AdminTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    @Test
    public void resetBootstrapKeepsTheOldConfigurationAndIsAudited() throws Exception {
        Path root = tmp.newFolder().toPath();
        DataDir d = new DataDir(root);
        ConfigStore c = new ConfigStore(d, SecretBox.open(d.keys().resolve("config.key")));
        c.update(0, "admin", "bootstrap", doc -> doc.put("directories", Map.of("prod", Map.of("host", "edir1"))));
        Files.writeString(d.trust().resolve("keep.txt"), "x");

        assertEquals(0, Admin.run(new String[] {"admin", "reset-bootstrap"}, root, 8443));

        assertFalse(Files.exists(d.config().resolve("current.json")));
        assertTrue("the next start is bootstrap mode", new ConfigStore(d, SecretBox.open(d.keys().resolve("config.key"))).empty());
        try (var s = Files.list(d.history())) {
            Path kept = s.filter(p -> p.getFileName().toString().startsWith("reset-")).findFirst().orElseThrow();
            assertTrue(Files.readString(kept, StandardCharsets.UTF_8).contains("edir1"));
        }
        assertTrue("trust and keys are kept", Files.exists(d.trust().resolve("keep.txt")) && Files.exists(d.keys().resolve("config.key")));
        AuditLog.Verification v = new AuditLog(d).verify();
        assertTrue(v.intact());
        assertEquals(1, v.lines());
        assertEquals("again: already unconfigured", 0, Admin.run(new String[] {"admin", "reset-bootstrap"}, root, 8443));
        assertEquals(2, Admin.run(new String[] {"admin", "nonsense"}, root, 8443));
    }
}
