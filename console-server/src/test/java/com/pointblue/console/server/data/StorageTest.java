package com.pointblue.console.server.data;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.pointblue.dirxml.dev.json.Json;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Map;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class StorageTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private DataDir data() throws Exception {
        return new DataDir(tmp.newFolder("data").toPath());
    }

    @Test
    public void directoriesAndFilesAreOwnerOnly() throws Exception {
        DataDir d = data();
        Path f = d.keys().resolve("x");
        DataDir.write(f, new byte[] {1});
        if (DataDir.posix()) {
            assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(d.keys())));
            assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(f)));
        }
        try (var s = Files.list(d.keys())) {
            assertEquals("no temp files left behind", List.of("x"), s.map(p -> p.getFileName().toString()).toList());
        }
    }

    // ---- SecretBox ------------------------------------------------------------------------------

    @Test
    public void aSealedSecretOpensOnlyWithItsKeyAndForItsField() throws Exception {
        DataDir d = data();
        SecretBox box = SecretBox.open(d.keys().resolve("config.key"));
        String sealed = box.seal("s3cr3t", "oidc/clientSecret");
        assertFalse(sealed.contains("s3cr3t"));
        assertNotEquals("each seal has a fresh IV", sealed, box.seal("s3cr3t", "oidc/clientSecret"));
        assertEquals("s3cr3t", box.open(sealed, "oidc/clientSecret"));
        assertEquals("the key is reused, not regenerated", "s3cr3t",
            SecretBox.open(d.keys().resolve("config.key")).open(sealed, "oidc/clientSecret"));
        assertThrows(IllegalArgumentException.class, () -> box.open(sealed, "directories/prod/serviceAccount/password"));
        SecretBox other = SecretBox.open(d.keys().resolve("other.key"));
        assertThrows(IllegalArgumentException.class, () -> other.open(sealed, "oidc/clientSecret"));
        String tampered = sealed.substring(0, sealed.length() - 4) + (sealed.endsWith("AAAA") ? "BBBB" : "AAAA");
        assertThrows(IllegalArgumentException.class, () -> box.open(tampered, "oidc/clientSecret"));
    }

    // ---- ConfigStore ----------------------------------------------------------------------------

    private ConfigStore store(DataDir d) throws Exception {
        return new ConfigStore(d, SecretBox.open(d.keys().resolve("config.key")));
    }

    @Test
    public void updatesAreVersionedAndThePreviousVersionIsKept() throws Exception {
        DataDir d = data();
        ConfigStore c = store(d);
        assertTrue(c.empty());
        assertEquals(1, c.update(0, "bootstrap", "setup", doc -> doc.put("directories", Map.of("prod", Map.of("host", "edir1:636")))));
        assertEquals(2, c.update(1, "admin", "rename", doc -> doc.put("name", "Acme console")));
        assertEquals(List.of(1), c.history());
        assertEquals(null, c.version(1).get("name"));
        assertEquals("Acme console", c.read().get("name"));
        assertEquals("admin", c.read().get("savedBy"));
        assertEquals(ConfigStore.SCHEMA_VERSION, Json.asInt(c.read().get("schemaVersion"), 0));
        ConfigStore reopened = store(d);
        assertEquals(2, reopened.version());
        assertFalse(reopened.empty());
    }

    @Test
    public void aStaleVersionIsAConflict() throws Exception {
        ConfigStore c = store(data());
        c.update(0, "a", "first", doc -> doc.put("x", 1));
        assertThrows(ConfigStore.Conflict.class, () -> c.update(0, "b", "lost the race", doc -> doc.put("x", 2)));
        assertEquals(1, Json.asInt(c.read().get("x"), 0));
    }

    @Test
    public void readReturnsACopy() throws Exception {
        ConfigStore c = store(data());
        c.update(0, "a", "r", doc -> doc.put("x", 1));
        c.read().put("x", 99);
        assertEquals(1, Json.asInt(c.read().get("x"), 0));
    }

    @Test
    public void secretsAreSealedOnDiskAndRedactedForDisplay() throws Exception {
        DataDir d = data();
        ConfigStore c = store(d);
        c.update(0, "a", "oidc", doc -> doc.put("oidc", Map.of("clientId", "console", "clientSecret", c.seal("s3cr3t", "oidc/clientSecret"))));
        assertEquals("s3cr3t", c.secret("oidc/clientSecret"));
        assertNull(c.secret("oidc/missing"));
        assertFalse(Files.readString(d.config().resolve("current.json"), StandardCharsets.UTF_8).contains("s3cr3t"));
        Map<?, ?> shown = (Map<?, ?>) c.redacted().get("oidc");
        assertEquals(Map.of("set", true), shown.get("clientSecret"));
        assertEquals("console", shown.get("clientId"));
        assertFalse(Json.compact(c.redacted()).contains("v1:"));
    }

    @Test
    public void aNewerSchemaIsRefused() throws Exception {
        DataDir d = data();
        DataDir.write(d.config().resolve("current.json"), ("{\"schemaVersion\": " + (ConfigStore.SCHEMA_VERSION + 1) + ", \"version\": 7}").getBytes(StandardCharsets.UTF_8));
        Exception e = assertThrows(java.io.IOException.class, () -> store(d));
        assertTrue(e.getMessage(), e.getMessage().contains("newer than this build"));
    }
}
