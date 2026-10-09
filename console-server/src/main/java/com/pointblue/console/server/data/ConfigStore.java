package com.pointblue.console.server.data;

import com.pointblue.dirxml.dev.json.Json;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Stream;

/**
 * The console's configuration: one JSON document, changed only through {@link #update}, each change
 * a new version. The previous version is kept in {@code config/history/NNNNNN.json}, so an admin can
 * see what changed and roll back.
 *
 * <p>A secret is held as {@code {"sealed": "v1:…"}} (see {@link SecretBox}), sealed for its own path
 * in the document; {@link #redacted} replaces each with {@code {"set": true}} for anything shown.
 *
 * <p>The document carries {@code schemaVersion}. A newer image migrates an older document forward
 * (after keeping a copy in the history); an older image refuses a newer one rather than guess.
 */
public final class ConfigStore {

    /** The configuration schema this build reads and writes. */
    public static final int SCHEMA_VERSION = 1;

    /** A change that lost a race: the configuration moved since the caller read it. */
    public static final class Conflict extends Exception {
        public Conflict(String message) {
            super(message);
        }
    }

    private final DataDir dir;
    private final SecretBox box;
    private Map<String, Object> current;

    public ConfigStore(DataDir dir, SecretBox box) throws IOException {
        this.dir = dir;
        this.box = box;
        Path f = currentFile();
        if (Files.exists(f)) {
            current = Json.asMap(Json.parse(Files.readString(f, StandardCharsets.UTF_8)));
            int schema = Json.asInt(current.get("schemaVersion"), 0);
            if (schema > SCHEMA_VERSION) {
                throw new IOException("the configuration is schema version " + schema + ", newer than this build reads ("
                    + SCHEMA_VERSION + "): run a newer image, or restore a backup taken with this one");
            }
        }
    }

    private Path currentFile() {
        return dir.config().resolve("current.json");
    }

    /** True until the first configuration is written (bootstrap mode). */
    public synchronized boolean empty() {
        return current == null;
    }

    /** The version number of the current configuration; 0 when there is none. */
    public synchronized int version() {
        return current == null ? 0 : Json.asInt(current.get("version"), 0);
    }

    /** A copy of the current document (secrets still sealed). */
    public synchronized Map<String, Object> read() {
        return current == null ? new LinkedHashMap<>() : copy(current);
    }

    /**
     * Apply {@code change} to a copy of the current document and write it as the next version. Refused
     * with {@link Conflict} when {@code expectedVersion} is not the current version (another change
     * landed first). Returns the new version number.
     */
    public synchronized int update(int expectedVersion, String by, String reason, Consumer<Map<String, Object>> change) throws IOException, Conflict {
        if (expectedVersion != version()) {
            throw new Conflict("the configuration is at version " + version() + ", not " + expectedVersion + "; reload and try again");
        }
        Map<String, Object> next = read();
        change.accept(next);
        int v = version() + 1;
        next.put("schemaVersion", SCHEMA_VERSION);
        next.put("version", v);
        next.put("savedAt", Instant.now().toString());
        next.put("savedBy", by);
        next.put("reason", reason);
        if (current != null) {
            DataDir.write(dir.history().resolve(String.format("%06d.json", version())), Json.pretty(current).getBytes(StandardCharsets.UTF_8));
        }
        DataDir.write(currentFile(), Json.pretty(next).getBytes(StandardCharsets.UTF_8));
        current = next;
        return v;
    }

    /** The versions kept in the history, oldest first. */
    public List<Integer> history() throws IOException {
        List<Integer> out = new ArrayList<>();
        try (Stream<Path> s = Files.list(dir.history())) {
            s.map(p -> p.getFileName().toString()).filter(n -> n.matches("\\d{6}\\.json")).sorted()
                .forEach(n -> out.add(Integer.parseInt(n.substring(0, 6))));
        }
        return out;
    }

    /** One previous version, as written. */
    public Map<String, Object> version(int v) throws IOException {
        return Json.asMap(Json.parse(Files.readString(dir.history().resolve(String.format("%06d.json", v)), StandardCharsets.UTF_8)));
    }

    // ---- secrets --------------------------------------------------------------------------------

    /** A sealed value for the document at {@code path} (a slash path such as {@code oidc/clientSecret}). */
    public Map<String, Object> seal(String plaintext, String path) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("sealed", box.seal(plaintext, path));
        return m;
    }

    /** The plaintext of the sealed value at {@code path}, or null when none is set there. */
    public synchronized String secret(String path) {
        Object v = at(current, path);
        if (!(v instanceof Map<?, ?> m) || !(m.get("sealed") instanceof String s)) {
            return null;
        }
        return box.open(s, path);
    }

    /** A copy with every sealed value replaced by {@code {"set": true}}: safe to return or log. */
    public synchronized Map<String, Object> redacted() {
        return Json.asMap(redact(read()));
    }

    private static Object redact(Object o) {
        if (o instanceof Map<?, ?> m) {
            if (m.containsKey("sealed")) {
                return new LinkedHashMap<>(Map.of("set", true));
            }
            Map<String, Object> out = new LinkedHashMap<>();
            m.forEach((k, v) -> out.put(String.valueOf(k), redact(v)));
            return out;
        }
        if (o instanceof List<?> l) {
            List<Object> out = new ArrayList<>();
            l.forEach(v -> out.add(redact(v)));
            return out;
        }
        return o;
    }

    static Object at(Map<String, Object> doc, String path) {
        Object v = doc;
        for (String part : path.split("/")) {
            v = v instanceof Map<?, ?> m ? m.get(part) : null;
        }
        return v;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> copy(Map<String, Object> m) {
        return (Map<String, Object>) Json.parse(Json.compact(m));
    }
}
