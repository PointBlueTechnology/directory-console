package com.pointblue.console.server.audit;

import com.pointblue.console.server.data.DataDir;
import com.pointblue.dirxml.dev.json.Json;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Who did what: every sign-in, directory write, IDM operation, trust decision and configuration change,
 * one JSON line each in {@code audit/audit-YYYY-MM.jsonl}. Each line carries the SHA-256 of the line
 * before it ({@code prev}), across months, so removing or editing a line breaks the chain from there on
 * and {@link #verify} names where.
 *
 * <p>Details never carry secrets: a key that looks like one ({@code password}, {@code secret},
 * {@code token}, {@code key}) is written as {@code "[redacted]"} whatever the caller passed.
 */
public final class AuditLog {

    /** The {@code prev} of the very first line. */
    public static final String GENESIS = "0".repeat(64);
    private static final DateTimeFormatter MONTH = DateTimeFormatter.ofPattern("yyyy-MM").withZone(ZoneOffset.UTC);

    private final Path dir;
    private String last;
    private long seq;

    public AuditLog(DataDir data) throws IOException {
        this.dir = data.audit();
        this.last = GENESIS;
        List<Path> files = files();
        if (!files.isEmpty()) {
            List<String> lines = Files.readAllLines(files.get(files.size() - 1), StandardCharsets.UTF_8);
            for (int i = lines.size() - 1; i >= 0; i--) {
                if (!lines.get(i).isBlank()) {
                    last = sha256(lines.get(i));
                    seq = Json.asInt(Json.asMap(Json.parse(lines.get(i))).get("seq"), 0);
                    break;
                }
            }
        }
    }

    /**
     * Who acted: the IdP subject or the eDirectory DN, whichever applies. {@code agent} names the agent key a call
     * came with (its label and id), null for a person in a browser.
     */
    public record Actor(String subject, String dn, String via, String agent) {
        public static final Actor SYSTEM = new Actor("system", null, "system");

        public Actor(String subject, String dn, String via) {
            this(subject, dn, via, null);
        }

        Map<String, Object> json() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("subject", subject);
            if (dn != null) {
                m.put("dn", dn);
            }
            m.put("via", via);
            if (agent != null) {
                m.put("agent", agent);
            }
            return m;
        }
    }

    private final java.util.List<java.util.function.Consumer<Map<String, Object>>> listeners = new java.util.concurrent.CopyOnWriteArrayList<>();

    /** Called with each entry once it is written (such as the syslog forwarder); a listener's failure never stops the write. */
    public void onEntry(java.util.function.Consumer<Map<String, Object>> listener) {
        listeners.add(listener);
    }

    /** Append one line; returns its sequence number. */
    public synchronized long log(Actor who, String event, String target, Map<String, Object> details, String outcome) throws IOException {
        Map<String, Object> line = new LinkedHashMap<>();
        line.put("seq", ++seq);
        line.put("time", Instant.now().toString());
        line.put("actor", who.json());
        line.put("event", event);
        if (target != null) {
            line.put("target", target);
        }
        line.put("details", scrub(details == null ? Map.of() : details));
        line.put("outcome", outcome);
        line.put("prev", last);
        String text = Json.compact(line);
        Path f = dir.resolve("audit-" + MONTH.format(Instant.now()) + ".jsonl");
        if (!Files.exists(f)) {
            DataDir.write(f, new byte[0]);
        }
        Files.writeString(f, text + "\n", StandardCharsets.UTF_8, StandardOpenOption.APPEND);
        last = sha256(text);
        Map<String, Object> written = java.util.Collections.unmodifiableMap(line);
        for (java.util.function.Consumer<Map<String, Object>> l : listeners) {
            try {
                l.accept(written);
            } catch (RuntimeException e) {
                // the entry is written; a listener cannot undo or block that
            }
        }
        return seq;
    }

    /** The result of checking the chain. */
    public record Verification(boolean intact, long lines, String problem) {
    }

    /** Re-read every file in order and check each line's {@code prev} against the line before it. */
    public synchronized Verification verify() throws IOException {
        String prev = GENESIS;
        long n = 0;
        for (Path f : files()) {
            int lineNo = 0;
            for (String text : Files.readAllLines(f, StandardCharsets.UTF_8)) {
                lineNo++;
                if (text.isBlank()) {
                    continue;
                }
                Map<String, Object> line;
                try {
                    line = Json.asMap(Json.parse(text));
                } catch (RuntimeException e) {
                    return new Verification(false, n, f.getFileName() + " line " + lineNo + " is not JSON");
                }
                if (!prev.equals(line.get("prev"))) {
                    return new Verification(false, n, f.getFileName() + " line " + lineNo + " (seq " + line.get("seq")
                        + ") does not follow the line before it: a line was removed, inserted or edited");
                }
                prev = sha256(text);
                n++;
            }
        }
        return new Verification(true, n, null);
    }

    /**
     * Entries, newest first: those {@code keep} accepts, with a sequence number below {@code before} (null: from the
     * newest), at most {@code limit}. The log is read month by month from the newest file, so recent pages are cheap.
     */
    public synchronized List<Map<String, Object>> entries(java.util.function.Predicate<Map<String, Object>> keep, Long before, int limit) throws IOException {
        List<Map<String, Object>> out = new ArrayList<>();
        List<Path> fs = files();
        for (int i = fs.size() - 1; i >= 0 && out.size() < limit; i--) {
            List<String> lines = Files.readAllLines(fs.get(i), StandardCharsets.UTF_8);
            for (int j = lines.size() - 1; j >= 0 && out.size() < limit; j--) {
                if (lines.get(j).isBlank()) {
                    continue;
                }
                Map<String, Object> e = Json.asMap(Json.parse(lines.get(j)));
                long seq = e.get("seq") instanceof Number n ? n.longValue() : 0;
                if (before != null && seq >= before) {
                    continue;
                }
                if (keep.test(e)) {
                    out.add(e);
                }
            }
        }
        return out;
    }

    /** Every entry {@code keep} accepts, oldest first, to {@code sink} (an export). */
    public synchronized void each(java.util.function.Predicate<Map<String, Object>> keep, java.util.function.Consumer<Map<String, Object>> sink) throws IOException {
        for (Path f : files()) {
            for (String line : Files.readAllLines(f, StandardCharsets.UTF_8)) {
                if (!line.isBlank()) {
                    Map<String, Object> e = Json.asMap(Json.parse(line));
                    if (keep.test(e)) {
                        sink.accept(e);
                    }
                }
            }
        }
    }

    private List<Path> files() throws IOException {
        List<Path> out = new ArrayList<>();
        try (Stream<Path> s = Files.list(dir)) {
            s.filter(p -> p.getFileName().toString().matches("audit-\\d{4}-\\d{2}\\.jsonl")).sorted().forEach(out::add);
        }
        return out;
    }

    static Map<String, Object> scrub(Map<String, ?> details) {
        Map<String, Object> out = new LinkedHashMap<>();
        details.forEach((k, v) -> {
            String key = k.toLowerCase(Locale.ROOT);
            boolean secret = key.contains("password") || key.contains("secret") || key.contains("token") || key.endsWith("key");
            if (secret) {
                out.put(k, "[redacted]");
            } else if (v instanceof Map<?, ?> m) {
                Map<String, Object> inner = new LinkedHashMap<>();
                m.forEach((ik, iv) -> inner.put(String.valueOf(ik), iv));
                out.put(k, scrub(inner));
            } else {
                out.put(k, v);
            }
        });
        return out;
    }

    static String sha256(String s) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
