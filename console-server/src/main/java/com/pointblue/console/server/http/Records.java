package com.pointblue.console.server.http;

import com.pointblue.console.server.auth.Role;
import com.pointblue.console.server.auth.Sessions;
import com.pointblue.console.server.data.Backup;
import com.pointblue.console.server.data.ConfigStore;
import com.pointblue.dirxml.dev.json.Json;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;
import java.util.function.Predicate;

/**
 * The console's own records, for admins:
 *
 * <pre>
 * GET    /api/v2/audit                              entries, newest first: ?event= &amp;actor= &amp;outcome= &amp;text= &amp;from= &amp;to= (dates) &amp;before= (seq) &amp;limit=
 * GET    /api/v2/audit/export                       the same filters, every match, oldest first: ?format=jsonl|csv
 * GET    /api/v2/config/history                     saved versions, newest first: {version, savedAt, savedBy, reason}
 * GET    /api/v2/config/history/{v}                 one version (secrets shown only as set), and what changed from the one before
 * POST   /api/v2/config/history/{v}/restore         make that version current again (a new version); needs a recent sign-in
 * POST   /api/v2/console/backup                     {passphrase, audit?}: an encrypted backup of the data volume; needs a recent sign-in
 * POST   /api/v2/console/restore                    {backup (base64), passphrase}: checked, then staged for the next start; needs a recent sign-in
 * GET    /api/v2/console/restore                    what is staged, if anything
 * DELETE /api/v2/console/restore                    cancel it
 * </pre>
 */
final class Records {

    private static final List<String> META = List.of("version", "savedAt", "savedBy", "reason", "schemaVersion");

    private final Server server;

    Records(Server server) {
        this.server = server;
    }

    boolean handles(String path) {
        return path.equals("/api/v2/audit") || path.equals("/api/v2/audit/export") || path.startsWith("/api/v2/config/history")
            || path.equals("/api/v2/console/backup") || path.equals("/api/v2/console/restore");
    }

    void handle(HttpExchange ex, String method, String path) throws IOException {
        String route = method + " " + path.replaceAll("^/api/v2/config/history/\\d+", "/api/v2/config/history/{v}");
        Sessions.Session s = server.session(ex, Role.ADMIN);
        switch (route) {
            case "GET /api/v2/audit" -> audit(ex);
            case "GET /api/v2/audit/export" -> export(ex);
            case "GET /api/v2/config/history" -> Http.json(ex, 200, Map.of("versions", history()));
            case "GET /api/v2/config/history/{v}" -> Http.json(ex, 200, version(number(path)));
            case "POST /api/v2/config/history/{v}/restore" -> {
                server.stepUp(s);
                restoreVersion(ex, s, number(path));
            }
            case "POST /api/v2/console/backup" -> {
                server.stepUp(s);
                backup(ex, s);
            }
            case "POST /api/v2/console/restore" -> {
                server.stepUp(s);
                stage(ex, s);
            }
            case "GET /api/v2/console/restore" -> Http.json(ex, 200, Collections.singletonMap("pending", Backup.pending(server.data)));
            case "DELETE /api/v2/console/restore" -> {
                Map<String, Object> was = Backup.pending(server.data);
                Backup.cancel(server.data);
                if (was != null) {
                    server.audit.log(Server.who(s), "console.restore.cancel", "console", Map.of("backup", was), "ok");
                }
                Http.json(ex, 200, Collections.singletonMap("pending", null));
            }
            default -> throw new Http.Problem(405, "method-not-allowed", method + " " + path);
        }
    }

    private static int number(String path) {
        return Integer.parseInt(path.replaceAll("^/api/v2/config/history/(\\d+).*$", "$1"));
    }

    // ---- the audit log ----------------------------------------------------------------------------

    /** The filters in the query, as one test. */
    private static Predicate<Map<String, Object>> filter(Map<String, String> q) {
        String event = lower(q.get("event"));
        String actor = lower(q.get("actor"));
        String outcome = lower(q.get("outcome"));
        String text = lower(q.get("text"));
        Instant from = q.get("from") == null || q.get("from").isBlank() ? null : day(q.get("from"));
        Instant to = q.get("to") == null || q.get("to").isBlank() ? null : day(q.get("to")).plusSeconds(86_400);
        return e -> {
            if (event != null && !String.valueOf(e.get("event")).toLowerCase(Locale.ROOT).startsWith(event)) {
                return false;
            }
            if (actor != null && !Json.compact(e.get("actor")).toLowerCase(Locale.ROOT).contains(actor)) {
                return false;
            }
            if (outcome != null && !String.valueOf(e.get("outcome")).toLowerCase(Locale.ROOT).startsWith(outcome)) {
                return false;
            }
            if (from != null || to != null) {
                Instant t = Instant.parse(String.valueOf(e.get("time")));
                if (from != null && t.isBefore(from) || to != null && !t.isBefore(to)) {
                    return false;
                }
            }
            return text == null || Json.compact(e).toLowerCase(Locale.ROOT).contains(text);
        };
    }

    private static String lower(String v) {
        return v == null || v.isBlank() ? null : v.trim().toLowerCase(Locale.ROOT);
    }

    private static Instant day(String v) {
        try {
            return LocalDate.parse(v.trim()).atStartOfDay().toInstant(ZoneOffset.UTC);
        } catch (RuntimeException e) {
            throw new Http.Problem(400, "bad-field", "from and to are dates, such as 2026-10-18");
        }
    }

    private void audit(HttpExchange ex) throws IOException {
        Map<String, String> q = Http.query(ex);
        int limit = 100;
        Long before = null;
        try {
            if (q.get("limit") != null) {
                limit = Math.max(1, Math.min(500, Integer.parseInt(q.get("limit"))));
            }
            if (q.get("before") != null && !q.get("before").isBlank()) {
                before = Long.parseLong(q.get("before"));
            }
        } catch (NumberFormatException e) {
            throw new Http.Problem(400, "bad-field", "limit and before are numbers");
        }
        List<Map<String, Object>> entries = server.audit.entries(filter(q), before, limit + 1);
        boolean more = entries.size() > limit;
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("entries", more ? entries.subList(0, limit) : entries);
        out.put("more", more);
        Http.json(ex, 200, out);
    }

    private void export(HttpExchange ex) throws IOException {
        Map<String, String> q = Http.query(ex);
        boolean csv = "csv".equalsIgnoreCase(q.get("format"));
        StringBuilder b = new StringBuilder();
        if (csv) {
            b.append("seq,time,event,outcome,actor,via,target,details\r\n");
        }
        server.audit.each(filter(q), e -> {
            if (csv) {
                Map<String, Object> a = e.get("actor") instanceof Map<?, ?> m ? Json.asMap(m) : Map.of();
                b.append(e.get("seq")).append(',').append(csv(e.get("time"))).append(',').append(csv(e.get("event"))).append(',')
                    .append(csv(e.get("outcome"))).append(',').append(csv(a.get("dn") != null ? a.get("dn") : a.get("subject"))).append(',')
                    .append(csv(a.get("via"))).append(',').append(csv(e.get("target"))).append(',').append(csv(Json.compact(e.get("details")))).append("\r\n");
            } else {
                b.append(Json.compact(e)).append('\n');
            }
        });
        String name = "directory-console-audit-" + LocalDate.now(ZoneOffset.UTC) + (csv ? ".csv" : ".jsonl");
        Http.file(ex, b.toString().getBytes(StandardCharsets.UTF_8), csv ? "text/csv; charset=utf-8" : "application/x-ndjson", name);
    }

    private static String csv(Object v) {
        String s = v == null ? "" : String.valueOf(v);
        // a cell that a spreadsheet would run as a formula is quoted as text
        if (!s.isEmpty() && "=+-@".indexOf(s.charAt(0)) >= 0) {
            s = "'" + s;
        }
        return s.contains(",") || s.contains("\"") || s.contains("\n") || s.contains("\r") ? "\"" + s.replace("\"", "\"\"") + "\"" : s;
    }

    // ---- configuration history --------------------------------------------------------------------

    private List<Map<String, Object>> history() throws IOException {
        List<Map<String, Object>> out = new ArrayList<>();
        out.add(meta(server.config.read(), true));
        List<Integer> vs = server.config.history();
        for (int i = vs.size() - 1; i >= 0; i--) {
            out.add(meta(server.config.version(vs.get(i)), false));
        }
        return out;
    }

    private static Map<String, Object> meta(Map<String, Object> doc, boolean current) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("version", doc.get("version"));
        m.put("savedAt", doc.get("savedAt"));
        m.put("savedBy", doc.get("savedBy"));
        m.put("reason", doc.get("reason"));
        m.put("current", current);
        return m;
    }

    private Map<String, Object> doc(int v) throws IOException {
        Map<String, Object> cur = server.config.read();
        if (cur.get("version") instanceof Number n && n.intValue() == v) {
            return cur;
        }
        if (!server.config.history().contains(v)) {
            throw new Http.Problem(404, "not-found", "no configuration version " + v);
        }
        return server.config.version(v);
    }

    private Map<String, Object> version(int v) throws IOException {
        Map<String, Object> d = doc(v);
        Map<String, Object> prev = server.config.history().contains(v - 1) ? server.config.version(v - 1) : Map.of();
        Map<String, Object> out = new LinkedHashMap<>(meta(d, v == server.config.version()));
        out.put("changes", changes(ConfigStore.redacted(prev), ConfigStore.redacted(d)));
        out.put("configuration", ConfigStore.redacted(d));
        return out;
    }

    /** What differs between two versions, path by path (secrets only as set or not). */
    static List<Map<String, Object>> changes(Map<String, Object> before, Map<String, Object> after) {
        Map<String, Object> a = new LinkedHashMap<>();
        Map<String, Object> b = new LinkedHashMap<>();
        flatten("", before, a);
        flatten("", after, b);
        TreeSet<String> paths = new TreeSet<>(a.keySet());
        paths.addAll(b.keySet());
        List<Map<String, Object>> out = new ArrayList<>();
        for (String p : paths) {
            if (META.contains(p)) {
                continue;
            }
            Object x = a.get(p);
            Object y = b.get(p);
            if (!java.util.Objects.equals(x, y)) {
                Map<String, Object> c = new LinkedHashMap<>();
                c.put("path", p);
                c.put("before", x);
                c.put("after", y);
                out.add(c);
            }
        }
        return out;
    }

    private static void flatten(String prefix, Object o, Map<String, Object> out) {
        if (o instanceof Map<?, ?> m && !(m.size() == 1 && m.containsKey("set"))) {
            for (Map.Entry<?, ?> e : m.entrySet()) {
                flatten(prefix.isEmpty() ? String.valueOf(e.getKey()) : prefix + "." + e.getKey(), e.getValue(), out);
            }
        } else {
            out.put(prefix, o instanceof List<?> || o instanceof Map<?, ?> ? Json.compact(o) : o);
        }
    }

    private void restoreVersion(HttpExchange ex, Sessions.Session s, int v) throws IOException {
        Map<String, Object> old = doc(v);
        if (v == server.config.version()) {
            throw new Http.Problem(409, "current", "version " + v + " is the current configuration");
        }
        try {
            server.config.update(server.config.version(), s.principal.dn(), "restore version " + v, doc -> {
                doc.keySet().removeIf(k -> !META.contains(k));
                old.forEach((k, val) -> {
                    if (!META.contains(k)) {
                        doc.put(k, val);
                    }
                });
            });
        } catch (ConfigStore.Conflict c) {
            throw new Http.Problem(409, "conflict", "the configuration changed meanwhile; try again");
        }
        server.audit.log(Server.who(s), "config.restore", "console", Map.of("version", v, "now", server.config.version()), "ok");
        Http.json(ex, 200, Map.of("versions", history()));
    }

    // ---- backup and restore -----------------------------------------------------------------------

    private void backup(HttpExchange ex, Sessions.Session s) throws IOException {
        Map<String, Object> b = Http.body(ex);
        String passphrase = Http.string(b, "passphrase", true);
        if (passphrase.length() < 12) {
            throw new Http.Problem(400, "bad-field", "the passphrase is at least 12 characters: the backup holds the console's keys");
        }
        boolean withAudit = !Boolean.FALSE.equals(b.get("audit"));
        byte[] file = Backup.create(server.data, passphrase.toCharArray(), withAudit, server.updates.version());
        server.audit.log(Server.who(s), "console.backup", "console", Map.of("audit", withAudit, "bytes", file.length), "ok");
        Http.file(ex, file, "application/octet-stream", "directory-console-" + LocalDate.now(ZoneOffset.UTC) + ".dcbackup");
    }

    private void stage(HttpExchange ex, Sessions.Session s) throws IOException {
        Map<String, Object> b = Http.body(ex);
        byte[] file;
        try {
            file = java.util.Base64.getMimeDecoder().decode(Http.string(b, "backup", true));
        } catch (IllegalArgumentException x) {
            throw new Http.Problem(400, "bad-field", "backup is the file, base64-encoded");
        }
        Map<String, byte[]> files;
        try {
            files = Backup.open(file, Http.string(b, "passphrase", true).toCharArray());
        } catch (IllegalArgumentException x) {
            throw new Http.Problem(400, "bad-backup", x.getMessage());
        }
        Backup.stage(server.data, files);
        Map<String, Object> m = Backup.manifest(files);
        server.audit.log(Server.who(s), "console.restore.stage", "console", m, "ok");
        Http.json(ex, 200, Collections.singletonMap("pending", Backup.pending(server.data)));
    }
}
