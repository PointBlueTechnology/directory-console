package com.pointblue.console.server.http;

import com.sun.net.httpserver.HttpExchange;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.GZIPOutputStream;

/**
 * The web UI, built into the jar under {@code web/} (console-web's {@code dist}). Hashed files under
 * {@code /assets/} are cached for a year; everything else, {@code index.html} included, is not cached.
 * A path without a file extension is a page of the single-page app and gets {@code index.html}. Text
 * is gzipped once and kept. Only fixed files from the class path are ever served: no file system path
 * is built from the request.
 */
final class StaticFiles {

    private static final Map<String, String> TYPES = Map.ofEntries(
        Map.entry("html", "text/html; charset=utf-8"),
        Map.entry("js", "text/javascript; charset=utf-8"),
        Map.entry("css", "text/css; charset=utf-8"),
        Map.entry("json", "application/json; charset=utf-8"),
        Map.entry("svg", "image/svg+xml"),
        Map.entry("png", "image/png"),
        Map.entry("ico", "image/x-icon"),
        Map.entry("woff2", "font/woff2"),
        Map.entry("woff", "font/woff"),
        Map.entry("txt", "text/plain; charset=utf-8"));

    private record File(byte[] bytes, byte[] gzipped, String type) {
    }

    private final String root;
    private final Map<String, File> cache = new ConcurrentHashMap<>();

    StaticFiles(String root) {
        this.root = root;
    }

    /** Whether a UI is built into this server. */
    boolean present() {
        return load("/index.html") != null;
    }

    void serve(HttpExchange ex, String path, String method) throws IOException {
        if (!method.equals("GET") && !method.equals("HEAD")) {
            throw new Http.Problem(405, "method-not-allowed", method + " " + path);
        }
        if (path.contains("..") || path.contains("\\") || path.contains("//") || path.indexOf('\0') >= 0) {
            throw new Http.Problem(400, "bad-path", "that path is not allowed");
        }
        String last = path.substring(path.lastIndexOf('/') + 1);
        int dot = last.lastIndexOf('.');
        File f = dot > 0 ? load(path) : load("/index.html");
        if (f == null) {
            if (dot <= 0 && !present()) {
                throw new Http.Problem(404, "no-ui", "the web UI is not built into this server; the API is at /api/v2");
            }
            throw new Http.Problem(404, "not-found", path);
        }
        var h = ex.getResponseHeaders();
        h.set("Content-Type", f.type);
        if (dot > 0 && path.startsWith("/assets/")) {
            h.set("Cache-Control", "public, max-age=31536000, immutable");
        }
        String accept = ex.getRequestHeaders().getFirst("Accept-Encoding");
        byte[] body = f.bytes;
        if (f.gzipped != null && accept != null && accept.contains("gzip")) {
            h.set("Content-Encoding", "gzip");
            h.set("Vary", "Accept-Encoding");
            body = f.gzipped;
        }
        if (method.equals("HEAD")) {
            ex.sendResponseHeaders(200, -1);
        } else {
            ex.sendResponseHeaders(200, body.length);
            ex.getResponseBody().write(body);
        }
        ex.close();
    }

    private File load(String path) {
        File cached = cache.get(path);
        if (cached != null) {
            return cached;
        }
        String ext = path.substring(path.lastIndexOf('.') + 1).toLowerCase(java.util.Locale.ROOT);
        String type = TYPES.get(ext);
        if (type == null) {
            return null;
        }
        try (InputStream in = StaticFiles.class.getClassLoader().getResourceAsStream(root + path)) {
            if (in == null) {
                return null;
            }
            byte[] bytes = in.readAllBytes();
            byte[] gz = null;
            if (type.startsWith("text/") || type.startsWith("application/json") || type.startsWith("image/svg")) {
                ByteArrayOutputStream b = new ByteArrayOutputStream();
                try (GZIPOutputStream z = new GZIPOutputStream(b)) {
                    z.write(bytes);
                }
                gz = b.toByteArray();
            }
            File f = new File(bytes, gz, type);
            cache.put(path, f);
            return f;
        } catch (IOException e) {
            return null;
        }
    }
}
