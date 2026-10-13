package com.pointblue.console.server.http;

import com.pointblue.dirxml.dev.json.Json;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/** Request and response helpers: JSON bodies with a size limit, RFC 9457 problems, cookies, headers. */
public final class Http {

    /** Largest JSON body accepted. */
    static final int MAX_BODY = 256 * 1024;

    private Http() {
    }

    /** A refusal that becomes a problem document. */
    public static final class Problem extends RuntimeException {
        public final int status;
        public final String type;
        public final Map<String, Object> extra;

        public Problem(int status, String type, String detail) {
            this(status, type, detail, Map.of());
        }

        public Problem(int status, String type, String detail, Map<String, Object> extra) {
            super(detail);
            this.status = status;
            this.type = type;
            this.extra = extra;
        }
    }

    public static Map<String, Object> body(HttpExchange ex) throws IOException {
        String ct = ex.getRequestHeaders().getFirst("Content-Type");
        if (ct == null || !ct.toLowerCase(java.util.Locale.ROOT).startsWith("application/json")) {
            throw new Problem(415, "unsupported-media-type", "send application/json");
        }
        try (InputStream in = ex.getRequestBody()) {
            byte[] b = in.readNBytes(MAX_BODY + 1);
            if (b.length > MAX_BODY) {
                throw new Problem(413, "too-large", "the request body is larger than " + MAX_BODY + " bytes");
            }
            Object o;
            try {
                o = Json.parse(new String(b, StandardCharsets.UTF_8));
            } catch (RuntimeException e) {
                throw new Problem(400, "bad-json", "the body is not JSON: " + e.getMessage());
            }
            if (!(o instanceof Map)) {
                throw new Problem(400, "bad-json", "the body must be a JSON object");
            }
            return Json.asMap(o);
        }
    }

    public static String string(Map<String, Object> body, String key, boolean required) {
        Object v = body.get(key);
        if (v == null || (v instanceof String s && s.isBlank())) {
            if (required) {
                throw new Problem(400, "missing-field", key + " is required");
            }
            return null;
        }
        if (!(v instanceof String s)) {
            throw new Problem(400, "bad-field", key + " must be a string");
        }
        return s;
    }

    public static int integer(Map<String, Object> body, String key, int dflt) {
        Object v = body.get(key);
        if (v == null) {
            return dflt;
        }
        if (!(v instanceof Number n)) {
            throw new Problem(400, "bad-field", key + " must be a number");
        }
        return n.intValue();
    }

    public static void json(HttpExchange ex, int status, Object body) throws IOException {
        byte[] b = Json.compact(body).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(status, status == 204 ? -1 : b.length);
        if (status != 204) {
            ex.getResponseBody().write(b);
        }
        ex.close();
    }

    public static void problem(HttpExchange ex, Problem p) throws IOException {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("type", "urn:directory-console:problem:" + p.type);
        m.put("title", p.type);
        m.put("status", p.status);
        m.put("detail", p.getMessage());
        m.putAll(p.extra);
        byte[] b = Json.compact(m).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/problem+json; charset=utf-8");
        ex.sendResponseHeaders(p.status, b.length);
        ex.getResponseBody().write(b);
        ex.close();
    }

    public static String cookie(HttpExchange ex, String name) {
        for (String h : ex.getRequestHeaders().getOrDefault("Cookie", java.util.List.of())) {
            for (String part : h.split(";")) {
                int i = part.indexOf('=');
                if (i > 0 && part.substring(0, i).trim().equals(name)) {
                    return part.substring(i + 1).trim();
                }
            }
        }
        return null;
    }

    public static Map<String, String> query(HttpExchange ex) {
        Map<String, String> out = new LinkedHashMap<>();
        String q = ex.getRequestURI().getRawQuery();
        if (q != null) {
            for (String kv : q.split("&")) {
                int i = kv.indexOf('=');
                String k = URLDecoder.decode(i < 0 ? kv : kv.substring(0, i), StandardCharsets.UTF_8);
                out.put(k, i < 0 ? "" : URLDecoder.decode(kv.substring(i + 1), StandardCharsets.UTF_8));
            }
        }
        return out;
    }

    /** The socket's address; Server.client applies trusted proxies' X-Forwarded-For. */
    public static String client(HttpExchange ex) {
        return ex.getRemoteAddress().getAddress().getHostAddress();
    }
}
