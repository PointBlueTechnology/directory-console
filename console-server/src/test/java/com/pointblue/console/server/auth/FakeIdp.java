package com.pointblue.console.server.auth;

import com.pointblue.dirxml.dev.json.Json;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * An OpenID Connect provider on loopback for tests and the demo: discovery, JWKS, the authorization
 * endpoint and the token endpoint (PKCE checked). Each person is a set of claims. With
 * {@link #signInAs} set, the authorization endpoint redirects straight back as that person (tests);
 * without it, it shows a page listing the people to choose from (the demo).
 */
public final class FakeIdp implements AutoCloseable {

    private final HttpServer server;
    public final String issuer;
    private final KeyPair rsa;
    /** Claims per person (without iss, aud, exp, nonce). */
    public final Map<String, Map<String, Object>> people = new LinkedHashMap<>();
    /** Who the next authorization signs in as; null shows the chooser page. */
    public volatile String signInAs;
    private final Map<String, String[]> codes = new ConcurrentHashMap<>();   // code -> {challenge, nonce, person, clientId}

    public FakeIdp() throws Exception {
        this(0);
    }

    public FakeIdp(int port) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        rsa = g.generateKeyPair();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        issuer = "http://127.0.0.1:" + server.getAddress().getPort() + "/realm";
        server.createContext("/realm/.well-known/openid-configuration", ex -> respond(ex, 200, "application/json", Json.compact(Map.of(
            "issuer", issuer, "authorization_endpoint", issuer + "/auth", "token_endpoint", issuer + "/token", "jwks_uri", issuer + "/jwks"))));
        server.createContext("/realm/jwks", ex -> {
            RSAPublicKey pub = (RSAPublicKey) rsa.getPublic();
            respond(ex, 200, "application/json", Json.compact(Map.of("keys", List.of(Map.of("kty", "RSA", "kid", "k1", "alg", "RS256",
                "n", b64(pub.getModulus()), "e", b64(pub.getPublicExponent()))))));
        });
        server.createContext("/realm/auth", this::authorize);
        server.createContext("/realm/token", this::token);
        server.start();
    }

    public FakeIdp person(String id, Map<String, Object> claims) {
        Map<String, Object> c = new LinkedHashMap<>(claims);
        c.putIfAbsent("sub", id);
        people.put(id, c);
        return this;
    }

    private void authorize(HttpExchange ex) throws IOException {
        Map<String, String> q = form(ex.getRequestURI().getRawQuery());
        String who = q.containsKey("person") ? q.get("person") : signInAs;
        if (who == null) {
            StringBuilder page = new StringBuilder("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Demo identity provider</title>"
                + "<body style=\"font-family:sans-serif;max-width:32rem;margin:3rem auto\"><h1>Demo identity provider</h1><p>Sign in to Directory Console as:</p><ul>");
            for (Map.Entry<String, Map<String, Object>> p : people.entrySet()) {
                page.append("<li><a href=\"/realm/auth?").append(esc(ex.getRequestURI().getRawQuery())).append("&amp;person=")
                    .append(URLEncoder.encode(p.getKey(), StandardCharsets.UTF_8)).append("\">").append(esc(String.valueOf(p.getValue().getOrDefault("name", p.getKey()))))
                    .append("</a> <small>").append(esc(String.valueOf(p.getValue().getOrDefault("groups", "")))).append("</small></li>");
            }
            respond(ex, 200, "text/html; charset=utf-8", page.append("</ul></body></html>").toString());
            return;
        }
        String code = "c" + Long.toHexString(System.nanoTime());
        codes.put(code, new String[] {q.get("code_challenge"), q.get("nonce"), who, q.get("client_id")});
        ex.getResponseHeaders().set("Location", q.get("redirect_uri") + "?code=" + code + "&state=" + URLEncoder.encode(q.get("state"), StandardCharsets.UTF_8));
        ex.sendResponseHeaders(302, -1);
        ex.close();
    }

    private void token(HttpExchange ex) throws IOException {
        Map<String, String> f = form(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
        String[] c = codes.remove(f.get("code"));
        if (c == null || f.get("code_verifier") == null || !c[0].equals(b64(sha256(f.get("code_verifier"))))) {
            respond(ex, 400, "application/json", "{\"error\":\"invalid_grant\"}");
            return;
        }
        Map<String, Object> claims = new LinkedHashMap<>(people.getOrDefault(c[2], Map.of("sub", c[2])));
        claims.put("iss", issuer);
        claims.put("aud", c[3]);
        claims.put("exp", Instant.now().plusSeconds(300).getEpochSecond());
        claims.put("iat", Instant.now().getEpochSecond());
        claims.put("nonce", c[1]);
        respond(ex, 200, "application/json", Json.compact(Map.of("id_token", jwt(claims), "access_token", "at", "token_type", "Bearer")));
    }

    private String jwt(Map<String, Object> claims) {
        try {
            String header = b64(Json.compact(Map.of("alg", "RS256", "kid", "k1")).getBytes(StandardCharsets.UTF_8));
            String body = b64(Json.compact(claims).getBytes(StandardCharsets.UTF_8));
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initSign(rsa.getPrivate());
            s.update((header + "." + body).getBytes(StandardCharsets.US_ASCII));
            return header + "." + body + "." + b64(s.sign());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private static String esc(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private static String b64(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private static String b64(BigInteger i) {
        byte[] b = i.toByteArray();
        if (b[0] == 0) {
            b = java.util.Arrays.copyOfRange(b, 1, b.length);
        }
        return b64(b);
    }

    private static byte[] sha256(String s) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.US_ASCII));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static Map<String, String> form(String q) {
        Map<String, String> m = new LinkedHashMap<>();
        if (q == null || q.isEmpty()) {
            return m;
        }
        for (String kv : q.split("&")) {
            int i = kv.indexOf('=');
            if (i > 0) {
                m.put(URLDecoder.decode(kv.substring(0, i), StandardCharsets.UTF_8), URLDecoder.decode(kv.substring(i + 1), StandardCharsets.UTF_8));
            }
        }
        return m;
    }

    private static void respond(HttpExchange ex, int status, String type, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", type);
        ex.sendResponseHeaders(status, b.length);
        ex.getResponseBody().write(b);
        ex.close();
    }
}
