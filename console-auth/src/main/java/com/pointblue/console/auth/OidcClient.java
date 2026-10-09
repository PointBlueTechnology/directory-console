package com.pointblue.console.auth;

import com.pointblue.dirxml.dev.json.Json;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * OpenID Connect sign-in with discovery: the authorization-code flow with PKCE against any provider
 * (Keycloak, Entra ID, Okta, OSP). The ID token is verified here — signature against the provider's
 * JWKS (RS256/384/512, ES256), issuer, audience, expiry, nonce — and its claims are returned; groups
 * come from a configurable claim path, with the userinfo endpoint consulted when the token lacks it.
 *
 * <p>No HTTP server is assumed: {@link #start} returns the URL to redirect the browser to, and
 * {@link #finish} takes the callback's query parameters.
 */
public final class OidcClient {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final OidcConfig config;
    private final HttpClient http;
    private volatile Map<String, Object> discovery;
    private volatile Map<String, Map<String, Object>> keys = Map.of();   // kid -> JWK
    private final Map<String, Pending> pending = new ConcurrentHashMap<>();

    private record Pending(String next, String nonce, String verifier, Instant created) {
    }

    /** Where to send the browser, and the state that will come back with it. */
    public record Start(String url, String state) {
    }

    /** A verified sign-in. {@code claims} are the ID token's, topped up from userinfo. */
    public record SignIn(String subject, String name, String email, List<String> groups, Map<String, Object> claims, String next) {
    }

    public OidcClient(OidcConfig config) {
        this.config = config;
        HttpClient.Builder b = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).followRedirects(HttpClient.Redirect.NEVER);
        if (config.tls() != null) {
            b.sslContext(config.tls());
        }
        this.http = b.build();
    }

    public OidcConfig config() {
        return config;
    }

    /** Begin a sign-in. {@code next} is handed back by {@link #finish} (where to go afterwards). */
    public Start start(String next) throws IOException {
        Map<String, Object> d = discovery();
        String state = random();
        String nonce = random();
        String verifier = random() + random();
        pending.entrySet().removeIf(e -> e.getValue().created.plusSeconds(600).isBefore(Instant.now()));
        pending.put(state, new Pending(next, nonce, verifier, Instant.now()));
        String challenge;
        try {
            challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        } catch (NoSuchAlgorithmException e) {
            throw new IOException(e);
        }
        String url = d.get("authorization_endpoint") + "?response_type=code&client_id=" + enc(config.clientId()) + "&redirect_uri=" + enc(config.redirectUri())
            + "&scope=" + enc(config.scopes()) + "&state=" + enc(state) + "&nonce=" + enc(nonce) + "&code_challenge=" + challenge + "&code_challenge_method=S256";
        return new Start(url, state);
    }

    /** Finish a sign-in from the callback's query parameters ({@code code}, {@code state}, or {@code error}). */
    public SignIn finish(Map<String, String> query) throws IOException {
        if (query.get("error") != null) {
            throw new OidcException("the identity provider refused: " + query.get("error")
                + (query.get("error_description") == null ? "" : " — " + query.get("error_description")));
        }
        Pending p = query.get("state") == null ? null : pending.remove(query.get("state"));
        if (p == null || query.get("code") == null) {
            throw new OidcException("this sign-in was not started here, or it expired; start again");
        }
        Map<String, Object> d = discovery();
        String form = "grant_type=authorization_code&code=" + enc(query.get("code")) + "&redirect_uri=" + enc(config.redirectUri()) + "&client_id=" + enc(config.clientId())
            + "&code_verifier=" + enc(p.verifier) + (config.clientSecret() == null ? "" : "&client_secret=" + enc(config.clientSecret()));
        Map<String, Object> tokens;
        try {
            HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create((String) d.get("token_endpoint"))).timeout(Duration.ofSeconds(15))
                .header("Content-Type", "application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(form)).build(), HttpResponse.BodyHandlers.ofString());
            tokens = Json.asMap(Json.parse(r.body()));
            if (r.statusCode() != 200) {
                throw new OidcException("the token exchange failed: " + tokens.getOrDefault("error", "HTTP " + r.statusCode()) + " " + tokens.getOrDefault("error_description", ""));
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted");
        }
        String idToken = Json.asString(tokens.get("id_token"));
        if (idToken == null) {
            throw new OidcException("the provider returned no ID token");
        }
        Map<String, Object> claims = verify(idToken, p.nonce);
        List<String> groups = groups(claims);
        if (groups.isEmpty() && d.get("userinfo_endpoint") instanceof String && tokens.get("access_token") != null) {
            try {
                HttpResponse<String> u = http.send(HttpRequest.newBuilder(URI.create((String) d.get("userinfo_endpoint"))).timeout(Duration.ofSeconds(10))
                    .header("Authorization", "Bearer " + tokens.get("access_token")).GET().build(), HttpResponse.BodyHandlers.ofString());
                if (u.statusCode() == 200) {
                    Map<String, Object> info = Json.asMap(Json.parse(u.body()));
                    groups = groups(info);
                    for (String k : new String[] {"name", "preferred_username", "email"}) {
                        if (claims.get(k) == null && info.get(k) != null) {
                            claims.put(k, info.get(k));
                        }
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted");
            }
        }
        String subject = Json.asString(claims.get("sub"));
        String name = Json.asString(claims.get("name"));
        if (name == null) {
            name = Json.asString(claims.get("preferred_username"));
        }
        if (name == null) {
            name = subject;
        }
        return new SignIn(subject, name, Json.asString(claims.get("email")), groups, claims, p.next);
    }

    /** The groups claim at the configured dotted path; names are taken as given, a leading '/' (Keycloak group paths) dropped. */
    public List<String> groups(Map<String, Object> claims) {
        Object v = claims;
        for (String part : config.groupsClaim().split("\\.")) {
            v = v instanceof Map ? ((Map<?, ?>) v).get(part) : null;
        }
        List<String> out = new ArrayList<>();
        if (v instanceof List) {
            for (Object o : (List<?>) v) {
                String s = String.valueOf(o);
                out.add(s.startsWith("/") ? s.substring(1) : s);
            }
        } else if (v instanceof String) {
            out.add((String) v);
        }
        return out;
    }

    /** The ID token's claims once its signature, issuer, audience, expiry and nonce hold. */
    Map<String, Object> verify(String jwt, String nonce) throws IOException {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new OidcException("the ID token is not a JWS");
        }
        Base64.Decoder b64 = Base64.getUrlDecoder();
        Map<String, Object> header = Json.asMap(Json.parse(new String(b64.decode(parts[0]), StandardCharsets.UTF_8)));
        Map<String, Object> claims = Json.asMap(Json.parse(new String(b64.decode(parts[1]), StandardCharsets.UTF_8)));
        String alg = Json.asString(header.get("alg"));
        String kid = Json.asString(header.get("kid"));
        Map<String, Object> jwk = key(kid);
        if (!signatureHolds(alg, jwk, (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII), b64.decode(parts[2]))) {
            throw new OidcException("the ID token's signature does not verify");
        }
        if (!config.issuer().equals(Json.asString(claims.get("iss")))) {
            throw new OidcException("the ID token is from " + claims.get("iss") + ", not " + config.issuer());
        }
        Object aud = claims.get("aud");
        boolean audOk = config.clientId().equals(aud) || (aud instanceof List && ((List<?>) aud).contains(config.clientId()));
        if (!audOk) {
            throw new OidcException("the ID token is for another client");
        }
        Object exp = claims.get("exp");
        if (!(exp instanceof Number) || Instant.ofEpochSecond(((Number) exp).longValue()).plusSeconds(60).isBefore(Instant.now())) {
            throw new OidcException("the ID token has expired");
        }
        if (nonce != null && !nonce.equals(Json.asString(claims.get("nonce")))) {
            throw new OidcException("the ID token's nonce does not match this sign-in");
        }
        return claims;
    }

    private Map<String, Object> key(String kid) throws IOException {
        Map<String, Object> k = kid == null ? null : keys.get(kid);
        if (k == null) {
            // a key we have not seen: read the JWKS again (rotation), once
            Map<String, Map<String, Object>> fresh = new ConcurrentHashMap<>();
            Object list = Json.asMap(Json.parse(get((String) discovery().get("jwks_uri")))).get("keys");
            if (list instanceof List) {
                for (Object o : (List<?>) list) {
                    Map<String, Object> jwk = Json.asMap(o);
                    String id = Json.asString(jwk.get("kid"));
                    fresh.put(id == null ? "" : id, jwk);
                }
            }
            keys = fresh;
            k = kid == null ? (fresh.size() == 1 ? fresh.values().iterator().next() : null) : fresh.get(kid);
        }
        if (k == null) {
            throw new OidcException("the ID token is signed with a key (" + kid + ") the provider does not publish");
        }
        return k;
    }

    private Map<String, Object> discovery() throws IOException {
        Map<String, Object> d = discovery;
        if (d == null) {
            d = Json.asMap(Json.parse(get(config.issuer() + "/.well-known/openid-configuration")));
            for (String k : new String[] {"authorization_endpoint", "token_endpoint", "jwks_uri"}) {
                if (!(d.get(k) instanceof String)) {
                    throw new IOException("the provider's discovery document lacks " + k);
                }
            }
            discovery = d;
        }
        return d;
    }

    private String get(String url) throws IOException {
        try {
            HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10)).GET().build(), HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() != 200) {
                throw new IOException("GET " + url + ": HTTP " + r.statusCode());
            }
            return r.body();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted");
        }
    }

    static String random() {
        byte[] b = new byte[32];
        RANDOM.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    /** Whether {@code signature} over {@code signed} verifies with the JWK, for RS256/384/512 and ES256. */
    public static boolean signatureHolds(String alg, Map<String, Object> jwk, byte[] signed, byte[] signature) throws IOException {
        try {
            Base64.Decoder b64 = Base64.getUrlDecoder();
            PublicKey key;
            Signature sig;
            byte[] sigBytes = signature;
            switch (alg == null ? "" : alg) {
                case "RS256", "RS384", "RS512" -> {
                    BigInteger n = new BigInteger(1, b64.decode(Json.asString(jwk.get("n"))));
                    BigInteger e = new BigInteger(1, b64.decode(Json.asString(jwk.get("e"))));
                    key = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
                    sig = Signature.getInstance("SHA" + alg.substring(2) + "withRSA");
                }
                case "ES256" -> {
                    BigInteger x = new BigInteger(1, b64.decode(Json.asString(jwk.get("x"))));
                    BigInteger y = new BigInteger(1, b64.decode(Json.asString(jwk.get("y"))));
                    AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
                    params.init(new ECGenParameterSpec("secp256r1"));
                    key = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), params.getParameterSpec(ECParameterSpec.class)));
                    sig = Signature.getInstance("SHA256withECDSA");
                    sigBytes = derFromJose(signature);
                }
                default -> throw new OidcException("the ID token's algorithm " + alg + " is not supported (RS256/384/512, ES256 are)");
            }
            sig.initVerify(key);
            sig.update(signed);
            return sig.verify(sigBytes);
        } catch (GeneralSecurityException e) {
            throw new IOException("verifying the ID token: " + e.getMessage(), e);
        }
    }

    /** A JOSE ECDSA signature is r||s; the JDK verifies DER. */
    static byte[] derFromJose(byte[] rs) {
        int half = rs.length / 2;
        byte[] r = unsigned(Arrays.copyOfRange(rs, 0, half));
        byte[] s = unsigned(Arrays.copyOfRange(rs, half, rs.length));
        byte[] out = new byte[6 + r.length + s.length];
        int i = 0;
        out[i++] = 0x30;
        out[i++] = (byte) (4 + r.length + s.length);
        out[i++] = 0x02;
        out[i++] = (byte) r.length;
        System.arraycopy(r, 0, out, i, r.length);
        i += r.length;
        out[i++] = 0x02;
        out[i++] = (byte) s.length;
        System.arraycopy(s, 0, out, i, s.length);
        return out;
    }

    private static byte[] unsigned(byte[] v) {
        int start = 0;
        while (start < v.length - 1 && v[start] == 0) {
            start++;
        }
        byte[] t = Arrays.copyOfRange(v, start, v.length);
        if ((t[0] & 0x80) != 0) {
            byte[] p = new byte[t.length + 1];
            System.arraycopy(t, 0, p, 1, t.length);
            return p;
        }
        return t;
    }
}
