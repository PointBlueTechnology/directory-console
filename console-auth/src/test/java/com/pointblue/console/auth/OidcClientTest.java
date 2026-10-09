package com.pointblue.console.auth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.pointblue.dirxml.dev.json.Json;
import com.sun.net.httpserver.HttpServer;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Signatures against a JWK and the groups claim (moved from DirXMLDevWeb's OidcIdentityTest), and
 * the whole code + PKCE flow against a fake provider on loopback, including every refusal.
 */
public class OidcClientTest {

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

    // ---- signatures and groups ------------------------------------------------------------------

    @Test
    public void anRs256SignatureVerifiesAgainstTheJwkAndATamperedTokenDoesNot() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair kp = g.generateKeyPair();
        RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
        Map<String, Object> jwk = Map.of("kty", "RSA", "n", b64(pub.getModulus()), "e", b64(pub.getPublicExponent()));
        byte[] signed = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9".getBytes(StandardCharsets.US_ASCII);
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(kp.getPrivate());
        s.update(signed);
        byte[] sig = s.sign();
        assertTrue(OidcClient.signatureHolds("RS256", jwk, signed, sig));
        assertFalse(OidcClient.signatureHolds("RS256", jwk, "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJldmUifQ".getBytes(StandardCharsets.US_ASCII), sig));
    }

    @Test
    public void anEs256SignatureInJoseFormVerifies() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        KeyPair kp = g.generateKeyPair();
        ECPublicKey pub = (ECPublicKey) kp.getPublic();
        Map<String, Object> jwk = Map.of("kty", "EC", "crv", "P-256", "x", b64(pub.getW().getAffineX()), "y", b64(pub.getW().getAffineY()));
        byte[] signed = "a.b".getBytes(StandardCharsets.US_ASCII);
        Signature s = Signature.getInstance("SHA256withECDSAinP1363Format");
        s.initSign(kp.getPrivate());
        s.update(signed);
        assertTrue(OidcClient.signatureHolds("ES256", jwk, signed, s.sign()));
    }

    @Test
    public void unsupportedAlgorithmsAreRefused() {
        assertThrows(OidcException.class, () -> OidcClient.signatureHolds("none", Map.of(), new byte[0], new byte[0]));
        assertThrows(OidcException.class, () -> OidcClient.signatureHolds("HS256", Map.of(), new byte[0], new byte[0]));
    }

    @Test
    public void groupsComeFromADottedClaimPath() {
        OidcClient roles = new OidcClient(new OidcConfig("https://kc/realms/idm", "idmweb", null, null, "realm_access.roles", "https://x/auth/callback", null));
        assertEquals(List.of("idm-editors", "offline_access"), roles.groups(Map.of("realm_access", Map.of("roles", List.of("idm-editors", "offline_access")))));
        assertEquals(List.of(), roles.groups(Map.of("sub", "x")));
        OidcClient dflt = new OidcClient(new OidcConfig("https://kc/realms/idm/", "idmweb", null, null, null, "https://x/auth/callback", null));
        assertEquals(List.of("idm-editors"), dflt.groups(Map.of("groups", List.of("/idm-editors"))));
        assertEquals("https://kc/realms/idm", dflt.config().issuer());
    }

    @Test
    public void configNeverPrintsTheSecret() {
        OidcConfig c = new OidcConfig("https://kc", "id", "s3cr3t-value", null, null, "https://x/cb", null);
        assertFalse(c.toString().contains("s3cr3t-value"));
        assertThrows(IllegalArgumentException.class, () -> new OidcConfig(" ", "id", null, null, null, "https://x/cb", null));
    }

    // ---- the whole flow against a fake provider ---------------------------------------------------

    private HttpServer server;
    private String issuer;
    private KeyPair rsa;
    /** What the token endpoint puts in the next ID token; tests change it to provoke each refusal. */
    private Map<String, Object> nextClaims;
    private String nextKid = "k1";
    private boolean corruptSignature;
    private final Map<String, String> codes = new HashMap<>();   // code -> code_challenge
    private final Map<String, String> nonces = new HashMap<>();  // code -> nonce

    @Before
    public void provider() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        rsa = g.generateKeyPair();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        issuer = "http://127.0.0.1:" + server.getAddress().getPort() + "/realm";
        server.createContext("/realm/.well-known/openid-configuration", ex -> respond(ex, 200, Json.compact(Map.of(
            "issuer", issuer, "authorization_endpoint", issuer + "/auth", "token_endpoint", issuer + "/token", "jwks_uri", issuer + "/jwks"))));
        server.createContext("/realm/jwks", ex -> {
            RSAPublicKey pub = (RSAPublicKey) rsa.getPublic();
            respond(ex, 200, Json.compact(Map.of("keys", List.of(Map.of("kty", "RSA", "kid", "k1", "n", b64(pub.getModulus()), "e", b64(pub.getPublicExponent()))))));
        });
        server.createContext("/realm/token", ex -> {
            Map<String, String> form = form(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            String code = form.get("code");
            String challenge = codes.remove(code);
            String expected = challenge == null ? null : b64(sha256(form.get("code_verifier")));
            if (challenge == null || !challenge.equals(expected)) {
                respond(ex, 400, "{\"error\":\"invalid_grant\",\"error_description\":\"PKCE verifier does not match\"}");
                return;
            }
            Map<String, Object> claims = new LinkedHashMap<>(nextClaims);
            claims.putIfAbsent("nonce", nonces.remove(code));
            respond(ex, 200, Json.compact(Map.of("id_token", jwt(claims), "access_token", "at")));
        });
        server.start();
        nextClaims = new LinkedHashMap<>(Map.of("iss", issuer, "aud", "console", "sub", "u-1", "name", "Pat Smith",
            "email", "pat@example.test", "groups", List.of("/console-admins"), "exp", Instant.now().plusSeconds(300).getEpochSecond()));
    }

    @After
    public void stop() {
        server.stop(0);
    }

    private OidcClient client() {
        return new OidcClient(new OidcConfig(issuer, "console", "secret", null, null, "https://console.test/auth/callback", null));
    }

    /** What the browser and the provider do between start and finish: follow the URL, get a code back. */
    private Map<String, String> authorize(OidcClient.Start start) {
        Map<String, String> q = form(URI.create(start.url()).getRawQuery());
        assertEquals("S256", q.get("code_challenge_method"));
        assertEquals("console", q.get("client_id"));
        assertEquals("https://console.test/auth/callback", q.get("redirect_uri"));
        String code = "code-" + codes.size();
        codes.put(code, q.get("code_challenge"));
        nonces.put(code, q.get("nonce"));
        return Map.of("code", code, "state", q.get("state"));
    }

    @Test
    public void aCompleteSignInReturnsTheVerifiedPerson() throws Exception {
        OidcClient c = client();
        OidcClient.SignIn s = c.finish(authorize(c.start("/after")));
        assertEquals("u-1", s.subject());
        assertEquals("Pat Smith", s.name());
        assertEquals("pat@example.test", s.email());
        assertEquals(List.of("console-admins"), s.groups());
        assertEquals("/after", s.next());
    }

    @Test
    public void aStateCanBeUsedOnceAndAnUnknownStateIsRefused() throws Exception {
        OidcClient c = client();
        Map<String, String> cb = authorize(c.start("/"));
        c.finish(cb);
        assertThrows(OidcException.class, () -> c.finish(cb));
        assertThrows(OidcException.class, () -> c.finish(Map.of("code", "x", "state", "never-issued")));
    }

    @Test
    public void providerErrorsAreReportedToThePerson() {
        OidcException e = assertThrows(OidcException.class, () -> client().finish(Map.of("error", "access_denied", "error_description", "user cancelled")));
        assertTrue(e.getMessage(), e.getMessage().contains("access_denied") && e.getMessage().contains("user cancelled"));
    }

    @Test
    public void eachTokenCheckRefuses() throws Exception {
        String[][] cases = {
            {"iss", "https://evil.test/realm", "is from"},
            {"aud", "another-client", "another client"},
            {"exp", String.valueOf(Instant.now().minusSeconds(3600).getEpochSecond()), "expired"},
            {"nonce", "not-the-nonce", "nonce"},
        };
        stop();   // each case runs against its own provider
        for (String[] c : cases) {
            provider();
            Object v = c[0].equals("exp") ? (Object) Long.parseLong(c[1]) : c[1];
            nextClaims.put(c[0], v);
            OidcClient client = client();
            Map<String, String> cb = authorize(client.start("/"));
            OidcException e = assertThrows(c[0], OidcException.class, () -> client.finish(cb));
            assertTrue(c[0] + ": " + e.getMessage(), e.getMessage().contains(c[2]));
            stop();
        }
    }

    @Test
    public void aForgedSignatureOrAnUnpublishedKeyIsRefused() throws Exception {
        OidcClient c = client();
        corruptSignature = true;
        OidcException bad = assertThrows(OidcException.class, () -> c.finish(authorize(c.start("/"))));
        assertTrue(bad.getMessage(), bad.getMessage().contains("signature"));
        corruptSignature = false;
        nextKid = "k-unknown";
        OidcException unknown = assertThrows(OidcException.class, () -> c.finish(authorize(c.start("/"))));
        assertTrue(unknown.getMessage(), unknown.getMessage().contains("does not publish"));
    }

    @Test
    public void aMissingSecretSendsNone() {
        assertNull(new OidcConfig("https://kc", "id", "  ", null, null, "https://x/cb", null).clientSecret());
    }

    // ---- fake provider helpers ------------------------------------------------------------------

    private String jwt(Map<String, Object> claims) {
        try {
            String header = b64(Json.compact(Map.of("alg", "RS256", "kid", nextKid)).getBytes(StandardCharsets.UTF_8));
            String body = b64(Json.compact(claims).getBytes(StandardCharsets.UTF_8));
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initSign(rsa.getPrivate());
            s.update((header + "." + body).getBytes(StandardCharsets.US_ASCII));
            byte[] sig = s.sign();
            if (corruptSignature) {
                sig[0] ^= 1;
            }
            return header + "." + body + "." + b64(sig);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] sha256(String s) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.US_ASCII));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static Map<String, String> form(String q) {
        Map<String, String> m = new HashMap<>();
        for (String kv : q.split("&")) {
            int i = kv.indexOf('=');
            m.put(URLDecoder.decode(kv.substring(0, i), StandardCharsets.UTF_8), URLDecoder.decode(kv.substring(i + 1), StandardCharsets.UTF_8));
        }
        return m;
    }

    private static void respond(com.sun.net.httpserver.HttpExchange ex, int status, String body) throws java.io.IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(status, b.length);
        ex.getResponseBody().write(b);
        ex.close();
    }
}
