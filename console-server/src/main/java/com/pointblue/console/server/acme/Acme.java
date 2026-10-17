package com.pointblue.console.server.acme;

import com.pointblue.dirxml.dev.json.Json;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import javax.net.ssl.SSLContext;

/**
 * A small ACME client (RFC 8555) for one account: requests are JWS signed with the account's P-256 key (ES256),
 * POST-as-GET for reads, and a fresh nonce for each (a bad nonce is retried once).
 */
public final class Acme {

    /** The ACME server's problem document, or another failure talking to it. */
    public static final class Problem extends IOException {
        public final String type;

        public Problem(String type, String detail) {
            super(detail);
            this.type = type;
        }
    }

    /** A response: its status, body (parsed when JSON), Location header and raw text. */
    public record Reply(int status, Map<String, Object> json, String location, String text) {
    }

    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

    private final URI directoryUrl;
    private final KeyPair key;
    private final HttpClient http;
    private Map<String, Object> directory;
    private String nonce;
    private String kid;

    public Acme(URI directoryUrl, KeyPair accountKey, SSLContext tls, java.net.ProxySelector proxy) {
        this.directoryUrl = directoryUrl;
        this.key = accountKey;
        HttpClient.Builder b = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).sslContext(tls);
        if (proxy != null) {
            b.proxy(proxy);
        }
        this.http = b.build();
    }

    public Map<String, Object> directory() throws IOException {
        if (directory == null) {
            Reply r = get(directoryUrl);
            if (r.status() != 200 || r.json() == null) {
                throw new Problem("directory", "the ACME directory at " + directoryUrl + " answered HTTP " + r.status());
            }
            directory = r.json();
        }
        return directory;
    }

    /** The CA's terms of service, when it has some. */
    public String termsOfService() throws IOException {
        Object meta = directory().get("meta");
        return meta instanceof Map<?, ?> m && m.get("termsOfService") != null ? String.valueOf(m.get("termsOfService")) : null;
    }

    /** Find or create the account for this key (agreeing to the terms), and use its URL from now on. */
    public String account(String email) throws IOException {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("termsOfServiceAgreed", true);
        if (email != null && !email.isBlank()) {
            p.put("contact", List.of("mailto:" + email.trim()));
        }
        Reply r = post(url("newAccount"), p, false);
        if (r.status() != 200 && r.status() != 201) {
            throw problem(r);
        }
        kid = r.location();
        return kid;
    }

    /** A new order for {@code names}: {status, authorizations, finalize, ...} and its URL under "url". */
    public Map<String, Object> order(List<String> names) throws IOException {
        List<Map<String, Object>> ids = new ArrayList<>();
        for (String n : names) {
            ids.add(Map.of("type", "dns", "value", n));
        }
        Reply r = post(url("newOrder"), Map.of("identifiers", ids), true);
        if (r.status() != 201) {
            throw problem(r);
        }
        Map<String, Object> o = new LinkedHashMap<>(r.json());
        o.put("url", r.location());
        return o;
    }

    /** POST-as-GET a resource. */
    public Map<String, Object> fetch(String url) throws IOException {
        Reply r = post(url, null, true);
        if (r.status() != 200) {
            throw problem(r);
        }
        return r.json();
    }

    /** Tell the server the challenge at {@code url} is ready. */
    public void respond(String url) throws IOException {
        Reply r = post(url, Map.of(), true);
        if (r.status() != 200) {
            throw problem(r);
        }
    }

    /** Fetch {@code url} until its status leaves pending/processing (or {@code timeout} passes). */
    public Map<String, Object> await(String url, Duration timeout) throws IOException {
        long end = System.nanoTime() + timeout.toNanos();
        while (true) {
            Map<String, Object> m = fetch(url);
            String st = String.valueOf(m.get("status"));
            if (!st.equals("pending") && !st.equals("processing") || System.nanoTime() > end) {
                return m;
            }
            try {
                Thread.sleep(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted");
            }
        }
    }

    /** Finalize the order with a CSR (DER). */
    public void finalizeOrder(String finalizeUrl, byte[] csr) throws IOException {
        Reply r = post(finalizeUrl, Map.of("csr", B64.encodeToString(csr)), true);
        if (r.status() != 200) {
            throw problem(r);
        }
    }

    /** The issued chain, leaf first. */
    public X509Certificate[] certificate(String url) throws IOException {
        Reply r = post(url, null, true);
        if (r.status() != 200) {
            throw problem(r);
        }
        try {
            List<X509Certificate> out = new ArrayList<>();
            for (java.security.cert.Certificate c : CertificateFactory.getInstance("X.509")
                    .generateCertificates(new ByteArrayInputStream(r.text().getBytes(StandardCharsets.US_ASCII)))) {
                out.add((X509Certificate) c);
            }
            if (out.isEmpty()) {
                throw new Problem("certificate", "the CA sent no certificate");
            }
            return out.toArray(X509Certificate[]::new);
        } catch (java.security.cert.CertificateException e) {
            throw new Problem("certificate", "the CA's certificate could not be read: " + e.getMessage());
        }
    }

    /** The key authorization for a challenge token: {@code token.thumbprint}. */
    public String keyAuthorization(String token) {
        return token + "." + thumbprint();
    }

    /** The TXT value DNS-01 asks for: base64url(SHA-256(key authorization)). */
    public String dnsValue(String token) {
        try {
            return B64.encodeToString(MessageDigest.getInstance("SHA-256").digest(keyAuthorization(token).getBytes(StandardCharsets.US_ASCII)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    // ---- JWS --------------------------------------------------------------------------------------

    private Map<String, Object> jwk() {
        ECPublicKey pub = (ECPublicKey) key.getPublic();
        Map<String, Object> m = new TreeMap<>();
        m.put("crv", "P-256");
        m.put("kty", "EC");
        m.put("x", B64.encodeToString(unsigned(pub.getW().getAffineX(), 32)));
        m.put("y", B64.encodeToString(unsigned(pub.getW().getAffineY(), 32)));
        return m;
    }

    private String thumbprint() {
        try {
            return B64.encodeToString(MessageDigest.getInstance("SHA-256").digest(Json.compact(jwk()).getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] unsigned(BigInteger v, int len) {
        byte[] b = v.toByteArray();
        byte[] out = new byte[len];
        int copy = Math.min(b.length, len);
        System.arraycopy(b, b.length - copy, out, len - copy, copy);
        return out;
    }

    private Reply post(String url, Map<String, Object> payload, boolean useKid) throws IOException {
        for (int attempt = 0; ; attempt++) {
            Map<String, Object> prot = new LinkedHashMap<>();
            prot.put("alg", "ES256");
            prot.put("nonce", freshNonce());
            prot.put("url", url);
            if (useKid) {
                if (kid == null) {
                    throw new Problem("account", "no ACME account yet");
                }
                prot.put("kid", kid);
            } else {
                prot.put("jwk", jwk());
            }
            String p64 = B64.encodeToString(Json.compact(prot).getBytes(StandardCharsets.UTF_8));
            String b64 = payload == null ? "" : B64.encodeToString(Json.compact(payload).getBytes(StandardCharsets.UTF_8));
            String sig = B64.encodeToString(sign((p64 + "." + b64).getBytes(StandardCharsets.US_ASCII)));
            String body = Json.compact(Map.of("protected", p64, "payload", b64, "signature", sig));
            Reply r = send(HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(30)).header("Content-Type", "application/jose+json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build());
            if (r.status() == 400 && r.json() != null && String.valueOf(r.json().get("type")).endsWith(":badNonce") && attempt == 0) {
                continue;
            }
            return r;
        }
    }

    /** ES256: a raw r || s signature, as JWS wants (Java gives DER). */
    private byte[] sign(byte[] data) throws IOException {
        try {
            Signature s = Signature.getInstance("SHA256withECDSAinP1363Format");
            s.initSign(key.getPrivate());
            s.update(data);
            return s.sign();
        } catch (GeneralSecurityException e) {
            throw new IOException(e.getMessage(), e);
        }
    }

    private String freshNonce() throws IOException {
        if (nonce != null) {
            String n = nonce;
            nonce = null;
            return n;
        }
        Reply r = send(HttpRequest.newBuilder(URI.create(url("newNonce"))).timeout(Duration.ofSeconds(15)).method("HEAD", HttpRequest.BodyPublishers.noBody()).build());
        String n = nonce;
        nonce = null;
        if (n == null) {
            throw new Problem("nonce", "the ACME server gave no nonce (HTTP " + r.status() + ")");
        }
        return n;
    }

    private String url(String name) throws IOException {
        Object u = directory().get(name);
        if (u == null) {
            throw new Problem("directory", "the ACME directory has no " + name);
        }
        return String.valueOf(u);
    }

    private Reply get(URI u) throws IOException {
        return send(HttpRequest.newBuilder(u).timeout(Duration.ofSeconds(15)).GET().build());
    }

    private Reply send(HttpRequest req) throws IOException {
        try {
            HttpResponse<String> r = http.send(req, HttpResponse.BodyHandlers.ofString());
            r.headers().firstValue("Replay-Nonce").ifPresent(n -> nonce = n);
            String type = r.headers().firstValue("Content-Type").orElse("");
            Map<String, Object> json = null;
            if (type.contains("json") && !r.body().isBlank()) {
                json = Json.asMap(Json.parse(r.body()));
            }
            return new Reply(r.statusCode(), json, r.headers().firstValue("Location").orElse(null), r.body());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted");
        }
    }

    private static Problem problem(Reply r) {
        if (r.json() != null && r.json().get("detail") != null) {
            return new Problem(String.valueOf(r.json().get("type")), String.valueOf(r.json().get("detail")));
        }
        return new Problem("http", "the ACME server answered HTTP " + r.status());
    }
}
