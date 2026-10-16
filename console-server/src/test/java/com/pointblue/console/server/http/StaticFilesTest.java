package com.pointblue.console.server.http;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.pointblue.console.server.data.DataDir;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.zip.GZIPInputStream;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/** The web UI from the class path (the test's own web/ stands in for console-web's build). */
public class StaticFilesTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private Server server;
    private HttpClient http;
    private String base;

    @Before
    public void start() throws Exception {
        server = new Server(new DataDir(tmp.newFolder("data").toPath()), ServerClient.loopback(), "https://localhost:8443", new PrintStream(new ByteArrayOutputStream()));
        server.start();
        base = "https://127.0.0.1:" + server.port();
        http = ServerClient.trusting(server);
    }

    @After
    public void stop() {
        server.stop();
    }

    private HttpResponse<byte[]> get(String path, String... headers) throws Exception {
        HttpRequest.Builder b = ServerClient.request(URI.create(base + path));
        for (int i = 0; i < headers.length; i += 2) {
            b.header(headers[i], headers[i + 1]);
        }
        return http.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    @Test
    public void pagesGetTheAppUnderTheStrictPolicy() throws Exception {
        HttpResponse<byte[]> r = get("/");
        assertEquals("served in bootstrap mode too", 200, r.statusCode());
        assertTrue(new String(r.body(), StandardCharsets.UTF_8).contains("Directory Console (test)"));
        assertEquals("text/html; charset=utf-8", r.headers().firstValue("Content-Type").orElse(""));
        assertEquals("no-store", r.headers().firstValue("Cache-Control").orElse(""));
        assertTrue(r.headers().firstValue("Content-Security-Policy").orElse("").startsWith("default-src 'self'"));
        HttpResponse<byte[]> page = get("/browse/00112233445566778899aabbccddeeff?object=x");
        assertEquals("a client-side route gets index.html", 200, page.statusCode());
        assertTrue(new String(page.body(), StandardCharsets.UTF_8).contains("Directory Console (test)"));
    }

    @Test
    public void assetsAreCachedAndCompressed() throws Exception {
        HttpResponse<byte[]> r = get("/assets/app-test.js", "Accept-Encoding", "gzip");
        assertEquals(200, r.statusCode());
        assertEquals("public, max-age=31536000, immutable", r.headers().firstValue("Cache-Control").orElse(""));
        assertEquals("gzip", r.headers().firstValue("Content-Encoding").orElse(""));
        try (InputStream in = new GZIPInputStream(new java.io.ByteArrayInputStream(r.body()))) {
            assertTrue(new String(in.readAllBytes(), StandardCharsets.UTF_8).startsWith("console.log(\"test ui\");"));
        }
        assertEquals("text/javascript; charset=utf-8", get("/assets/app-test.js").headers().firstValue("Content-Type").orElse(""));
        assertEquals(404, get("/assets/missing.js").statusCode());
        assertEquals("an unknown type is never served", 404, get("/assets/app-test.class").statusCode());
    }

    @Test
    public void onlyFilesUnderWebAreReachable() throws Exception {
        assertEquals(400, get("/assets/..%2f..%2fcom/pointblue/console/server/http/Server.class").statusCode());
        assertEquals(404, get("/com/pointblue/console/server/http/Server.class").statusCode());
        HttpResponse<String> post = http.send(ServerClient.request(URI.create(base + "/")).POST(HttpRequest.BodyPublishers.noBody()).build(),
            HttpResponse.BodyHandlers.ofString());
        assertEquals(405, post.statusCode());
        assertEquals("the API is unchanged", 503, get("/api/v2/session").statusCode());
    }
}
