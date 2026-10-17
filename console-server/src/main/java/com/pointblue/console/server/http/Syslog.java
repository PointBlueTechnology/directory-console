package com.pointblue.console.server.http;

import com.pointblue.console.server.auth.Role;
import com.pointblue.console.server.auth.Sessions;
import com.pointblue.console.server.data.ConfigStore;
import com.pointblue.console.server.tls.TrustStore;
import com.pointblue.dirxml.dev.json.Json;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Every audit-log entry, sent on to a syslog server as it is written: RFC 5424 messages whose text is CEF
 * (ArcSight Common Event Format, as eDirectory's own audit events), over TLS (RFC 5425, the default), TCP
 * (octet counting, RFC 6587) or UDP. Delivery is best effort: entries wait in a bounded queue and are dropped,
 * and counted, when the server stays unreachable; the console's own audit log keeps them all. A TLS server's
 * certificate must chain to a public CA or to a CA in the console's trust store, and name the host.
 *
 * <p>Configuration ({@code syslog}): {enabled, host, port, transport: tls | tcp | udp, facility}.
 */
final class Syslog {

    static final List<String> FACILITIES = List.of("kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv",
        "ftp", "ntp", "audit", "alert", "clock", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7");

    private final Server server;
    private final BlockingQueue<Map<String, Object>> queue = new ArrayBlockingQueue<>(2000);
    private final AtomicLong sent = new AtomicLong();
    private final AtomicLong dropped = new AtomicLong();
    private volatile String lastError;
    private volatile Instant lastSent;
    private volatile Thread worker;
    private Socket socket;
    private String connectedTo;

    Syslog(Server server) {
        this.server = server;
    }

    boolean handles(String path) {
        return path.startsWith("/api/v2/console/syslog");
    }

    void start() {
        server.audit.onEntry(e -> {
            if (enabled() && !queue.offer(e)) {
                dropped.incrementAndGet();
            }
        });
        Thread t = new Thread(this::run, "syslog");
        t.setDaemon(true);
        t.start();
        worker = t;
    }

    void stop() {
        Thread t = worker;
        if (t != null) {
            t.interrupt();
        }
        close();
    }

    void handle(HttpExchange ex, String method, String path) throws IOException {
        switch (method + " " + path) {
            case "GET /api/v2/console/syslog" -> {
                server.session(ex, Role.ADMIN);
                Http.json(ex, 200, state());
            }
            case "PUT /api/v2/console/syslog" -> {
                Sessions.Session s = server.session(ex, Role.ADMIN);
                server.stepUp(s);
                save(s, Http.body(ex));
                Http.json(ex, 200, state());
            }
            case "POST /api/v2/console/syslog/test" -> {
                Sessions.Session s = server.session(ex, Role.ADMIN);
                Map<String, Object> c = config();
                if (c.get("host") == null) {
                    throw new Http.Problem(409, "not-configured", "no syslog server is set");
                }
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("seq", 0);
                entry.put("time", Instant.now().toString());
                entry.put("actor", Map.of("subject", s.principal.subject(), "dn", String.valueOf(s.principal.dn()), "via", s.principal.via()));
                entry.put("event", "syslog.test");
                entry.put("target", "console");
                entry.put("details", Map.of("text", "a test message from Directory Console"));
                entry.put("outcome", "ok");
                Map<String, Object> r = new LinkedHashMap<>();
                try {
                    synchronized (this) {
                        deliver(c, message(entry, c));
                    }
                    r.put("ok", true);
                } catch (IOException | RuntimeException x) {
                    r.put("ok", false);
                    r.put("error", x.getMessage() == null ? x.getClass().getSimpleName() : x.getMessage());
                }
                Http.json(ex, 200, r);
            }
            default -> throw new Http.Problem(405, "method-not-allowed", method + " " + path);
        }
    }

    // ---- settings ---------------------------------------------------------------------------------

    Map<String, Object> config() {
        return server.config.read().get("syslog") instanceof Map<?, ?> m ? Json.asMap(m) : Map.of();
    }

    boolean enabled() {
        Map<String, Object> c = config();
        return Boolean.TRUE.equals(c.get("enabled")) && c.get("host") != null;
    }

    Map<String, Object> state() {
        Map<String, Object> c = config();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("enabled", Boolean.TRUE.equals(c.get("enabled")));
        m.put("host", c.get("host"));
        m.put("transport", c.getOrDefault("transport", "tls"));
        m.put("port", c.getOrDefault("port", defaultPort(String.valueOf(c.getOrDefault("transport", "tls")))));
        m.put("facility", c.getOrDefault("facility", "authpriv"));
        m.put("sent", sent.get());
        m.put("dropped", dropped.get());
        m.put("waiting", queue.size());
        m.put("lastSent", lastSent == null ? null : lastSent.toString());
        m.put("lastError", lastError);
        return m;
    }

    static int defaultPort(String transport) {
        return transport.equals("tls") ? 6514 : 514;
    }

    private void save(Sessions.Session s, Map<String, Object> b) throws IOException {
        Map<String, Object> next = new LinkedHashMap<>();
        next.put("enabled", Boolean.TRUE.equals(b.get("enabled")));
        String host = b.get("host") == null ? "" : String.valueOf(b.get("host")).trim();
        if (!host.isEmpty()) {
            if (!host.matches("[A-Za-z0-9.:\\[\\]-]{1,253}")) {
                throw new Http.Problem(400, "bad-field", "host is a host name or address");
            }
            next.put("host", host);
        } else if (Boolean.TRUE.equals(b.get("enabled"))) {
            throw new Http.Problem(400, "bad-field", "a syslog server's host is needed to turn it on");
        }
        String transport = b.get("transport") == null ? "tls" : String.valueOf(b.get("transport"));
        if (!List.of("tls", "tcp", "udp").contains(transport)) {
            throw new Http.Problem(400, "bad-field", "transport is tls, tcp or udp");
        }
        next.put("transport", transport);
        int port = b.get("port") instanceof Number n ? n.intValue() : defaultPort(transport);
        if (port < 1 || port > 65535) {
            throw new Http.Problem(400, "bad-field", "port is 1 to 65535");
        }
        next.put("port", port);
        String facility = b.get("facility") == null ? "authpriv" : String.valueOf(b.get("facility"));
        if (!FACILITIES.contains(facility)) {
            throw new Http.Problem(400, "bad-field", "facility is one of " + String.join(", ", FACILITIES));
        }
        next.put("facility", facility);
        try {
            server.config.update(server.config.version(), s.principal.dn(), "syslog forwarding", doc -> doc.put("syslog", next));
        } catch (ConfigStore.Conflict c) {
            throw new Http.Problem(409, "conflict", "the configuration changed meanwhile; try again");
        }
        synchronized (this) {
            close();
            lastError = null;
        }
        server.audit.log(Server.who(s), "settings.syslog", "console", next, "ok");
    }

    // ---- delivery ---------------------------------------------------------------------------------

    private void run() {
        while (!Thread.currentThread().isInterrupted()) {
            Map<String, Object> e;
            try {
                e = queue.poll(30, TimeUnit.SECONDS);
            } catch (InterruptedException x) {
                return;
            }
            if (e == null) {
                continue;
            }
            Map<String, Object> c = config();
            if (!enabled()) {
                continue;
            }
            byte[] msg = message(e, c);
            for (int attempt = 0; ; attempt++) {
                try {
                    synchronized (this) {
                        deliver(c, msg);
                    }
                    break;
                } catch (IOException | RuntimeException x) {
                    lastError = x.getMessage() == null ? x.getClass().getSimpleName() : x.getMessage();
                    synchronized (this) {
                        close();
                    }
                    if (attempt >= 2) {
                        dropped.incrementAndGet();
                        break;
                    }
                    try {
                        Thread.sleep(2000L * (attempt + 1));
                    } catch (InterruptedException ie) {
                        return;
                    }
                }
            }
        }
    }

    /** Send one message, connecting first when needed. */
    private void deliver(Map<String, Object> c, byte[] msg) throws IOException {
        String host = String.valueOf(c.get("host"));
        String transport = String.valueOf(c.getOrDefault("transport", "tls"));
        int port = c.get("port") instanceof Number n ? n.intValue() : defaultPort(transport);
        if (transport.equals("udp")) {
            try (DatagramSocket d = new DatagramSocket()) {
                byte[] b = msg.length > 8192 ? java.util.Arrays.copyOf(msg, 8192) : msg;
                d.send(new DatagramPacket(b, b.length, InetAddress.getByName(host), port));
            }
        } else {
            String to = transport + "://" + host + ":" + port;
            if (socket == null || socket.isClosed() || !to.equals(connectedTo)) {
                close();
                Socket raw = new Socket();
                raw.connect(new InetSocketAddress(host, port), 10_000);
                raw.setSoTimeout(15_000);
                socket = transport.equals("tls") ? tls(raw, host) : raw;
                connectedTo = to;
            }
            OutputStream out = socket.getOutputStream();
            out.write((msg.length + " ").getBytes(StandardCharsets.US_ASCII));
            out.write(msg);
            out.flush();
        }
        sent.incrementAndGet();
        lastSent = Instant.now();
        lastError = null;
    }

    private void close() {
        if (socket != null) {
            try {
                socket.close();
            } catch (IOException e) {
                // gone already
            }
        }
        socket = null;
        connectedTo = null;
    }

    private Socket tls(Socket raw, String host) throws IOException {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[] {trustManager()}, null);
            SSLSocket t = (SSLSocket) ctx.getSocketFactory().createSocket(raw, host, raw.getPort(), true);
            SSLParameters p = t.getSSLParameters();
            p.setEndpointIdentificationAlgorithm("HTTPS");
            if (!host.matches("[0-9.]+|\\[.*\\]")) {
                p.setServerNames(List.of(new SNIHostName(host)));
            }
            t.setSSLParameters(p);
            t.startHandshake();
            return t;
        } catch (java.security.GeneralSecurityException e) {
            throw new IOException(e.getMessage(), e);
        }
    }

    /** The JDK's public CAs, and the CAs the console trusts for every directory. */
    private X509TrustManager trustManager() throws java.security.GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        TrustManagerFactory jdk = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        jdk.init((KeyStore) null);
        int i = 0;
        for (TrustManager tm : jdk.getTrustManagers()) {
            if (tm instanceof X509TrustManager x) {
                for (X509Certificate c : x.getAcceptedIssuers()) {
                    ks.setCertificateEntry("jdk" + i++, c);
                }
            }
        }
        for (TrustStore.Entry e : server.trust.entries()) {
            if (e.kind() == TrustStore.Kind.CA && "global".equals(e.scope())) {
                ks.setCertificateEntry("console" + i++, e.cert());
            }
        }
        TrustManagerFactory f = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        f.init(ks);
        for (TrustManager tm : f.getTrustManagers()) {
            if (tm instanceof X509TrustManager x) {
                return x;
            }
        }
        throw new java.security.GeneralSecurityException("no trust manager");
    }

    // ---- the message ------------------------------------------------------------------------------

    /** One audit entry as an RFC 5424 message carrying CEF. */
    byte[] message(Map<String, Object> e, Map<String, Object> c) {
        String outcome = String.valueOf(e.getOrDefault("outcome", ""));
        int severity = severity(outcome);
        int facility = FACILITIES.indexOf(String.valueOf(c.getOrDefault("facility", "authpriv")));
        int pri = Math.max(facility, 0) * 8 + (severity >= 7 ? 3 : severity >= 5 ? 4 : 5);
        String host = hostname();
        String event = String.valueOf(e.get("event"));
        StringBuilder m = new StringBuilder();
        m.append('<').append(pri).append(">1 ").append(e.get("time")).append(' ').append(host).append(" directory-console ")
            .append(ProcessHandle.current().pid()).append(' ').append(msgId(event)).append(" - ");
        m.append(cef(e, severity));
        return m.toString().getBytes(StandardCharsets.UTF_8);
    }

    /** CEF:0|Point Blue|Directory Console|version|event|name|severity|extensions. */
    String cef(Map<String, Object> e, int severity) {
        Map<String, Object> actor = e.get("actor") instanceof Map<?, ?> a ? Json.asMap(a) : Map.of();
        String event = String.valueOf(e.get("event"));
        StringBuilder s = new StringBuilder("CEF:0|Point Blue|Directory Console|");
        s.append(header(server.updates.version())).append('|').append(header(event)).append('|').append(header(name(event))).append('|')
            .append(severity).append('|');
        List<String> ext = new ArrayList<>();
        ext.add("rt=" + Instant.parse(String.valueOf(e.get("time"))).toEpochMilli());
        ext.add("act=" + value(event));
        ext.add("outcome=" + value(String.valueOf(e.getOrDefault("outcome", ""))));
        if (actor.get("dn") != null && !"null".equals(String.valueOf(actor.get("dn")))) {
            ext.add("suser=" + value(String.valueOf(actor.get("dn"))));
        } else if (actor.get("subject") != null) {
            ext.add("suser=" + value(String.valueOf(actor.get("subject"))));
        }
        if (actor.get("via") != null) {
            ext.add("cs1Label=via cs1=" + value(String.valueOf(actor.get("via"))));
        }
        if (e.get("target") != null) {
            ext.add("cs2Label=target cs2=" + value(String.valueOf(e.get("target"))));
        }
        Map<String, Object> details = e.get("details") instanceof Map<?, ?> d ? Json.asMap(d) : Map.of();
        if (details.get("client") != null) {
            ext.add("src=" + value(String.valueOf(details.get("client"))));
        }
        if (!details.isEmpty()) {
            String json = Json.compact(details);
            ext.add("cs3Label=details cs3=" + value(json.length() > 3000 ? json.substring(0, 3000) + "…" : json));
        }
        ext.add("cn1Label=sequence cn1=" + e.getOrDefault("seq", 0));
        s.append(String.join(" ", ext));
        return s.toString();
    }

    /** 3 for what went through, 5 for a refusal, 7 for a failure; a few events matter more. */
    static int severity(String outcome) {
        String o = outcome.toLowerCase(Locale.ROOT);
        return o.startsWith("ok") ? 3 : o.contains("refused") || o.contains("denied") ? 5 : 7;
    }

    private static String name(String event) {
        return event.replace('.', ' ').replace('-', ' ');
    }

    private static String msgId(String event) {
        String id = event.replaceAll("[^!-~]", "_");
        return id.length() > 32 ? id.substring(0, 32) : id;
    }

    private String hostname() {
        try {
            String h = server.publicUrl == null ? null : java.net.URI.create(server.publicUrl).getHost();
            return h != null && !h.isBlank() ? h : InetAddress.getLocalHost().getHostName();
        } catch (IOException | RuntimeException e) {
            return "-";
        }
    }

    /** A CEF header field: | and \ escaped, no line breaks. */
    static String header(String v) {
        return v.replace("\\", "\\\\").replace("|", "\\|").replaceAll("[\r\n]", " ");
    }

    /** A CEF extension value: \ and = escaped, line breaks as \n. */
    static String value(String v) {
        return v.replace("\\", "\\\\").replace("=", "\\=").replace("\r", "\\r").replace("\n", "\\n");
    }
}
