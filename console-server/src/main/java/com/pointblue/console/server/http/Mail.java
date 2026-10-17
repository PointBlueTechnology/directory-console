package com.pointblue.console.server.http;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.List;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * A plain-text e-mail over SMTP: STARTTLS (port 587, the default), TLS from the start (465), or none (a relay on
 * a trusted network). The server's certificate is checked against the JDK's trusted CAs and its name, and AUTH
 * PLAIN is used when a user name is given (only over TLS).
 */
final class Mail {

    enum Security { STARTTLS, TLS, NONE }

    record Smtp(String host, int port, Security security, String user, String password, String from) {
    }

    private Mail() {
    }

    static void send(Smtp smtp, List<String> to, String subject, String body) throws IOException {
        if (to.isEmpty()) {
            throw new IOException("no recipients");
        }
        Socket raw = new Socket();
        raw.connect(new InetSocketAddress(smtp.host(), smtp.port()), 10_000);
        raw.setSoTimeout(20_000);
        Socket s = smtp.security() == Security.TLS ? tls(raw, smtp.host()) : raw;
        try {
            Conversation c = new Conversation(s);
            c.expect(220);
            c.command("EHLO directory-console", 250);
            if (smtp.security() == Security.STARTTLS) {
                c.command("STARTTLS", 220);
                s = tls(s, smtp.host());
                c = new Conversation(s);
                c.command("EHLO directory-console", 250);
            }
            if (smtp.user() != null && !smtp.user().isBlank()) {
                if (smtp.security() == Security.NONE) {
                    throw new IOException("the console sends a password only over TLS");
                }
                String token = Base64.getEncoder().encodeToString(("\0" + smtp.user() + "\0" + smtp.password()).getBytes(StandardCharsets.UTF_8));
                c.command("AUTH PLAIN " + token, 235);
            }
            c.command("MAIL FROM:<" + address(smtp.from()) + ">", 250);
            for (String r : to) {
                c.command("RCPT TO:<" + address(r) + ">", 250);
            }
            c.command("DATA", 354);
            StringBuilder m = new StringBuilder();
            m.append("From: ").append(address(smtp.from())).append("\r\n");
            m.append("To: ").append(String.join(", ", to.stream().map(Mail::address).toList())).append("\r\n");
            m.append("Subject: ").append(subject.replaceAll("[\r\n]", " ")).append("\r\n");
            m.append("Date: ").append(DateTimeFormatter.RFC_1123_DATE_TIME.format(ZonedDateTime.now())).append("\r\n");
            m.append("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n");
            for (String line : body.split("\r?\n", -1)) {
                m.append(line.startsWith(".") ? "." : "").append(line).append("\r\n");
            }
            m.append(".");
            c.command(m.toString(), 250);
            c.command("QUIT", 221);
        } finally {
            s.close();
        }
    }

    /** An address with nothing that could start another SMTP command or header. */
    static String address(String a) {
        String t = a == null ? "" : a.trim();
        if (!t.matches("[^\\s<>@,;]+@[^\\s<>@,;]+")) {
            throw new IllegalArgumentException(t + " is not an e-mail address");
        }
        return t;
    }

    private static Socket tls(Socket under, String host) throws IOException {
        SSLSocket t = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(under, host, under.getPort(), true);
        SSLParameters p = t.getSSLParameters();
        p.setEndpointIdentificationAlgorithm("HTTPS");
        p.setServerNames(List.of(new SNIHostName(host)));
        t.setSSLParameters(p);
        t.startHandshake();
        return t;
    }

    /** One SMTP exchange: a command, and the (possibly multi-line) reply, which must have the code expected. */
    private static final class Conversation {
        private final BufferedReader in;
        private final OutputStream out;

        Conversation(Socket s) throws IOException {
            in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
            out = s.getOutputStream();
        }

        void command(String line, int code) throws IOException {
            out.write((line + "\r\n").getBytes(StandardCharsets.UTF_8));
            out.flush();
            expect(code);
        }

        void expect(int code) throws IOException {
            String line;
            StringBuilder said = new StringBuilder();
            do {
                line = in.readLine();
                if (line == null) {
                    throw new IOException("the mail server closed the connection");
                }
                said.append(line).append(' ');
            } while (line.length() > 3 && line.charAt(3) == '-');
            if (!line.startsWith(String.valueOf(code))) {
                throw new IOException("the mail server answered " + said.toString().trim());
            }
        }
    }
}
