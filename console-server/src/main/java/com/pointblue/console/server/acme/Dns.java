package com.pointblue.console.server.acme;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Just enough DNS for ACME's DNS-01 challenge: adding and deleting a TXT record with a dynamic update (RFC 2136)
 * signed with TSIG (RFC 8945, HMAC-SHA256 or HMAC-SHA512), and asking a server for a name's TXT records. Over
 * TCP, so answers are never truncated.
 */
public final class Dns {

    /** The server that takes updates for the zone, and the TSIG key it knows. */
    public record Server(String host, int port, String zone, String keyName, String algorithm, byte[] secret) {
    }

    /** The server refused or failed the request. */
    public static final class Failure extends IOException {
        public Failure(String message) {
            super(message);
        }
    }

    private static final int TYPE_SOA = 6;
    private static final int TYPE_TXT = 16;
    private static final int TYPE_TSIG = 250;
    private static final int CLASS_IN = 1;
    private static final int CLASS_NONE = 254;
    private static final int CLASS_ANY = 255;
    private static final String[] RCODES = {"no error", "format error", "server failure", "name does not exist", "not implemented", "refused",
        "name exists when it should not", "record set exists when it should not", "record set does not exist when it should",
        "not authoritative for the zone (or the key is not accepted)", "name not in the zone"};

    private Dns() {
    }

    /** Add {@code value} as a TXT record at {@code name}, with a short TTL. */
    public static void addTxt(Server s, String name, String value) throws IOException {
        update(s, name, value, true);
    }

    /** Delete the TXT record {@code name} = {@code value}. */
    public static void deleteTxt(Server s, String name, String value) throws IOException {
        update(s, name, value, false);
    }

    private static void update(Server s, String name, String value, boolean add) throws IOException {
        if (!inZone(name, s.zone())) {
            throw new Failure(name + " is not in the zone " + s.zone());
        }
        ByteArrayOutputStream m = new ByteArrayOutputStream();
        int id = new SecureRandom().nextInt(0x10000);
        writeShort(m, id);
        writeShort(m, 5 << 11); // opcode UPDATE
        writeShort(m, 1);       // zone
        writeShort(m, 0);       // prerequisites
        writeShort(m, 1);       // updates
        writeShort(m, 0);       // additional (TSIG is added when signed)
        writeName(m, s.zone());
        writeShort(m, TYPE_SOA);
        writeShort(m, CLASS_IN);
        writeName(m, name);
        writeShort(m, TYPE_TXT);
        writeShort(m, add ? CLASS_IN : CLASS_NONE);
        writeInt(m, add ? 60 : 0);
        byte[] rdata = txt(value);
        writeShort(m, rdata.length);
        m.writeBytes(rdata);
        byte[] answer = exchange(s, sign(s, m.toByteArray(), id));
        int rcode = answer.length >= 4 ? answer[3] & 0xF : 2;
        if (rcode != 0) {
            throw new Failure("the DNS server refused the update: " + (rcode < RCODES.length ? RCODES[rcode] : "error " + rcode));
        }
    }

    /** The TXT values the server {@code s} answers for {@code name} (asked directly, not through a resolver). */
    public static List<String> txt(Server s, String name) throws IOException {
        ByteArrayOutputStream m = new ByteArrayOutputStream();
        writeShort(m, new SecureRandom().nextInt(0x10000));
        writeShort(m, 0); // a query, no recursion wanted
        writeShort(m, 1);
        writeShort(m, 0);
        writeShort(m, 0);
        writeShort(m, 0);
        writeName(m, name);
        writeShort(m, TYPE_TXT);
        writeShort(m, CLASS_IN);
        byte[] a = exchange(s, m.toByteArray());
        ByteBuffer b = ByteBuffer.wrap(a);
        b.position(4);
        int qd = b.getShort() & 0xffff;
        int an = b.getShort() & 0xffff;
        b.position(12);
        for (int i = 0; i < qd; i++) {
            skipName(b);
            b.position(b.position() + 4);
        }
        List<String> out = new ArrayList<>();
        for (int i = 0; i < an; i++) {
            skipName(b);
            int type = b.getShort() & 0xffff;
            b.position(b.position() + 6);
            int len = b.getShort() & 0xffff;
            int end = b.position() + len;
            if (type == TYPE_TXT) {
                StringBuilder v = new StringBuilder();
                while (b.position() < end) {
                    int l = b.get() & 0xff;
                    byte[] part = new byte[l];
                    b.get(part);
                    v.append(new String(part, StandardCharsets.UTF_8));
                }
                out.add(v.toString());
            }
            b.position(end);
        }
        return out;
    }

    static boolean inZone(String name, String zone) {
        String n = trim(name).toLowerCase(Locale.ROOT);
        String z = trim(zone).toLowerCase(Locale.ROOT);
        return n.equals(z) || n.endsWith("." + z);
    }

    private static String trim(String n) {
        return n.endsWith(".") ? n.substring(0, n.length() - 1) : n;
    }

    /** The message with a TSIG record (RFC 8945) appended and the additional count raised. */
    static byte[] sign(Server s, byte[] message, int id) throws IOException {
        String alg = switch (s.algorithm().toLowerCase(Locale.ROOT)) {
            case "hmac-sha256" -> "HmacSHA256";
            case "hmac-sha512" -> "HmacSHA512";
            default -> throw new Failure("the TSIG algorithm is hmac-sha256 or hmac-sha512");
        };
        long now = System.currentTimeMillis() / 1000;
        // the variables the MAC covers, after the message
        ByteArrayOutputStream vars = new ByteArrayOutputStream();
        writeName(vars, s.keyName());
        writeShort(vars, CLASS_ANY);
        writeInt(vars, 0);
        writeName(vars, s.algorithm().toLowerCase(Locale.ROOT));
        writeShort(vars, (int) (now >> 32));
        writeInt(vars, (int) now);
        writeShort(vars, 300); // fudge
        writeShort(vars, 0);   // error
        writeShort(vars, 0);   // other length
        byte[] mac;
        try {
            Mac h = Mac.getInstance(alg);
            h.init(new SecretKeySpec(s.secret(), alg));
            h.update(message);
            h.update(vars.toByteArray());
            mac = h.doFinal();
        } catch (GeneralSecurityException e) {
            throw new Failure("TSIG: " + e.getMessage());
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(message);
        writeName(out, s.keyName());
        writeShort(out, TYPE_TSIG);
        writeShort(out, CLASS_ANY);
        writeInt(out, 0);
        ByteArrayOutputStream rd = new ByteArrayOutputStream();
        writeName(rd, s.algorithm().toLowerCase(Locale.ROOT));
        writeShort(rd, (int) (now >> 32));
        writeInt(rd, (int) now);
        writeShort(rd, 300);
        writeShort(rd, mac.length);
        rd.writeBytes(mac);
        writeShort(rd, id);
        writeShort(rd, 0);
        writeShort(rd, 0);
        writeShort(out, rd.size());
        out.writeBytes(rd.toByteArray());
        byte[] signed = out.toByteArray();
        signed[10] = 0;
        signed[11] = 1; // one additional record: the TSIG
        return signed;
    }

    private static byte[] exchange(Server s, byte[] message) throws IOException {
        try (Socket sock = new Socket()) {
            sock.connect(new InetSocketAddress(s.host(), s.port()), 10_000);
            sock.setSoTimeout(15_000);
            OutputStream o = sock.getOutputStream();
            o.write(new byte[] {(byte) (message.length >> 8), (byte) message.length});
            o.write(message);
            o.flush();
            InputStream in = sock.getInputStream();
            DataInputStream d = new DataInputStream(in);
            int len = d.readUnsignedShort();
            byte[] a = new byte[len];
            d.readFully(a);
            return a;
        }
    }

    private static byte[] txt(String value) {
        byte[] v = value.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (int i = 0; i < v.length; i += 255) {
            int n = Math.min(255, v.length - i);
            o.write(n);
            o.write(v, i, n);
        }
        return o.toByteArray();
    }

    private static void writeName(ByteArrayOutputStream o, String name) {
        for (String label : trim(name).split("\\.")) {
            if (label.isEmpty()) {
                continue;
            }
            byte[] b = label.getBytes(StandardCharsets.US_ASCII);
            o.write(b.length);
            o.writeBytes(b);
        }
        o.write(0);
    }

    private static void skipName(ByteBuffer b) {
        while (true) {
            int l = b.get() & 0xff;
            if (l == 0) {
                return;
            }
            if ((l & 0xC0) == 0xC0) {
                b.get();
                return;
            }
            b.position(b.position() + l);
        }
    }

    private static void writeShort(ByteArrayOutputStream o, int v) {
        o.write((v >> 8) & 0xff);
        o.write(v & 0xff);
    }

    private static void writeInt(ByteArrayOutputStream o, int v) {
        writeShort(o, (v >> 16) & 0xffff);
        writeShort(o, v & 0xffff);
    }

    /** A TSIG secret as the DNS server shows it (base64). */
    public static byte[] secret(String base64) {
        return Base64.getDecoder().decode(base64.trim());
    }
}
