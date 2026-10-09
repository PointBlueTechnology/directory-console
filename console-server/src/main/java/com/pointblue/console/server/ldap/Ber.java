package com.pointblue.console.server.ldap;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * The little BER the console writes and reads itself: the virtual list view request and response
 * (draft-ietf-ldapext-ldapv3-vlv), which the JDK has no control classes for.
 */
final class Ber {

    private Ber() {
    }

    /** One decoded element: its tag and its contents. */
    record Element(int tag, byte[] value) {
        long integer() {
            long n = value.length > 0 && value[0] < 0 ? -1 : 0;
            for (byte b : value) {
                n = (n << 8) | (b & 0xff);
            }
            return n;
        }

        List<Element> children() {
            return Ber.read(value);
        }
    }

    static byte[] tlv(int tag, byte[] value) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(tag);
        int n = value.length;
        if (n < 128) {
            b.write(n);
        } else if (n < 256) {
            b.write(0x81);
            b.write(n);
        } else if (n < 65536) {
            b.write(0x82);
            b.write(n >> 8);
            b.write(n & 0xff);
        } else {
            b.write(0x83);
            b.write(n >> 16);
            b.write((n >> 8) & 0xff);
            b.write(n & 0xff);
        }
        b.write(value, 0, n);
        return b.toByteArray();
    }

    static byte[] integer(int tag, long v) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int bytes = 1;
        while (bytes < 8 && (v >> (bytes * 8 - 1)) != 0 && (v >> (bytes * 8 - 1)) != -1) {
            bytes++;
        }
        for (int i = bytes - 1; i >= 0; i--) {
            b.write((int) (v >> (i * 8)) & 0xff);
        }
        return tlv(tag, b.toByteArray());
    }

    static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            b.write(p, 0, p.length);
        }
        return b.toByteArray();
    }

    /** The elements in {@code data}, back to back. */
    static List<Element> read(byte[] data) {
        List<Element> out = new ArrayList<>();
        int i = 0;
        while (i < data.length) {
            int tag = data[i++] & 0xff;
            int len = data[i++] & 0xff;
            if (len > 0x80) {
                int k = len & 0x7f;
                len = 0;
                for (int j = 0; j < k; j++) {
                    len = (len << 8) | (data[i++] & 0xff);
                }
            }
            if (len < 0 || i + len > data.length) {
                throw new IllegalArgumentException("truncated BER");
            }
            byte[] v = java.util.Arrays.copyOfRange(data, i, i + len);
            i += len;
            out.add(new Element(tag, v));
        }
        return out;
    }
}
