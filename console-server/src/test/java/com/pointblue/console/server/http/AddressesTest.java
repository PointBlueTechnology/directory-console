package com.pointblue.console.server.http;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.Test;

/** Client addresses: trusted reverse proxies' X-Forwarded-For, and the intruder lockout address. */
public class AddressesTest {

    @Test
    public void entriesAreAddressesOrRangesNeverNames() {
        assertEquals("10.0.0.5", Proxies.normalize(" 10.0.0.5 "));
        assertEquals("10.20.0.0/16", Proxies.normalize("10.20.0.0/16"));
        assertEquals("0:0:0:0:0:0:0:1", Proxies.normalize("::1"));
        assertThrows(IllegalArgumentException.class, () -> Proxies.normalize("proxy.example.com"));
        assertThrows(IllegalArgumentException.class, () -> Proxies.normalize("10.0.0.0/33"));
        assertThrows(IllegalArgumentException.class, () -> Proxies.normalize("10.0.0.0/x"));
    }

    @Test
    public void rangesMatchByPrefix() {
        List<String> p = List.of("10.20.0.0/16", "192.168.1.7", "172.16.0.0/12");
        assertTrue(Proxies.trusted(p, "10.20.255.1"));
        assertFalse(Proxies.trusted(p, "10.21.0.1"));
        assertTrue(Proxies.trusted(p, "192.168.1.7"));
        assertFalse(Proxies.trusted(p, "192.168.1.8"));
        assertTrue(Proxies.trusted(p, "172.31.0.1"));
        assertFalse(Proxies.trusted(p, "172.32.0.1"));
        assertFalse("IPv6 never matches an IPv4 range", Proxies.trusted(p, "::1"));
    }

    @Test
    public void theHeaderIsBelievedOnlyFromATrustedProxy() {
        List<String> p = List.of("10.0.0.5", "10.0.1.0/24");
        assertEquals("no proxies: the socket", "203.0.113.9", Proxies.client(List.of(), "203.0.113.9", List.of("198.51.100.1")));
        assertEquals("not from a proxy: the header is ignored", "203.0.113.9", Proxies.client(p, "203.0.113.9", List.of("198.51.100.1")));
        assertEquals("through the proxy", "198.51.100.1", Proxies.client(p, "10.0.0.5", List.of("198.51.100.1")));
        assertEquals("a client's own forged entry on the left is skipped", "198.51.100.1",
            Proxies.client(p, "10.0.0.5", List.of("1.2.3.4, 198.51.100.1")));
        assertEquals("through two trusted proxies", "198.51.100.1", Proxies.client(p, "10.0.0.5", List.of("198.51.100.1, 10.0.1.9")));
        assertEquals("no header: the proxy", "10.0.0.5", Proxies.client(p, "10.0.0.5", null));
        assertEquals("garbage stops the walk", "10.0.0.5", Proxies.client(p, "10.0.0.5", List.of("unknown")));
    }

    private static byte[] net(String type, int... bytes) {
        byte[] t = (type + "#").getBytes(StandardCharsets.US_ASCII);
        byte[] out = new byte[t.length + bytes.length];
        System.arraycopy(t, 0, out, 0, t.length);
        for (int i = 0; i < bytes.length; i++) {
            out[t.length + i] = (byte) bytes[i];
        }
        return out;
    }

    @Test
    public void intruderAddressIsShownAsAnIpAddress() {
        assertEquals("192.168.1.20", NetAddress.ip(net("1", 192, 168, 1, 20)));
        assertEquals("TCP: the client's port is left out", "10.1.2.3", NetAddress.ip(net("9", 0xc3, 0x50, 10, 1, 2, 3)));
        assertNull(NetAddress.ip("x#1".getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    public void onlyIpAddressesCountForCertificates() {
        assertEquals("10.1.2.3", NetAddress.ipOnly(net("9", 0x02, 0x0c, 10, 1, 2, 3)));
        int[] v6 = {0x02, 0x0c, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x02, 0x02, 0x50, 0x56, 0xff, 0xfe, 0xb9, 0x3e, 0x74};
        assertEquals("port then IPv6, as eDirectory writes it", "2001:db8:1:2:250:56ff:feb9:3e74", NetAddress.ipOnly(net("11", v6)));
        assertNull("a URL is not an address", NetAddress.ipOnly("13#h\0t\0".getBytes(StandardCharsets.US_ASCII)));
    }
}
