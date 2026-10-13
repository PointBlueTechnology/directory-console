package com.pointblue.console.server.http;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

/**
 * Reverse proxies the console trusts to report the client's address in {@code X-Forwarded-For}
 * (console setting {@code trustedProxies}: addresses or CIDR ranges). A request from anywhere else
 * keeps its socket address, so a client cannot choose the address that audit and sign-in throttling
 * see by sending the header itself.
 */
final class Proxies {

    private Proxies() {
    }

    /** Throws IllegalArgumentException for an entry that is neither an address nor a CIDR range. */
    static String normalize(String entry) {
        String e = entry.trim();
        int slash = e.indexOf('/');
        InetAddress a = literal(slash < 0 ? e : e.substring(0, slash));
        if (a == null) {
            throw new IllegalArgumentException("not an IP address or CIDR range: " + entry);
        }
        if (slash < 0) {
            return a.getHostAddress();
        }
        int bits;
        try {
            bits = Integer.parseInt(e.substring(slash + 1));
        } catch (NumberFormatException x) {
            throw new IllegalArgumentException("not a CIDR range: " + entry);
        }
        if (bits < 0 || bits > a.getAddress().length * 8) {
            throw new IllegalArgumentException("not a CIDR range: " + entry);
        }
        return a.getHostAddress() + "/" + bits;
    }

    static boolean trusted(List<String> proxies, String address) {
        InetAddress a = literal(address);
        if (a == null) {
            return false;
        }
        for (String p : proxies) {
            int slash = p.indexOf('/');
            InetAddress net = literal(slash < 0 ? p : p.substring(0, slash));
            if (net == null || net.getAddress().length != a.getAddress().length) {
                continue;
            }
            int bits = slash < 0 ? a.getAddress().length * 8 : Integer.parseInt(p.substring(slash + 1));
            if (matches(net.getAddress(), a.getAddress(), bits)) {
                return true;
            }
        }
        return false;
    }

    /**
     * The client: the socket's address, or, when that is a trusted proxy, the right-most address in
     * {@code X-Forwarded-For} that is not itself a trusted proxy.
     */
    static String client(List<String> proxies, String socket, List<String> forwardedFor) {
        if (proxies.isEmpty() || forwardedFor == null || !trusted(proxies, socket)) {
            return socket;
        }
        List<String> hops = new ArrayList<>();
        for (String h : forwardedFor) {
            for (String part : h.split(",")) {
                if (!part.isBlank()) {
                    hops.add(part.trim());
                }
            }
        }
        String client = socket;
        for (int i = hops.size() - 1; i >= 0; i--) {
            InetAddress a = literal(hops.get(i));
            if (a == null) {
                break;
            }
            client = a.getHostAddress();
            if (!trusted(proxies, client)) {
                break;
            }
        }
        return client;
    }

    private static boolean matches(byte[] net, byte[] a, int bits) {
        for (int i = 0; i < bits / 8; i++) {
            if (net[i] != a[i]) {
                return false;
            }
        }
        int rest = bits % 8;
        if (rest == 0) {
            return true;
        }
        int mask = (0xff << (8 - rest)) & 0xff;
        return (net[bits / 8] & mask) == (a[bits / 8] & mask);
    }

    /** An IP literal only; never a name lookup. */
    private static InetAddress literal(String s) {
        String v = s.trim();
        if (v.startsWith("[") && v.endsWith("]")) {
            v = v.substring(1, v.length() - 1);
        }
        boolean ipv4 = v.matches("\\d{1,3}(\\.\\d{1,3}){3}");
        boolean ipv6 = v.contains(":") && v.matches("[0-9A-Fa-f:.]+");
        if (!ipv4 && !ipv6) {
            return null;
        }
        try {
            return InetAddress.getByName(v);
        } catch (UnknownHostException e) {
            return null;
        }
    }
}
