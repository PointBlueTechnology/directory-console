package com.pointblue.console.server.http;

import com.pointblue.console.server.ldap.Partitions;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * eDirectory's Net Address syntax over LDAP (networkAddress, loginIntruderAddress): the address type
 * in ASCII digits, '#', then the address itself.
 */
final class NetAddress {

    private NetAddress() {
    }

    /**
     * The IP address: IP (1) is four bytes; TCP and UDP (9, 8) are port then IPv4, shown without the
     * port. Other types as eDirectory's tools show them; null when the value is not a Net Address.
     */
    static String ip(byte[] b) {
        int hash = -1;
        for (int i = 0; i < Math.min(b.length, 4); i++) {
            if (b[i] == '#') {
                hash = i;
                break;
            }
            if (b[i] < '0' || b[i] > '9') {
                return null;
            }
        }
        if (hash <= 0) {
            return null;
        }
        int type = Integer.parseInt(new String(b, 0, hash, StandardCharsets.US_ASCII));
        byte[] v = Arrays.copyOfRange(b, hash + 1, b.length);
        if (type == 1 && v.length == 4) {
            return (v[0] & 0xff) + "." + (v[1] & 0xff) + "." + (v[2] & 0xff) + "." + (v[3] & 0xff);
        }
        if ((type == 8 || type == 9) && v.length == 6) {
            return (v[2] & 0xff) + "." + (v[3] & 0xff) + "." + (v[4] & 0xff) + "." + (v[5] & 0xff);
        }
        return Partitions.address(type, v);
    }
}
