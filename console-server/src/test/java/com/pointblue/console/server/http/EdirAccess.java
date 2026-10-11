package com.pointblue.console.server.http;

import java.util.Map;

/** Test access to Edir's decoders. */
public final class EdirAccess {

    private EdirAccess() {
    }

    public static Map<String, Object> index(String v) {
        return Edir.index(v);
    }

    public static String networkAddress(byte[] b) {
        return Edir.networkAddress(b);
    }

    public static String newOid() {
        return Edir.newOid();
    }
}
