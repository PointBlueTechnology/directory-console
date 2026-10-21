package com.pointblue.console.server.http;

import java.util.Map;

/** What NMAS's and eDirectory's password error codes mean, for people. Codes not listed are shown as numbers. */
final class PasswordRules {

    private PasswordRules() {
    }

    private static final Map<Integer, String> REASONS = Map.ofEntries(
        Map.entry(-215, "it was used before (the policy keeps a history)"),
        Map.entry(-216, "it is too short"));

    static String reason(int code) {
        String r = REASONS.get(code);
        return r != null ? r : "the policy refuses it (error " + code + ")";
    }
}
