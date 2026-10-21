package com.pointblue.console.server.http;

import java.util.Map;

/**
 * What NMAS's and eDirectory's password policy codes mean, for people: each found by breaking one rule at a time on a
 * lab tree (eDirectory 9.2.8, 2026-10-21). Codes not listed are shown as numbers.
 */
final class PasswordRules {

    private PasswordRules() {
    }

    private static final Map<Integer, String> REASONS = Map.ofEntries(
        Map.entry(-215, "it was used before (the policy keeps a history)"),
        Map.entry(-216, "it is too short"),
        Map.entry(-16000, "it is too long"),
        Map.entry(-16001, "it has too few capital letters"),
        Map.entry(-16002, "it has too many capital letters"),
        Map.entry(-16006, "it starts with a digit"),
        Map.entry(-16008, "it has too few digits"),
        Map.entry(-16012, "it ends with a special character"),
        Map.entry(-16013, "it has too few special characters"),
        Map.entry(-16015, "it has too few different characters"),
        Map.entry(-16016, "it has the same character too many times in a row"),
        Map.entry(-16019, "it contains a word the policy excludes"),
        Map.entry(-16057, "it has digits or special characters the policy does not allow"));

    static String reason(int code) {
        String r = REASONS.get(code);
        return r != null ? r : "the policy refuses it (error " + code + ")";
    }
}
