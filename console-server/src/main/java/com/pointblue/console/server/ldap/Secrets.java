package com.pointblue.console.server.ldap;

import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Attributes whose values the console never returns, whoever asks and however they are read: private
 * keys, NMAS login secrets and configuration keys, password values and distribution passwords, driver
 * passwords, stored challenge responses. eDirectory returns several of them to an administrator over
 * LDAP (NICI-wrapped, but still key material): on a lab tree an admin read returned {@code nDSPKIPrivateKey}
 * on the Organizational CA and every key material object, and {@code sASLoginSecret} on users. The
 * console reports that such an attribute is set and how many values it has, and refuses to write it
 * through the generic object editor.
 */
public final class Secrets {

    /** In place of a withheld attribute's values: how many there are. */
    public record Withheld(int count) {
    }

    private static final Set<String> NAMES = Set.of(
        "userpassword", "privatekey", "ndspkiprivatekey", "ndspkiprivatekeyec", "ndspkisdkeystruct", "ndspkikeyfile",
        "sasloginsecret", "sasloginsecretkey", "sasloginconfiguration", "sasloginconfigurationkey",
        "nspmpassword", "nspmpasswordkey", "nspmdistributionpassword", "nspmpreviousdistributionpassword", "nspmpasswordhistory",
        "dirxml-shimauthpassword", "dirxml-mutualauthpassword", "dirxml-namedpasswords",
        "pwmresponseset", "oidpinstancedata", "nsimhint");

    private static final Pattern RULE = Pattern.compile(".*(privatekey|secretkey|loginsecret).*|.*(password|passwords)$");

    private static final Set<String> NOT_SECRET = Set.of("sssdisablemasterpasswords", "passwordallowchange", "passwordrequired");

    private Secrets() {
    }

    public static boolean withheld(String attribute) {
        String a = attribute.toLowerCase(Locale.ROOT);
        int semi = a.indexOf(';');
        if (semi > 0) {
            a = a.substring(0, semi);
        }
        return !NOT_SECRET.contains(a) && (NAMES.contains(a) || RULE.matcher(a).matches());
    }
}
