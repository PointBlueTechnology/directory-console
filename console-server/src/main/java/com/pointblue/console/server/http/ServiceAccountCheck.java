package com.pointblue.console.server.http;

import com.pointblue.console.server.auth.DirectoryConfig;
import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.console.server.ldap.Names;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;

/**
 * Whether the console's service account has the rights its jobs need, read as the account itself
 * (its own effective rights, which eDirectory always answers):
 *
 * <ul>
 *   <li><b>sign-in:</b> finding people by a short name: Browse under each sign-in search base, and
 *       Compare and Read on the attributes matched and read, on a few of the people it finds;</li>
 *   <li><b>single sign-on:</b> acting as people (proxied authorization, Identity Manager too):
 *       Supervisor over a few of the people under each single sign-on container, and Compare and Read on
 *       the attribute the claim matches;</li>
 *   <li><b>broader than needed:</b> Supervisor over the whole tree, or over a break-glass account.</li>
 * </ul>
 *
 * Rights are inherited and filtered differently across a tree, so a sample of people stands for each
 * container; a pass is a good sign, not a proof for every account.
 */
final class ServiceAccountCheck {

    private static final int BROWSE = 0x01;
    private static final int SUPERVISOR = 0x10;
    private static final int COMPARE = 0x01;
    private static final int READ = 0x02;
    private static final int SAMPLE = 3;

    private final Ldap svc;
    private final DirectoryConfig d;
    private final List<Map<String, Object>> checks = new ArrayList<>();

    private ServiceAccountCheck(Ldap svc, DirectoryConfig d) {
        this.svc = svc;
        this.d = d;
    }

    /** The checks for {@code d}, run on {@code svc}, a connection bound as its service account. */
    static Map<String, Object> run(Ldap svc, DirectoryConfig d) {
        ServiceAccountCheck c = new ServiceAccountCheck(svc, d);
        c.signIn();
        if (d.oidc() != null) {
            c.singleSignOn();
        }
        c.breadth();
        String overall = c.checks.stream().anyMatch(x -> "missing".equals(x.get("result")) || "unknown".equals(x.get("result"))) ? "problems"
            : c.checks.stream().anyMatch(x -> "broad".equals(x.get("result"))) ? "warnings" : "ok";
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("account", d.serviceAccountDn());
        out.put("result", overall);
        out.put("checks", c.checks);
        return out;
    }

    private void signIn() {
        List<String> attrs = new ArrayList<>(d.matchAttributes());
        if (d.excludeInactive()) {
            attrs.add("loginDisabled");
            attrs.add("loginExpirationTime");
        }
        if (d.labelAttribute() != null) {
            attrs.add(d.labelAttribute());
        }
        for (String base : bases(d.searchBases())) {
            people("sign-in", base, d.objectClasses(), attrs, false);
        }
    }

    private void singleSignOn() {
        DirectoryConfig.Oidc o = d.oidc();
        List<String> bases = o.searchBases().isEmpty() ? d.searchBases() : o.searchBases();
        for (String base : bases(bases)) {
            List<String> attrs = new ArrayList<>(List.of(o.attribute()));
            attrs.addAll(List.of(com.pointblue.console.server.auth.OidcLogin.LOCK_ATTRIBUTES));   // a locked person is refused
            people("single sign-on", base, o.objectClasses(), attrs, true);
        }
    }

    /** Browse under {@code base}, then {@code attrs} (and Supervisor, to act as them) on a few people found there. */
    private void people(String purpose, String base, List<String> classes, List<String> attrs, boolean actAs) {
        String where = base.isEmpty() ? "the whole tree" : base;
        List<Ldap.Entry> found;
        int skipped = 0;
        try {
            StringBuilder f = new StringBuilder("(|");
            Object[] args = new Object[classes.size()];
            for (int i = 0; i < classes.size(); i++) {
                f.append("(objectClass={").append(i).append("})");
                args[i] = classes.get(i);
            }
            f.append(')');
            Set<String> skip = new LinkedHashSet<>();
            skip.add(d.serviceAccountDn());
            if (actAs) {
                skip.addAll(d.breakGlass());
                skip.addAll(d.oidc().neverProxy());
            }
            found = new ArrayList<>();
            for (Ldap.Entry e : svc.search(base, f.toString(), args, SearchControls.SUBTREE_SCOPE, new String[] {"1.1"}, 50)) {
                if (skip.stream().noneMatch(s -> Names.same(s, e.dn()))) {
                    if (found.size() < SAMPLE) {
                        found.add(e);
                    }
                } else {
                    skipped++;
                }
            }
        } catch (NamingException e) {
            add(purpose, where, "find people", "unknown", "the search failed: " + Ldap.Failure.of(e).getMessage());
            return;
        }
        if (found.isEmpty() && skipped > 0) {
            add(purpose, where, "find people", "ok", "only the service account" + (actAs ? ", break-glass or never-act-as accounts" : "")
                + " here, which " + (actAs ? "single sign-on never acts as" : "are not checked"));
            return;
        }
        if (found.isEmpty()) {
            add(purpose, where, "find people", "missing", "it finds nobody of class " + String.join(", ", classes)
                + " here: it needs Browse over the people, or there are none");
            return;
        }
        add(purpose, where, "find people", "ok", "found " + (found.size() == SAMPLE ? "at least " + SAMPLE : String.valueOf(found.size())));
        for (Ldap.Entry person : found) {
            List<String> lacking = new ArrayList<>();
            try {
                if (actAs && (rights(person.dn(), "[Entry Rights]") & SUPERVISOR) == 0) {
                    add(purpose, person.dn(), "act as them", "missing", "no Supervisor right over this person: single sign-on, and Identity Manager under it, are refused for them");
                } else if (actAs) {
                    add(purpose, person.dn(), "act as them", "ok", "Supervisor");
                }
                for (String a : attrs) {
                    int r = rights(person.dn(), a);
                    if ((r & COMPARE) == 0 || (r & READ) == 0) {
                        lacking.add(a + ((r & COMPARE) == 0 ? " (compare)" : " (read)"));
                    }
                }
            } catch (NamingException e) {
                add(purpose, person.dn(), "rights", "unknown", Ldap.Failure.of(e).getMessage());
                continue;
            }
            String what = actAs ? "match the claim's attribute and read the intruder lockout" : "match and read the sign-in attributes";
            add(purpose, person.dn(), what, lacking.isEmpty() ? "ok" : "missing",
                lacking.isEmpty() ? String.join(", ", attrs) : "missing on " + String.join(", ", lacking));
        }
    }

    /** Supervisor over the whole tree, or over a break-glass account: more than it needs. */
    private void breadth() {
        List<String> ssoBases = d.oidc() == null ? null : d.oidc().searchBases().isEmpty() ? d.searchBases() : d.oidc().searchBases();
        if (ssoBases == null || !ssoBases.isEmpty()) {
            // single sign-on over the whole tree needs Supervisor everywhere; otherwise it is more than needed
            try {
                if (Setup.supervisorOfTree(svc, d.serviceAccountDn())) {
                    add("scope", "the whole tree", "no more than needed", "broad", ssoBases == null
                        ? "Supervisor over the whole tree: finding people at sign-in needs only Browse, Compare and Read"
                        : "Supervisor over the whole tree: it can act as anyone, administrators included; limit it to the single sign-on containers");
                }
            } catch (NamingException e) {
                // not answerable here: nothing to report
            }
        }
        for (String bg : d.breakGlass()) {
            if (Names.same(bg, d.serviceAccountDn())) {
                continue;   // its rights over itself say nothing
            }
            try {
                if ((rights(bg, "[Entry Rights]") & SUPERVISOR) != 0) {
                    add("scope", bg, "no more than needed", "broad", "Supervisor over a break-glass account (the console never acts as it, but the account could)");
                }
            } catch (NamingException e) {
                // a break-glass account it cannot see is fine
            }
        }
    }

    private int rights(String target, String attr) throws NamingException {
        return svc.effectivePrivileges(target, d.serviceAccountDn(), attr);
    }

    private static List<String> bases(List<String> bases) {
        return bases.isEmpty() ? List.of("") : bases;
    }

    private void add(String purpose, String where, String what, String result, String detail) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("purpose", purpose);
        m.put("where", where);
        m.put("check", what);
        m.put("result", result);
        m.put("detail", detail);
        checks.add(m);
    }
}
