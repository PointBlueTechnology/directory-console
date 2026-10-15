package com.pointblue.console.server.idm;

import com.pointblue.console.server.ldap.FakeEdir;
import com.pointblue.dirxml.dev.deploy.Vault;
import com.pointblue.dirxml.dev.operate.Operate;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A stand-in for Identity Manager's engine over the in-memory directory: driver sets and drivers are
 * ordinary entries there; states, start options, named passwords and the cache live here. Records
 * every action so tests can check what was asked.
 */
public final class FakeEngine implements Operate.Engine {

    private final FakeEdir edir;
    public final Map<String, Integer> states = new ConcurrentHashMap<>();
    public final Map<String, Integer> startOptions = new ConcurrentHashMap<>();
    public final Map<String, List<String>> named = new ConcurrentHashMap<>();
    public final Map<String, String> cache = new ConcurrentHashMap<>();
    public final List<String> actions = java.util.Collections.synchronizedList(new ArrayList<>());

    /** The engine's DiscoverJobs answer, as ig4 gave it (IDM 4.8.7, 2026-10-15), trimmed. */
    public static final String JOB_TYPES = """
        <?xml version="1.0" encoding="UTF-8"?><jobs>
        <job-aggregation>
          <job-definition auto-delete="false" disabled="false" display-name="xlfid(job-display-name)Subscriber channel trigger" schedule="0 1 * * 0" scope-required="false" type="java">
            <description>xlfid(job-description)This job submits trigger documents.</description>
            <containment>DirXML-Driver</containment>
            <java-class>com.novell.nds.dirxml.job.trigger.Trigger</java-class>
            <configuration-values><definitions>
              <definition display-name="xlfid(process-unassociated)Submit for unassociated objects?" name="process-unassociated" type="boolean"><value>false</value></definition>
              <group>
                <definition display-name="xlfid(submit-method)Method" name="submit-method" type="enum">
                  <enum-choice display-name="xlfid(submit-queue)queue (use cache)">submit-queue</enum-choice>
                  <enum-choice display-name="xlfid(submit-direct)direct (bypass cache)">submit-direct</enum-choice>
                  <value>submit-queue</value>
                </definition>
                <subordinates active-value="submit-direct">
                  <definition display-name="Start driver if not running" name="start-driver" type="boolean"><value>true</value></definition>
                </subordinates>
              </group>
              <definition display-name="Days" name="days" type="list"><value><item>7</item></value></definition>
              <definition display-name="Interval" name="interval" type="integer"><value>1</value></definition>
              <definition display-name="Password" name="pw" type="password-ref"><value>pw</value></definition>
            </definitions></configuration-values>
          </job-definition>
          <xliff version="1.0"><file original="Trigger.xml" source-language="en"><body><trans-unit id="job-display-name"><source>Subscriber channel trigger</source></trans-unit></body></file></xliff>
        </job-aggregation>
        <job-aggregation>
          <job-definition display-name="xlfid(job-display-name)Driver Health" schedule="* * * * *" scope-required="true" type="java">
            <containment>DirXML-DriverSet</containment>
            <java-class>com.novell.nds.dirxml.job.ckdrvhealth.CheckDriverHealthJob</java-class>
          </job-definition>
        </job-aggregation>
        </jobs>""".strip();

    public FakeEngine(FakeEdir edir) {
        this.edir = edir;
    }

    /** An {@link Engines} that opens this engine for anyone who signs in. */
    public Engines engines() {
        FakeEngine self = this;
        return new Engines() {
            @Override
            public String unavailable() {
                return null;
            }

            @Override
            public Opened open(com.pointblue.console.server.ldap.Ldap ldap, com.pointblue.console.server.tls.TrustStore trust,
                               com.pointblue.console.server.ldap.Ldap.Target target, String dn, char[] password) {
                return new Opened(self, () -> { });
            }

            @Override
            public byte[] discoverJobs(com.pointblue.console.server.ldap.Ldap ldap, String dn) {
                self.actions.add("discover-jobs " + dn);
                return JOB_TYPES.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            }

            @Override
            public boolean notifyJob(com.pointblue.console.server.ldap.Ldap ldap, String jobDn) {
                self.actions.add("notify-job " + jobDn);
                return true;
            }
        };
    }

    private static String key(String dn) {
        return dn.toLowerCase(java.util.Locale.ROOT).replace(" ", "");
    }

    private static Vault.Entry entry(Entry e) {
        Vault.Entry v = new Vault.Entry(e.getDN());
        for (Attribute a : e.getAttributes()) {
            List<byte[]> values = new ArrayList<>();
            for (byte[] b : a.getValueByteArrays()) {
                values.add(b);
            }
            v.attrs.put(a.getName(), values);
        }
        return v;
    }

    @Override
    public int driverState(String dn) {
        return states.getOrDefault(key(dn), Vault.STATE_STOPPED);
    }

    @Override
    public int driverStartOption(String dn) {
        return startOptions.getOrDefault(key(dn), Vault.START_MANUAL);
    }

    @Override
    public void setDriverStartOption(String dn, int option) {
        actions.add("start-option " + option + " " + dn);
        startOptions.put(key(dn), option);
    }

    @Override
    public void startDriver(String dn) {
        actions.add("start " + dn);
        states.put(key(dn), Vault.STATE_RUNNING);
    }

    @Override
    public void stopDriver(String dn) {
        actions.add("stop " + dn);
        states.put(key(dn), Vault.STATE_STOPPED);
    }

    @Override
    public void restartDriver(String dn) {
        actions.add("restart " + dn);
        states.put(key(dn), Vault.STATE_RUNNING);
    }

    @Override
    public String waitForState(String dn, int wanted, int seconds) {
        return Vault.stateName(driverState(dn));
    }

    @Override
    public Vault.Entry read(String dn) {
        try {
            Entry e = edir.server.getEntry(dn);
            return e == null ? null : entry(e);
        } catch (Exception x) {
            return null;
        }
    }

    @Override
    public Vault.Entry read(String dn, String... attrs) {
        return read(dn);
    }

    @Override
    public List<Vault.Entry> children(String base) {
        return search(base, "(objectClass=*)", 1);
    }

    @Override
    public List<Vault.Entry> search(String base, String filter, int scope) {
        List<Vault.Entry> out = new ArrayList<>();
        try {
            for (SearchResultEntry e : edir.server.search(base, scope == 0 ? SearchScope.BASE : scope == 1 ? SearchScope.ONE : SearchScope.SUB, filter).getSearchEntries()) {
                out.add(entry(e));
            }
        } catch (Exception x) {
            // none
        }
        return out;
    }

    @Override
    public void replace(String dn, String attr, List<byte[]> values) {
        actions.add("replace " + attr + " " + dn);
    }

    @Override
    public Operate.CachePage viewCache(String dn, int position, int count) {
        return new Operate.CachePage(cache.getOrDefault(key(dn), ""), 0);
    }

    @Override
    public void deleteCacheEntries(String dn, int p2, int p3, String p4, int priority) {
        actions.add("cache-clear " + dn);
        cache.remove(key(dn));
    }

    @Override
    public void migrateApp(String dn, byte[] xds) {
        actions.add("migrate " + dn);
    }

    @Override
    public void resync(String dn, long sinceMillis) {
        actions.add("resync " + dn);
    }

    @Override
    public int engineVersion() {
        return 0x48070003; // 4.8.7.0 build 3, as ig4 reports
    }

    @Override
    public String driverStats(String dn, int arg) {
        return "<driver-stats/>";
    }

    @Override
    public String jvmStats(int a, int b) {
        return "<jvm-stats/>";
    }

    @Override
    public List<String> namedPasswords(String dn) {
        return new ArrayList<>(named.getOrDefault(key(dn), List.of()));
    }

    @Override
    public void setNamedPassword(String dn, String name, String displayName, char[] value) {
        actions.add("named-set " + name + " " + dn);
        named.computeIfAbsent(key(dn), k -> new ArrayList<>()).add(name);
    }

    @Override
    public void removeNamedPassword(String dn, String name) {
        actions.add("named-remove " + name + " " + dn);
        named.getOrDefault(key(dn), new ArrayList<>()).remove(name);
    }

    @Override
    public void setRemoteLoaderPassword(String dn, char[] value) {
        actions.add("remote-loader-set " + dn);
    }

    @Override
    public void clearRemoteLoaderPassword(String dn) {
        actions.add("remote-loader-clear " + dn);
    }

    @Override
    public void startJob(String jobDn) {
        actions.add("job-start " + jobDn);
    }

    @Override
    public void abortJob(String jobDn) {
        actions.add("job-abort " + jobDn);
    }

    @Override
    public Vault.JobState jobState(String jobDn) {
        return null;
    }
}
