package com.pointblue.console.server.http;

import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.console.server.ldap.Names;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * Version discovery for one server: the engine's version as it answers now, and what the driver set's
 * statistics job last collected on that server (the job's per-replica {@code DirXML-uiXMLBigPerReplica},
 * {@code <TelemetryResults>}: Identity Manager's version and edition, the host, and each driver's shim
 * version, driver ID and usage counts, as on a lab tree, 2026-10-14). The engine's driver statistics carry no
 * shim version (a lab tree, every flag tried). Each driver's base package, from {@code DirXML-pkgGUID}, too.
 */
final class Versions {

    private Versions() {
    }

    /** {@code l} must be the chosen server's own connection: the telemetry is per replica. */
    static Map<String, Object> read(Ldap l, String driverSetDn, Object engineVersion) throws NamingException {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("engineVersion", engineVersion);
        List<Ldap.Entry> jobs = l.search(driverSetDn, "(objectClass=DirXML-TelemetryJob)", null, SearchControls.SUBTREE_SCOPE,
            new String[] {"cn", "DirXML-uiXMLBigPerReplica"}, 5);
        Map<String, Object> collected = null;
        for (Ldap.Entry j : jobs) {
            List<Object> v = j.attributes().get("dirxml-uixmlbigperreplica");
            if (v != null && !v.isEmpty()) {
                Object o = v.get(0);
                collected = telemetry(o instanceof byte[] b ? b : String.valueOf(o).getBytes(StandardCharsets.UTF_8));
                if (collected != null) {
                    collected.put("job", Map.of("dn", j.dn(), "name", String.valueOf(Names.identity(j.dn()).get("name"))));
                    break;
                }
            }
        }
        out.put("statisticsJobFound", !jobs.isEmpty());
        out.put("collected", collected);
        List<Map<String, Object>> packages = new ArrayList<>();
        for (Ldap.Entry d : l.search(driverSetDn, "(objectClass=DirXML-Driver)", null, SearchControls.ONELEVEL_SCOPE, new String[] {"cn", "DirXML-pkgGUID"}, 500)) {
            String g = d.first("DirXML-pkgGUID");
            String[] parts = g == null ? new String[0] : g.split(";");
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("driver", String.valueOf(Names.identity(d.dn()).get("name")));
            m.put("package", parts.length >= 4 ? parts[3] : null);
            m.put("packageVersion", parts.length >= 3 ? parts[2] : null);
            packages.add(m);
        }
        packages.sort((a, b) -> String.valueOf(a.get("driver")).compareToIgnoreCase(String.valueOf(b.get("driver"))));
        out.put("packages", packages);
        return out;
    }

    /** The parts of {@code <TelemetryResults>} worth showing; null when it is not that. */
    static Map<String, Object> telemetry(byte[] xml) {
        Element root;
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            f.setExpandEntityReferences(false);
            javax.xml.parsers.DocumentBuilder b = f.newDocumentBuilder();
            b.setErrorHandler(new org.xml.sax.helpers.DefaultHandler());   // the failure is the answer; nothing on stderr
            root = b.parse(new ByteArrayInputStream(xml)).getDocumentElement();
        } catch (Exception x) {
            return null;
        }
        if (!root.getTagName().equals("TelemetryResults")) {
            return null;
        }
        Map<String, Object> m = new LinkedHashMap<>();
        String when = text(root, "TimeStamp");
        m.put("when", iso(when));
        m.put("whenText", when);
        m.put("product", text(root, "ProductName"));
        m.put("version", text(root, "VersionFull"));
        m.put("edition", text(root, "Edition"));
        m.put("patch", text(root, "PatchApplied"));
        m.put("host", text(root, "HostName"));
        m.put("hostIp", text(root, "HostIP"));
        m.put("os", join(text(root, "OSName"), text(root, "OSVersion")));
        m.put("hostType", text(root, "HostType"));
        List<Map<String, Object>> drivers = new ArrayList<>();
        NodeList ds = root.getElementsByTagName("Driver");
        for (int i = 0; i < ds.getLength(); i++) {
            Element d = (Element) ds.item(i);
            Map<String, Object> dm = new LinkedHashMap<>();
            dm.put("name", text(d, "Name"));
            dm.put("version", text(d, "Version"));
            dm.put("driverId", text(d, "DriverID"));
            NodeList u = d.getElementsByTagName("UsageCount");
            if (u.getLength() > 0) {
                Element ue = (Element) u.item(0);
                Map<String, Object> usage = new LinkedHashMap<>();
                for (String a : new String[] {"active", "inactive", "system", "total"}) {
                    usage.put(a, ue.hasAttribute(a) ? Integer.valueOf(parse(ue.getAttribute(a))) : null);
                }
                dm.put("usage", usage);
            }
            drivers.add(dm);
        }
        drivers.sort((a, b) -> String.valueOf(a.get("name")).compareToIgnoreCase(String.valueOf(b.get("name"))));
        m.put("drivers", drivers);
        return m;
    }

    private static int parse(String s) {
        try {
            return Integer.parseInt(s.trim());
        } catch (NumberFormatException x) {
            return 0;
        }
    }

    private static String join(String a, String b) {
        return a == null ? b : b == null ? a : a + " " + b;
    }

    /** The first element so named, its text; null when absent or empty. */
    private static String text(Element parent, String tag) {
        NodeList n = parent.getElementsByTagName(tag);
        if (n.getLength() == 0) {
            return null;
        }
        String t = n.item(0).getTextContent().trim();
        return t.isEmpty() ? null : t;
    }

    /** Java's Date.toString form ("Sat Oct 10 00:00:00 CDT 2026"), as the job writes it, to ISO-8601; null when not that. */
    static String iso(String when) {
        if (when == null) {
            return null;
        }
        try {
            SimpleDateFormat f = new SimpleDateFormat("EEE MMM dd HH:mm:ss zzz yyyy", Locale.US);
            return f.parse(when).toInstant().toString();
        } catch (java.text.ParseException x) {
            return null;
        }
    }
}
