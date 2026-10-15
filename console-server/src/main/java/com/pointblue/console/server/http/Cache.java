package com.pointblue.console.server.http;

import com.pointblue.dirxml.dev.operate.Operate;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * The Cache Inspector's reads and its delete, on one server's engine (a lab tree, IDM 4.8.7, 2026-10-15):
 * <ul>
 * <li>The summary comes from the engine's driver statistics ({@code <driver-info><subscriber><cache>}:
 *     size, unprocessed size, oldest and newest transaction, counts by type), which it gives for a running
 *     driver too.</li>
 * <li>The events come from ViewCacheEntries, which answers only for a stopped driver. Its position token is
 *     a byte offset into the cache (336 for a 336-byte cache), so reading one event at a time gives each
 *     event's position.</li>
 * <li>A delete names each event by position and event-id; the event at that position is read again first
 *     and must still have that event-id, then DeleteCacheEntries removes that one event. Several go from
 *     the last to the first, so the earlier positions stay valid.</li>
 * </ul>
 */
final class Cache {

    private Cache() {
    }

    /** The driver statistics' cache section, or null when the engine gives none. */
    static Map<String, Object> summary(String driverStatsXml) {
        Element root = parse(driverStatsXml);
        Element sub = root == null ? null : child(root, "subscriber");
        Element cache = sub == null ? null : child(sub, "cache");
        if (cache == null) {
            return null;
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("size", number(text(child(cache, "size"))));
        m.put("unprocessedSize", number(text(child(cache, "unprocessed-size"))));
        Element tx = child(cache, "transactions");
        m.put("oldest", tx == null ? null : time(text(child(tx, "oldest"))));
        m.put("newest", tx == null ? null : time(text(child(tx, "newest"))));
        Map<String, Object> counts = new LinkedHashMap<>();
        Element c = tx == null ? null : child(tx, "counts");
        if (c != null) {
            for (Node n = c.getFirstChild(); n != null; n = n.getNextSibling()) {
                if (n instanceof Element e) {
                    counts.put(e.getTagName(), number(e.getTextContent()));
                }
            }
        }
        m.put("counts", counts);
        return m;
    }

    /** Up to {@code count} events from {@code position}, one ViewCacheEntries each so that every event's position is known. */
    static Map<String, Object> events(Operate.Engine engine, String driverDn, int position, int count) {
        List<Map<String, Object>> events = new ArrayList<>();
        int pos = position;
        boolean more = true;
        for (int i = 0; i < count; i++) {
            Operate.CachePage page = engine.viewCache(driverDn, pos, 1);
            List<Element> got = page.empty ? List.of() : events(page.xds);
            if (got.isEmpty() || page.nextToken <= pos) {
                more = false;
                break;
            }
            Map<String, Object> e = event(got.get(0));
            e.put("position", pos);
            events.add(e);
            pos = page.nextToken;
        }
        if (more) {
            Operate.CachePage peek = engine.viewCache(driverDn, pos, 1);
            more = !peek.empty && !events(peek.xds).isEmpty();
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("events", events);
        out.put("next", more ? pos : null);
        return out;
    }

    /** The event-id of the event at {@code position}, or null when there is none. */
    static String eventIdAt(Operate.Engine engine, String driverDn, int position) {
        Operate.CachePage page = engine.viewCache(driverDn, position, 1);
        List<Element> got = page.empty ? List.of() : events(page.xds);
        return got.isEmpty() ? null : got.get(0).getAttribute("event-id");
    }

    /** The events of a cache page: the elements of {@code <nds><input>}. */
    static List<Element> events(String xds) {
        Element root = parse(xds);
        Element input = root == null ? null : child(root, "input");
        List<Element> out = new ArrayList<>();
        if (input != null) {
            for (Node n = input.getFirstChild(); n != null; n = n.getNextSibling()) {
                if (n instanceof Element e) {
                    out.add(e);
                }
            }
        }
        return out;
    }

    static Map<String, Object> event(Element e) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("type", e.getTagName());
        m.put("className", attr(e, "class-name"));
        m.put("srcDn", attr(e, "src-dn"));
        m.put("eventId", attr(e, "event-id"));
        m.put("cachedTime", time(attr(e, "cached-time")));
        List<String> attrs = new ArrayList<>();
        for (Node n = e.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element c && c.hasAttribute("attr-name") && !attrs.contains(c.getAttribute("attr-name"))) {
                attrs.add(c.getAttribute("attr-name"));
            }
        }
        m.put("attributes", attrs);
        m.put("xml", serialize(e));
        return m;
    }

    private static String attr(Element e, String name) {
        return e.hasAttribute(name) ? e.getAttribute(name) : null;
    }

    /** "20261013151206.041Z" → ISO-8601; the input when it is not that. */
    static String time(String t) {
        if (t == null || !t.matches("\\d{14}(\\.\\d+)?Z")) {
            return t;
        }
        return t.substring(0, 4) + "-" + t.substring(4, 6) + "-" + t.substring(6, 8) + "T" + t.substring(8, 10) + ":" + t.substring(10, 12) + ":" + t.substring(12);
    }

    private static Long number(String s) {
        try {
            return s == null ? null : Long.parseLong(s.trim());
        } catch (NumberFormatException x) {
            return null;
        }
    }

    private static Element parse(String xml) {
        if (xml == null || xml.isBlank()) {
            return null;
        }
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            f.setExpandEntityReferences(false);
            javax.xml.parsers.DocumentBuilder b = f.newDocumentBuilder();
            b.setErrorHandler(new org.xml.sax.helpers.DefaultHandler());
            return b.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8))).getDocumentElement();
        } catch (Exception x) {
            return null;
        }
    }

    private static Element child(Element parent, String tag) {
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element e && e.getTagName().equals(tag)) {
                return e;
            }
        }
        return null;
    }

    private static String text(Element e) {
        return e == null ? null : e.getTextContent().trim();
    }

    private static String serialize(Element e) {
        try {
            var t = TransformerFactory.newInstance().newTransformer();
            t.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            StringWriter w = new StringWriter();
            t.transform(new DOMSource(e), new StreamResult(w));
            return w.toString().trim();
        } catch (Exception x) {
            return null;
        }
    }
}
