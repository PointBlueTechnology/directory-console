package com.pointblue.console.server.http;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * A driver's statistics from the engine's GetDriverStats ({@code <driver-info>}, lab IDM 4.8.7,
 * 2026-10-15): the subscriber's cache (see {@link Cache#summary}) and, for each channel, its operation
 * counters since the last reset, grouped as the engine groups them (reported events, after the event
 * transformation, before the output transformation, commands, command results).
 */
final class Statistics {

    private Statistics() {
    }

    static Map<String, Object> driver(String driverStatsXml) {
        Map<String, Object> out = new LinkedHashMap<>();
        Element root = parse(driverStatsXml);
        if (root == null) {
            return out;
        }
        out.put("cache", Cache.summary(driverStatsXml));
        for (String channel : new String[] {"subscriber", "publisher"}) {
            Element ch = child(root, channel);
            Element ops = ch == null ? null : child(ch, "operations");
            if (ops == null) {
                continue;
            }
            Map<String, Object> c = new LinkedHashMap<>();
            c.put("lastReset", Cache.time(ops.getAttribute("last-reset-time").isEmpty() ? null : ops.getAttribute("last-reset-time")));
            Map<String, Object> groups = new LinkedHashMap<>();
            for (Node g = ops.getFirstChild(); g != null; g = g.getNextSibling()) {
                if (g instanceof Element ge) {
                    Map<String, Long> counts = new LinkedHashMap<>();
                    for (Node n = ge.getFirstChild(); n != null; n = n.getNextSibling()) {
                        if (n instanceof Element e) {
                            try {
                                counts.put(e.getTagName(), Long.parseLong(e.getTextContent().trim()));
                            } catch (NumberFormatException x) {
                                // not a counter
                            }
                        }
                    }
                    groups.put(ge.getTagName(), counts);
                }
            }
            c.put("groups", groups);
            out.put(channel, c);
        }
        return out;
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
}
