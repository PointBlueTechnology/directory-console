package com.pointblue.console.server.http;

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
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * The job types a server's engine offers, from its DiscoverJobs answer (see {@link
 * com.pointblue.console.server.idm.JobCatalog}): {@code <jobs>} holding one {@code <job-aggregation>} per
 * type, its {@code <job-definition>} (display name, default schedule, scope-required, containment, Java
 * class and configuration values) and its translations ({@code <xliff>}). A job object keeps the whole
 * aggregation, with its own values, in {@code XmlData} (a lab tree, IDM 4.8.7, 2026-10-15), so a new job is the
 * type's aggregation with the chosen values set. Every type is offered whatever object is named, so the
 * types are filtered here by their {@code <containment>}.
 */
final class JobTypes {

    private JobTypes() {
    }

    /** The job types whose containment is {@code objectClass} (DirXML-Driver or DirXML-DriverSet), as the console shows them. */
    static List<Map<String, Object>> types(byte[] answer, String objectClass) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Element agg : aggregations(answer)) {
            Element def = child(agg, "job-definition");
            if (def == null || !contains(def, objectClass)) {
                continue;
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("type", text(child(def, "java-class")));
            m.put("displayName", strip(def.getAttribute("display-name")));
            m.put("description", strip(text(child(def, "description"))));
            m.put("schedule", def.hasAttribute("schedule") ? def.getAttribute("schedule") : null);
            m.put("scopeRequired", "true".equalsIgnoreCase(def.getAttribute("scope-required")));
            m.put("parameters", parameters(def));
            out.add(m);
        }
        out.sort((a, b) -> String.valueOf(a.get("displayName")).compareToIgnoreCase(String.valueOf(b.get("displayName"))));
        return out;
    }

    /** The aggregation of the type whose Java class is {@code type} and whose containment is {@code objectClass}; null when there is none. */
    static Element aggregation(byte[] answer, String type, String objectClass) {
        for (Element agg : aggregations(answer)) {
            Element def = child(agg, "job-definition");
            if (def != null && type.equals(text(child(def, "java-class"))) && contains(def, objectClass)) {
                return agg;
            }
        }
        return null;
    }

    /** A job-definition's configuration values, as {@link #types} gives a type's: name, label, type, value, choices, depth and parent. */
    static List<Map<String, Object>> parameters(Element def) {
        List<Map<String, Object>> params = new ArrayList<>();
        Element cv = child(def, "configuration-values");
        Element defs = cv == null ? null : child(cv, "definitions");
        if (defs != null) {
            walk(defs, 0, null, null, params);
        }
        return params;
    }

    /**
     * {@code xml} (a job's XmlData) with the named configuration values changed, each checked against its
     * definition in {@code def} (the same document, parsed). Only each definition's {@code <value>} content
     * changes; everything else is kept as it was written. A password-ref is not changed here.
     */
    static String withValues(String xml, Element def, Map<String, Object> values) {
        Map<String, Element> byName = new LinkedHashMap<>();
        var all = def.getElementsByTagName("definition");
        for (int i = 0; i < all.getLength(); i++) {
            Element d = (Element) all.item(i);
            byName.putIfAbsent(d.getAttribute("name"), d);
        }
        for (Map.Entry<String, Object> v : values.entrySet()) {
            Element d = byName.get(v.getKey());
            if (d == null) {
                throw new IllegalArgumentException("this job has no parameter " + v.getKey());
            }
            Element checked = (Element) d.cloneNode(true);
            set(checked, v.getValue());
            StringBuilder inner = new StringBuilder();
            Element value = child(checked, "value");
            boolean items = false;
            for (Node c = value.getFirstChild(); c != null; c = c.getNextSibling()) {
                if (c instanceof Element i && i.getTagName().equals("item")) {
                    inner.append("<item>").append(escape(i.getTextContent())).append("</item>");
                    items = true;
                }
            }
            if (!items) {
                inner.append(escape(value.getTextContent()));
            }
            xml = valueIn(xml, v.getKey(), inner.toString());
        }
        return xml;
    }

    /** The definition named {@code name} with its value's content replaced by {@code inner} (escaped XML). */
    private static String valueIn(String xml, String name, String inner) {
        java.util.regex.Matcher start = java.util.regex.Pattern.compile(
            "<definition\\b[^>]*?\\sname\\s*=\\s*([\"'])" + java.util.regex.Pattern.quote(name) + "\\1[^>]*?(/?)>").matcher(xml);
        if (!start.find()) {
            throw new IllegalArgumentException("the job's XmlData has no definition " + name);
        }
        if (start.group(2).equals("/")) {
            String open = start.group().substring(0, start.group().length() - 2) + ">";
            return xml.substring(0, start.start()) + open + "<value>" + inner + "</value></definition>" + xml.substring(start.end());
        }
        // definitions do not nest (a group's subordinates are siblings), so the next end tag is this one's
        int end = xml.indexOf("</definition>", start.end());
        if (end < 0) {
            throw new IllegalArgumentException("the job's XmlData has an unclosed definition " + name);
        }
        String body = xml.substring(start.end(), end);
        java.util.regex.Matcher value = java.util.regex.Pattern.compile("<value\\b([^>]*?)(/>|>[\\s\\S]*?</value>)").matcher(body);
        String changed = value.find()
            ? body.substring(0, value.start()) + "<value" + value.group(1) + ">" + inner + "</value>" + body.substring(value.end())
            : body + "<value>" + inner + "</value>";
        return xml.substring(0, start.end()) + changed + xml.substring(end);
    }

    private static String escape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    /** Each definition, depth first: a group's subordinates are shown under its definition, active when it has their active value. */
    private static void walk(Element container, int depth, String parent, String activeValue, List<Map<String, Object>> out) {
        for (Node n = container.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (!(n instanceof Element e)) {
                continue;
            }
            if (e.getTagName().equals("definition")) {
                out.add(parameter(e, depth, parent, activeValue));
            } else if (e.getTagName().equals("group")) {
                Element head = child(e, "definition");
                if (head == null) {
                    continue;
                }
                out.add(parameter(head, depth, parent, activeValue));
                for (Node c = e.getFirstChild(); c != null; c = c.getNextSibling()) {
                    if (c instanceof Element sub && sub.getTagName().equals("subordinates")) {
                        walk(sub, depth + 1, head.getAttribute("name"), sub.getAttribute("active-value"), out);
                    }
                }
            }
        }
    }

    private static Map<String, Object> parameter(Element d, int depth, String parent, String activeValue) {
        Map<String, Object> m = new LinkedHashMap<>();
        String type = d.getAttribute("type");
        m.put("name", d.getAttribute("name"));
        m.put("label", strip(d.getAttribute("display-name")));
        m.put("description", strip(text(child(d, "description"))));
        m.put("type", type);
        Element value = child(d, "value");
        if (type.equals("list")) {
            List<String> items = new ArrayList<>();
            if (value != null) {
                for (Node c = value.getFirstChild(); c != null; c = c.getNextSibling()) {
                    if (c instanceof Element i && i.getTagName().equals("item")) {
                        items.add(i.getTextContent());
                    }
                }
            }
            m.put("value", items);
        } else {
            m.put("value", value == null ? "" : value.getTextContent().trim());
        }
        List<Map<String, String>> choices = new ArrayList<>();
        for (Node c = d.getFirstChild(); c != null; c = c.getNextSibling()) {
            if (c instanceof Element ch && ch.getTagName().equals("enum-choice")) {
                choices.add(Map.of("value", ch.getTextContent().trim(), "label", String.valueOf(strip(ch.getAttribute("display-name")))));
            }
        }
        if (!choices.isEmpty()) {
            m.put("choices", choices);
        }
        m.put("depth", depth);
        if (parent != null) {
            m.put("parent", parent);
            m.put("activeValue", activeValue);
        }
        return m;
    }

    /**
     * The new job's XmlData: the type's aggregation with its job-definition's {@code disabled} and
     * {@code schedule} (null for none) and the named configuration values set. A value is checked against
     * its definition's type; a password-ref names a named password and is not set here.
     */
    static byte[] build(Element aggregation, boolean disabled, String schedule, Map<String, Object> values) {
        Element agg = (Element) aggregation.cloneNode(true);
        Element def = child(agg, "job-definition");
        def.setAttribute("disabled", disabled ? "true" : "false");
        if (schedule == null) {
            def.removeAttribute("schedule");
        } else {
            def.setAttribute("schedule", schedule);
        }
        Map<String, Element> byName = new LinkedHashMap<>();
        Element cv = child(def, "configuration-values");
        if (cv != null) {
            var all = cv.getElementsByTagName("definition");
            for (int i = 0; i < all.getLength(); i++) {
                Element d = (Element) all.item(i);
                byName.put(d.getAttribute("name"), d);
            }
        }
        for (Map.Entry<String, Object> v : values.entrySet()) {
            Element d = byName.get(v.getKey());
            if (d == null) {
                throw new IllegalArgumentException("this job type has no parameter " + v.getKey());
            }
            set(d, v.getValue());
        }
        try {
            Document out = factory().newDocumentBuilder().newDocument();
            out.appendChild(out.importNode(agg, true));
            var t = TransformerFactory.newInstance().newTransformer();
            t.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            StringWriter w = new StringWriter();
            t.transform(new DOMSource(out), new StreamResult(w));
            return w.toString().getBytes(StandardCharsets.UTF_8);
        } catch (Exception x) {
            throw new IllegalStateException(x);
        }
    }

    static void set(Element d, Object raw) {
        String type = d.getAttribute("type");
        String name = d.getAttribute("name");
        Element value = child(d, "value");
        if (value == null) {
            value = d.getOwnerDocument().createElement("value");
            d.appendChild(value);
        }
        while (value.getFirstChild() != null) {
            value.removeChild(value.getFirstChild());
        }
        switch (type) {
            case "password-ref" -> throw new IllegalArgumentException(name + " names a named password: set the password on the job, not this parameter");
            case "list" -> {
                if (!(raw instanceof List<?> items)) {
                    throw new IllegalArgumentException(name + " is a list of values");
                }
                for (Object o : items) {
                    Element item = d.getOwnerDocument().createElement("item");
                    item.setTextContent(String.valueOf(o));
                    value.appendChild(item);
                }
                return;
            }
            default -> {
            }
        }
        String v = raw == null ? "" : String.valueOf(raw).trim();
        switch (type) {
            case "boolean" -> {
                if (!v.equals("true") && !v.equals("false")) {
                    throw new IllegalArgumentException(name + " is true or false");
                }
            }
            case "integer" -> {
                if (!v.matches("-?\\d{1,10}")) {
                    throw new IllegalArgumentException(name + " is a whole number");
                }
            }
            case "enum" -> {
                List<String> ok = new ArrayList<>();
                for (Node c = d.getFirstChild(); c != null; c = c.getNextSibling()) {
                    if (c instanceof Element ch && ch.getTagName().equals("enum-choice")) {
                        ok.add(ch.getTextContent().trim());
                    }
                }
                if (!ok.contains(v)) {
                    throw new IllegalArgumentException(name + " is one of " + String.join(", ", ok));
                }
            }
            default -> {
            }
        }
        value.setTextContent(v);
    }

    private static boolean contains(Element def, String objectClass) {
        String c = text(child(def, "containment"));
        if (c == null) {
            return false;
        }
        for (String one : c.split("[\\s,]+")) {
            if (one.equalsIgnoreCase(objectClass)) {
                return true;
            }
        }
        return false;
    }

    private static List<Element> aggregations(byte[] answer) {
        List<Element> out = new ArrayList<>();
        Element root;
        try {
            javax.xml.parsers.DocumentBuilder b = factory().newDocumentBuilder();
            b.setErrorHandler(new org.xml.sax.helpers.DefaultHandler());
            root = b.parse(new ByteArrayInputStream(answer)).getDocumentElement();
        } catch (Exception x) {
            throw new IllegalStateException("the engine's job definitions could not be read: " + x.getMessage());
        }
        for (Node n = root.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element e && e.getTagName().equals("job-aggregation")) {
                out.add(e);
            }
        }
        return out;
    }

    private static DocumentBuilderFactory factory() throws javax.xml.parsers.ParserConfigurationException {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.setExpandEntityReferences(false);
        return f;
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

    /** "xlfid(job-description)This job…" → "This job…": the localization key is not for people. */
    static String strip(String s) {
        return s == null ? null : s.replaceFirst("^xlfid\\([^)]*\\)", "");
    }
}
