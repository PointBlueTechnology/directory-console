package com.pointblue.console.server.http;

import com.pointblue.console.server.auth.Role;
import com.pointblue.console.server.auth.Sessions;
import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.console.server.ldap.Names;
import com.sun.net.httpserver.HttpExchange;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.naming.NamingException;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Identity Manager's e-mail notification templates, read and changed over LDAP with the person's own rights: a
 * {@code notfMergeTemplate} in {@code cn=Default Notification Collection,cn=Security} with its subject
 * ({@code notfMergeTemplateSubject}) and its message ({@code notfMergeTemplateData}): an XHTML document whose
 * {@code form:token-descriptions} describe the {@code $token$} markers the sender fills in (351 on a lab tree, every one
 * well-formed, 2026-11-02).
 *
 * <pre>
 * GET    /api/v2/trees/{tree}/idm/templates          name, subject, package
 * GET    /api/v2/trees/{tree}/idm/templates/{guid}   subject, tokens, message (body; text too when it is plain text), the whole document, markers used, version
 * PUT    same   {"version", "subject", "tokens": [{"name", "description"}], "body" | "text"}, or {"version", "subject", "xml"}
 * POST   /api/v2/trees/{tree}/idm/templates          {"name", "copyOf"?: guid, then as PUT without version}
 * DELETE /api/v2/trees/{tree}/idm/templates/{guid}   {"name"}: the template's name, typed
 * </pre>
 *
 * A save carries the version it was read at and is refused (409) when the template changed meanwhile. The message is what
 * follows the token descriptions in the document's root; a change to it or to the tokens keeps the rest of the document.
 */
final class Templates {

    static final String COLLECTION = "cn=Default Notification Collection,cn=Security";
    static final String FORM_NS = "http://www.novell.com/dirxml/workflow/form";
    static final Pattern TOKEN = Pattern.compile("\\$([A-Za-z_][A-Za-z0-9_.\\-]*)\\$");
    private static final String[] ATTRS = {"objectClass", "GUID", "cn", "notfMergeTemplateSubject", "notfMergeTemplateData", "DirXML-pkgGUID"};
    private static final String BLANK = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><html xmlns:form=\"" + FORM_NS + "\">\n"
        + "\t<form:token-descriptions/>\n\t<body>\n\t\t<p></p>\n\t</body>\n</html>";

    private final Server server;

    Templates(Server server) {
        this.server = server;
    }

    void handle(HttpExchange ex, Sessions.Session s, String method, String guid) throws IOException {
        Ldap l = s.ldap();
        if (l == null) {
            throw new Http.Problem(503, "unavailable", "no directory connection");
        }
        try {
            if (guid == null) {
                switch (method) {
                    case "GET" -> list(ex, l);
                    case "POST" -> create(ex, l, s);
                    default -> throw new Http.Problem(405, "method-not-allowed", method);
                }
                return;
            }
            Ldap.Entry e = template(l, guid);
            if (!method.equals("GET") && !s.principal.may(Role.OPERATOR, e.dn())) {
                throw new Http.Problem(403, "out-of-scope", "changing a template needs an operator role that reaches " + e.dn());
            }
            switch (method) {
                case "GET" -> Http.json(ex, 200, json(e));
                case "PUT" -> save(ex, l, s, guid, e);
                case "DELETE" -> delete(ex, l, s, guid, e);
                default -> throw new Http.Problem(405, "method-not-allowed", method);
            }
        } catch (NamingException x) {
            throw server.objects.problem(s, Ldap.Failure.of(x));
        } catch (IllegalArgumentException x) {
            throw new Http.Problem(400, "bad-request", x.getMessage());
        }
    }

    private Ldap.Entry template(Ldap l, String guid) throws NamingException {
        Ldap.Entry e = server.objects.byGuid(l, guid, ATTRS);
        if (e.attributes().getOrDefault("objectclass", List.of()).stream().noneMatch(c -> String.valueOf(c).equalsIgnoreCase("notfMergeTemplate"))) {
            throw new Http.Problem(404, "not-found", guid + " is not a notification template");
        }
        return e;
    }

    private static Ldap.Entry collection(Ldap l) throws NamingException {
        Ldap.Entry c = l.read(COLLECTION, "objectClass");
        if (c == null) {
            throw new Http.Problem(404, "no-collection", "this directory has no " + COLLECTION + " for notification templates");
        }
        return c;
    }

    private void list(HttpExchange ex, Ldap l) throws IOException, NamingException {
        collection(l);
        List<Map<String, Object>> out = new ArrayList<>();
        for (Ldap.Entry e : l.search(COLLECTION, "(objectClass=notfMergeTemplate)", null, SearchControls.ONELEVEL_SCOPE,
                new String[] {"GUID", "cn", "notfMergeTemplateSubject", "DirXML-pkgGUID"}, 5000)) {
            Map<String, Object> m = ref(e);
            m.put("subject", text(e, "notfMergeTemplateSubject"));
            m.put("package", packageName(e));
            out.add(m);
        }
        out.sort((a, b) -> String.valueOf(a.get("name")).compareToIgnoreCase(String.valueOf(b.get("name"))));
        Http.json(ex, 200, Map.of("items", out, "collection", COLLECTION));
    }

    private static Map<String, Object> ref(Ldap.Entry e) {
        Map<String, Object> m = new LinkedHashMap<>(Names.identity(e.dn()));
        List<Object> g = e.attributes().get("guid");
        m.put("guid", g == null || g.isEmpty() ? null : Names.guidHex(g.get(0)));
        return m;
    }

    private static String text(Ldap.Entry e, String attr) {
        List<Object> v = e.attributes().get(attr.toLowerCase(Locale.ROOT));
        if (v == null || v.isEmpty()) {
            return null;
        }
        Object o = v.get(0);
        return o instanceof byte[] b ? new String(b, StandardCharsets.UTF_8) : String.valueOf(o);
    }

    /** The package a template came from ("…;package display name;PREFIX"), or null. */
    private static String packageName(Ldap.Entry e) {
        String g = e.first("DirXML-pkgGUID");
        if (g == null) {
            return null;
        }
        String[] parts = g.split(";");
        return parts.length >= 4 ? parts[3] : g;
    }

    static String version(String subject, String data) {
        return Jobs.version(((subject == null ? "" : subject) + "\u0000" + (data == null ? "" : data)).getBytes(StandardCharsets.UTF_8));
    }

    private static Map<String, Object> json(Ldap.Entry e) {
        Map<String, Object> m = ref(e);
        String subject = text(e, "notfMergeTemplateSubject");
        String data = text(e, "notfMergeTemplateData");
        m.put("subject", subject);
        m.put("package", packageName(e));
        m.put("version", version(subject, data));
        m.put("xml", data);
        Parts p = data == null ? null : parts(data);
        m.put("readable", data == null || p != null);
        m.put("tokens", p == null ? List.of() : p.tokens());
        m.put("format", p != null && p.text() != null ? "text" : "html");
        m.put("body", p == null ? null : p.body());
        m.put("text", p == null ? null : p.text());
        m.put("used", used(subject, p == null ? data : p.text() != null ? p.text() : p.body()));
        return m;
    }

    /**
     * A template's token descriptions and its message: what follows them in the document's root, as XML; and the same
     * as plain text when it is only text. On a lab tree (351 templates) a message is XHTML in a {@code <body>}, XHTML or
     * text straight in {@code <html>}, a nested {@code <html>}, or plain text in a {@code <form:text>} root.
     */
    record Parts(List<Map<String, String>> tokens, String body, String text) {
    }

    /** The parts of a template's document; null when it is not well-formed XML. */
    static Parts parts(String xml) {
        Document doc = parse(xml);
        if (doc == null) {
            return null;
        }
        Element root = doc.getDocumentElement();
        Element descs = descriptions(doc);
        StringBuilder body = new StringBuilder();
        StringBuilder text = new StringBuilder();
        boolean onlyText = true;
        for (Node n : message(root, descs)) {
            body.append(serialize(n, true));
            if (n instanceof org.w3c.dom.Text t) {
                text.append(t.getData());
            } else {
                onlyText = false;
            }
        }
        return new Parts(tokens(descs), withoutRootDeclarations(root, body.toString()), onlyText ? text.toString() : null);
    }

    private static List<Map<String, String>> tokens(Element descs) {
        List<Map<String, String>> tokens = new ArrayList<>();
        if (descs != null) {
            for (Node n = descs.getFirstChild(); n != null; n = n.getNextSibling()) {
                if (n instanceof Element d && "token-description".equals(d.getLocalName())) {
                    Map<String, String> t = new LinkedHashMap<>();
                    t.put("name", d.getAttribute("item-name"));
                    t.put("description", d.getAttribute("description"));
                    tokens.add(t);
                }
            }
        }
        return tokens;
    }

    /** The root's children after the token descriptions (all of them when it has none). */
    private static List<Node> message(Element root, Element descs) {
        List<Node> out = new ArrayList<>();
        for (Node n = descs == null ? root.getFirstChild() : descs.getNextSibling(); n != null; n = n.getNextSibling()) {
            out.add(n);
        }
        return out;
    }

    /** Each element serialized alone declares the namespaces it uses; those the root declares already are left out. */
    private static String withoutRootDeclarations(Element root, String s) {
        org.w3c.dom.NamedNodeMap a = root.getAttributes();
        for (int i = 0; i < a.getLength(); i++) {
            Node x = a.item(i);
            if (x.getNodeName().equals("xmlns") || x.getNodeName().startsWith("xmlns:")) {
                s = s.replace(" " + x.getNodeName() + "=\"" + x.getNodeValue() + "\"", "");
            }
        }
        return root.hasAttribute("xmlns:form") ? s : s.replace(" xmlns:form=\"" + FORM_NS + "\"", "");
    }

    /** The {@code $token$} markers in the subject and message, each once, in order of appearance. */
    static List<String> used(String subject, String body) {
        Set<String> out = new LinkedHashSet<>();
        for (String s : new String[] {subject, body}) {
            if (s == null) {
                continue;
            }
            Matcher m = TOKEN.matcher(s);
            while (m.find()) {
                out.add(m.group(1));
            }
        }
        return new ArrayList<>(out);
    }

    private static Document parse(String xml) {
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setNamespaceAware(true);
            f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            f.setExpandEntityReferences(false);
            javax.xml.parsers.DocumentBuilder b = f.newDocumentBuilder();
            // a message that is not XML is reported to the person, not printed on the server's stderr
            b.setErrorHandler(new org.xml.sax.helpers.DefaultHandler());
            return b.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception x) {
            return null;
        }
    }

    private static String why(String xml) {
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setNamespaceAware(true);
            f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            javax.xml.parsers.DocumentBuilder b = f.newDocumentBuilder();
            b.setErrorHandler(new org.xml.sax.helpers.DefaultHandler());
            b.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
            return null;
        } catch (org.xml.sax.SAXParseException x) {
            return "line " + x.getLineNumber() + ", column " + x.getColumnNumber() + ": " + x.getMessage();
        } catch (Exception x) {
            return x.getMessage();
        }
    }

    private static Element descriptions(Document doc) {
        for (Node n = doc.getDocumentElement().getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element el && "token-descriptions".equals(el.getLocalName())) {
                return el;
            }
        }
        return null;
    }

    private static String serialize(Node n, boolean fragment) {
        try {
            Transformer t = TransformerFactory.newInstance().newTransformer();
            // XML, though the root is <html>: the default would write HTML (<br>, a META element)
            t.setOutputProperty(OutputKeys.METHOD, "xml");
            t.setOutputProperty(OutputKeys.INDENT, "no");
            t.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, fragment ? "yes" : "no");
            if (n instanceof Document d) {
                // no standalone="no" in the declaration, which the templates do not carry
                d.setXmlStandalone(true);
            }
            t.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            StringWriter w = new StringWriter();
            t.transform(new DOMSource(n), new StreamResult(w));
            return w.toString();
        } catch (Exception x) {
            throw new IllegalStateException(x);
        }
    }

    /**
     * {@code base} with its token descriptions and message replaced, the rest of the document as it was: the message as
     * XML ({@code body}, a fragment in the root's namespaces) or as plain text ({@code text}). Unchanged tokens are left
     * as they are written.
     */
    static String rebuild(String base, List<Map<String, String>> tokens, String body, String text) {
        Document doc = parse(base);
        if (doc == null) {
            throw new IllegalArgumentException("the template's document is not well-formed XML; change it as XML instead");
        }
        Element root = doc.getDocumentElement();
        List<Node> nodes = new ArrayList<>();
        if (text != null) {
            nodes.add(doc.createTextNode(text));
        } else {
            // the fragment in the namespaces the root declares (form: the workflow form's, unless the root binds it otherwise)
            StringBuilder open = new StringBuilder("<message" + (root.hasAttribute("xmlns:form") ? "" : " xmlns:form=\"" + FORM_NS + "\""));
            org.w3c.dom.NamedNodeMap a = root.getAttributes();
            for (int i = 0; i < a.getLength(); i++) {
                Node x = a.item(i);
                if (x.getNodeName().equals("xmlns") || x.getNodeName().startsWith("xmlns:")) {
                    open.append(' ').append(x.getNodeName()).append("=\"").append(escape(x.getNodeValue())).append('"');
                }
            }
            Document frag = parse(open + ">" + body + "</message>");
            if (frag == null) {
                String why = why("<message>" + body + "</message>");
                throw new IllegalArgumentException("the message is not well-formed XML" + (why == null ? "" : " (" + why + ")")
                    + "; write <br/> rather than <br>, and &amp; for &");
            }
            for (Node n = frag.getDocumentElement().getFirstChild(); n != null; n = n.getNextSibling()) {
                nodes.add(doc.importNode(n, true));
            }
        }
        Element descs = descriptions(doc);
        if (!tokens.equals(tokens(descs))) {
            if (descs == null) {
                descs = doc.createElementNS(FORM_NS, "form:token-descriptions");
                root.insertBefore(descs, root.getFirstChild());
            }
            while (descs.getFirstChild() != null) {
                descs.removeChild(descs.getFirstChild());
            }
            String prefix = descs.getPrefix() == null ? "form" : descs.getPrefix();
            for (Map<String, String> t : tokens) {
                descs.appendChild(doc.createTextNode("\n\t\t"));
                Element d = doc.createElementNS(FORM_NS, prefix + ":token-description");
                d.setAttribute("description", t.getOrDefault("description", ""));
                d.setAttribute("item-name", t.get("name"));
                descs.appendChild(d);
            }
            if (!tokens.isEmpty()) {
                descs.appendChild(doc.createTextNode("\n\t"));
            }
        }
        for (Node n : message(root, descs)) {
            root.removeChild(n);
        }
        nodes.forEach(root::appendChild);
        // a declaration only when the document had one (one lab template has none)
        return serialize(doc, !base.stripLeading().startsWith("<?xml"));
    }

    private static String escape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace("\"", "&quot;");
    }

    /** The tokens from a request, checked: each named as a marker may be, and named once. */
    static List<Map<String, String>> tokens(Object raw) {
        if (raw != null && !(raw instanceof List)) {
            throw new IllegalArgumentException("tokens is a list of {name, description}");
        }
        List<Map<String, String>> out = new ArrayList<>();
        Set<String> names = new LinkedHashSet<>();
        for (Object o : raw == null ? List.of() : (List<?>) raw) {
            if (!(o instanceof Map<?, ?> m) || m.get("name") == null) {
                throw new IllegalArgumentException("every token has a name");
            }
            String name = String.valueOf(m.get("name")).trim();
            if (!name.matches("[A-Za-z_][A-Za-z0-9_.\\-]*")) {
                throw new IllegalArgumentException("a token's name is letters, digits, _ . and -, as in $name$: " + name);
            }
            if (!names.add(name)) {
                throw new IllegalArgumentException("two tokens are named " + name);
            }
            out.add(Map.of("name", name, "description", m.get("description") == null ? "" : String.valueOf(m.get("description"))));
        }
        return out;
    }

    /** The document a request gives: the whole XML, or the tokens and body applied to {@code base}. */
    static String document(Map<String, Object> b, String base) {
        if (b.containsKey("xml")) {
            String xml = Http.string(b, "xml", true);
            String why = why(xml);
            if (why != null) {
                throw new IllegalArgumentException("the document is not well-formed XML (" + why + ")");
            }
            return xml;
        }
        Object body = b.get("body");
        Object text = b.get("text");
        if (!(body instanceof String) && !(text instanceof String)) {
            throw new IllegalArgumentException("give the message as body (XML) or text (plain text), or xml for the whole document");
        }
        return rebuild(base, tokens(b.get("tokens")), body instanceof String s ? s : null, text instanceof String s ? s : null);
    }

    private static String subject(Map<String, Object> b) {
        String s = Http.string(b, "subject", true).strip();
        if (s.length() > 1000) {
            throw new IllegalArgumentException("a subject is at most 1000 characters");
        }
        return s;
    }

    private void save(HttpExchange ex, Ldap l, Sessions.Session s, String guid, Ldap.Entry e) throws IOException, NamingException {
        Map<String, Object> b = Http.body(ex);
        String data = text(e, "notfMergeTemplateData");
        if (!Http.string(b, "version", true).equals(version(text(e, "notfMergeTemplateSubject"), data))) {
            throw new Http.Problem(409, "changed", "the template changed meanwhile; reload it and try again");
        }
        String subject = subject(b);
        String xml = document(b, data == null ? BLANK : data);
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("dn", e.dn());
        detail.put("subject", !subject.equals(text(e, "notfMergeTemplateSubject")));
        detail.put("message", !xml.equals(data));
        try {
            l.modify(e.dn(), List.of(
                new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("notfMergeTemplateSubject", subject)),
                new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("notfMergeTemplateData", xml))));
        } catch (NamingException x) {
            server.objects.audit(s, "idm.template.change", guid, detail, Ldap.Failure.of(x));
            throw x;
        }
        server.objects.audit(s, "idm.template.change", guid, detail, null);
        Http.json(ex, 200, json(template(l, guid)));
    }

    private void create(HttpExchange ex, Ldap l, Sessions.Session s) throws IOException, NamingException {
        collection(l);
        if (!s.principal.may(Role.OPERATOR, COLLECTION)) {
            throw new Http.Problem(403, "out-of-scope", "creating a template needs an operator role that reaches " + COLLECTION);
        }
        Map<String, Object> b = Http.body(ex);
        String name = Http.string(b, "name", true).trim();
        if (name.isEmpty() || name.length() > 64) {
            throw new IllegalArgumentException("a template's name is 1 to 64 characters");
        }
        String dn = Names.child(COLLECTION, "cn", name);
        if (l.read(dn, "1.1") != null) {
            throw new Http.Problem(409, "exists", "there is already a template named " + name);
        }
        String base = BLANK;
        String copyOf = Http.string(b, "copyOf", false);
        if (copyOf != null) {
            String from = text(template(l, copyOf), "notfMergeTemplateData");
            if (from != null) {
                base = from;
            }
        }
        String subject = subject(b);
        String xml = b.containsKey("xml") || b.containsKey("body") || b.containsKey("text") ? document(b, base) : base;
        Map<String, List<Object>> attrs = new LinkedHashMap<>();
        attrs.put("objectClass", List.of("Top", "notfMergeTemplate"));
        attrs.put("cn", List.of(name));
        attrs.put("notfMergeTemplateSubject", List.of(subject));
        attrs.put("notfMergeTemplateData", List.of(xml));
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("dn", dn);
        if (copyOf != null) {
            detail.put("copyOf", copyOf);
        }
        try {
            l.create(dn, attrs);
        } catch (NamingException x) {
            server.objects.audit(s, "idm.template.create", null, detail, Ldap.Failure.of(x));
            throw x;
        }
        Ldap.Entry made = l.read(dn, ATTRS);
        String guid = made == null ? null : String.valueOf(ref(made).get("guid"));
        server.objects.audit(s, "idm.template.create", guid, detail, null);
        Http.json(ex, 201, made == null ? Map.of("dn", dn) : json(made));
    }

    private void delete(HttpExchange ex, Ldap l, Sessions.Session s, String guid, Ldap.Entry e) throws IOException, NamingException {
        String typed = Http.string(Http.body(ex), "name", true);
        String name = String.valueOf(Names.identity(e.dn()).get("name"));
        if (!typed.equals(name)) {
            throw new Http.Problem(409, "confirm-name", "type the template's name, " + name + ", to delete it");
        }
        Map<String, Object> detail = Map.of("dn", e.dn());
        try {
            l.delete(e.dn());
        } catch (NamingException x) {
            server.objects.audit(s, "idm.template.delete", guid, detail, Ldap.Failure.of(x));
            throw x;
        }
        server.objects.audit(s, "idm.template.delete", guid, detail, null);
        Http.json(ex, 204, Map.of());
    }
}
