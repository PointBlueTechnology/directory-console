package com.pointblue.console.server.http;

import com.pointblue.console.server.ldap.Ldap;
import com.pointblue.console.server.ldap.Names;
import com.pointblue.console.server.ldap.Secrets;
import com.pointblue.dirxml.dev.json.Json;
import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Search results written out as they are read: LDIF (RFC 2849), CSV (RFC 4180, with the separators
 * chosen) or JSON. Withheld attributes (passwords, private keys) are never written: LDIF notes them in
 * a comment, CSV and JSON as "(withheld)".
 */
final class Export {

    enum Format { LDIF, CSV, JSON }

    /**
     * How to write: LDIF's line width (0: no folding) and version line; CSV's separators, quote, whether a
     * cell a spreadsheet would run as a formula is kept as text, and a byte-order mark for Excel; the line
     * ending for both.
     */
    record Options(String eol, int wrap, boolean version, String delimiter, String valueDelimiter, String quote, boolean formulaGuard, boolean bom) {

        static Options of(Format f, Object spec) {
            Map<String, Object> o = spec instanceof Map<?, ?> ? Json.asMap(spec) : Map.of();
            String eol = switch (String.valueOf(o.getOrDefault("eol", f == Format.CSV ? "crlf" : "lf"))) {
                case "lf" -> "\n";
                case "crlf" -> "\r\n";
                default -> throw new Http.Problem(400, "bad-field", "eol is lf or crlf");
            };
            int wrap = Json.asInt(o.get("wrap"), 76);
            if (wrap != 0 && (wrap < 20 || wrap > 1000)) {
                throw new Http.Problem(400, "bad-field", "wrap is 0 (no folding) or 20 to 1000");
            }
            String delimiter = one(o, "delimiter", ",");
            String valueDelimiter = String.valueOf(o.getOrDefault("valueDelimiter", "|"));
            String quote = one(o, "quote", "\"");
            if (valueDelimiter.isEmpty() || valueDelimiter.length() > 4 || valueDelimiter.contains(quote)
                || delimiter.equals(quote) || "\r\n".contains(delimiter) || "\r\n".contains(quote)) {
                throw new Http.Problem(400, "bad-field", "the delimiters and quote must differ, and none may be a line break");
            }
            return new Options(eol, wrap, !Boolean.FALSE.equals(o.get("version")), delimiter, valueDelimiter, quote,
                !Boolean.FALSE.equals(o.get("formulaGuard")), Boolean.TRUE.equals(o.get("bom")));
        }

        private static String one(Map<String, Object> o, String key, String dflt) {
            String v = String.valueOf(o.getOrDefault(key, dflt));
            if (v.length() != 1) {
                throw new Http.Problem(400, "bad-field", key + " is one character");
            }
            return v;
        }
    }

    private final Format format;
    private final Options o;
    private final List<String> columns;
    private final Writer w;
    private int written;

    /** {@code columns}: the attributes for CSV and JSON (after dn, name and objectClass), and LDIF's order. */
    Export(Format format, Options o, List<String> columns, Writer w) {
        this.format = format;
        this.o = o;
        this.columns = columns;
        this.w = w;
    }

    int written() {
        return written;
    }

    void begin() throws IOException {
        switch (format) {
            case LDIF -> {
                if (o.version) {
                    w.write("version: 1" + o.eol + o.eol);
                }
            }
            case CSV -> {
                if (o.bom) {
                    w.write('﻿');
                }
                List<String> head = new ArrayList<>(List.of("dn", "name", "objectClass"));
                head.addAll(columns);
                row(head);
            }
            case JSON -> w.write("[");
        }
    }

    void entry(Ldap.Entry e) throws IOException {
        switch (format) {
            case LDIF -> ldif(e);
            case CSV -> {
                List<String> cells = new ArrayList<>(List.of(e.dn(), name(e.dn()), String.join(o.valueDelimiter, texts(e, "objectClass"))));
                for (String c : columns) {
                    cells.add(String.join(o.valueDelimiter, texts(e, c)));
                }
                row(cells);
            }
            case JSON -> {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("dn", e.dn());
                m.put("name", name(e.dn()));
                m.put("objectClass", texts(e, "objectClass"));
                Map<String, Object> attrs = new LinkedHashMap<>();
                for (String c : columns.isEmpty() ? names(e) : columns) {
                    attrs.put(columns.isEmpty() ? e.name(c) : c, texts(e, c));
                }
                m.put("attributes", attrs);
                w.write((written == 0 ? "" : ",") + "\n  " + Json.compact(m));
            }
        }
        written++;
    }

    /** The end; {@code stopped}, when not null, says why the export ended early (LDIF and JSON can carry it). */
    void end(String stopped) throws IOException {
        switch (format) {
            case LDIF -> {
                if (stopped != null) {
                    w.write("# export stopped after " + written + " entries: " + stopped.replaceAll("[\r\n]+", " ") + o.eol);
                }
            }
            case CSV -> {
                // no place for a note in CSV: the person is told by the missing rows and the audit log
            }
            case JSON -> w.write((written == 0 ? "" : "\n") + "]" + (stopped == null ? "" : "\n") + "\n");
        }
        w.flush();
    }

    // ---- LDIF -----------------------------------------------------------------------------------

    private void ldif(Ldap.Entry e) throws IOException {
        line("dn", e.dn().getBytes(StandardCharsets.UTF_8), e.dn());
        List<String> order = new ArrayList<>();
        if (e.attributes().containsKey("objectclass")) {
            order.add("objectclass");
        }
        List<String> rest = columns.isEmpty() || columns.contains("*") || columns.contains("+") ? names(e)
            : columns.stream().map(c -> c.toLowerCase(Locale.ROOT)).filter(e.attributes()::containsKey).toList();
        for (String k : rest) {
            if (!order.contains(k)) {
                order.add(k);
            }
        }
        for (String k : order) {
            String name = e.name(k);
            for (Object v : e.attributes().get(k)) {
                if (v instanceof Secrets.Withheld wh) {
                    w.write("# " + name + ": withheld (" + wh.count() + (wh.count() == 1 ? " value" : " values") + ")" + o.eol);
                } else if (v instanceof byte[] b) {
                    line(name, b, null);
                } else {
                    String s = String.valueOf(v);
                    line(name, s.getBytes(StandardCharsets.UTF_8), s);
                }
            }
        }
        w.write(o.eol);
    }

    /** {@code name: value}, or {@code name:: base64} when the value is not a SAFE-STRING (RFC 2849), folded at the width. */
    private void line(String name, byte[] bytes, String text) throws IOException {
        String l = text != null && safe(text) ? name + ": " + text : name + ":: " + Base64.getEncoder().encodeToString(bytes);
        if (text != null && text.isEmpty()) {
            l = name + ":";
        }
        if (o.wrap == 0 || l.length() <= o.wrap) {
            w.write(l + o.eol);
            return;
        }
        w.write(l.substring(0, o.wrap) + o.eol);
        for (int i = o.wrap; i < l.length(); i += o.wrap - 1) {
            w.write(" " + l.substring(i, Math.min(l.length(), i + o.wrap - 1)) + o.eol);
        }
    }

    /** RFC 2849 SAFE-STRING: ASCII without NUL, CR or LF, not starting with a space, colon or "<", and no trailing space. */
    static boolean safe(String s) {
        if (s.isEmpty()) {
            return true;
        }
        char first = s.charAt(0);
        if (first == ' ' || first == ':' || first == '<' || s.charAt(s.length() - 1) == ' ') {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == 0 || c == '\r' || c == '\n' || c > 0x7e) {
                return false;
            }
        }
        return true;
    }

    // ---- CSV ------------------------------------------------------------------------------------

    private void row(List<String> cells) throws IOException {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < cells.size(); i++) {
            if (i > 0) {
                b.append(o.delimiter);
            }
            String c = cells.get(i);
            if (o.formulaGuard && !c.isEmpty() && "=+-@\t\r".indexOf(c.charAt(0)) >= 0) {
                c = "'" + c;
            }
            if (c.contains(o.delimiter) || c.contains(o.quote) || c.contains("\n") || c.contains("\r")) {
                c = o.quote + c.replace(o.quote, o.quote + o.quote) + o.quote;
            }
            b.append(c);
        }
        w.write(b + o.eol);
    }

    // ---- values ---------------------------------------------------------------------------------

    /** An attribute's values as text: binary as base64 (a GUID as 32 hex digits), withheld ones as "(withheld)". */
    private static List<String> texts(Ldap.Entry e, String attribute) {
        List<Object> vs = e.attributes().getOrDefault(attribute.toLowerCase(Locale.ROOT), List.of());
        List<String> out = new ArrayList<>();
        for (Object v : vs) {
            if (v instanceof Secrets.Withheld) {
                out.add("(withheld)");
            } else if (v instanceof byte[] b) {
                out.add(attribute.equalsIgnoreCase("GUID") ? HexFormat.of().formatHex(b) : Base64.getEncoder().encodeToString(b));
            } else {
                out.add(String.valueOf(v));
            }
        }
        return out;
    }

    /** The entry's attribute keys in name order. */
    private static List<String> names(Ldap.Entry e) {
        return e.attributes().keySet().stream().sorted().toList();
    }

    /** The value of the DN's first RDN. */
    static String name(String dn) {
        if (dn.isEmpty()) {
            return "";
        }
        javax.naming.ldap.Rdn r = Names.leaf(dn);
        return r == null ? dn : String.valueOf(r.getValue());
    }
}
