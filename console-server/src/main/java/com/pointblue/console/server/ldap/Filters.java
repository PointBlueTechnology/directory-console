package com.pointblue.console.server.ldap;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The structured search filter (Design Proposal for Safe Object Identity, section 5.5) as an LDAP filter
 * whose values are all JNDI arguments ({@code {0}}, {@code {1}}…), escaped by JNDI per RFC 4515. Wildcards
 * are operators, so a {@code *}, {@code (}, {@code )} or {@code \} in a value is ordinary text.
 *
 * <pre>
 * {"and": [ {"eq": {"objectClass": "inetOrgPerson"}}, {"prefix": {"cn": "Smith (Admin"}},
 *           {"not": {"present": "loginDisabled"}} ]}
 * </pre>
 */
public final class Filters {

    /** At most this many nodes in one filter. */
    static final int MAX_NODES = 200;

    /** An LDAP filter template and its arguments. */
    public record Built(String filter, Object[] args) {
    }

    private Filters() {
    }

    public static Built build(Object spec) {
        List<Object> args = new ArrayList<>();
        StringBuilder b = new StringBuilder();
        int[] nodes = {0};
        node(spec, b, args, nodes, 0);
        return new Built(b.toString(), args.toArray());
    }

    private static void node(Object spec, StringBuilder b, List<Object> args, int[] nodes, int depth) {
        if (++nodes[0] > MAX_NODES || depth > 20) {
            throw new IllegalArgumentException("the filter is too large");
        }
        if (!(spec instanceof Map<?, ?> m) || m.size() != 1) {
            throw new IllegalArgumentException("each filter node is an object with exactly one operator");
        }
        Map.Entry<?, ?> e = m.entrySet().iterator().next();
        String op = String.valueOf(e.getKey());
        Object v = e.getValue();
        switch (op) {
            case "and", "or" -> {
                if (!(v instanceof List<?> l) || l.isEmpty()) {
                    throw new IllegalArgumentException(op + " takes a non-empty list");
                }
                b.append('(').append(op.equals("and") ? '&' : '|');
                for (Object o : l) {
                    node(o, b, args, nodes, depth + 1);
                }
                b.append(')');
            }
            case "not" -> {
                b.append("(!");
                node(v, b, args, nodes, depth + 1);
                b.append(')');
            }
            case "present" -> b.append('(').append(attribute(v)).append("=*)");
            case "eq", "prefix", "suffix", "contains", "gte", "lte", "approx" -> {
                if (!(v instanceof Map<?, ?> av) || av.size() != 1) {
                    throw new IllegalArgumentException(op + " takes {\"attribute\": \"value\"}");
                }
                Map.Entry<?, ?> a = av.entrySet().iterator().next();
                String attr = attribute(a.getKey());
                Object value = a.getValue();
                if (!(value instanceof String) && !(value instanceof Number) && !(value instanceof Boolean)) {
                    throw new IllegalArgumentException(op + " on " + attr + " takes a string");
                }
                String s = value instanceof Boolean x ? (x ? "TRUE" : "FALSE") : String.valueOf(value);
                Object arg = attr.equalsIgnoreCase("GUID") && Names.guid(s) ? Names.guidBytes(s) : s;
                String n = "{" + args.size() + "}";
                args.add(arg);
                b.append('(').append(attr);
                switch (op) {
                    case "eq" -> b.append('=').append(n);
                    case "prefix" -> b.append('=').append(n).append('*');
                    case "suffix" -> b.append("=*").append(n);
                    case "contains" -> b.append("=*").append(n).append('*');
                    case "gte" -> b.append(">=").append(n);
                    case "lte" -> b.append("<=").append(n);
                    default -> b.append("~=").append(n);
                }
                b.append(')');
            }
            default -> throw new IllegalArgumentException("unknown filter operator " + op
                + "; use eq, prefix, suffix, contains, present, gte, lte, approx, and, or, not");
        }
    }

    /**
     * Whether {@code f} is one parenthesized filter, so wrapping it in {@code (&…)} cannot change its
     * structure. A parenthesis inside a value is escaped ({@code \\28}, {@code \\29}) in LDAP filter text,
     * so every raw parenthesis is structural.
     */
    public static boolean single(String f) {
        if (f == null || f.length() < 3 || f.charAt(0) != '(' || f.charAt(f.length() - 1) != ')') {
            return false;
        }
        int depth = 0;
        for (int i = 0; i < f.length(); i++) {
            char c = f.charAt(i);
            if (c == '\\') {
                i += 2;
            } else if (c == '(') {
                depth++;
            } else if (c == ')') {
                depth--;
                if (depth == 0 && i != f.length() - 1) {
                    return false;
                }
            }
            if (depth < 0) {
                return false;
            }
        }
        return depth == 0;
    }

    private static String attribute(Object a) {
        String s = String.valueOf(a);
        if (!Names.attributeName(s)) {
            throw new IllegalArgumentException("not an attribute name: " + s);
        }
        return s;
    }
}
