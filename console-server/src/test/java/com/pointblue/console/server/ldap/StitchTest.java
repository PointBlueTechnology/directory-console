package com.pointblue.console.server.ldap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.Test;

/** Laying a large container's sorted segments end to end, when eDirectory's sizes are only estimates. */
public class StitchTest {

    private static List<Ldap.Entry> entries(String prefix, int n) {
        List<Ldap.Entry> out = new ArrayList<>();
        for (int i = 1; i <= n; i++) {
            out.add(new Ldap.Entry("cn=" + prefix + i + ",o=acme", Map.of(), Map.of()));
        }
        return out;
    }

    /** A segment that reports {@code reported} entries but holds only {@code real}, as VLV's content count can. */
    private static Ldap.Part part(int reported, List<Ldap.Entry> real) {
        return new Ldap.Part(reported, (local, want) -> real.subList(Math.min(local - 1, real.size()), Math.min(real.size(), local - 1 + want)));
    }

    private static List<String> names(Ldap.Stitched s) {
        return s.entries().stream().map(Ldap.Entry::dn).toList();
    }

    @Test
    public void segmentsAreLaidEndToEnd() throws Exception {
        List<Ldap.Part> parts = List.of(part(3, entries("a", 3)), part(2, entries("b", 2)));
        assertEquals(List.of("cn=a3,o=acme", "cn=b1,o=acme", "cn=b2,o=acme"), names(Ldap.stitch(parts, 3, 10)));
    }

    @Test
    public void aSegmentShorterThanItsReportedSizeDoesNotBreakTheNext() throws Exception {
        // the first segment reports 1500 but returns 1490: the listing must not read before the second's start
        List<Ldap.Part> parts = List.of(part(1500, entries("a", 1490)), part(300, entries("b", 300)));
        Ldap.Stitched s = Ldap.stitch(parts, 1481, 50);
        List<String> n = names(s);
        assertEquals("the ten that exist, then the second segment from its start", "cn=a1481,o=acme", n.get(0));
        assertEquals("cn=a1490,o=acme", n.get(9));
        assertEquals("cn=b1,o=acme", n.get(10));
        assertEquals(50, n.size());
        // a page that starts inside the missing part still lands in the second segment
        assertEquals("cn=b1,o=acme", names(Ldap.stitch(parts, 1495, 5)).get(0));
    }

    @Test
    public void anEntryListedTwiceIsKeptOnce() throws Exception {
        List<Ldap.Entry> twice = new ArrayList<>(entries("a", 2));
        twice.add(twice.get(0));
        Ldap.Stitched s = Ldap.stitch(List.of(part(3, twice)), 1, 10);
        assertEquals(2, s.entries().size());
        assertTrue(s.repeats());
    }

    @Test
    public void aPageBeyondTheEndIsEmpty() throws Exception {
        assertEquals(List.of(), names(Ldap.stitch(List.of(part(3, entries("a", 3))), 10, 5)));
    }
}
