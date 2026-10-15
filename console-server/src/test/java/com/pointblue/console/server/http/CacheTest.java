package com.pointblue.console.server.http;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.List;
import java.util.Map;
import org.junit.Test;

/** The Cache Inspector's parsing: the driver statistics' cache section and a cached event, as the engine gives them. */
public class CacheTest {

    @Test
    public void summaryFromTheDriverStatistics() {
        String stats = "<?xml version=\"1.0\"?><driver-info driver-dn=\"CN=AD\"><subscriber><cache><size>663</size><unprocessed-size>663</unprocessed-size>"
            + "<transactions><oldest>20261013151206.016Z</oldest><newest>20261013161447.655Z</newest><counts><add>2</add><remove>2</remove></counts>"
            + "</transactions></cache><operations/></subscriber><publisher/></driver-info>";
        Map<String, Object> s = Cache.summary(stats);
        assertEquals(663L, s.get("size"));
        assertEquals("2026-10-13T15:12:06.016Z", s.get("oldest"));
        assertEquals(Map.of("add", 2L, "remove", 2L), s.get("counts"));
        assertNull(Cache.summary("<driver-info/>"));
        assertNull(Cache.summary("not xml"));
    }

    @Test
    public void anEventsParts() {
        String xds = "<nds dtdversion=\"4.0\"><source/><input><add cached-time=\"20261013151206.041Z\" class-name=\"User\" event-id=\"idm1#1\""
            + " src-dn=\"\\T\\data\\u1\"><add-attr attr-name=\"Surname\"><value>a</value></add-attr><add-attr attr-name=\"Surname\"><value>b</value></add-attr>"
            + "</add></input></nds>";
        List<org.w3c.dom.Element> events = Cache.events(xds);
        Map<String, Object> e = Cache.event(events.get(0));
        assertEquals("add", e.get("type"));
        assertEquals("idm1#1", e.get("eventId"));
        assertEquals("\\T\\data\\u1", e.get("srcDn"));
        assertEquals("each attribute once", List.of("Surname"), e.get("attributes"));
        assertEquals("2026-10-13T15:12:06.041Z", e.get("cachedTime"));
    }

    @Test
    public void eachChannelsCountersByGroup() {
        String stats = "<driver-info><subscriber><cache><size>10</size></cache><operations last-reset-time=\"20240215163705.663Z\">"
            + "<reported-events><modify>162</modify><add>320</add></reported-events><commands/></operations></subscriber>"
            + "<publisher><operations><command-results><status>541</status></command-results></operations></publisher></driver-info>";
        Map<String, Object> d = Statistics.driver(stats);
        Map<?, ?> sub = (Map<?, ?>) d.get("subscriber");
        assertEquals("2024-02-15T16:37:05.663Z", sub.get("lastReset"));
        assertEquals(Map.of("modify", 162L, "add", 320L), ((Map<?, ?>) sub.get("groups")).get("reported-events"));
        assertEquals(Map.of("status", 541L), ((Map<?, ?>) ((Map<?, ?>) d.get("publisher")).get("groups")).get("command-results"));
        assertEquals(10L, ((Map<?, ?>) d.get("cache")).get("size"));
        assertEquals(Map.of(), Statistics.driver("not xml"));
    }
}
