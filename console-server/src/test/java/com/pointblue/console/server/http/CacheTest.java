package com.pointblue.console.server.http;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.pointblue.dirxml.dev.operate.Operate;

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
    public void charactersXmlForbidsAreRemovedBeforeParsing() {
        assertEquals("a\tb\nc", Cache.clean("a\u0001\tb\n\u001Fc"));
        assertEquals("ok", Cache.clean("o&#1;&#x0B;&#31;&#xfffe;k"));
        assertEquals("tab, newline and return references stay", "&#9;&#10;&#13;&#x9;&#xA;&#xD;&#65;", Cache.clean("&#9;&#10;&#13;&#x9;&#xA;&#xD;&#65;"));
        assertEquals("other scripts and emoji stay", "Ωλ漢🔑", Cache.clean("Ωλ漢🔑"));
        String xds = "<nds><input><modify event-id=\"e1\" class-name=\"User\"><modify-attr attr-name=\"Description\"><add-value><value>x\u0002y&#3;</value>"
            + "</add-value></modify-attr></modify></input></nds>";
        assertEquals("e1", Cache.event(Cache.events(xds).get(0)).get("eventId"));
    }

    @Test
    public void aPageThatIsNotXmlIsShownAsUnreadableAndTheListGoesOn() {
        String good = "<nds><input><add event-id=\"e%d\" class-name=\"User\"/></input></nds>";
        Map<Integer, Operate.CachePage> pages = Map.of(
            0, new Operate.CachePage(String.format(good, 1), 10),
            10, new Operate.CachePage("<nds><input><add event-id=\"broken\"", 20),
            20, new Operate.CachePage("<nds><input><add event-id=\"e3\" class-name=\"User\"><add-attr attr-name=\"CN\"><value>a\u0007</value></add-attr></add></input></nds>", 30),
            30, new Operate.CachePage("<nds><input/></nds>", 40));
        Operate.Engine engine = (Operate.Engine) java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] {Operate.Engine.class},
            (proxy, m, args) -> {
                if (!m.getName().equals("viewCache")) {
                    throw new UnsupportedOperationException(m.getName());
                }
                return pages.getOrDefault((Integer) args[1], new Operate.CachePage("", 0));
            });
        Map<String, Object> out = Cache.events(engine, "cn=d", 0, 10);
        List<?> events = (List<?>) out.get("events");
        assertEquals("a page with no event ends the list", 3, events.size());
        Map<String, Object> broken = com.pointblue.dirxml.dev.json.Json.asMap(events.get(1));
        assertEquals("unreadable", broken.get("type"));
        assertEquals(10, broken.get("position"));
        assertNull("never chosen for delete", broken.get("eventId"));
        assertTrue(String.valueOf(broken.get("xml")).startsWith("<nds><input>"));
        Map<String, Object> cleaned = com.pointblue.dirxml.dev.json.Json.asMap(events.get(2));
        assertEquals("e3", cleaned.get("eventId"));
        assertEquals(true, cleaned.get("cleaned"));
        assertNull(com.pointblue.dirxml.dev.json.Json.asMap(events.get(0)).get("cleaned"));
        assertNull(out.get("next"));
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
