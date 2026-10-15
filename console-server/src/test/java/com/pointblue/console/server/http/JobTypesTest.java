package com.pointblue.console.server.http;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.Test;

/** Job types from the engine's DiscoverJobs answer (FakeEngine's, trimmed from ig4's). */
public class JobTypesTest {

    private static byte[] answer() {
        return com.pointblue.console.server.idm.FakeEngine.JOB_TYPES.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    public void typesAreFilteredByContainment() {
        List<Map<String, Object>> driver = JobTypes.types(answer(), "DirXML-Driver");
        assertEquals(1, driver.size());
        Map<String, Object> t = driver.get(0);
        assertEquals("com.novell.nds.dirxml.job.trigger.Trigger", t.get("type"));
        assertEquals("the localization key is dropped", "Subscriber channel trigger", t.get("displayName"));
        assertEquals("0 1 * * 0", t.get("schedule"));
        assertEquals(false, t.get("scopeRequired"));
        List<Map<String, Object>> set = JobTypes.types(answer(), "DirXML-DriverSet");
        assertEquals(List.of("Driver Health"), set.stream().map(x -> x.get("displayName")).toList());
        assertEquals(true, set.get(0).get("scopeRequired"));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void parametersCarryTheirGroupStructure() {
        List<Map<String, Object>> p = (List<Map<String, Object>>) JobTypes.types(answer(), "DirXML-Driver").get(0).get("parameters");
        assertEquals(List.of("process-unassociated", "submit-method", "start-driver", "days", "interval", "pw"), p.stream().map(x -> x.get("name")).toList());
        Map<String, Object> method = p.get(1);
        assertEquals("submit-queue", method.get("value"));
        assertEquals(List.of(Map.of("value", "submit-queue", "label", "queue (use cache)"), Map.of("value", "submit-direct", "label", "direct (bypass cache)")), method.get("choices"));
        Map<String, Object> start = p.get(2);
        assertEquals(1, start.get("depth"));
        assertEquals("submit-method", start.get("parent"));
        assertEquals("submit-direct", start.get("activeValue"));
        assertEquals(List.of("7"), p.get(3).get("value"));
        assertNull(p.get(0).get("parent"));
    }

    @Test
    public void buildSetsTheChosenValuesAndKeepsTheRest() {
        var agg = JobTypes.aggregation(answer(), "com.novell.nds.dirxml.job.trigger.Trigger", "DirXML-Driver");
        String xml = new String(JobTypes.build(agg, true, null, Map.of("submit-method", "submit-direct", "start-driver", "false", "days", List.of("7", "14"), "interval", "5")),
            StandardCharsets.UTF_8);
        assertTrue(xml, xml.contains("disabled=\"true\""));
        assertTrue("no schedule: the attribute goes", !xml.contains("schedule="));
        assertTrue(xml.contains("<value>submit-direct</value>"));
        assertTrue(xml.contains("name=\"start-driver\" type=\"boolean\"><value>false</value>"));
        assertTrue(xml.contains("<value><item>7</item><item>14</item></value>"));
        assertTrue(xml.contains("<value>5</value>"));
        assertTrue("the translations are kept, as a job object keeps them", xml.contains("<xliff"));
        assertTrue(xml.startsWith("<?xml") && xml.contains("<job-aggregation>"));
        assertNull("a type offered only for drivers is not one for a driver set",
            JobTypes.aggregation(answer(), "com.novell.nds.dirxml.job.trigger.Trigger", "DirXML-DriverSet"));
    }

    @Test
    public void valuesAreCheckedAgainstTheirType() {
        var agg = JobTypes.aggregation(answer(), "com.novell.nds.dirxml.job.trigger.Trigger", "DirXML-Driver");
        assertThrows(IllegalArgumentException.class, () -> JobTypes.build(agg, false, null, Map.of("submit-method", "sideways")));
        assertThrows(IllegalArgumentException.class, () -> JobTypes.build(agg, false, null, Map.of("process-unassociated", "yes")));
        assertThrows(IllegalArgumentException.class, () -> JobTypes.build(agg, false, null, Map.of("interval", "soon")));
        assertThrows(IllegalArgumentException.class, () -> JobTypes.build(agg, false, null, Map.of("days", "7")));
        assertThrows("a named password is not set here", IllegalArgumentException.class, () -> JobTypes.build(agg, false, null, Map.of("pw", "secret")));
        assertThrows(IllegalArgumentException.class, () -> JobTypes.build(agg, false, null, Map.of("nonesuch", "1")));
        String kept = new String(JobTypes.build(agg, false, "0 3 * * *", Map.of()), StandardCharsets.UTF_8);
        assertTrue(kept.contains("schedule=\"0 3 * * *\""));
    }
}
