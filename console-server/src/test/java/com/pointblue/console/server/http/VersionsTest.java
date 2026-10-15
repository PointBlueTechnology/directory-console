package com.pointblue.console.server.http;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.Test;

/** The statistics job's telemetry, as a lab tree has it: Identity Manager's version, the host, and each driver's shim version. */
public class VersionsTest {

    private static final String XML = "<TelemetryResults><Telemetry><TimeStamp>Sat Oct 10 00:00:00 CDT 2026</TimeStamp>"
        + "<Software><ProductInfo><ProductName>NetIQ Identity Manager</ProductName><VersionFull>4.8.7.0000 AE</VersionFull><Edition>Advanced</Edition>"
        + "<PatchApplied/></ProductInfo><Host><OSName>Linux</OSName><OSVersion>5.14.21</OSVersion><HostType>Virtual</HostType><HostName>idm1</HostName>"
        + "<HostIP>192.0.2.81</HostIP></Host><OtherItems><DriverSet Name=\"driverset1\"><DriverGroup id=\"AD\"><Driver entry-id=\"1\"><Name>Active Directory Driver</Name>"
        + "<Version>4.1.2.0</Version><DriverID>AD</DriverID><UsageCount active=\"1\" inactive=\"0\" system=\"0\" total=\"1\"/></Driver></DriverGroup>"
        + "<DriverGroup id=\"\"><Driver entry-id=\"2\"><Name>HR Feed</Name><Version/><DriverID/></Driver></DriverGroup></DriverSet></OtherItems></Software>"
        + "</Telemetry></TelemetryResults>";

    @Test
    public void readsTheTelemetry() {
        Map<String, Object> t = Versions.telemetry(XML.getBytes(StandardCharsets.UTF_8));
        assertEquals("4.8.7.0000 AE", t.get("version"));
        assertEquals("Advanced", t.get("edition"));
        assertEquals("Linux 5.14.21", t.get("os"));
        assertEquals("CDT midnight is 05:00 UTC", "2026-10-10T05:00:00Z", t.get("when"));
        assertNull("an empty element is no value", t.get("patch"));
        List<?> drivers = (List<?>) t.get("drivers");
        Map<?, ?> ad = (Map<?, ?>) drivers.get(0);
        assertEquals("4.1.2.0", ad.get("version"));
        assertEquals(1, ((Map<?, ?>) ad.get("usage")).get("active"));
        assertNull(((Map<?, ?>) drivers.get(1)).get("version"));
    }

    @Test
    public void refusesOtherDocuments() {
        assertNull(Versions.telemetry("<other/>".getBytes(StandardCharsets.UTF_8)));
        assertNull(Versions.telemetry("not xml".getBytes(StandardCharsets.UTF_8)));
        assertNull(Versions.iso("yesterday"));
    }
}
