package com.pointblue.console.server.http;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.Test;

public class MonitoringTest {

    @Test
    public void cefValuesRoundTripAndKeepWhatIsNotUnderstood() {
        List<String> stored = List.of("DSNoReplicatedEvents=0", "loglargevalues=true", "cefEvents=LOGIN$$LDAP_BIND", "dsobject=User$Group",
            "dsExcludeList=$$Login Time$Revision", "futureKey=something");
        Map<String, Object> s = Monitoring.parseCef(stored);
        assertEquals(false, s.get("noReplicatedEvents"));
        assertEquals(true, s.get("logLargeValues"));
        assertEquals(List.of("LOGIN", "LDAP_BIND"), s.get("events"));
        assertEquals(List.of("User", "Group"), s.get("objectClasses"));
        assertEquals(Map.of("classes", List.of(), "attributes", List.of("Login Time", "Revision")), s.get("exclude"));
        assertEquals(List.of("futureKey=something"), s.get("unknown"));
        @SuppressWarnings("unchecked")
        List<String> back = Monitoring.cefValues(s, (List<String>) s.get("unknown"));
        assertEquals(List.of("DSNoReplicatedEvents=0", "loglargevalues=true", "logattributevalues=false", "logencryptedattributevalues=false",
            "cefEvents=LOGIN$$LDAP_BIND", "dsobject=User$Group", "dsExcludeList=$$Login Time$Revision", "futureKey=something"), back);
        assertThrows(Http.Problem.class, () -> Monitoring.cefValues(Map.of("events", List.of("EVERYTHING")), List.of()));
        assertThrows(Http.Problem.class, () -> Monitoring.cefValues(Map.of("objectClasses", List.of("a$b")), List.of()));
    }

    private static byte[] record(int number, int active, int failure, int interval) {
        ByteBuffer b = ByteBuffer.allocate(36).order(ByteOrder.LITTLE_ENDIAN);
        b.put("1.3.6.1.4.1.23.2.98".getBytes(StandardCharsets.US_ASCII));
        b.position(20);
        b.putInt(number).putInt(active).putInt(failure).putInt(interval);
        return b.array();
    }

    @Test
    public void trapRecordsChangeOnlyTheFieldsNamed() {
        byte[] config = new byte[72];
        System.arraycopy(record(1, 0, 0, 5), 0, config, 0, 36);
        System.arraycopy(record(2, 1, 1, 0), 0, config, 36, 36);
        byte[] names = "ndsCreateEntry\0ndsDeleteEntry\0".getBytes(StandardCharsets.ISO_8859_1);
        List<Monitoring.Trap> traps = Monitoring.traps(config, names);
        assertEquals(new Monitoring.Trap(1, "ndsCreateEntry", false, false, 5), traps.get(0));
        assertEquals(new Monitoring.Trap(2, "ndsDeleteEntry", true, true, 0), traps.get(1));

        byte[] changed = Monitoring.withTraps(config, Map.of(1, Map.of("active", true, "interval", 300)));
        assertEquals(new Monitoring.Trap(1, "ndsCreateEntry", true, false, 300), Monitoring.traps(changed, names).get(0));
        assertArrayEquals("the other record is untouched", java.util.Arrays.copyOfRange(config, 36, 72), java.util.Arrays.copyOfRange(changed, 36, 72));
        assertArrayEquals("and back", config, Monitoring.withTraps(changed, Map.of(1, Map.of("active", false, "interval", 5))));
        assertThrows(Http.Problem.class, () -> Monitoring.withTraps(config, Map.of(9, Map.of("active", true))));
        assertThrows(Http.Problem.class, () -> Monitoring.withTraps(config, Map.of(1, Map.of("interval", -1))));
    }
}
