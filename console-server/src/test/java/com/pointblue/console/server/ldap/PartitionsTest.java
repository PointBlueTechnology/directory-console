package com.pointblue.console.server.ldap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.pointblue.console.server.http.EdirAccess;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.Test;

/** Decoding what eDirectory sends for partitions, replicas, indexes and addresses (shapes read on ig4, 2026-10-11). */
public class PartitionsTest {

    private static byte[] seq(byte[]... parts) {
        return Ber.tlv(0x30, Ber.concat(parts));
    }

    private static byte[] str(String s) {
        return Ber.tlv(0x04, s.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] i(long v) {
        return Ber.integer(0x02, v);
    }

    @Test
    public void getReplicaInfoFieldsAreInJldapsOrder() {
        // partitionID, state, modTime, purgeTime, localPartitionID, partitionDN, type (state in the high 16 bits), flags
        byte[] r = Ber.concat(i(32866), i(0), i(1791753112L), i(1791753107L), i(6), str("o=data"), i(0x310001), i(1));
        Partitions.ReplicaInfo info = Partitions.decodeInfo(r);
        assertEquals("o=data", info.partitionDn());
        assertEquals(32866, info.partitionId());
        assertEquals("the low 16 bits", 1, info.type());
        assertEquals("split state 1 in the high bits", 0x31, info.transition());
        assertEquals("not the replica number", 6, info.localPartitionId());
        assertEquals(1, info.flags());
        assertEquals(Partitions.Type.READ_WRITE, Partitions.Type.of(info.type()));
    }

    @Test
    public void aReplicaValueDecodesServerTypeNumberAndAddresses() {
        byte[] tcp = HexFormat.of().parseHex("020cac110251");
        byte[] url = "http://172.17.2.81:8028/portal".getBytes(StandardCharsets.UTF_16LE);
        byte[] v = seq(str("cn=idm-ig4,ou=servers,o=system"), i(0), i(32866), i(1),
            seq(seq(i(9), Ber.tlv(0x04, tcp)), seq(i(8), Ber.tlv(0x04, tcp)), seq(i(13), Ber.tlv(0x04, url))));
        Partitions.ReplicaPointer p = Partitions.decodePointer(v);
        assertEquals("cn=idm-ig4,ou=servers,o=system", p.serverDn());
        assertEquals(0, p.type());
        assertEquals(32866, p.partitionId());
        assertEquals(1, p.number());
        assertEquals(List.of(new Partitions.Address(9, "172.17.2.81:524"), new Partitions.Address(8, "172.17.2.81:524"),
            new Partitions.Address(13, "http://172.17.2.81:8028/portal")), p.addresses());
    }

    @Test
    public void indexDefinitionsAndNetworkAddresses() {
        Map<String, Object> ix = EdirAccess.index("0$GnSnIndex$0$0$0$1$Given Name$Surname");
        assertEquals("GnSnIndex", ix.get("name"));
        assertEquals("value", ix.get("rule"));
        assertEquals("user", ix.get("type"));
        assertEquals(List.of("Given Name", "Surname"), ix.get("attributes"));
        assertEquals(true, ix.get("removable"));
        Map<String, Object> sys = EdirAccess.index("0$CN_SS$0$2$1$1$CN");
        assertEquals("substring", sys.get("rule"));
        assertEquals(false, sys.get("removable"));
        assertNull(EdirAccess.index("garbage"));

        byte[] na = Ber.concat("9#".getBytes(StandardCharsets.US_ASCII), HexFormat.of().parseHex("020cac110251"));
        assertEquals("tcp 172.17.2.81:524", EdirAccess.networkAddress(na));
        assertNull("IPX and others are not shown", EdirAccess.networkAddress(Ber.concat("0#".getBytes(StandardCharsets.US_ASCII), new byte[12])));
        assertTrue(EdirAccess.newOid().matches("2\\.25\\.[0-9]{1,19}"));
    }

    @Test
    public void requestsAreEncodedAsJldapDoes() {
        // split: INTEGER flags then the container's DN, back to back (no SEQUENCE)
        assertEquals("020101" + "0406" + HexFormat.of().formatHex("o=data".getBytes(StandardCharsets.UTF_8)),
            HexFormat.of().formatHex(Ber.concat(Ber.integer(0x02, Partitions.ENSURE_SERVERS_UP), Partitions.octets("o=data"))));
    }
}
