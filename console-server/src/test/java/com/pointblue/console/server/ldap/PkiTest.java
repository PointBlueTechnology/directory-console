package com.pointblue.console.server.ldap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.Test;

public class PkiTest {

    @Test
    public void dnsAreSentInEdirectorysDottedForm() {
        assertEquals("cn=edir1.ou=servers.o=system", Pki.dotted("cn=edir1,ou=servers,o=system"));
        assertEquals("a dot in a value is escaped; a comma is not special there", "cn=a,b.ou=c\\.d.o=e", Pki.dotted("cn=a\\,b,ou=c.d,o=e"));
    }

    @Test
    public void theRequestIsTwoOctetStringsOneAfterTheOther() {
        byte[] v = Pki.request("getCertificates", "{}");
        assertEquals(0x04, v[0]);
        assertEquals(15, v[1]);
        assertEquals(0x04, v[17]);
        assertEquals(2, v[18]);
    }

    @Test
    public void responsesAreJsonInAnOctetStringAndRefusalsCarryACode() throws Exception {
        byte[] ok = Ber.tlv(0x04, "{\n\t\"certificates\":\t[]\n}".getBytes(StandardCharsets.UTF_8));
        assertEquals(List.of(), Pki.decode(ok).get("certificates"));
        assertEquals(Map.of(), Pki.decode(null));
        Pki.Refused r = assertThrows(Pki.Refused.class, () -> Pki.decode(Ber.tlv(0x04, "{\"code\":\t-1214,\"message\":\"pki error: bad request syntax\"}".getBytes(StandardCharsets.UTF_8))));
        assertEquals(-1214, r.code);
        assertEquals("pki error: bad request syntax (-1214)", r.getMessage());
        assertEquals(-610, assertThrows(Pki.Refused.class, () -> Pki.decode(Ber.tlv(0x04, "{\"code\":-610}".getBytes(StandardCharsets.UTF_8)))).code);
    }

    @Test
    public void payloadsUseIdentityConsolesCodes() {
        Map<String, Object> p = Pki.payload(new Pki.Spec("x", "ec256", 0, "sha384", 3, "cn=x,o=acme", List.of("dns:x.example", "ip:10.0.0.1", "email:a@b.c", "uri:https://x"), true, null), true);
        assertEquals(2, p.get("keyAlgorithm"));
        assertEquals(256, p.get("keySize"));
        assertEquals("ECDSA with SHA-384", 128, p.get("signatureAlgorithm"));
        assertEquals(0x8000, p.get("keyUsage"));
        assertEquals("server authentication", 2, p.get("extendedKeyUsage"));
        assertEquals(1, p.get("allowExportPrivateKey"));
        assertEquals("cn=x.o=acme", p.get("subjectDN"));
        assertEquals(List.of(Map.of("type", 2, "value", "x.example"), Map.of("type", 7, "value", "10.0.0.1"), Map.of("type", 1, "value", "a@b.c"),
            Map.of("type", 6, "value", "https://x")), p.get("subjectAltNames"));
    }
}
