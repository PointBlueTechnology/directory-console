package com.pointblue.console.server.ldap;

import com.pointblue.console.server.tls.TestPki;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryExtendedOperationHandler;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.InMemoryRequestHandler;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.ResultCode;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

/**
 * An in-memory LDAPS server standing in for eDirectory in tests: the test PKI's server certificate,
 * no schema checking (eDirectory attributes such as groupMembership and loginDisabled), and the
 * GetEffectivePrivileges extended operation answering a fixed value and recording what it was asked.
 */
public final class FakeEdir implements AutoCloseable {

    public final TestPki pki;
    public final InMemoryDirectoryServer server;
    /** What GetEffectivePrivileges was asked: target, trustee, attribute. */
    public final List<String[]> privilegeRequests = new ArrayList<>();
    public volatile int privileges = 0x1f;

    public FakeEdir(String... ldif) throws Exception {
        pki = new TestPki("ACME_TREE");
        TestPki.Server cert = pki.server("edir1", List.of("127.0.0.1", "localhost"));
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("s", cert.key().getPrivate(), "pw".toCharArray(), new java.security.cert.X509Certificate[] {cert.cert(), pki.ca});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "pw".toCharArray());
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);

        InMemoryDirectoryServerConfig cfg = new InMemoryDirectoryServerConfig("o=acme", "o=system");
        cfg.setSchema(null);
        cfg.setListenerConfigs(InMemoryListenerConfig.createLDAPSConfig("ldaps", InetAddress.getLoopbackAddress(), 0,
            ctx.getServerSocketFactory(), null));
        cfg.addExtendedOperationHandler(new InMemoryExtendedOperationHandler() {
            @Override
            public String getExtendedOperationHandlerName() {
                return "effective privileges";
            }

            @Override
            public List<String> getSupportedExtendedRequestOIDs() {
                return List.of(Ldap.EFFECTIVE_PRIVILEGES);
            }

            @Override
            public ExtendedResult processExtendedOperation(InMemoryRequestHandler handler, int messageID, ExtendedRequest request) {
                ByteBuffer v = ByteBuffer.wrap(request.getValue().getValue());
                String[] parts = new String[3];
                for (int i = 0; i < 3; i++) {
                    if (v.get() != 0x04) {
                        return new ExtendedResult(messageID, ResultCode.PROTOCOL_ERROR, "expected an OCTET STRING", null, null, null, null, null);
                    }
                    int len = v.get() & 0xff;
                    if (len == 0x81) {
                        len = v.get() & 0xff;
                    }
                    byte[] b = new byte[len];
                    v.get(b);
                    parts[i] = new String(b, StandardCharsets.UTF_8);
                }
                privilegeRequests.add(parts);
                return new ExtendedResult(messageID, ResultCode.SUCCESS, null, null, null, "2.16.840.1.113719.1.27.100.34",
                    new ASN1OctetString(new ASN1Integer(privileges).encode()), null);
            }
        });
        server = new InMemoryDirectoryServer(cfg);
        server.add("dn: o=acme", "objectClass: organization", "o: acme");
        server.add("dn: o=system", "objectClass: organization", "o: system");
        for (String entry : ldif) {
            server.add(entry.split("\n"));
        }
        server.startListening();
    }

    public int port() {
        return server.getListenPort();
    }

    @Override
    public void close() {
        server.shutDown(true);
    }
}
