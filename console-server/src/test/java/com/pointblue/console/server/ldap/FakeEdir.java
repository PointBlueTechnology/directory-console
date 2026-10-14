package com.pointblue.console.server.ldap;

import com.pointblue.console.server.tls.TestPki;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryExtendedOperationHandler;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedAddRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedModifyRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ReadOnlyAddRequest;
import com.unboundid.ldap.sdk.ReadOnlyModifyRequest;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.ModifyRequest;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicLong;
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
 * Like eDirectory, every entry gets a 16-byte {@code GUID} and a {@code revision} that changes on each
 * modify; {@code cn=subschema,o=system} (named by the root DSE) holds eDirectory-style class and attribute descriptions (a sample of ig4's).
 */
public final class FakeEdir implements AutoCloseable {

    public final TestPki pki;
    public final InMemoryDirectoryServer server;
    /** What GetEffectivePrivileges was asked: target, trustee, attribute. */
    public final List<String[]> privilegeRequests = new ArrayList<>();
    public volatile int privileges = 0x1f;
    /** The authorization id of the last modify's RFC 4370 control ("dn:…"), or null when it had none. */
    public volatile String lastProxied;
    /** Partitions and replicas (empty until a test or the demo adds some). */
    public final FakePartitions partitions = new FakePartitions();
    /** PKI extended operations: server certificates as key material objects, user certificates in memory. */
    public final FakePki pkiOps;

    public FakeEdir(String... ldif) throws Exception {
        pki = new TestPki("ACME_TREE");
        pkiOps = new FakePki(pki);
        // names only the address the console uses: reaching it as "localhost" is a host-name mismatch, as behind NAT
        TestPki.Server cert = pki.server("edir1", List.of("127.0.0.1"));
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("s", cert.key().getPrivate(), "pw".toCharArray(), new java.security.cert.X509Certificate[] {cert.cert(), pki.ca});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "pw".toCharArray());
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);

        InMemoryDirectoryServerConfig cfg = new InMemoryDirectoryServerConfig("o=acme", "o=system");
        cfg.setSchema(null);
        // the in-memory server keeps cn=schema for itself; the root DSE names this fake's schema entry instead
        cfg.setRootDSEEntry(new com.unboundid.ldap.sdk.Entry("", new Attribute("objectClass", "top", "ds-root-dse"),
            new Attribute("subschemaSubentry", "cn=subschema,o=system"), new Attribute("namingContexts", "o=acme", "o=system"),
            new Attribute("vendorName", "FakeEdir"), new Attribute("dsaName", "cn=edir1,ou=servers,o=system")));
        SecureRandom random = new SecureRandom();
        AtomicLong revision = new AtomicLong(1);
        cfg.addInMemoryOperationInterceptor(new InMemoryOperationInterceptor() {
            @Override
            public void processAddRequest(InMemoryInterceptedAddRequest request) {
                ReadOnlyAddRequest r = request.getRequest();
                if (r.getDN().equalsIgnoreCase("cn=subschema,o=system")) {
                    return;
                }
                AddRequest a = r.duplicate();
                if (!a.hasAttribute("GUID")) {
                    byte[] g = new byte[16];
                    random.nextBytes(g);
                    a.addAttribute(new Attribute("GUID", g));
                }
                a.addAttribute("revision", String.valueOf(revision.incrementAndGet()));
                request.setRequest(a);
            }

            @Override
            public void processModifyRequest(InMemoryInterceptedModifyRequest request) {
                ReadOnlyModifyRequest r = request.getRequest();
                com.unboundid.ldap.sdk.Control proxied = r.getControl("2.16.840.1.113730.3.4.18");
                lastProxied = proxied == null || proxied.getValue() == null ? null : proxied.getValue().stringValue();
                java.util.List<Modification> mods = new ArrayList<>(r.getModifications());
                mods.add(new Modification(ModificationType.REPLACE, "revision", String.valueOf(revision.incrementAndGet())));
                request.setRequest(new ModifyRequest(r.getDN(), mods, r.getControls()));
            }
        });
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
        cfg.addExtendedOperationHandler(partitions);
        cfg.addExtendedOperationHandler(pkiOps);
        server = new InMemoryDirectoryServer(cfg);
        this.random = random;
        this.revision = revision;
        add("dn: o=acme", "objectClass: organization", "o: acme");
        add("dn: o=system", "objectClass: organization", "o: system");
        server.add(SCHEMA);
        for (String entry : ldif) {
            add(entry.split("\n"));
        }
        server.startListening();
    }

    /** A sample of eDirectory 9.2.8's schema (ig4), enough for the console's container and syntax decisions. */
    public static final String[] SCHEMA = {
        "dn: cn=subschema,o=system",
        "objectClass: subschema",
        "cn: schema",
        "objectClasses: ( 2.5.6.0 NAME 'Top' STRUCTURAL MUST objectClass MAY ( ACL $ GUID $ revision $ DirXML-Associations ) X-NDS_NONREMOVABLE '1' X-NDS_AMBIGUOUS_NAMING '1' X-NDS_AMBIGUOUS_CONTAINMENT '1' X-NDS_ACL_TEMPLATES '16#subtree#[Creator]#[Entry Rights]' )",
        "objectClasses: ( 2.5.6.4 NAME 'Organization' SUP ( ndsLoginProperties $ ndsContainerLoginProperties ) STRUCTURAL MUST o MAY ( description $ l ) X-NDS_NAMING 'o' X-NDS_CONTAINMENT ( 'Top' 'treeRoot' 'domain' ) X-NDS_NAME 'Organization' )",
        "objectClasses: ( 2.5.6.5 NAME 'organizationalUnit' SUP ( ndsLoginProperties $ ndsContainerLoginProperties ) STRUCTURAL MUST ou MAY ( description $ l ) X-NDS_NAMING 'ou' X-NDS_CONTAINMENT ( 'Locality' 'Organization' 'organizationalUnit' 'domain' ) X-NDS_NAME 'Organizational Unit' )",
        "objectClasses: ( 2.16.840.1.113719.1.1.6.1.30 NAME 'ndsLoginProperties' SUP Top ABSTRACT MAY ( loginDisabled $ groupMembership ) )",
        "objectClasses: ( 2.16.840.1.113719.1.1.6.1.31 NAME 'ndsContainerLoginProperties' SUP Top ABSTRACT MAY loginScript )",
        "objectClasses: ( 2.5.6.6 NAME 'Person' SUP ndsLoginProperties STRUCTURAL MUST ( cn $ sn ) MAY ( description $ telephoneNumber ) X-NDS_NAMING ( 'cn' 'uid' ) X-NDS_CONTAINMENT ( 'Organization' 'organizationalUnit' 'domain' ) X-NDS_NAME 'Person' X-NDS_NOT_CONTAINER '1' )",
        "objectClasses: ( 2.5.6.7 NAME 'organizationalPerson' SUP Person STRUCTURAL MAY ( ou $ title ) X-NDS_NAMING ( 'cn' 'ou' 'uid' ) X-NDS_NOT_CONTAINER '1' )",
        "objectClasses: ( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP organizationalPerson STRUCTURAL MAY ( groupMembership $ mail $ jpegPhoto $ uid ) X-NDS_NAME 'User' X-NDS_NOT_CONTAINER '1' )",
        "objectClasses: ( 2.5.6.9 NAME ( 'groupOfNames' 'group' 'groupOfUniqueNames' ) SUP Top STRUCTURAL MUST cn MAY ( description $ member $ owner ) X-NDS_NAMING 'cn' X-NDS_CONTAINMENT ( 'Organization' 'organizationalUnit' 'domain' ) X-NDS_NAME 'Group' X-NDS_NOT_CONTAINER '1' X-NDS_NONREMOVABLE '1' )",
        "objectClasses: ( 2.16.840.1.113719.1.1.6.1.33 NAME 'dynamicGroup' SUP groupOfNames STRUCTURAL MAY ( memberQueryURL $ excludedMember $ dgIdentity $ dgTimeOut ) X-NDS_NOT_CONTAINER '1' )",
        "objectClasses: ( 2.16.840.1.113719.1.1.6.1.34 NAME 'dynamicGroupAux' SUP Top AUXILIARY MAY ( memberQueryURL $ excludedMember $ dgIdentity $ dgTimeOut ) )",
        "objectClasses: ( 2.16.840.1.113719.1.1.6.1.45 NAME 'nestedGroupAux' AUXILIARY MAY ( groupMember $ excludedMember $ nestedConfig $ groupMembership ) )",
        "objectClasses: ( 2.5.6.1 NAME 'aliasObject' SUP Top STRUCTURAL MUST aliasedObjectName X-NDS_NAME 'Alias' X-NDS_NOT_CONTAINER '1' )",
        "objectClasses: ( 1.3.6.1.1.1.2.0 NAME 'posixAccount' SUP Top AUXILIARY MUST ( uidNumber $ gidNumber $ homeDirectory ) MAY loginShell )",
        "objectClasses: ( 2.16.840.1.113719.1.14.6.1.1 NAME 'DirXML-DriverSet' SUP Top STRUCTURAL MUST cn MAY ( description $ DirXML-DriverTraceLevel $ DirXML-XSLTraceLevel $ DirXML-JavaDebugPort $ DirXML-JavaTraceFile $ DirXML-TraceSizeLimit $ DirXML-TraceFileEncoding ) X-NDS_NAMING 'cn' X-NDS_CONTAINMENT ( 'Organization' 'organizationalUnit' ) )",
        "objectClasses: ( 2.16.840.1.113719.1.14.6.1.6 NAME 'DirXML-Resource' SUP Top STRUCTURAL MUST cn MAY ( DirXML-ContentType $ DirXML-Data $ DirXML-pkgGUID ) X-NDS_NAMING 'cn' )",
        "objectClasses: ( 2.16.840.1.113719.1.14.6.1.20 NAME 'DirXML-Library' SUP Top STRUCTURAL MUST cn X-NDS_NAMING 'cn' )",
        "objectClasses: ( 2.16.840.1.113719.1.14.6.1.13 NAME 'DirXML-Job' SUP Top STRUCTURAL MUST cn MAY ( XmlData $ DirXML-ServerList $ DirXML-Scope $ DirXML-TraceLevel $ DirXML-TraceFile ) X-NDS_NAMING 'cn' X-NDS_CONTAINMENT ( 'DirXML-Driver' 'DirXML-DriverSet' ) )",
        "objectClasses: ( 2.16.840.1.113719.1.14.6.1.2 NAME 'DirXML-Driver' SUP Top STRUCTURAL MUST cn MAY ( description $ DirXML-DriverTraceLevel $ DirXML-TraceLevel $ DirXML-TraceFile $ DirXML-TraceName $ DirXML-TraceSizeLimit $ DirXML-TraceFileEncoding ) X-NDS_NAMING 'cn' X-NDS_CONTAINMENT 'DirXML-DriverSet' )",
        "attributeTypes: ( 2.16.840.1.113719.1.14.4.1.3 NAME 'DirXML-Data' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 SINGLE-VALUE )",
        "attributeTypes: ( 2.16.840.1.113719.1.14.4.1.4 NAME 'DirXML-ContentType' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
        "attributeTypes: ( 2.16.840.1.113719.1.14.4.1.200 NAME 'DirXML-pkgGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
        "attributeTypes: ( 2.16.840.1.113719.1.14.4.1.104 NAME 'XmlData' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 SINGLE-VALUE )",
        "attributeTypes: ( 2.16.840.1.113719.1.14.4.1.6 NAME 'DirXML-ServerList' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
        "attributeTypes: ( 2.16.840.1.113719.1.14.4.1.105 NAME 'DirXML-Scope' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        "attributeTypes: ( 2.16.840.1.113719.1.14.4.1.25 NAME 'DirXML-DriverTraceLevel' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
        "attributeTypes: ( 2.16.840.1.113719.1.14.4.1.26 NAME 'DirXML-XSLTraceLevel' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
        "attributeTypes: ( 2.16.840.1.113719.1.14.4.1.27 NAME 'DirXML-JavaDebugPort' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
        "attributeTypes: ( 2.16.840.1.113719.1.14.4.1.28 NAME 'DirXML-JavaTraceFile' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
        "attributeTypes: ( 2.16.840.1.113719.1.14.4.1.51 NAME 'DirXML-TraceLevel' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
        "attributeTypes: ( 2.16.840.1.113719.1.14.4.1.52 NAME 'DirXML-TraceFile' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
        "attributeTypes: ( 2.16.840.1.113719.1.14.4.1.53 NAME 'DirXML-TraceName' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
        "attributeTypes: ( 2.16.840.1.113719.1.14.4.1.60 NAME 'DirXML-TraceSizeLimit' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
        "attributeTypes: ( 2.16.840.1.113719.1.14.4.1.81 NAME 'DirXML-TraceFileEncoding' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
        "attributeTypes: ( 2.16.840.1.113719.1.14.4.1.1 NAME 'DirXML-Associations' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-NDS_NAME 'DirXML-Associations' )",
        "attributeTypes: ( 2.5.4.0 NAME 'objectClass' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 X-NDS_NAME 'Object Class' )",
        "attributeTypes: ( 2.5.4.3 NAME ( 'cn' 'commonName' ) SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{64} X-NDS_NAME 'CN' X-NDS_LOWER_BOUND '1' X-NDS_UPPER_BOUND '64' )",
        "attributeTypes: ( 2.5.4.4 NAME ( 'sn' 'surname' ) SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{64} X-NDS_NAME 'Surname' )",
        "attributeTypes: ( 2.5.4.10 NAME ( 'o' 'organizationName' ) SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{64} X-NDS_NAME 'O' )",
        "attributeTypes: ( 2.5.4.11 NAME ( 'ou' 'organizationalUnitName' ) SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{64} X-NDS_NAME 'OU' )",
        "attributeTypes: ( 2.5.4.13 NAME 'description' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{1024} X-NDS_NAME 'Description' )",
        "attributeTypes: ( 2.16.840.1.113719.1.14.4.1.13 NAME 'DirXML-DriverStartOption' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE X-NDS_NEVER_SYNC '1' )",
        "attributeTypes: ( 2.5.4.31 NAME ( 'member' 'uniqueMember' ) SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 X-NDS_NAME 'Member' X-NDS_NONREMOVABLE '1' )",
        "attributeTypes: ( 2.16.840.1.113719.1.1.4.1.25 NAME 'groupMembership' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 X-NDS_NAME 'Group Membership' )",
        "attributeTypes: ( 2.16.840.1.113719.1.1.4.1.24 NAME 'securityEquals' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 X-NDS_NAME 'Security Equals' )",
        "attributeTypes: ( 2.16.840.1.113719.1.1.4.1.89 NAME 'equivalentToMe' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 X-NDS_NAME 'Equivalent To Me' )",
        "attributeTypes: ( 2.5.4.1 NAME 'aliasedObjectName' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE X-NDS_NAME 'Aliased Object Name' )",
        "attributeTypes: ( 2.16.840.1.113719.1.1.4.1.81 NAME 'lockedByIntruder' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE X-NDS_NAME 'Locked By Intruder' )",
        "attributeTypes: ( 2.16.840.1.113719.1.1.4.1.48 NAME 'loginAllowedTimeMap' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40{42} SINGLE-VALUE X-NDS_NAME 'Login Allowed Time Map' )",
        "attributeTypes: ( 2.16.840.1.113719.1.1.4.1.155 NAME 'memberQueryURL' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
        "attributeTypes: ( 1.3.6.1.1.1.1.0 NAME 'uidNumber' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
        "attributeTypes: ( 1.3.6.1.1.1.1.1 NAME 'gidNumber' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
        "attributeTypes: ( 1.3.6.1.1.1.1.3 NAME 'homeDirectory' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
        "attributeTypes: ( 2.16.840.1.113719.1.1.4.1.2 NAME 'ACL' SYNTAX 2.16.840.1.113719.1.1.5.1.17 X-NDS_NONREMOVABLE '1' X-NDS_FILTERED_REQUIRED '1' )",
        "attributeTypes: ( 2.16.840.1.113719.1.1.4.1.501 NAME 'GUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40{16} SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation X-NDS_PUBLIC_READ '1' )",
        "attributeTypes: ( 2.16.840.1.113719.1.27.4.48 NAME 'revision' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
        "attributeTypes: ( 0.9.2342.19200300.100.1.60 NAME 'jpegPhoto' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40{32768} X-NDS_NAME 'jpegPhoto' )",
        "attributeTypes: ( 0.9.2342.19200300.100.1.3 NAME 'mail' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{256} X-NDS_NAME 'Internet EMail Address' )",
        "attributeTypes: ( 2.5.4.12 NAME 'title' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{64} X-NDS_NAME 'Title' )",
        "attributeTypes: ( 2.5.4.20 NAME 'telephoneNumber' SYNTAX 1.3.6.1.4.1.1466.115.121.1.50{32} X-NDS_NAME 'Telephone Number' )",
        "attributeTypes: ( 2.16.840.1.113719.1.1.4.1.46 NAME 'loginDisabled' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE X-NDS_NAME 'Login Disabled' )",
    };

    private SecureRandom random;
    private AtomicLong revision;

    /** Load an entry directly (no client request), with the GUID and revision eDirectory would give it. */
    public void add(String... lines) throws com.unboundid.ldap.sdk.LDAPException, com.unboundid.ldif.LDIFException {
        com.unboundid.ldap.sdk.Entry e = new com.unboundid.ldap.sdk.Entry(lines);
        if (!e.hasAttribute("GUID")) {
            byte[] g = new byte[16];
            random.nextBytes(g);
            e.addAttribute(new Attribute("GUID", g));
        }
        e.setAttribute("revision", String.valueOf(revision.incrementAndGet()));
        server.add(e);
    }

    /** An entry as the fake holds it, read without a client request; null when there is none. */
    public com.unboundid.ldap.sdk.Entry entry(String dn) throws com.unboundid.ldap.sdk.LDAPException {
        return server.getEntry(dn);
    }

    public int port() {
        return server.getListenPort();
    }

    @Override
    public void close() {
        server.shutDown(true);
    }
}
