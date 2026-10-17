package com.pointblue.console.server.live;

import com.pointblue.console.server.data.DataDir;
import com.pointblue.console.server.http.DemoAccess;
import com.pointblue.console.server.http.Server;
import com.pointblue.console.server.http.ServerClient;
import com.pointblue.console.server.idm.FakeEngine;
import com.pointblue.console.server.ldap.FakeEdir;
import com.pointblue.console.server.tls.Certs;
import com.pointblue.dirxml.dev.json.Json;
import java.io.PrintStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A console for UI work: the in-memory fake directory with a sample tree, set up through the real
 * setup API, listening on 8443 until stopped. Not a JUnit test; nothing here touches a real directory.
 * Sign in as {@code cn=admin,o=system} (password {@code admin-pw}, a test fixture value), or as
 * {@code viewer} (contextless, {@code viewer-pw}) to see the read-only role, {@code pat} ({@code pat-pw}, an
 * editor limited to ou=Sales) or {@code help} ({@code help-pw}, task presets only). "Sign in with Acme
 * SSO" goes to a demo identity provider on port 9443 that lists who to sign in as.
 *
 *   java -cp … DemoServer [port]
 */
public final class DemoServer {

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8443;
        List<String> ldif = new ArrayList<>(List.of(
            "dn: cn=admin,o=system\nobjectClass: inetOrgPerson\ncn: admin\nsn: Admin\nfullName: Tree Admin\nuserPassword: admin-pw",
            "dn: cn=console,o=system\nobjectClass: inetOrgPerson\ncn: console\nsn: c\nuserPassword: console-pw",
            "dn: ou=Users,o=acme\nobjectClass: organizationalUnit\nou: Users\ndescription: Everyone",
            "dn: ou=Sales,ou=Users,o=acme\nobjectClass: organizationalUnit\nou: Sales",
            "dn: ou=Engineering,ou=Users,o=acme\nobjectClass: organizationalUnit\nou: Engineering",
            "dn: ou=Groups,o=acme\nobjectClass: organizationalUnit\nou: Groups",
            "dn: cn=Driver Set,o=system\nobjectClass: DirXML-DriverSet\ncn: Driver Set\nDirXML-JavaEnvironmentParameters: DHOST_JVM_INITIAL_HEAP$512M"
                + "\nDirXML-JavaEnvironmentParameters: DHOST_JVM_MAX_HEAP$2G\nDirXML-ServerList: cn=edir1,ou=servers,o=system\nDirXML-LogLimit: 500"
                + "\nDirXML-ConfigValues:: PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48Y29uZmlndXJhdGlvbi12YWx1ZXM+PGRlZmluaXRpb25zPjxkZWZpbml0aW9uIGRpc3BsYXktbmFtZT0iSWRlbnRpdHkgVmF1bHQgbmFtZSIgbmFtZT0iaWR2Lm5hbWUiIHR5cGU9InN0cmluZyI+PHZhbHVlPkFDTUUtSURWPC92YWx1ZT48L2RlZmluaXRpb24+PGRlZmluaXRpb24gZGlzcGxheS1uYW1lPSJOb3RpZmljYXRpb24gZW1haWwiIG5hbWU9Im5vdGlmeS5mcm9tIiB0eXBlPSJzdHJpbmciPjx2YWx1ZT5pZG1AYWNtZS5leGFtcGxlPC92YWx1ZT48L2RlZmluaXRpb24+PC9kZWZpbml0aW9ucz48L2NvbmZpZ3VyYXRpb24tdmFsdWVzPg==",
            "dn: ou=servers,o=system\nobjectClass: organizationalUnit\nou: servers",
            "dn: cn=edir1,ou=servers,o=system\nobjectClass: ncpServer\ncn: edir1\nencryptionPolicyDN: cn=Secrets,o=system\nversion: eDirectory for Linux x86_64 v9.2.8.0000 [DS]\nstatus: 2\nDSRevision: 4020900\n"
                + "indexDefinition: 0$CN$0$0$1$1$CN\nindexDefinition: 0$CN_SS$0$2$1$1$CN\nindexDefinition: 0$Surname$0$0$1$1$Surname\n"
                + "indexDefinition: 0$GUID$0$0$2$1$GUID\nindexDefinition: 0$GnSnIndex$0$0$0$1$Given Name$Surname\nindexDefinition: 0$mailIdx$0$0$0$1$Internet EMail Address",
            "dn: cn=edir2,ou=servers,o=system\nobjectClass: ncpServer\ncn: edir2\nversion: eDirectory for Linux x86_64 v9.3.2.0000 [DS]\nstatus: 2\nDSRevision: 4030300\n"
                + "indexDefinition: 0$CN$0$0$1$1$CN\nindexDefinition: 0$GUID$0$0$2$1$GUID",
            "dn: cn=LDAP Server - edir1,ou=servers,o=system\nobjectClass: ldapServer\ncn: LDAP Server - edir1\nldapHostServer: cn=edir1,ou=servers,o=system\nldapInterfaces: ldap://:389\nldapInterfaces: ldaps://:636"
                + "\nldapGroupDN: cn=LDAP Group - edir1,ou=servers,o=system\nldapKeyMaterialName: SSL CertificateDNS\nldapTLSRequired: FALSE\nldapBindRestrictions: 48"
                + "\nldapTLSVerifyClientCertificate: 0\nsearchSizeLimit: 0\nsearchTimeLimit: 0\nldapEnablePSearch: TRUE\nldapTraceLevel: 12288\nldapNonStdAllUserAttrsMode: TRUE"
                + "\nldapSSLConfig: {\"Version\":1,\"Info\":{\"Protocol\":\"\",\"Ciphers\":\"\"}}",
            "dn: cn=SNMP Group - edir1,ou=servers,o=system\nobjectClass: snmpGroup\ncn: SNMP Group - edir1\nsnmpServerList: cn=edir1,ou=servers,o=system"
                + "\nsnmpTrapInterval: 5\nsnmpTrapDisable: FALSE\nsnmpTrapConfig:: MS4zLjYuMS40LjEuMjMuMi45OAABAAAAAAAAAAAAAAAFAAAAMS4zLjYuMS40LjEuMjMuMi45OAACAAAAAQAAAAEAAAAAAAAAMS4zLjYuMS40LjEuMjMuMi45OAADAAAAAQAAAAAAAAAsAQAA\nsnmpTrapDescription:: bmRzQ3JlYXRlRW50cnkAbmRzRGVsZXRlRW50cnkAbmRzUmVuYW1lRW50cnkA",
            "dn: cn=Secrets,o=system\nobjectClass: encryptionPolicy\ncn: Secrets\nattrEncryptionDefinition: aes256$acmeBadge\nattrEncryptionRequiresSecure: 1",
            "dn: cn=LDAP Group - edir1,ou=servers,o=system\nobjectClass: ldapGroup\ncn: LDAP Group - edir1\nldapServerList: cn=LDAP Server - edir1,ou=servers,o=system"
                + "\nldapAllowClearTextPassword: FALSE\nldapSearchReferralUsage: 1\nlDAPOtherReferralUsage: 1\nldapDefaultReferralBehavior: 2"
                + "\nldapClassList: NDSName=User$LDAPNames=inetOrgPerson\nldapClassList: NDSName=Group$LDAPNames=groupOfNames\\24groupOfUniqueNames\\24group"
                + "\nldapClassList: NDSName=Organizational Unit$LDAPNames=organizationalUnit"
                + "\nldapAttributeList: NDSName=CN$LDAPNames=cn\\24commonName\nldapAttributeList: NDSName=Surname$LDAPNames=sn\\24surname"
                + "\nldapAttributeList: NDSName=Internet EMail Address$LDAPNames=mail$Obselete=false$Description=e-mail address",
            "dn: cn=Active Directory,cn=Driver Set,o=system\nobjectClass: DirXML-Driver\ncn: Active Directory\nDirXML-TraceLevel: 3"
                + "\nDirXML-JavaModule: com.novell.nds.dirxml.remote.driver.DriverShimImpl\nDirXML-ShimAuthID: ACME\\idm"
                + "\nDirXML-ShimAuthServer: REMOTE(hostname=dc1.acme.example port=8090 kmo=idm)dc1.acme.example"
                + "\nDirXML-Policies: cn=smp,cn=Active Directory,cn=Driver Set,o=system#0#0"
                + "\nDirXML-Policies: cn=sub-mp-Users,cn=Active Directory,cn=Driver Set,o=system#0#6"
                + "\nDirXML-Policies: cn=sub-cp-Users,cn=Active Directory,cn=Driver Set,o=system#0#8"
                + "\nDirXML-Policies: cn=pub-pp,cn=Active Directory,cn=Driver Set,o=system#0#13"
                + "\nDirXML-ShimConfigInfo:: PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48ZHJpdmVyLWNvbmZpZyBuYW1lPSJBY3RpdmUgRGlyZWN0b3J5Ij48ZHJpdmVyLW9wdGlvbnM+PGNvbmZpZ3VyYXRpb24tdmFsdWVzPjxkZWZpbml0aW9ucz4KPGhlYWRlciBkaXNwbGF5LW5hbWU9IkF1dGhlbnRpY2F0aW9uIE9wdGlvbnMiLz4KPGdyb3VwPjxkZWZpbml0aW9uIGRpc3BsYXktbmFtZT0iU2hvdyBhdXRoZW50aWNhdGlvbiBvcHRpb25zIiBuYW1lPSJzaG93LWF1dGgiIHR5cGU9ImVudW0iPjxlbnVtLWNob2ljZSBkaXNwbGF5LW5hbWU9InNob3ciPnNob3c8L2VudW0tY2hvaWNlPjxlbnVtLWNob2ljZSBkaXNwbGF5LW5hbWU9ImhpZGUiPmhpZGU8L2VudW0tY2hvaWNlPjx2YWx1ZT5zaG93PC92YWx1ZT48L2RlZmluaXRpb24+CjxzdWJvcmRpbmF0ZXMgYWN0aXZlLXZhbHVlPSJzaG93Ij48ZGVmaW5pdGlvbiBkaXNwbGF5LW5hbWU9IkF1dGhlbnRpY2F0aW9uIE1ldGhvZCIgbmFtZT0iYXV0aC1tZXRob2QiIHR5cGU9ImVudW0iPjxlbnVtLWNob2ljZSBkaXNwbGF5LW5hbWU9Ik5lZ290aWF0ZSI+bmVnb3RpYXRlPC9lbnVtLWNob2ljZT48ZW51bS1jaG9pY2UgZGlzcGxheS1uYW1lPSJTaW1wbGUiPnNpbXBsZTwvZW51bS1jaG9pY2U+PHZhbHVlPm5lZ290aWF0ZTwvdmFsdWU+PGRlc2NyaXB0aW9uPkhvdyB0aGUgc2hpbSBzaWducyBpbiB0byBBY3RpdmUgRGlyZWN0b3J5LjwvZGVzY3JpcHRpb24+PC9kZWZpbml0aW9uPgo8ZGVmaW5pdGlvbiBkaXNwbGF5LW5hbWU9IlVzZSBTU0wgZm9yIExEQVAgY29ubmVjdGlvbiIgbmFtZT0idXNlLXNzbCIgdHlwZT0iYm9vbGVhbiI+PHZhbHVlPnRydWU8L3ZhbHVlPjwvZGVmaW5pdGlvbj48L3N1Ym9yZGluYXRlcz48L2dyb3VwPgo8L2RlZmluaXRpb25zPjwvY29uZmlndXJhdGlvbi12YWx1ZXM+PC9kcml2ZXItb3B0aW9ucz48c3Vic2NyaWJlci1vcHRpb25zLz48cHVibGlzaGVyLW9wdGlvbnM+PGNvbmZpZ3VyYXRpb24tdmFsdWVzPjxkZWZpbml0aW9ucz4KPGRlZmluaXRpb24gZGlzcGxheS1uYW1lPSJQb2xsaW5nIGludGVydmFsIGluIHNlY29uZHMiIG5hbWU9InB1Yi1wb2xsaW5nLWludGVydmFsIiB0eXBlPSJpbnRlZ2VyIj48dmFsdWU+NjA8L3ZhbHVlPjwvZGVmaW5pdGlvbj4KPC9kZWZpbml0aW9ucz48L2NvbmZpZ3VyYXRpb24tdmFsdWVzPjwvcHVibGlzaGVyLW9wdGlvbnM+PC9kcml2ZXItY29uZmlnPg=="
                + "\nDirXML-ConfigValues:: PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48Y29uZmlndXJhdGlvbi12YWx1ZXM+PGRlZmluaXRpb25zPjxoZWFkZXIgZGlzcGxheS1uYW1lPSJTeW5jaHJvbml6YXRpb24gU2V0dGluZ3MiLz4KPGRlZmluaXRpb24gZGlzcGxheS1uYW1lPSJEb21haW4gRE5TIE5hbWUiIG5hbWU9IkFELkRvbWFpbkROU05hbWUiIHR5cGU9InN0cmluZyI+PHZhbHVlPmFjbWUuZXhhbXBsZTwvdmFsdWU+PC9kZWZpbml0aW9uPgo8ZGVmaW5pdGlvbiBkaXNwbGF5LW5hbWU9IlN1YnNjcmliZXIgQ2hhbm5lbCBQbGFjZW1lbnQgVHlwZSIgbmFtZT0iQUQuU3ViUGxhY2VtZW50VHlwZSIgdHlwZT0iZW51bSI+PGVudW0tY2hvaWNlIGRpc3BsYXktbmFtZT0iRmxhdCI+ZmxhdDwvZW51bS1jaG9pY2U+PGVudW0tY2hvaWNlIGRpc3BsYXktbmFtZT0iTWlycm9yIj5taXJyb3I8L2VudW0tY2hvaWNlPjx2YWx1ZT5taXJyb3I8L3ZhbHVlPjwvZGVmaW5pdGlvbj4KPC9kZWZpbml0aW9ucz48L2NvbmZpZ3VyYXRpb24tdmFsdWVzPg=="
                + "\nDirXML-DriverFilter:: PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48ZmlsdGVyPjxmaWx0ZXItY2xhc3MgY2xhc3MtbmFtZT0iVXNlciIgcHVibGlzaGVyPSJzeW5jIiBzdWJzY3JpYmVyPSJzeW5jIj4KPGZpbHRlci1hdHRyIGF0dHItbmFtZT0iU3VybmFtZSIgcHVibGlzaGVyPSJzeW5jIiBzdWJzY3JpYmVyPSJzeW5jIi8+PGZpbHRlci1hdHRyIGF0dHItbmFtZT0iR2l2ZW4gTmFtZSIgcHVibGlzaGVyPSJzeW5jIiBzdWJzY3JpYmVyPSJzeW5jIi8+CjxmaWx0ZXItYXR0ciBhdHRyLW5hbWU9IkxvZ2luIERpc2FibGVkIiBwdWJsaXNoZXI9Im5vdGlmeSIgc3Vic2NyaWJlcj0ic3luYyIvPjxmaWx0ZXItYXR0ciBhdHRyLW5hbWU9IlRlbGVwaG9uZSBOdW1iZXIiIHB1Ymxpc2hlcj0iaWdub3JlIiBzdWJzY3JpYmVyPSJzeW5jIi8+PC9maWx0ZXItY2xhc3M+CjxmaWx0ZXItY2xhc3MgY2xhc3MtbmFtZT0iR3JvdXAiIHB1Ymxpc2hlcj0iaWdub3JlIiBzdWJzY3JpYmVyPSJzeW5jIj48ZmlsdGVyLWF0dHIgYXR0ci1uYW1lPSJNZW1iZXIiIHB1Ymxpc2hlcj0iaWdub3JlIiBzdWJzY3JpYmVyPSJzeW5jIi8+PC9maWx0ZXItY2xhc3M+PC9maWx0ZXI+",
            "dn: cn=LDAP\\, primary,cn=Driver Set,o=system\nobjectClass: DirXML-Driver\ncn: LDAP, primary",
            "dn: cn=Delimited Text,cn=Driver Set,o=system\nobjectClass: DirXML-Driver\ncn: Delimited Text",
            "dn: cn=Department placement,cn=Active Directory,cn=Driver Set,o=system\nobjectClass: DirXML-Resource\ncn: Department placement"
                + "\nDirXML-ContentType: application/vnd.novell.dirxml.mapping-table+xml ;charset=UTF-8\nDirXML-Data:: PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48bWFwcGluZy10YWJsZT4KCTxjb2wtZGVmIG5hbWU9ImRlcGFydG1lbnQiIHR5cGU9Im5vY2FzZSIvPgoJPHJvdz4KCQk8Y29sPjEwMDwvY29sPgoJCTxjb2w+T1U9U2FsZXMsREM9YWNtZSxEQz1leGFtcGxlPC9jb2w+CgkJPGNvbD5TYWxlczwvY29sPgoJPC9yb3c+Cgk8Y29sLWRlZiBuYW1lPSJhZC1jb250YWluZXIiIHR5cGU9ImNhc2UiLz4KCTxjb2wtZGVmIG5hbWU9ImRpc3BsYXkiIHR5cGU9Im5vY2FzZSIvPgoJPHJvdz4KCQk8Y29sPjIwMDwvY29sPgoJCTxjb2w+T1U9U3VwcG9ydCxEQz1hY21lLERDPWV4YW1wbGU8L2NvbD4KCQk8Y29sPlN1cHBvcnQgJmFtcDsgU2VydmljZXM8L2NvbD4KCTwvcm93PgoJPHJvdz4KCQk8Y29sPjMwMDwvY29sPgoJCTxjb2w+T1U9RW5naW5lZXJpbmcsREM9YWNtZSxEQz1leGFtcGxlPC9jb2w+CgkJPGNvbD5FbmdpbmVlcmluZzwvY29sPgoJPC9yb3c+CjwvbWFwcGluZy10YWJsZT4=",
            "dn: cn=Weekly trigger,cn=Active Directory,cn=Driver Set,o=system\nobjectClass: DirXML-Job\ncn: Weekly trigger\nDirXML-ServerList: cn=edir1,ou=servers,o=system"
                + "\nDirXML-Scope: ou=Users,o=acme#0#<scope-def scope=\"subtree\"/>\nXmlData:: PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48am9iLWFnZ3JlZ2F0aW9uPgoJPGpvYi1kZWZpbml0aW9uIGF1dG8tZGVsZXRlPSJmYWxzZSIgZGlzYWJsZWQ9ImZhbHNlIiBkaXNwbGF5LW5hbWU9InhsZmlkKGpvYi1kaXNwbGF5LW5hbWUpU3Vic2NyaWJlciBjaGFubmVsIHRyaWdnZXIiIHNjaGVkdWxlPSIwIDIgKiAqIDYiIHNjb3BlLXJlcXVpcmVkPSJ0cnVlIiB0eXBlPSJqYXZhIj4KCQk8ZGVzY3JpcHRpb24+eGxmaWQoam9iLWRlc2NyaXB0aW9uKVN1Ym1pdHMgYSB0cmlnZ2VyIGRvY3VtZW50IHRvIHRoZSBzdWJzY3JpYmVyIGNoYW5uZWwgZm9yIGVhY2ggb2JqZWN0IGluIHNjb3BlLjwvZGVzY3JpcHRpb24+CgkJPGNvbnRhaW5tZW50PkRpclhNTC1Ecml2ZXI8L2NvbnRhaW5tZW50PgoJCTxqYXZhLWNsYXNzPmNvbS5ub3ZlbGwubmRzLmRpcnhtbC5qb2IudHJpZ2dlci5UcmlnZ2VyPC9qYXZhLWNsYXNzPgoJCTxjb25maWd1cmF0aW9uLXZhbHVlcz48ZGVmaW5pdGlvbnM+CgkJCTxkZWZpbml0aW9uIGRpc3BsYXktbmFtZT0ieGxmaWQodXNlLWpvYi1jbilVc2UgSm9iIENOIGFzIHRyaWdnZXIgZG9jdW1lbnQgaWRlbnRpZmllcj8iIG5hbWU9InVzZS1qb2ItY24iIHR5cGU9ImJvb2xlYW4iPjx2YWx1ZT50cnVlPC92YWx1ZT48L2RlZmluaXRpb24+CgkJCTxkZWZpbml0aW9uIGRpc3BsYXktbmFtZT0ieGxmaWQoc3VibWl0LW1ldGhvZClNZXRob2QgZm9yIHN1Ym1pdHRpbmcgdHJpZ2dlciBkb2N1bWVudHMiIG5hbWU9InN1Ym1pdC1tZXRob2QiIHR5cGU9ImVudW0iPjx2YWx1ZT5zdWJtaXQtcXVldWU8L3ZhbHVlPjwvZGVmaW5pdGlvbj4KCQk8L2RlZmluaXRpb25zPjwvY29uZmlndXJhdGlvbi12YWx1ZXM+Cgk8L2pvYi1kZWZpbml0aW9uPgo8L2pvYi1hZ2dyZWdhdGlvbj4=",
            "dn: cn=Viewers,ou=Groups,o=acme\nobjectClass: groupOfNames\ncn: Viewers\nmember: cn=viewer,ou=Users,o=acme",
            "dn: cn=Sales Editors,ou=Groups,o=acme\nobjectClass: groupOfNames\ncn: Sales Editors\nmember: cn=pat,ou=Sales,ou=Users,o=acme",
            "dn: cn=Help Desk,ou=Groups,o=acme\nobjectClass: groupOfNames\ncn: Help Desk\nmember: cn=help,ou=Users,o=acme",
            "dn: cn=pat,ou=Sales,ou=Users,o=acme\nobjectClass: inetOrgPerson\ncn: pat\nsn: Lee\ngivenName: Pat\nfullName: Pat Lee\nuid: pat\nuserPassword: pat-pw\ngroupMembership: cn=Sales Editors,ou=Groups,o=acme"
                + "\nDirXML-Associations: cn=Active Directory,cn=Driver Set,o=system#1#{6F9619FF-8B86-D011-B42D-00C04FC964FF}"
                + "\nDirXML-Associations: cn=Delimited Text,cn=Driver Set,o=system#3#E1001",
            "dn: cn=help,ou=Users,o=acme\nobjectClass: inetOrgPerson\ncn: help\nsn: Desk\nfullName: Help Desk\nuid: help\nuserPassword: help-pw\ngroupMembership: cn=Help Desk,ou=Groups,o=acme",
            "dn: cn=viewer,ou=Users,o=acme\nobjectClass: inetOrgPerson\ncn: viewer\nsn: Viewer\nuserPassword: viewer-pw\ngroupMembership: cn=Viewers,ou=Groups,o=acme",
            "dn: cn=Smith\\, John,ou=Sales,ou=Users,o=acme\nobjectClass: inetOrgPerson\ncn: Smith, John\nsn: Smith\ngivenName: John\nuid: jsmith\nmail: jsmith@acme.example\ntitle: Account manager\ngroupMembership: cn=Viewers,ou=Groups,o=acme",
            "dn: cn=Smith (Admin),ou=Engineering,ou=Users,o=acme\nobjectClass: inetOrgPerson\ncn: Smith (Admin)\nsn: Smith\nloginDisabled: TRUE\nlockedByIntruder: TRUE\nloginIntruderAttempts: 5\nloginIntruderResetTime: 20301231120000Z",
            "dn: cn=Everyone in Sales,ou=Groups,o=acme\nobjectClass: dynamicGroup\ncn: Everyone in Sales\nmemberQueryURL: ldap:///ou=Sales,ou=Users,o=acme??sub?(objectClass=inetOrgPerson)\nmember: cn=Smith\\, John,ou=Sales,ou=Users,o=acme",
            "dn: cn=Team #1,ou=Groups,o=acme\nobjectClass: groupOfNames\ncn: Team #1\ndescription: A name with a hash\nmember: cn=Smith\\, John,ou=Sales,ou=Users,o=acme\n"
                + "ACL: 2#entry#cn=Viewers,ou=Groups,o=acme#member\nACL: 16#subtree#[Creator]#[Entry Rights]"));
        String[] given = {"Ann", "Bob", "Carla", "Dev", "Eve", "Femi", "Gus", "Hana", "Ivan", "Jo"};
        for (int i = 0; i < 1200; i++) {
            String cn = "user" + String.format("%04d", i);
            ldif.add("dn: cn=" + cn + ",ou=Engineering,ou=Users,o=acme\nobjectClass: inetOrgPerson\ncn: " + cn + "\nsn: Person" + i
                + "\ngivenName: " + given[i % given.length] + "\nmail: " + cn + "@acme.example");
        }
        FakeEdir edir = new FakeEdir(ldif.toArray(new String[0]));
        // two servers holding three partitions, for the eDirectory pages
        for (String[] srv : new String[][] {{"cn=edir1,ou=servers,o=system", "7f000001"}, {"cn=edir2,ou=servers,o=system", "7f000002"}}) {
            // "9#" (TCP), then port 524 and the IPv4 address, as eDirectory sends networkAddress over LDAP
            byte[] tcp = java.util.HexFormat.of().parseHex("3923" + "020c" + srv[1]);
            edir.server.modify(srv[0], new com.unboundid.ldap.sdk.Modification(com.unboundid.ldap.sdk.ModificationType.ADD, "networkAddress", tcp));
        }
        securityServices(edir);
        edir.partitions.partition("", Map.of("cn=edir1,ou=servers,o=system", 0, "cn=edir2,ou=servers,o=system", 1))
            .partition("o=acme", Map.of("cn=edir1,ou=servers,o=system", 0, "cn=edir2,ou=servers,o=system", 1))
            .partition("o=system", Map.of("cn=edir1,ou=servers,o=system", 0, "cn=edir2,ou=servers,o=system", 2));
        Path data = Files.createTempDirectory("dc-demo-");
        // the address browsers use: the Vite dev server, which proxies /api here (so single sign-on comes back there)
        String publicUrl = System.getProperty("demo.publicUrl", "http://localhost:5173");
        Server server = new Server(new DataDir(data), port, publicUrl, new PrintStream(System.out));
        {
            FakeEngine engine = new FakeEngine(edir);
            engine.states.put("cn=activedirectory,cn=driverset,o=system", com.pointblue.dirxml.dev.deploy.Vault.STATE_RUNNING);
            engine.startOptions.put("cn=activedirectory,cn=driverset,o=system", com.pointblue.dirxml.dev.deploy.Vault.START_AUTO);
            engine.startOptions.put("cn=delimitedtext,cn=driverset,o=system", com.pointblue.dirxml.dev.deploy.Vault.START_DISABLED);
            DemoAccess.engines(server, engine.engines());
        }
        server.start();
        HttpClient http = ServerClient.trusting(server);
        String base = "https://127.0.0.1:" + port;
        Matcher m = Pattern.compile("Setup token: ([0-9a-f]{32})").matcher(Files.readString(data.resolve("bootstrap.txt")));
        m.find();
        Map<String, String> t = Map.of("X-Setup-Token", m.group(1));
        call(http, base, "PUT", "/api/v2/setup/directory", Map.of("id", "acme", "name", "Acme (demo)", "host", "127.0.0.1", "port", edir.port(), "tier", "lab"), t);
        Map<String, Object> probe = call(http, base, "POST", "/api/v2/setup/probe", Map.of(), t);
        call(http, base, "POST", "/api/v2/setup/trust", Map.of("probeId", probe.get("probeId"), "confirm", Certs.tail(edir.pki.ca, 8)), t);
        call(http, base, "POST", "/api/v2/setup/authority", Map.of("dn", "cn=admin,o=system", "password", "admin-pw"), t);
        call(http, base, "PUT", "/api/v2/setup/service-account", Map.of("dn", "cn=console,o=system", "password", "console-pw"), t);
        call(http, base, "PUT", "/api/v2/setup/login", Map.of("duplicates", "choose", "searchBases", List.of("o=acme")), t);
        call(http, base, "POST", "/api/v2/setup/finish", Map.of(), t);
        DemoAccess.mapViewers(server);
        // single sign-on through a demo identity provider on loopback (it lists the people to sign in as)
        com.pointblue.console.server.auth.FakeIdp idp = new com.pointblue.console.server.auth.FakeIdp(9443)
            .person("pat", Map.of("name", "Pat Lee", "preferred_username", "pat", "groups", List.of("sales-editors")))
            .person("help", Map.of("name", "Help Desk", "preferred_username", "help", "groups", List.of("help-desk")))
            .person("john", Map.of("name", "John Smith (no console role)", "preferred_username", "jsmith", "groups", List.of("staff")))
            .person("admin", Map.of("name", "Tree admin (never through SSO)", "preferred_username", "admin", "groups", List.of("console-admins")));
        DemoAccess.phase3(server, idp.issuer);
        // edir2 is reached by a name its certificate lacks, as behind NAT or a tunnel: signing in to it asks
        // an administrator to accept the certificate at that address
        DemoAccess.serverAddresses(server, Map.of("cn=edir2,ou=servers,o=system", "localhost:" + edir.port()));
        // a partner tree's CA, trusted for every directory and expiring soon: the certificate list and banner warn
        DemoAccess.trust(server, new com.pointblue.console.server.tls.TestPki("PARTNER_TREE", java.time.Duration.ofDays(21)).ca, "global", "cn=admin,o=system");
        // EBA: edir1 is the tree's EBA CA; both servers have NCP certificates
        edir.pkiOps.ebaCa = "127.0.0.1:524";
        edir.pkiOps.ncp.put(com.pointblue.console.server.ldap.FakePki.uid(edir.entry("cn=edir1,ou=servers,o=system").getAttributeValueBytes("GUID")), "127.0.0.1:524");
        edir.pkiOps.ncp.put(com.pointblue.console.server.ldap.FakePki.uid(edir.entry("cn=edir2,ou=servers,o=system").getAttributeValueBytes("GUID")), "127.0.0.2:524");
        // a server at another address whose pinned certificate changed: the Certificates page shows the alert
        DemoAccess.pinAlert(server, "acme", "edir3.acme.example", 636,
            new java.security.cert.X509Certificate[] {new com.pointblue.console.server.tls.TestPki("ROGUE_TREE").server("edir3", List.of("edir3.acme.example")).cert()});
        System.out.println("\nDemo console ready at " + base + " (data " + data + "). Ctrl-C to stop.");
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            server.stop();
            edir.close();
        }));
        Thread.currentThread().join();
    }

    private static Map<String, Object> call(HttpClient http, String base, String method, String path, Object body, Map<String, String> headers) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path)).header("Content-Type", "application/json")
            .method(method, HttpRequest.BodyPublishers.ofString(Json.compact(body)));
        headers.forEach(b::header);
        HttpResponse<String> r = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
        if (r.statusCode() / 100 != 2) {
            throw new IllegalStateException(method + " " + path + " -> " + r.statusCode() + " " + r.body());
        }
        return r.body().isBlank() ? Map.of() : Json.asMap(Json.parse(r.body()));
    }

    /**
     * eDirectory keeps cn=Security at the tree root; the fake's naming contexts are o=acme and o=system,
     * so the demo's Security container is under o=system (the console finds it by its class).
     */
    private static void securityServices(FakeEdir edir) throws Exception {
        java.util.Base64.Encoder b64 = java.util.Base64.getEncoder();
        String sec = "cn=Security,o=system";
        String ca = b64.encodeToString(edir.pki.ca.getEncoded());
        String s1 = b64.encodeToString(edir.pki.server("edir1", List.of("127.0.0.1", "edir1.acme.example")).cert().getEncoded());
        String s2 = b64.encodeToString(edir.pki.server("edir2", List.of("127.0.0.2", "edir2.acme.example")).cert().getEncoded());
        edir.add("dn: " + sec, "objectClass: sASSecurity", "cn: Security", "nDSPKITreeCADN: cn=ACME_TREE CA," + sec, "sASLoginPolicyDN: cn=Login Policy," + sec);
        edir.add("dn: cn=ACME_TREE CA," + sec, "objectClass: nDSPKICertificateAuthority", "cn: ACME_TREE CA", "hostServer: cn=edir1,ou=servers,o=system",
            "ndspkiDefaultRSAKeySize: 4096", "ndspkiDefaultCertificateLife: 10", "nDSPKIPublicKeyCertificate:: " + ca, "nDSPKIPrivateKey:: " + b64.encodeToString("wrapped-key".getBytes()),
            "ndspkiCRLConfigurationDNList: cn=One - Configuration," + sec + "#0#", "ndspkiCRLECConfigurationDNList: cn=One - Configuration EC," + sec + "#0#");
        String nextIssue = java.time.format.DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(java.time.ZoneOffset.UTC).format(java.time.Instant.now().plus(java.time.Duration.ofDays(14)));
        for (String c : new String[] {"One - Configuration", "One - Configuration EC"}) {
            edir.add("dn: cn=" + c + "," + sec, "objectClass: ndspkiCRLConfiguration", "cn: " + c, "ndspkiNextIssueTime: " + nextIssue);
        }
        edir.add("dn: cn=SSL CertificateDNS - edir1,ou=servers,o=system", "objectClass: nDSPKIKeyMaterial", "cn: SSL CertificateDNS - edir1",
            "hostServer: cn=edir1,ou=servers,o=system", "nDSPKIPublicKeyCertificate:: " + s1, "nDSPKIPrivateKey:: " + b64.encodeToString("wrapped".getBytes()));
        edir.add("dn: cn=SSL CertificateDNS - edir2,ou=servers,o=system", "objectClass: nDSPKIKeyMaterial", "cn: SSL CertificateDNS - edir2",
            "hostServer: cn=edir2,ou=servers,o=system", "nDSPKIPublicKeyCertificate:: " + s2);
        edir.server.modify("cn=LDAP Server - edir1,ou=servers,o=system", new com.unboundid.ldap.sdk.Modification(
            com.unboundid.ldap.sdk.ModificationType.REPLACE, "ldapKeyMaterialName", "SSL CertificateDNS"));
        edir.add("dn: cn=Login Policy," + sec, "objectClass: sASLoginPolicy", "cn: Login Policy", "sasDefaultLoginSequence: <no default>",
            "sASLoginSequence: NDS;Password;NDS", "sASLoginSequence: Challenge Response;Password;Challenge Response");
        edir.add("dn: cn=Authorized Login Methods," + sec, "objectClass: sASLoginMethodContainer", "cn: Authorized Login Methods");
        edir.add("dn: cn=NDS,cn=Authorized Login Methods," + sec, "objectClass: sASNMASLoginMethod", "cn: NDS", "sASMethodVendor: Novell, Inc.");
        edir.add("dn: cn=Challenge Response,cn=Authorized Login Methods," + sec, "objectClass: sASNMASLoginMethod", "cn: Challenge Response", "sASMethodVendor: NetIQ Corporation");
        edir.add("dn: cn=Password Policies," + sec, "objectClass: nspmPasswordPolicyContainer", "cn: Password Policies");
        edir.add("dn: cn=Basics,cn=Password Policies," + sec, "objectClass: nsimChallengeSet", "cn: Basics", "description: Two questions to reset a password",
            "nsimRequiredQuestions: <RequiredQuestions><UserDefined MaxLength=\"128\" MinLength=\"4\"/><AdminDefined><Question MaxLength=\"64\" MinLength=\"2\"><![CDATA[First school?]]></Question></AdminDefined></RequiredQuestions>",
            "nsimRandomQuestions: <RandomQuestions><AdminDefined><Question MaxLength=\"64\" MinLength=\"2\"><![CDATA[City of birth?]]></Question></AdminDefined></RandomQuestions>",
            "nsimNumberRandomQuestions: 0");
        edir.add("dn: cn=Staff,cn=Password Policies," + sec, "objectClass: nspmPasswordPolicy", "cn: Staff", "description: Everyone in ou=Users",
            "nspmConfigurationOptions: 884", "passwordMinimumLength: 10", "nspmMaximumLength: 64", "nspmMinUpperCaseCharacters: 1", "nspmMinNumericCharacters: 1",
            "passwordExpirationInterval: 7776000", "passwordUniqueRequired: TRUE", "nspmPasswordHistoryLimit: 8", "nspmCaseSensitive: TRUE",
            "nsimChallengeSetDN: cn=Basics,cn=Password Policies," + sec, "nsimAssignments: ou=Sales,ou=Users,o=acme");
        edir.add("dn: cn=Service accounts,cn=Password Policies," + sec, "objectClass: nspmPasswordPolicy", "cn: Service accounts",
            "nspmConfigurationOptions: 596", "passwordMinimumLength: 24", "nspmMaximumLength: 128");
        edir.server.modify("ou=Sales,ou=Users,o=acme", new com.unboundid.ldap.sdk.Modification(com.unboundid.ldap.sdk.ModificationType.REPLACE,
            "nspmPasswordPolicyDN", "cn=Staff,cn=Password Policies," + sec));
    }
}
