package com.pointblue.console.server.live;

import com.pointblue.console.server.data.DataDir;
import com.pointblue.console.server.http.DemoAccess;
import com.pointblue.console.server.http.Server;
import com.pointblue.console.server.http.ServerClient;
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
 * {@code viewer} (contextless, {@code viewer-pw}) to see the read-only role.
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
            "dn: cn=Driver Set,o=system\nobjectClass: DirXML-DriverSet\ncn: Driver Set",
            "dn: cn=Viewers,ou=Groups,o=acme\nobjectClass: groupOfNames\ncn: Viewers\nmember: cn=viewer,ou=Users,o=acme",
            "dn: cn=viewer,ou=Users,o=acme\nobjectClass: inetOrgPerson\ncn: viewer\nsn: Viewer\nuserPassword: viewer-pw\ngroupMembership: cn=Viewers,ou=Groups,o=acme",
            "dn: cn=Smith\\, John,ou=Sales,ou=Users,o=acme\nobjectClass: inetOrgPerson\ncn: Smith, John\nsn: Smith\ngivenName: John\nmail: jsmith@acme.example\ntitle: Account manager\ngroupMembership: cn=Viewers,ou=Groups,o=acme",
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
        Path data = Files.createTempDirectory("dc-demo-");
        Server server = new Server(new DataDir(data), port, "https://localhost:" + port, new PrintStream(System.out));
        server.start();
        HttpClient http = ServerClient.trusting(server);
        String base = "https://localhost:" + port;
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
}
