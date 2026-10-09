package com.pointblue.console.server;

import com.pointblue.console.server.data.DataDir;
import com.pointblue.console.server.http.Server;
import com.pointblue.dirxml.dev.LegacyTls;
import java.nio.file.Path;

/**
 * Starts Directory Console. Its only inputs are the data volume and the port (DESIGN-directory-console.md
 * section 12.1); everything else is configured through the API.
 *
 * <pre>
 *   CONSOLE_DATA        data volume (default /data)
 *   CONSOLE_PORT        HTTPS port (default 8443)
 *   CONSOLE_PUBLIC_URL  how browsers reach it (default https://localhost:&lt;port&gt;); its host goes in the
 *                       generated certificate and the accepted Host names
 * </pre>
 *
 * <p>{@code admin …} runs a host-side command instead (see {@link Admin}).
 */
public final class Main {

    private Main() {
    }

    public static void main(String[] args) throws Exception {
        // eDirectory listeners often offer only static-RSA suites; keep them available (IDM_TLS_LEGACY=false opts out)
        LegacyTls.enable();
        Path dataPath = Path.of(env("CONSOLE_DATA", "/data"));
        int port = Integer.parseInt(env("CONSOLE_PORT", "8443"));
        if (args.length > 0 && args[0].equals("admin")) {
            System.exit(Admin.run(args, dataPath, port));
        }
        String publicUrl = env("CONSOLE_PUBLIC_URL", "https://localhost:" + port);
        Server server = new Server(new DataDir(dataPath), port, publicUrl, System.out);
        server.start();
        System.out.println("Directory Console listening on " + port + (server.bootstrapping() ? " (setup required)" : ""));
        Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
    }

    private static String env(String key, String dflt) {
        String v = System.getenv(key);
        return v == null || v.isBlank() ? dflt : v.trim();
    }
}
