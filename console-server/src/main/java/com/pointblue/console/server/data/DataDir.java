package com.pointblue.console.server.data;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;

/**
 * The data volume ({@code /data} in the container): everything the console keeps. Directories are
 * owner-only ({@code 0700}) and files {@code 0600} where the file system supports POSIX modes, and
 * every file is replaced atomically, so a crash leaves the old content or the new, never half.
 *
 * <pre>
 *   config/current.json, config/history/NNNNNN.json   configuration (secrets sealed)
 *   trust/                                            trusted certificates + metadata
 *   tls/                                              the console's own key and certificate
 *   keys/config.key                                   the configuration encryption key
 *   audit/audit-YYYY-MM.jsonl                         the hash-chained audit log
 *   bootstrap.txt                                     only while unconfigured
 * </pre>
 */
public final class DataDir {

    private static final boolean POSIX = FileSystems.getDefault().supportedFileAttributeViews().contains("posix");

    private final Path root;

    public DataDir(Path root) throws IOException {
        this.root = root.toAbsolutePath();
        for (Path d : new Path[] {this.root, config(), history(), trust(), tls(), keys(), audit()}) {
            directory(d);
        }
    }

    public Path root() {
        return root;
    }

    public Path config() {
        return root.resolve("config");
    }

    public Path history() {
        return config().resolve("history");
    }

    public Path trust() {
        return root.resolve("trust");
    }

    public Path tls() {
        return root.resolve("tls");
    }

    public Path keys() {
        return root.resolve("keys");
    }

    public Path audit() {
        return root.resolve("audit");
    }

    public Path bootstrapFile() {
        return root.resolve("bootstrap.txt");
    }

    /** Create {@code dir} (and parents) owner-only. */
    public static void directory(Path dir) throws IOException {
        Files.createDirectories(dir);
        if (POSIX) {
            Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
        }
    }

    /** Replace {@code file} with {@code bytes} atomically, owner-only. */
    public static void write(Path file, byte[] bytes) throws IOException {
        directory(file.getParent());
        Path tmp = Files.createTempFile(file.getParent(), "." + file.getFileName(), ".tmp");
        try {
            if (POSIX) {
                Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-------"));
            }
            Files.write(tmp, bytes);
            try {
                Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    /** Whether the file system enforces owner-only modes (false on Windows hosts). */
    public static boolean posix() {
        return POSIX;
    }
}
