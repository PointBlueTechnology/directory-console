package com.pointblue.console.server.data;

import com.pointblue.dirxml.dev.json.Json;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A backup of the data volume, protected with a passphrase: the configuration with its history, the trust store,
 * the console's TLS key and certificate, the configuration key, and optionally the audit log, zipped and
 * encrypted with AES-256-GCM under a key from PBKDF2-HMAC-SHA256 (600,000 iterations). Format:
 * {@code "DCBACKUP1"}, a 16-byte salt, a 12-byte IV, then the ciphertext.
 *
 * <p>A restore is staged in {@code restore-pending/} and applied when the console next starts, before anything
 * is loaded: the running console keeps all of this in memory, so swapping it underneath would not be safe. The
 * audit log in a backup is restored only into an empty audit log (a fresh volume), so a restore never rewrites
 * the record of what happened since.
 */
public final class Backup {

    private static final byte[] MAGIC = "DCBACKUP1".getBytes(StandardCharsets.US_ASCII);
    private static final int ITERATIONS = 600_000;
    /** The paths a backup may hold: nothing else is read from one. */
    private static final Pattern ALLOWED = Pattern.compile(
        "manifest\\.json|config/current\\.json|config/history/\\d{6}\\.json|trust/[A-Za-z0-9._-]+|tls/[A-Za-z0-9._-]+|keys/config\\.key"
            + "|expiry-notified\\.json|audit/audit-\\d{4}-\\d{2}\\.jsonl");

    private Backup() {
    }

    /** The encrypted backup of {@code data}. */
    public static byte[] create(DataDir data, char[] passphrase, boolean withAudit, String consoleVersion) throws IOException {
        Map<String, byte[]> files = new LinkedHashMap<>();
        Map<String, Object> manifest = new LinkedHashMap<>();
        manifest.put("format", 1);
        manifest.put("createdAt", Instant.now().toString());
        manifest.put("consoleVersion", consoleVersion);
        manifest.put("audit", withAudit);
        files.put("manifest.json", Json.pretty(manifest).getBytes(StandardCharsets.UTF_8));
        Path root = data.root();
        List<Path> dirs = new ArrayList<>(List.of(data.config(), data.history(), data.trust(), data.tls(), data.keys()));
        if (withAudit) {
            dirs.add(data.audit());
        }
        for (Path d : dirs) {
            try (Stream<Path> s = Files.list(d)) {
                for (Path f : s.filter(Files::isRegularFile).sorted().toList()) {
                    String rel = root.relativize(f).toString().replace('\\', '/');
                    if (ALLOWED.matcher(rel).matches()) {
                        files.put(rel, Files.readAllBytes(f));
                    }
                }
            }
        }
        Path notified = root.resolve("expiry-notified.json");
        if (Files.exists(notified)) {
            files.put("expiry-notified.json", Files.readAllBytes(notified));
        }
        ByteArrayOutputStream zip = new ByteArrayOutputStream();
        try (ZipOutputStream z = new ZipOutputStream(zip)) {
            for (Map.Entry<String, byte[]> f : files.entrySet()) {
                z.putNextEntry(new ZipEntry(f.getKey()));
                z.write(f.getValue());
                z.closeEntry();
            }
        }
        try {
            byte[] salt = new byte[16];
            byte[] iv = new byte[12];
            SecureRandom r = new SecureRandom();
            r.nextBytes(salt);
            r.nextBytes(iv);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key(passphrase, salt), new GCMParameterSpec(128, iv));
            c.updateAAD(MAGIC);
            byte[] body = c.doFinal(zip.toByteArray());
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.writeBytes(MAGIC);
            out.writeBytes(salt);
            out.writeBytes(iv);
            out.writeBytes(body);
            return out.toByteArray();
        } catch (GeneralSecurityException e) {
            throw new IOException(e.getMessage(), e);
        }
    }

    /** The files in a backup, checked: the right passphrase, only allowed paths, a configuration and its key. */
    public static Map<String, byte[]> open(byte[] backup, char[] passphrase) {
        if (backup.length < MAGIC.length + 28 || !Arrays.equals(Arrays.copyOf(backup, MAGIC.length), MAGIC)) {
            throw new IllegalArgumentException("this is not a Directory Console backup");
        }
        byte[] salt = Arrays.copyOfRange(backup, MAGIC.length, MAGIC.length + 16);
        byte[] iv = Arrays.copyOfRange(backup, MAGIC.length + 16, MAGIC.length + 28);
        byte[] zip;
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, key(passphrase, salt), new GCMParameterSpec(128, iv));
            c.updateAAD(MAGIC);
            zip = c.doFinal(backup, MAGIC.length + 28, backup.length - MAGIC.length - 28);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("the passphrase is wrong, or the file is damaged");
        }
        Map<String, byte[]> files = new LinkedHashMap<>();
        try (ZipInputStream z = new ZipInputStream(new ByteArrayInputStream(zip))) {
            ZipEntry e;
            while ((e = z.getNextEntry()) != null) {
                if (!ALLOWED.matcher(e.getName()).matches()) {
                    throw new IllegalArgumentException("the backup holds an unexpected file: " + e.getName());
                }
                files.put(e.getName(), z.readAllBytes());
            }
        } catch (IOException e) {
            throw new IllegalArgumentException("the backup could not be read: " + e.getMessage());
        }
        if (!files.containsKey("config/current.json") || !files.containsKey("keys/config.key") || files.get("keys/config.key").length != 32) {
            throw new IllegalArgumentException("the backup has no configuration, or no key for it");
        }
        try {
            Json.asMap(Json.parse(new String(files.get("config/current.json"), StandardCharsets.UTF_8)));
        } catch (RuntimeException x) {
            throw new IllegalArgumentException("the backup's configuration is not readable");
        }
        return files;
    }

    /** What a backup says about itself. */
    public static Map<String, Object> manifest(Map<String, byte[]> files) {
        byte[] m = files.get("manifest.json");
        Map<String, Object> out = m == null ? new LinkedHashMap<>() : new LinkedHashMap<>(Json.asMap(Json.parse(new String(m, StandardCharsets.UTF_8))));
        Map<String, Object> cfg = Json.asMap(Json.parse(new String(files.get("config/current.json"), StandardCharsets.UTF_8)));
        out.put("configurationVersion", cfg.get("version"));
        out.put("savedAt", cfg.get("savedAt"));
        out.put("directories", cfg.get("directories") instanceof Map<?, ?> d ? new ArrayList<>(d.keySet()) : List.of());
        out.put("files", files.size());
        return out;
    }

    /** Stage {@code files} to be applied at the next start, replacing anything already staged. */
    public static void stage(DataDir data, Map<String, byte[]> files) throws IOException {
        Path pending = data.root().resolve("restore-pending");
        clear(pending);
        DataDir.directory(pending);
        for (Map.Entry<String, byte[]> f : files.entrySet()) {
            Path to = pending.resolve(f.getKey());
            DataDir.directory(to.getParent());
            DataDir.write(to, f.getValue());
        }
    }

    /** What is staged, or null. */
    public static Map<String, Object> pending(DataDir data) throws IOException {
        Path m = data.root().resolve("restore-pending/manifest.json");
        if (!Files.exists(m)) {
            return null;
        }
        return Json.asMap(Json.parse(Files.readString(m, StandardCharsets.UTF_8)));
    }

    public static void cancel(DataDir data) throws IOException {
        clear(data.root().resolve("restore-pending"));
    }

    /**
     * At start, before the configuration and keys are loaded: replace the configuration (with its history), trust
     * store, TLS identity, configuration key and expiry record with the staged ones. Answers the staged manifest when
     * something was applied (the caller records it in the audit log), else null.
     */
    public static Map<String, Object> applyPending(DataDir data) throws IOException {
        Path pending = data.root().resolve("restore-pending");
        if (!Files.exists(pending.resolve("manifest.json")) || !Files.exists(pending.resolve("config/current.json"))) {
            return null;
        }
        Map<String, Object> manifest = Json.asMap(Json.parse(Files.readString(pending.resolve("manifest.json"), StandardCharsets.UTF_8)));
        boolean auditEmpty;
        try (Stream<Path> s = Files.list(data.audit())) {
            auditEmpty = s.noneMatch(p -> p.getFileName().toString().endsWith(".jsonl"));
        }
        for (Path d : new Path[] {data.history(), data.trust(), data.tls()}) {
            try (Stream<Path> s = Files.list(d)) {
                // only numbered versions in history: a reset-*.json kept by reset-bootstrap stays
                for (Path f : s.filter(Files::isRegularFile)
                    .filter(f -> !d.equals(data.history()) || f.getFileName().toString().matches("\\d{6}\\.json")).toList()) {
                    Files.delete(f);
                }
            }
        }
        try (Stream<Path> s = Files.walk(pending)) {
            for (Path f : s.filter(Files::isRegularFile).sorted().toList()) {
                String rel = pending.relativize(f).toString().replace('\\', '/');
                if (rel.equals("manifest.json") || !ALLOWED.matcher(rel).matches() || rel.startsWith("audit/") && !auditEmpty) {
                    continue;
                }
                Path to = data.root().resolve(rel);
                DataDir.directory(to.getParent());
                DataDir.write(to, Files.readAllBytes(f));
            }
        }
        clear(pending);
        manifest.put("auditRestored", auditEmpty && Boolean.TRUE.equals(manifest.get("audit")));
        return manifest;
    }

    private static void clear(Path dir) throws IOException {
        if (!Files.exists(dir)) {
            return;
        }
        try (Stream<Path> s = Files.walk(dir)) {
            for (Path p : s.sorted((a, b) -> b.getNameCount() - a.getNameCount()).toList()) {
                Files.delete(p);
            }
        }
    }

    private static SecretKeySpec key(char[] passphrase, byte[] salt) throws GeneralSecurityException {
        byte[] k = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(new PBEKeySpec(passphrase, salt, ITERATIONS, 256)).getEncoded();
        return new SecretKeySpec(k, "AES");
    }
}
