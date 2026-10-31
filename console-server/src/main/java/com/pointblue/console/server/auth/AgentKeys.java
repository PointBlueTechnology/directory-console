package com.pointblue.console.server.auth;

import com.pointblue.console.server.data.DataDir;
import com.pointblue.dirxml.dev.json.Json;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Agent keys (docs/MCP.md): a person makes one for their AI agent, which then calls the console's MCP server as them.
 * A key is {@code dc_} and 32 random bytes; only its SHA-256 is kept, with its label, directory, the person, the
 * roles it may use (never admin) and its times. Keys live in {@code agents/keys.json} on the data volume, outside the
 * versioned configuration and outside backups, so restoring an earlier configuration or a backup never brings back a
 * revoked key.
 *
 * <p>A key stops working when it expires (30 days by default, at most the directory's longest life, and at most 14
 * days for a person who signed in with single sign-on), and after 14 days unused. Keys expired for a month are
 * dropped from the file.
 */
public final class AgentKeys {

    public static final String PREFIX = "dc_";
    public static final Duration IDLE = Duration.ofDays(14);
    public static final int DEFAULT_DAYS = 30;
    public static final int MAX_DAYS = 90;
    /** A single sign-on person's grants come from their last sign-in, so their keys live shorter. */
    public static final int SSO_MAX_DAYS = 14;
    /** The most keys one person may have in one directory. */
    public static final int PER_PERSON = 20;
    /** The roles a key may carry: never admin. */
    public static final Set<Role> CEILING = Set.copyOf(EnumSet.of(Role.VIEWER, Role.EDITOR, Role.OPERATOR));
    private static final Duration KEEP_EXPIRED = Duration.ofDays(30);
    /** Last use is written at most this often (it only decides the 14-day idle limit). */
    private static final Duration TOUCH = Duration.ofMinutes(10);
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * One key. {@code via} is how the person signed in when they made it ({@code direct} or {@code oidc});
     * {@code grants} are a single sign-on person's grants as of their last sign-in (empty for direct sign-in, whose
     * grants are read from the directory on every call). {@code apps} is the person's Identity Applications refresh
     * token, sealed with the console's key ({@code {"sealed": …}}), or null; {@code appsState} is {@code authorized},
     * {@code authorize-again} (the token stopped working) or null (never authorized).
     */
    public record Key(String id, String hash, String label, String directoryId, String dn, String subject, String name, String via,
                      Set<Role> roles, List<Grant> grants, Instant created, Instant expires, Instant lastUsed,
                      Map<String, Object> apps, String appsState) {

        public Key {
            roles = Set.copyOf(roles);
            grants = List.copyOf(grants);
        }

        public boolean expired(Instant now) {
            return !expires.isAfter(now);
        }

        public boolean idle(Instant now) {
            return !(lastUsed == null ? created : lastUsed).plus(IDLE).isAfter(now);
        }

        /** {@code active}, {@code expired} or {@code idle}. */
        public String state(Instant now) {
            return expired(now) ? "expired" : idle(now) ? "idle" : "active";
        }

        /** How the audit names it: the label and the id. */
        public String ref() {
            return label + " (" + id + ")";
        }

        /** For the key's owner and administrators: never the hash. */
        public Map<String, Object> json(Instant now) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id);
            m.put("label", label);
            m.put("directory", directoryId);
            m.put("dn", dn);
            m.put("name", name);
            m.put("via", via);
            m.put("roles", roles.stream().map(Role::id).sorted().toList());
            m.put("created", created.toString());
            m.put("expires", expires.toString());
            m.put("lastUsed", lastUsed == null ? null : lastUsed.toString());
            m.put("state", state(now));
            m.put("apps", appsState);
            return m;
        }

        Key used(Instant at) {
            return new Key(id, hash, label, directoryId, dn, subject, name, via, roles, grants, created, expires, at, apps, appsState);
        }

        Key withGrants(List<Grant> g) {
            return new Key(id, hash, label, directoryId, dn, subject, name, via, roles, g, created, expires, lastUsed, apps, appsState);
        }

        Key withApps(Map<String, Object> sealed, String state) {
            return new Key(id, hash, label, directoryId, dn, subject, name, via, roles, grants, created, expires, lastUsed, sealed, state);
        }
    }

    /** A new key: the token, shown to the person once, and what is kept. */
    public record Made(String token, Key key) {
    }

    private final Path file;
    private final Clock clock;
    /** By hash. */
    private final Map<String, Key> keys = new LinkedHashMap<>();

    public AgentKeys(DataDir data) throws IOException {
        this(data.agents().resolve("keys.json"), Clock.systemUTC());
    }

    AgentKeys(Path file, Clock clock) throws IOException {
        this.file = file;
        this.clock = clock;
        if (Files.exists(file)) {
            Map<String, Object> doc = Json.asMap(Json.parse(Files.readString(file, StandardCharsets.UTF_8)));
            for (Object o : Json.asList(doc.get("keys"))) {
                Key k = parse(Json.asMap(o));
                keys.put(k.hash(), k);
            }
        }
        Instant now = clock.instant();
        if (keys.values().removeIf(k -> k.expires().plus(KEEP_EXPIRED).isBefore(now))) {
            save();
        }
    }

    public Instant now() {
        return clock.instant();
    }

    /** Make a key for {@code p} in its directory, using at most {@code roles}, for {@code life}. */
    public synchronized Made create(String label, Sessions.Principal p, Set<Role> roles, Duration life) throws IOException {
        byte[] b = new byte[32];
        RANDOM.nextBytes(b);
        String token = PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(b);
        String hash = sha256(token);
        Instant now = clock.instant();
        List<Grant> grants = "oidc".equals(p.via()) ? withoutPresets(p.grants()) : List.of();
        Key k = new Key(hash.substring(0, 12), hash, label, p.directoryId(), p.dn(), p.subject(), p.name(), p.via(), roles, grants,
            now, now.plus(life), null, null, null);
        keys.put(hash, k);
        save();
        return new Made(token, k);
    }

    /** The key {@code token} stands for, whatever its state; null when it is none. */
    public synchronized Key find(String token) {
        if (token == null || !token.startsWith(PREFIX) || token.length() > 100) {
            return null;
        }
        return keys.get(sha256(token));
    }

    /** Note a use of {@code k} (written to disk at most every ten minutes); the key as it is now. */
    public synchronized Key used(Key k) throws IOException {
        Key current = keys.get(k.hash());
        if (current == null) {
            return k;
        }
        Instant now = clock.instant();
        Key u = current.used(now);
        keys.put(k.hash(), u);
        if (current.lastUsed() == null || current.lastUsed().plus(TOUCH).isBefore(now)) {
            save();
        }
        return u;
    }

    /** {@code dn}'s keys in {@code directoryId}, newest first. */
    public synchronized List<Key> of(String directoryId, String dn) {
        return keys.values().stream().filter(k -> k.directoryId().equals(directoryId) && DirectLogin.sameDn(k.dn(), dn))
            .sorted((a, b) -> b.created().compareTo(a.created())).toList();
    }

    /** Every key in {@code directoryId}, newest first. */
    public synchronized List<Key> all(String directoryId) {
        return keys.values().stream().filter(k -> k.directoryId().equals(directoryId))
            .sorted((a, b) -> b.created().compareTo(a.created())).toList();
    }

    /** The key with this id; null when there is none. */
    public synchronized Key byId(String id) {
        return keys.values().stream().filter(k -> k.id().equals(id)).findFirst().orElse(null);
    }

    /**
     * Keep (or drop, {@code sealed} null) the person's Identity Applications refresh token for key {@code id}, with its
     * state; the key as it is now, or null when it is gone.
     */
    public synchronized Key apps(String id, Map<String, Object> sealed, String state) throws IOException {
        Key k = byId(id);
        if (k == null) {
            return null;
        }
        Key u = k.withApps(sealed, state);
        keys.put(k.hash(), u);
        save();
        return u;
    }

    /** Remove the key with this id; the removed key, or null. */
    public synchronized Key revoke(String id) throws IOException {
        Key k = byId(id);
        if (k != null) {
            keys.remove(k.hash());
            save();
        }
        return k;
    }

    /** Remove every key of a directory that was removed; the ids removed. */
    public synchronized List<String> removeDirectory(String directoryId) throws IOException {
        List<String> ids = all(directoryId).stream().map(Key::id).toList();
        if (keys.values().removeIf(k -> k.directoryId().equals(directoryId))) {
            save();
        }
        return ids;
    }

    /**
     * A single sign-on person signed in again: their keys take the grants of this sign-in, so a role taken away at
     * the provider leaves their keys at once. A key never goes past the roles it was made with.
     */
    public synchronized void signedIn(Sessions.Principal p) throws IOException {
        boolean changed = false;
        for (Map.Entry<String, Key> e : keys.entrySet()) {
            Key k = e.getValue();
            if ("oidc".equals(k.via()) && k.directoryId().equals(p.directoryId()) && DirectLogin.sameDn(k.dn(), p.dn())) {
                List<Grant> g = withoutPresets(p.grants());
                if (!g.equals(k.grants())) {
                    e.setValue(k.withGrants(g));
                    changed = true;
                }
            }
        }
        if (changed) {
            save();
        }
    }

    /**
     * What a key may do with a person's {@code grants}: each grant of a role the key carries, kept with its scopes;
     * a grant of another role reads only (viewer, same scopes); admin becomes each of the key's roles, everywhere.
     * Task presets are left out: they are changes.
     */
    public static List<Grant> limit(List<Grant> grants, Set<Role> roles) {
        List<Grant> out = new ArrayList<>();
        for (Grant g : grants) {
            if (g.role() == null) {
                continue;
            }
            if (g.role() == Role.ADMIN) {
                roles.stream().sorted().forEach(r -> out.add(Grant.everywhere(r)));
            } else {
                out.add(new Grant(roles.contains(g.role()) ? g.role() : Role.VIEWER, g.scopes(), List.of()));
            }
        }
        return out.stream().distinct().toList();
    }

    /**
     * {@code requested} role ids as a key's roles: viewer always, and only roles of the key ceiling the person has
     * (admin has them all). Throws IllegalArgumentException naming what is wrong.
     */
    public static Set<Role> roles(List<String> requested, Sessions.Principal p) {
        Set<Role> out = EnumSet.of(Role.VIEWER);
        for (String r : requested) {
            Role role = Role.parse(r);
            if (!CEILING.contains(role)) {
                throw new IllegalArgumentException("an agent key never carries the " + role.id() + " role");
            }
            if (!p.has(role) && role != Role.VIEWER) {
                throw new IllegalArgumentException("you do not have the " + role.id() + " role, so your key cannot have it");
            }
            out.add(role);
        }
        return Set.copyOf(out);
    }

    private static List<Grant> withoutPresets(List<Grant> grants) {
        return grants.stream().filter(g -> g.role() != null).map(g -> new Grant(g.role(), g.scopes(), List.of())).toList();
    }

    private void save() throws IOException {
        List<Object> list = new ArrayList<>();
        for (Key k : keys.values()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", k.id());
            m.put("hash", k.hash());
            m.put("label", k.label());
            m.put("directory", k.directoryId());
            m.put("dn", k.dn());
            m.put("subject", k.subject());
            m.put("name", k.name());
            m.put("via", k.via());
            m.put("roles", k.roles().stream().map(Role::id).sorted().toList());
            m.put("grants", k.grants().stream().map(g -> Map.of("role", g.role().id(), "scopes", g.scopes())).toList());
            m.put("created", k.created().toString());
            m.put("expires", k.expires().toString());
            if (k.lastUsed() != null) {
                m.put("lastUsed", k.lastUsed().toString());
            }
            if (k.apps() != null) {
                m.put("apps", k.apps());
            }
            if (k.appsState() != null) {
                m.put("appsState", k.appsState());
            }
            list.add(m);
        }
        DataDir.write(file, Json.pretty(Map.of("keys", list)).getBytes(StandardCharsets.UTF_8));
    }

    private static Key parse(Map<String, Object> m) {
        Set<Role> roles = EnumSet.noneOf(Role.class);
        for (Object r : Json.asList(m.get("roles"))) {
            Role role = Role.parse(String.valueOf(r));
            if (CEILING.contains(role)) {
                roles.add(role);
            }
        }
        List<Grant> grants = new ArrayList<>();
        for (Object o : Json.asList(m.get("grants"))) {
            Map<String, Object> g = Json.asMap(o);
            grants.add(new Grant(Role.parse(String.valueOf(g.get("role"))), Json.asList(g.get("scopes")).stream().map(String::valueOf).toList(), List.of()));
        }
        Object used = m.get("lastUsed");
        return new Key(String.valueOf(m.get("id")), String.valueOf(m.get("hash")).toLowerCase(Locale.ROOT), String.valueOf(m.get("label")),
            String.valueOf(m.get("directory")), String.valueOf(m.get("dn")), String.valueOf(m.get("subject")), String.valueOf(m.get("name")),
            String.valueOf(m.get("via")), roles, grants, Instant.parse(String.valueOf(m.get("created"))), Instant.parse(String.valueOf(m.get("expires"))),
            used == null ? null : Instant.parse(String.valueOf(used)), m.get("apps") instanceof Map<?, ?> a ? Json.asMap(a) : null, Json.asString(m.get("appsState")));
    }

    static String sha256(String token) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.US_ASCII)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
