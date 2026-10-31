package com.pointblue.console.server.auth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class AgentKeysTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    /** A clock the test moves. */
    private static final class Moving extends Clock {
        Instant now = Instant.parse("2026-10-30T12:00:00Z");

        @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId z) { return this; }
        @Override public Instant instant() { return now; }
    }

    private static Sessions.Principal pat(String via, List<Grant> grants) {
        return new Sessions.Principal("cn=pat,ou=users,o=acme", "cn=pat,ou=users,o=acme", "Pat", "acme", DirectLogin.roles(grants), via, grants);
    }

    @Test
    public void onlyTheHashIsKeptAndTheKeyIsFoundByItsToken() throws Exception {
        Path file = tmp.getRoot().toPath().resolve("agents/keys.json");
        Moving clock = new Moving();
        AgentKeys keys = new AgentKeys(file, clock);
        AgentKeys.Made m = keys.create("laptop", pat("direct", List.of(Grant.everywhere(Role.EDITOR))), Set.of(Role.VIEWER), Duration.ofDays(30));
        assertTrue(m.token().startsWith("dc_"));
        assertEquals(46, m.token().length());
        String stored = Files.readString(file);
        assertFalse("the token is never written", stored.contains(m.token().substring(3)));
        assertTrue(stored.contains(AgentKeys.sha256(m.token())));
        assertFalse("the listing carries no hash", m.key().json(clock.now).containsKey("hash"));

        AgentKeys again = new AgentKeys(file, clock);
        assertEquals("laptop", again.find(m.token()).label());
        assertNull(again.find("dc_nothing"));
        assertNull(again.find(m.token().substring(3)));
        assertEquals(m.key().id(), again.revoke(m.key().id()).id());
        assertNull(new AgentKeys(file, clock).find(m.token()));
    }

    @Test
    public void aKeyExpiresAndStopsWhenIdle() throws Exception {
        Moving clock = new Moving();
        AgentKeys keys = new AgentKeys(tmp.getRoot().toPath().resolve("k.json"), clock);
        AgentKeys.Key k = keys.create("ci", pat("direct", List.of(Grant.everywhere(Role.VIEWER))), Set.of(Role.VIEWER), Duration.ofDays(30)).key();
        assertEquals("active", k.state(clock.now));
        clock.now = clock.now.plus(Duration.ofDays(13));
        k = keys.used(k);
        clock.now = clock.now.plus(Duration.ofDays(13));
        assertEquals("used 13 days ago", "active", k.state(clock.now));
        clock.now = clock.now.plus(Duration.ofDays(1));
        assertEquals("14 days unused", "idle", k.state(clock.now));
        clock.now = Instant.parse("2026-11-29T12:00:00Z");
        assertEquals("expired", k.state(clock.now));
        clock.now = clock.now.plus(Duration.ofDays(31));
        assertNull("a month after it expired the key is dropped", new AgentKeys(tmp.getRoot().toPath().resolve("k.json"), clock).byId(k.id()));
    }

    @Test
    public void whatAKeyMayDo() {
        List<Grant> grants = List.of(new Grant(Role.EDITOR, List.of("ou=sales,o=acme"), List.of("reset")), new Grant(null, List.of(), List.of("hr")));
        assertEquals("a role the key does not carry reads only, in the same scopes; presets are left out",
            List.of(new Grant(Role.VIEWER, List.of("ou=sales,o=acme"), List.of())), AgentKeys.limit(grants, Set.of(Role.VIEWER)));
        assertEquals(List.of(new Grant(Role.EDITOR, List.of("ou=sales,o=acme"), List.of())), AgentKeys.limit(grants, Set.of(Role.VIEWER, Role.EDITOR)));
        assertEquals("admin becomes the key's roles, never admin",
            List.of(Grant.everywhere(Role.VIEWER), Grant.everywhere(Role.OPERATOR)),
            AgentKeys.limit(List.of(Grant.everywhere(Role.ADMIN)), Set.of(Role.VIEWER, Role.OPERATOR)));
        assertTrue("presets alone give a key nothing", AgentKeys.limit(List.of(new Grant(null, List.of(), List.of("hr"))), Set.of(Role.VIEWER)).isEmpty());

        Sessions.Principal editor = pat("direct", List.of(Grant.everywhere(Role.EDITOR)));
        assertEquals(Set.of(Role.VIEWER), AgentKeys.roles(List.of(), editor));
        assertEquals(Set.of(Role.VIEWER, Role.EDITOR), AgentKeys.roles(List.of("editor"), editor));
        assertThrows(IllegalArgumentException.class, () -> AgentKeys.roles(List.of("operator"), editor));
        assertThrows(IllegalArgumentException.class, () -> AgentKeys.roles(List.of("admin"), pat("direct", List.of(Grant.everywhere(Role.ADMIN)))));
        assertEquals(Set.of(Role.VIEWER, Role.OPERATOR), AgentKeys.roles(List.of("operator"), pat("direct", List.of(Grant.everywhere(Role.ADMIN)))));
    }

    @Test
    public void aSingleSignOnKeyTakesTheGrantsOfTheNextSignIn() throws Exception {
        AgentKeys keys = new AgentKeys(tmp.getRoot().toPath().resolve("k.json"), new Moving());
        AgentKeys.Key k = keys.create("sso", pat("oidc", List.of(Grant.everywhere(Role.EDITOR))), Set.of(Role.VIEWER, Role.EDITOR), Duration.ofDays(14)).key();
        assertEquals(List.of(Grant.everywhere(Role.EDITOR)), k.grants());
        keys.signedIn(pat("oidc", List.of(Grant.everywhere(Role.VIEWER))));
        assertEquals(List.of(Grant.everywhere(Role.VIEWER)), keys.byId(k.id()).grants());
        AgentKeys.Key direct = keys.create("d", pat("direct", List.of(Grant.everywhere(Role.EDITOR))), Set.of(Role.VIEWER), Duration.ofDays(1)).key();
        assertNotNull(direct);
        assertTrue("a direct sign-in's key keeps no grants: they are read on every call", direct.grants().isEmpty());
    }
}
