import { describe, expect, it } from 'vitest';
import { TOPICS, topicFor, topicForPath } from './topics';

/** Every page and tab of the console, as the shell and the tabbed pages name them. */
const PAGES = [
  'browse', 'object', 'search', 'schema', 'certificates', 'settings',
  'edir.partitions', 'edir.servers', 'edir.server', 'edir.ldap', 'edir.ldap-server', 'edir.ldap-group',
  'security.certificates', 'security.password-policies', 'security.challenge-sets', 'security.login-methods', 'security.eba',
  'security.password-policy', 'security.challenge-set',
  ...['attributes', 'account', 'certificates', 'groups', 'members', 'associations', 'rights', 'replicas', 'identity'].map((t) => `object.${t}`),
  ...['drivers', 'jobs', 'servers', 'properties', 'statistics', 'versions', 'trace', 'mapping-tables', 'log', 'passwords'].map((t) => `idm.${t}`),
  ...['overview', 'jobs', 'associations', 'cache', 'health', 'properties', 'trace', 'mapping-tables', 'log', 'passwords', 'password-sync'].map((t) => `idm.driver.${t}`),
  ...['directory', 'roles', 'presets', 'sso', 'trees', 'other', 'updates', 'proxy'].map((t) => `settings.${t}`),
];

describe('help topics', () => {
  it('give every page and tab help of its own, not only the general topic', () => {
    for (const p of PAGES) {
      expect(topicFor(p).id, p).not.toBe('console');
    }
  });

  it('link only to topics that exist', () => {
    for (const [id, t] of Object.entries(TOPICS)) {
      for (const r of t.related ?? []) {
        expect(TOPICS[r], `${id} → ${r}`).toBeDefined();
      }
    }
  });

  it('pick a page\'s topic from its address', () => {
    expect(topicForPath('/browse/0123456789abcdef0123456789abcdef')).toBe('browse');
    expect(topicForPath('/security/password-policies')).toBe('security.password-policies');
    expect(topicForPath('/security/password-policies/0123456789abcdef0123456789abcdef')).toBe('security.password-policy');
    expect(topicForPath('/idm/drivers/0123456789abcdef0123456789abcdef')).toBe('idm.driver');
    expect(topicForPath('/settings')).toBe('settings');
  });
});
