/**
 * The console's help, one topic per page or tab, shown in the help panel (the ? in the header). Plain
 * structured text rather than HTML or Markdown: it renders with PatternFly under the console's strict
 * content security policy, needs no network, and changes with each version of the console.
 */

/** A section: a heading and paragraphs, or a list when {@code list} is set. */
export interface HelpSection {
  title: string;
  paragraphs?: string[];
  list?: string[];
  /** A caution: shown as a warning. */
  caution?: boolean;
}

export interface HelpTopic {
  title: string;
  /** One or two sentences: what the screen is for. */
  summary: string;
  sections: HelpSection[];
  /** Other topics worth reading next, by id. */
  related?: string[];
}

import { CONTENT } from './content';

export const TOPICS: Record<string, HelpTopic> = {
  ...CONTENT,
  // a driver's tabs that read as the driver set's
  'idm.driver.jobs': CONTENT['idm.jobs'],
  'idm.driver.mapping-tables': CONTENT['idm.mapping-tables'],
  console: {
    title: 'Directory Console',
    summary: 'Directory Console manages eDirectory objects and Identity Manager drivers in a web browser. Everything you do runs with your own eDirectory rights.',
    sections: [
      {
        title: 'Getting around',
        list: [
          'The navigation on the left lists what your role lets you use. Its foot shows the console\'s version.',
          'The ? in the header opens help for the page you are on.',
          'Your name, top right, shows which directory you are signed in to and your roles, and signs you out.',
          'The sun and moon in the header switch between light and dark.',
        ],
      },
    ],
  },
};

/** The help topic for a page: the most specific one that exists, falling back to the console's own. */
export function topicFor(id: string): { id: string; topic: HelpTopic } {
  const parts = id.split('.');
  while (parts.length > 0) {
    const key = parts.join('.');
    if (TOPICS[key]) {
      return { id: key, topic: TOPICS[key] };
    }
    parts.pop();
  }
  return { id: 'console', topic: TOPICS.console };
}

/** A page's help topic from its address, before the page names a more specific one (a tab). */
export function topicForPath(path: string): string {
  const p = path.split('?')[0].replace(/\/+$/, '');
  if (p === '' || p === '/' || p.startsWith('/browse')) {
    return 'browse';
  }
  if (p.startsWith('/objects/')) {
    return 'object';
  }
  if (p.startsWith('/security/password-policies/')) {
    return 'security.password-policy';
  }
  if (p.startsWith('/security/challenge-sets/')) {
    return 'security.challenge-set';
  }
  if (p.startsWith('/edir/ldap-servers/')) {
    return 'edir.ldap-server';
  }
  if (p.startsWith('/edir/ldap-groups/')) {
    return 'edir.ldap-group';
  }
  if (p.startsWith('/edir/servers/')) {
    return 'edir.server';
  }
  if (p.startsWith('/idm/drivers/')) {
    return 'idm.driver';
  }
  if (p.startsWith('/idm')) {
    return 'idm';
  }
  if (p.startsWith('/schema')) {
    return 'schema';
  }
  const first = p.split('/')[1];
  const second = p.split('/')[2];
  return second && !/^[0-9a-f]{32}$/.test(second) ? `${first}.${second}` : first;
}
