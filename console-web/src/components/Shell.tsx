import { Suspense, lazy, useEffect, useState } from 'react';
import {
  Dropdown, DropdownItem, DropdownList, Masthead, MastheadBrand, MastheadContent, MastheadLogo, MastheadMain,
  MastheadToggle, MenuToggle, Nav, NavItem, NavList, Page, PageSidebar, PageSidebarBody, PageToggleButton,
  Alert, AlertActionLink, Bullseye, Button, Drawer, DrawerContent, DrawerContentBody, Tooltip, PageSection, Spinner, ToggleGroup, ToggleGroupItem, Toolbar, ToolbarContent, ToolbarGroup, ToolbarItem,
} from '@patternfly/react-core';
import { MoonIcon, OutlinedQuestionCircleIcon, SunIcon, UserIcon } from '@patternfly/react-icons';
import { HelpContext, HelpPanel, useHelpState } from '../help/Help';
import { topicForPath } from '../help/topics';
import { useSession } from '../session';
import { type UpdateState, daysUntil, trust, updates } from '../api';
import { linkProps, match, navigate, useLocation } from '../router';
import { Browser } from '../pages/Browser';
import { Search } from '../pages/Search';
import { SchemaPage } from '../pages/SchemaPage';
import { ObjectPage } from '../pages/ObjectPage';
import { NotFound } from '../pages/NotFound';
import { ErrorBoundary } from './ErrorBoundary';
import { SessionWarning } from './SessionWarning';
import { UpdateBanner } from './UpdateBanner';
import { WARN_DAYS } from './Certificates';
import { LdapGroupPage, LdapServerPage } from '../pages/LdapPages';

// administration pages load when first opened: most sessions never visit them
const IdmPage = lazy(() => import('../pages/IdmPage').then((m) => ({ default: m.IdmPage })));
const DriverPage = lazy(() => import('../pages/DriverPage').then((m) => ({ default: m.DriverPage })));
const CertificatesPage = lazy(() => import('../pages/CertificatesPage').then((m) => ({ default: m.CertificatesPage })));
const SettingsPage = lazy(() => import('../pages/SettingsPage').then((m) => ({ default: m.SettingsPage })));
const EdirPage = lazy(() => import('../pages/EdirPage').then((m) => ({ default: m.EdirPage })));
const ServerPage = lazy(() => import('../pages/EdirPage').then((m) => ({ default: m.ServerPage })));
const SecurityPage = lazy(() => import('../pages/SecurityPage').then((m) => ({ default: m.SecurityPage })));
const PasswordPolicyPage = lazy(() => import('../pages/PolicyPages').then((m) => ({ default: m.PasswordPolicyPage })));
const ChallengeSetPage = lazy(() => import('../pages/PolicyPages').then((m) => ({ default: m.ChallengeSetPage })));

const NAV: { to: string; label: string; show?: (s: ReturnType<typeof useSession>) => boolean }[] = [
  { to: '/browse', label: 'Browse' },
  { to: '/search', label: 'Search' },
  { to: '/schema', label: 'Schema' },
  // a person with task presets only has no role: Identity Manager is not for them
  { to: '/edir', label: 'eDirectory', show: (s) => s.me.roles.length > 0 },
  { to: '/security', label: 'Security', show: (s) => s.me.roles.length > 0 },
  // Identity Manager needs a configured directory: not for one the person entered themselves
  { to: '/idm', label: 'Identity Manager', show: (s) => s.me.roles.length > 0 && s.me.via !== 'user-directory' },
  { to: '/certificates', label: 'Certificates', show: (s) => s.can('admin') },
  { to: '/settings', label: 'Settings', show: (s) => s.can('admin') },
];

export function Shell() {
  const sessionState = useSession();
  const { me, signOut } = sessionState;
  const { path } = useLocation();
  const [userOpen, setUserOpen] = useState(false);
  const help = useHelpState(topicForPath(path));
  const [version, setVersion] = useState<{ version: string; update?: UpdateState } | null>(null);
  useEffect(() => { updates.version().then(setVersion).catch(() => setVersion(null)); }, []);
  const [dark, setDark] = useDarkTheme();

  useEffect(() => {
    if (path === '/' || path === '') {
      navigate('/browse', true);
    }
  }, [path]);

  const masthead = (
    <Masthead>
      <MastheadMain>
        <MastheadToggle>
          <PageToggleButton isHamburgerButton aria-label="Navigation" />
        </MastheadToggle>
        <MastheadBrand>
          <MastheadLogo component="a" {...linkProps('/browse')}>
            <span className="pb-wordmark">Directory <span className="pb-wordmark__accent">Console</span></span>
          </MastheadLogo>
        </MastheadBrand>
      </MastheadMain>
      <MastheadContent>
        <Toolbar isFullHeight isStatic>
          <ToolbarContent>
            <ToolbarGroup align={{ default: 'alignEnd' }} gap={{ default: 'gapMd' }}>
              <ToolbarItem>
                <Tooltip content="Help for this page">
                  <Button variant={help.open ? 'secondary' : 'plain'} aria-label="Help for this page" aria-expanded={help.open}
                    icon={<OutlinedQuestionCircleIcon />} onClick={() => help.setOpen(!help.open)} />
                </Tooltip>
              </ToolbarItem>
              <ToolbarItem>
                <ToggleGroup aria-label="Colour theme">
                  <ToggleGroupItem icon={<SunIcon />} aria-label="Light theme" isSelected={!dark} onChange={() => setDark(false)} />
                  <ToggleGroupItem icon={<MoonIcon />} aria-label="Dark theme" isSelected={dark} onChange={() => setDark(true)} />
                </ToggleGroup>
              </ToolbarItem>
              <ToolbarItem>
                <Dropdown isOpen={userOpen} onOpenChange={setUserOpen} popperProps={{ position: 'right', appendTo: 'inline' }}
                  toggle={(ref) => (
                    <MenuToggle ref={ref} variant="plainText" icon={<UserIcon />} isExpanded={userOpen} onClick={() => setUserOpen(!userOpen)}>
                      {me.name}
                    </MenuToggle>
                  )}>
                  <DropdownList>
                    <DropdownItem key="who" isDisabled description={me.via === 'user-directory' ? 'a directory you entered · your own rights' : `${me.directory} · ${me.roles.join(', ')}`}>{me.dn}</DropdownItem>
                    {version && (
                      <DropdownItem key="version" isDisabled description={version.update?.newer ? `${version.update.latest} is available`
                        : version.update?.enabled && version.update.error ? 'Cannot check for new versions' : undefined}>
                        Directory Console {version.version}
                      </DropdownItem>
                    )}
                    <DropdownItem key="out" onClick={signOut}>Sign out</DropdownItem>
                  </DropdownList>
                </Dropdown>
              </ToolbarItem>
            </ToolbarGroup>
          </ToolbarContent>
        </Toolbar>
      </MastheadContent>
    </Masthead>
  );

  const sidebar = (
    <PageSidebar>
      <PageSidebarBody isFilled>
        <Nav aria-label="Main">
          <NavList>
            {NAV.filter((n) => !n.show || n.show(sessionState)).map((n) => (
              <NavItem key={n.to} to={n.to} isActive={path === n.to || path.startsWith(n.to + '/')}
                onClick={(e) => { e.preventDefault(); navigate(n.to); }}>{n.label}</NavItem>
            ))}
          </NavList>
        </Nav>
      </PageSidebarBody>
      {version && (
        <PageSidebarBody isFilled={false} className="dc-version">
          Directory Console {version.version}
          {version.update?.newer && (
            <> · <Button variant="link" isInline onClick={() => navigate('/settings?tab=updates')}>{version.update.latest} available</Button></>
          )}
        </PageSidebarBody>
      )}
    </PageSidebar>
  );

  return (
    <HelpContext.Provider value={help}>
    <Page masthead={masthead} sidebar={sidebar} isManagedSidebar mainAriaLabel="Directory Console">
      {sessionState.can('admin') && path !== '/certificates' && <ExpiryBanner />}
      {sessionState.can('admin') && path !== '/settings' && <UpdateBanner update={version?.update ?? null} />}
      <SessionWarning />
      <Drawer isExpanded={help.open} isInline position="end">
        <DrawerContent panelContent={<HelpPanel onClose={() => help.setOpen(false)} />}>
          <DrawerContentBody>
            <ErrorBoundary resetKey={path}>
              <Suspense fallback={<Bullseye><Spinner aria-label="Loading" /></Bullseye>}>{route(path)}</Suspense>
            </ErrorBoundary>
          </DrawerContentBody>
        </DrawerContent>
      </Drawer>
    </Page>
    </HelpContext.Provider>
  );
}

function route(path: string) {
  if (path === '/browse' || path === '/') {
    return <Browser />;
  }
  let m = match('/browse/:guid', path);
  if (m) {
    return <Browser container={m.guid} />;
  }
  m = match('/objects/:guid', path);
  if (m) {
    return <ObjectPage guid={m.guid} />;
  }
  if (path === '/search') {
    return <Search />;
  }
  if (path === '/schema') {
    return <SchemaPage />;
  }
  m = match('/schema/:kind/:name', path);
  if (m && (m.kind === 'classes' || m.kind === 'attributes')) {
    return <SchemaPage kind={m.kind} name={m.name} />;
  }
  if (path === '/security') {
    return <SecurityPage />;
  }
  m = match('/security/:tab', path);
  if (m) {
    return <SecurityPage tab={m.tab} />;
  }
  m = match('/security/password-policies/:guid', path);
  if (m) {
    return <PasswordPolicyPage guid={m.guid} />;
  }
  m = match('/security/challenge-sets/:guid', path);
  if (m) {
    return <ChallengeSetPage guid={m.guid} />;
  }
  if (path === '/edir') {
    return <EdirPage />;
  }
  if (path === '/edir/servers') {
    return <EdirPage tab="servers" />;
  }
  if (path === '/edir/ldap') {
    return <EdirPage tab="ldap" />;
  }
  m = match('/edir/ldap-servers/:guid', path);
  if (m) {
    return <LdapServerPage guid={m.guid} />;
  }
  m = match('/edir/ldap-groups/:guid', path);
  if (m) {
    return <LdapGroupPage guid={m.guid} />;
  }
  m = match('/edir/servers/:guid', path);
  if (m) {
    return <ServerPage guid={m.guid} />;
  }
  if (path === '/settings') {
    return <SettingsPage />;
  }
  if (path === '/certificates') {
    return <CertificatesPage />;
  }
  if (path === '/idm') {
    return <IdmPage />;
  }
  m = match('/idm/driversets/:guid', path);
  if (m) {
    return <IdmPage driverSet={m.guid} />;
  }
  m = match('/idm/drivers/:guid', path);
  if (m) {
    return <DriverPage guid={m.guid} />;
  }
  return <NotFound />;
}

/** Administrators are told of changed pinned certificates, and of trusted ones expired or expiring within WARN_DAYS. */
function ExpiryBanner() {
  const [soon, setSoon] = useState<{ expired: number; expiring: number; changed: number } | null>(null);
  useEffect(() => {
    trust.list().then((t) => {
      const days = t.certificates.map((c) => daysUntil(c.notAfter));
      setSoon({ expired: days.filter((d) => d < 0).length, expiring: days.filter((d) => d >= 0 && d <= WARN_DAYS).length, changed: t.alerts.length });
    }).catch(() => setSoon(null));
  }, []);
  if (!soon || (soon.expired === 0 && soon.expiring === 0 && soon.changed === 0)) {
    return null;
  }
  const parts = [
    soon.changed && `${soon.changed} pinned ${soon.changed === 1 ? 'certificate has' : 'certificates have'} changed`,
    soon.expired && `${soon.expired} expired`,
    soon.expiring && `${soon.expiring} expiring within ${WARN_DAYS} days`,
  ].filter(Boolean).join(', ');
  return (
    <PageSection padding={{ default: 'noPadding' }}>
      <Alert variant={soon.changed || soon.expired ? 'danger' : 'warning'} isInline component="h2" title={`Certificates: ${parts}`}
        actionLinks={<AlertActionLink onClick={() => navigate('/certificates')}>Review certificates</AlertActionLink>} />
    </PageSection>
  );
}

/** Light or dark, following the system until the person picks; the choice is kept in this browser only. */
function useDarkTheme(): [boolean, (d: boolean) => void] {
  const [dark, setDark] = useState(() => {
    try {
      const saved = localStorage.getItem('dc-theme');
      if (saved) {
        return saved === 'dark';
      }
    } catch {
      // storage unavailable: follow the system
    }
    return window.matchMedia?.('(prefers-color-scheme: dark)').matches ?? false;
  });
  useEffect(() => {
    document.documentElement.classList.toggle('pf-v6-theme-dark', dark);
  }, [dark]);
  return [dark, (d) => {
    setDark(d);
    try {
      localStorage.setItem('dc-theme', d ? 'dark' : 'light');
    } catch {
      // not remembered
    }
  }];
}
