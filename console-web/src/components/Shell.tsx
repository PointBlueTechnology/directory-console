import { useEffect, useState } from 'react';
import {
  Dropdown, DropdownItem, DropdownList, Masthead, MastheadBrand, MastheadContent, MastheadLogo, MastheadMain,
  MastheadToggle, MenuToggle, Nav, NavItem, NavList, Page, PageSidebar, PageSidebarBody, PageToggleButton,
  ToggleGroup, ToggleGroupItem, Toolbar, ToolbarContent, ToolbarGroup, ToolbarItem,
} from '@patternfly/react-core';
import { MoonIcon, SunIcon, UserIcon } from '@patternfly/react-icons';
import { useSession } from '../session';
import { linkProps, match, navigate, useLocation } from '../router';
import { Browser } from '../pages/Browser';
import { Search } from '../pages/Search';
import { SchemaPage } from '../pages/SchemaPage';
import { ObjectPage } from '../pages/ObjectPage';
import { NotFound } from '../pages/NotFound';
import { ErrorBoundary } from './ErrorBoundary';

const NAV = [
  { to: '/browse', label: 'Browse' },
  { to: '/search', label: 'Search' },
  { to: '/schema', label: 'Schema' },
];

export function Shell() {
  const { me, signOut } = useSession();
  const { path } = useLocation();
  const [userOpen, setUserOpen] = useState(false);
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
                <ToggleGroup aria-label="Colour theme">
                  <ToggleGroupItem icon={<SunIcon />} aria-label="Light theme" isSelected={!dark} onChange={() => setDark(false)} />
                  <ToggleGroupItem icon={<MoonIcon />} aria-label="Dark theme" isSelected={dark} onChange={() => setDark(true)} />
                </ToggleGroup>
              </ToolbarItem>
              <ToolbarItem>
                <Dropdown isOpen={userOpen} onOpenChange={setUserOpen} popperProps={{ position: 'right' }}
                  toggle={(ref) => (
                    <MenuToggle ref={ref} variant="plainText" icon={<UserIcon />} isExpanded={userOpen} onClick={() => setUserOpen(!userOpen)}>
                      {me.name}
                    </MenuToggle>
                  )}>
                  <DropdownList>
                    <DropdownItem key="who" isDisabled description={`${me.directory} · ${me.roles.join(', ')}`}>{me.dn}</DropdownItem>
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
      <PageSidebarBody>
        <Nav aria-label="Main">
          <NavList>
            {NAV.map((n) => (
              <NavItem key={n.to} to={n.to} isActive={path === n.to || path.startsWith(n.to + '/')}
                onClick={(e) => { e.preventDefault(); navigate(n.to); }}>{n.label}</NavItem>
            ))}
          </NavList>
        </Nav>
      </PageSidebarBody>
    </PageSidebar>
  );

  return (
    <Page masthead={masthead} sidebar={sidebar} isManagedSidebar mainAriaLabel="Directory Console">
      <ErrorBoundary resetKey={path}>{route(path)}</ErrorBoundary>
    </Page>
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
  return <NotFound />;
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
