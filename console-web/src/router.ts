import { useEffect, useState } from 'react';

// A minimal history router: the console has a handful of pages and no need for a dependency. Paths
// carry GUIDs and fixed words only; a DN never appears in a URL path.

export function navigate(to: string, replace = false): void {
  if (to === location.pathname + location.search) {
    return;
  }
  if (replace) {
    history.replaceState(null, '', to);
  } else {
    history.pushState(null, '', to);
  }
  window.dispatchEvent(new PopStateEvent('popstate'));
}

export function useLocation(): { path: string; query: URLSearchParams } {
  const [loc, setLoc] = useState(() => ({ path: location.pathname, query: new URLSearchParams(location.search) }));
  useEffect(() => {
    const on = () => setLoc({ path: location.pathname, query: new URLSearchParams(location.search) });
    window.addEventListener('popstate', on);
    return () => window.removeEventListener('popstate', on);
  }, []);
  return loc;
}

/** {@code match('/browse/:guid', '/browse/abc')} → {@code {guid: 'abc'}}; null when it does not match. */
export function match(pattern: string, path: string): Record<string, string> | null {
  const p = pattern.split('/');
  const s = path.replace(/\/+$/, '').split('/');
  if (p.length !== s.length) {
    return null;
  }
  const out: Record<string, string> = {};
  for (let i = 0; i < p.length; i++) {
    if (p[i].startsWith(':')) {
      out[p[i].slice(1)] = decodeURIComponent(s[i]);
    } else if (p[i] !== s[i]) {
      return null;
    }
  }
  return out;
}

/** Same-page link clicks become history navigation (modified clicks still open new tabs). */
export function linkProps(to: string) {
  return {
    href: to,
    onClick: (e: React.MouseEvent) => {
      if (e.button === 0 && !e.metaKey && !e.ctrlKey && !e.shiftKey && !e.altKey) {
        e.preventDefault();
        navigate(to);
      }
    },
  };
}
