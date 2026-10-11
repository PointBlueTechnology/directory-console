import { createContext, useContext } from 'react';
import { type Me, type RoleId, type Tree, tree } from './api';
import { within } from './dn';

export interface SessionState {
  me: Me;
  tree: Tree;
  /** Whether some grant gives {@code role} anywhere (what menus to show at all). */
  can: (role: RoleId) => boolean;
  /** Whether a grant of {@code role} reaches {@code dn}, as the server decides (Sessions.Principal.may). */
  canAt: (role: RoleId, dn: string) => boolean;
  signOut: () => void;
}

export const Session = createContext<SessionState | null>(null);

export function useSession(): SessionState {
  const s = useContext(Session);
  if (!s) {
    throw new Error('no session');
  }
  return s;
}

export function sessionState(me: Me, signOut: () => void): SessionState {
  return {
    me,
    tree: tree(me.directory),
    // admin implies every role, as on the server (Sessions.Principal.has)
    can: (role) => me.roles.includes(role) || me.roles.includes('admin'),
    canAt: (role, dn) => (me.grants ?? []).some((g) => (g.role === role || g.role === 'admin')
      && (g.role === 'admin' || g.scopes.length === 0 || g.scopes.some((s) => within(dn, s)))),
    signOut,
  };
}
