import { createContext, useContext } from 'react';
import { type Me, type Tree, tree } from './api';

export interface SessionState {
  me: Me;
  tree: Tree;
  can: (role: 'viewer' | 'editor' | 'operator' | 'admin') => boolean;
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
    signOut,
  };
}
