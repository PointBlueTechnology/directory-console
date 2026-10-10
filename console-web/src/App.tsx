import { useCallback, useEffect, useMemo, useState } from 'react';
import { Bullseye, Spinner } from '@patternfly/react-core';
import { ApiError, type Me, session, setCsrf, whenSignedOut } from './api';
import { Session, sessionState } from './session';
import { Shell } from './components/Shell';
import { SignIn } from './pages/SignIn';
import { SetupRequired } from './pages/SetupRequired';

type State = { kind: 'loading' } | { kind: 'signed-out'; reason?: string } | { kind: 'setup' } | { kind: 'signed-in'; me: Me };

export function App() {
  const [state, setState] = useState<State>({ kind: 'loading' });

  const signedIn = useCallback((me: Me) => {
    setCsrf(me.csrf);
    setState({ kind: 'signed-in', me });
  }, []);

  useEffect(() => {
    whenSignedOut(() => {
      setCsrf(null);
      setState({ kind: 'signed-out', reason: 'Your session ended. Sign in again.' });
    });
    session.me().then(signedIn).catch((e) => {
      if (e instanceof ApiError && e.status === 503 && e.code === 'setup-required') {
        setState({ kind: 'setup' });
      } else {
        setState({ kind: 'signed-out' });
      }
    });
  }, [signedIn]);

  const signOut = useCallback(() => {
    session.signOut().catch(() => undefined).finally(() => {
      setCsrf(null);
      setState({ kind: 'signed-out' });
    });
  }, []);

  const value = useMemo(() => (state.kind === 'signed-in' ? sessionState(state.me, signOut) : null), [state, signOut]);

  switch (state.kind) {
    case 'loading':
      return (
        <Bullseye>
          <Spinner aria-label="Loading" />
        </Bullseye>
      );
    case 'setup':
      return <SetupRequired />;
    case 'signed-out':
      return <SignIn reason={state.reason} onSignedIn={signedIn} />;
    case 'signed-in':
      return (
        <Session.Provider value={value}>
          <Shell />
        </Session.Provider>
      );
  }
}
