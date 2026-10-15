import { useEffect, useState } from 'react';
import {
  ActionGroup, Alert, Button, ExpandableSection, Form, FormGroup, FormHelperText, HelperText, HelperTextItem, LoginPage, TextInput,
} from '@patternfly/react-core';
import { ApiError, type Me, type Probe, session, setup } from '../api';
import { CertificateOffer, confirmed } from '../components/CertificateOffer';

/** The setup token from the setup link (#token=…), taken out of the address bar once read. */
function tokenFromLink(): string {
  const m = /(?:^#|&)token=([0-9a-fA-F]{32})/.exec(location.hash);
  if (m) {
    history.replaceState(null, '', location.pathname === '/setup' ? '/' : location.pathname);
  }
  return m ? m[1].toLowerCase() : '';
}

/**
 * First sign-in (bootstrap mode): the console has no tree yet. The person opens the setup link from the
 * console's log, enters the tree's address and a tree administrator's name and password; when the console
 * does not trust the tree's certificate it is shown, and trusted once they type the last 8 digits of its
 * fingerprint. That tree becomes the console's, the administrator its break-glass account, and they are
 * signed in. Everything else (service account, sign-in options, tier) is set later in Settings.
 */
export function SetupRequired({ onSignedIn }: { onSignedIn: (me: Me) => void }) {
  const [token, setToken] = useState(tokenFromLink);
  const [tokenOk, setTokenOk] = useState<boolean | null>(null);
  const [fingerprint, setFingerprint] = useState<string | null>(null);
  const [host, setHost] = useState('');
  const [port, setPort] = useState('636');
  const [dn, setDn] = useState('');
  const [password, setPassword] = useState('');
  const [offer, setOffer] = useState<Probe | null>(null);
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!/^[0-9a-f]{32}$/i.test(token.trim())) {
      setTokenOk(null);
      return;
    }
    setup.state(token.trim()).then((s) => { setTokenOk(true); setFingerprint(s.consoleCertificate.sha256); }, () => setTokenOk(false));
  }, [token]);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const done = await setup.firstSignIn(token.trim(), {
        host: host.trim(), port: Number(port), dn: dn.trim(), password,
        accept: offer ? { probeId: offer.probeId, confirm: confirm.replace(/[^0-9a-fA-F]/g, '') } : undefined,
      });
      onSignedIn(await session.signIn(done.directory, dn.trim(), password));
    } catch (x) {
      if (x instanceof ApiError && x.code === 'untrusted-certificate' && x.problem.probe) {
        setOffer(x.problem.probe as Probe);
        setConfirm('');
      } else if (x instanceof ApiError && x.code === 'setup-token') {
        setTokenOk(false);
        setError('That setup token is not the current one. Open the newest setup link in the console\'s log.');
      } else {
        setError(x instanceof ApiError ? (x.code === 'confirmation-mismatch' ? 'Those are not the last 8 digits of the fingerprint.' : x.message) : 'Setup failed.');
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <LoginPage loginTitle="Set up Directory Console" loginSubtitle="Sign in to your eDirectory tree as an administrator to start.">
      {tokenOk !== true ? (
        <Form onSubmit={(e) => e.preventDefault()}>
          <p>Open the <strong>setup link</strong> printed in the console's log, or paste the setup token from it here.</p>
          <p className="dc-subtle">Docker: <code className="dc-mono">docker compose logs console</code> (or the container's Logs tab in Docker Desktop).</p>
          <FormGroup label="Setup token" fieldId="setup-token">
            <TextInput id="setup-token" className="dc-mono" value={token} onChange={(_e, v) => setToken(v.trim())} autoFocus
              validated={tokenOk === false ? 'error' : 'default'} />
            {tokenOk === false && <FormHelperText><HelperText><HelperTextItem variant="error">
              That token is not the current one (each is valid for an hour, and a restart prints a new one).
            </HelperTextItem></HelperText></FormHelperText>}
          </FormGroup>
        </Form>
      ) : (
        <Form onSubmit={(e) => { e.preventDefault(); submit(); }}>
          <ExpandableSection toggleText="Check that you reached your console">
            <p className="dc-subtle">
              The log printed this console's certificate fingerprint beside the setup link. Your browser shows the certificate
              of this page (the padlock or "Not secure" in the address bar, then the certificate). Its SHA-256 fingerprint should be:
            </p>
            <p className="dc-mono">{fingerprint}</p>
          </ExpandableSection>
          <FormGroup label="Tree address" fieldId="setup-host" isRequired>
            <TextInput id="setup-host" value={host} onChange={(_e, v) => { setHost(v); setOffer(null); }} isRequired autoFocus />
            <FormHelperText><HelperText><HelperTextItem>An eDirectory server's host name or IP address, as the console's container reaches it.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <FormGroup label="LDAPS port" fieldId="setup-port" isRequired>
            <TextInput id="setup-port" type="number" value={port} onChange={(_e, v) => { setPort(v); setOffer(null); }} isRequired />
          </FormGroup>
          <FormGroup label="Administrator" fieldId="setup-dn" isRequired>
            <TextInput id="setup-dn" value={dn} onChange={(_e, v) => setDn(v)} autoComplete="username" isRequired />
            <FormHelperText><HelperText><HelperTextItem>A tree administrator's full name (DN), such as cn=admin,o=system. It becomes the console's break-glass account.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <FormGroup label="Password" fieldId="setup-password" isRequired>
            <TextInput id="setup-password" type="password" value={password} onChange={(_e, v) => setPassword(v)} autoComplete="current-password" isRequired />
          </FormGroup>
          {offer && <CertificateOffer id="setup-offer" offer={offer} confirm={confirm} onConfirm={setConfirm} />}
          {error && <Alert variant="danger" isInline isPlain title={error} />}
          <ActionGroup>
            <Button type="submit" isBlock isLoading={busy}
              isDisabled={busy || !host.trim() || !(Number(port) > 0) || !dn.trim() || !password || (!!offer && !confirmed(confirm))}>
              {offer ? 'Trust and sign in' : 'Sign in'}
            </Button>
          </ActionGroup>
        </Form>
      )}
    </LoginPage>
  );
}
