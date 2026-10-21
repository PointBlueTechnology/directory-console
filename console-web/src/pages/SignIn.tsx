import { useEffect, useState } from 'react';
import {
  ActionGroup, Alert, Button, Checkbox, Form, FormGroup, FormHelperText, FormSelect, FormSelectOption, HelperText, HelperTextItem,
  Divider, LoginPage, Radio, TextInput,
} from '@patternfly/react-core';
import { ApiError, type Candidate, type Directory, type Me, type Probe, session } from '../api';
import { CertificateDetails } from '../components/Certificates';
import { explain } from '../help/glossary';
import { Hint } from '../help/Help';

/** What "Remember my name" keeps, in this browser only: never the password. */
interface Remembered {
  name: string;
  directory: string;
  host?: string;
  port?: string;
}

const REMEMBER_KEY = 'directory-console.sign-in';

function remembered(): Remembered | null {
  try {
    const v = JSON.parse(localStorage.getItem(REMEMBER_KEY) ?? 'null') as Remembered | null;
    return v && typeof v.name === 'string' && typeof v.directory === 'string' ? v : null;
  } catch {
    return null;
  }
}

function remember(v: Remembered | null): void {
  try {
    if (v) {
      localStorage.setItem(REMEMBER_KEY, JSON.stringify(v));
    } else {
      localStorage.removeItem(REMEMBER_KEY);
    }
  } catch {
    // storage blocked (a private window, site data cleared): sign-in still works, it just is not remembered
  }
}

/** The directory list's choice for an address the person types. */
const OTHER = '__other__';

interface Props {
  reason?: string;
  onSignedIn: (me: Me) => void;
}

const SSO_ERRORS: Record<string, string> = {
  state: 'That single sign-on attempt expired or was started in another browser. Try again.',
  provider: 'The identity provider refused or could not be reached. Try again, or ask an administrator.',
  'claim-missing': 'The identity provider did not say who you are in the way this console expects. Ask an administrator.',
  'no-account': 'No active account in this directory matches your single sign-on identity.',
  'ambiguous-account': 'More than one account matches your single sign-on identity. Ask an administrator to fix the mapping.',
  'never-proxy': 'This account signs in with its name and password, not through single sign-on.',
  'no-role': 'Your account has no Directory Console role. Ask an administrator to map one of your groups to a role.',
  'proxy-refused': 'The directory would not let the console act for you: your account may be disabled or expired.',
  'not-configured': 'Single sign-on is not set up for this directory.',
  unavailable: 'The directory did not answer. Try again in a moment.',
};

/** The message for a failed single sign-on, from the callback's redirect (?sso-error=…), once. */
function ssoError(): string | null {
  const code = new URLSearchParams(location.search).get('sso-error');
  if (!code) {
    return null;
  }
  history.replaceState(null, '', location.pathname);
  return SSO_ERRORS[code] ?? 'Single sign-on failed.';
}

/**
 * Direct sign-in (section 7.2), and single sign-on (section 7.3) where the directory has it: a full
 * page navigation to the provider, which comes back to the console signed in. A bare name is resolved by the console; when it matches several
 * accounts and the directory's policy is "choose", the person picks theirs and the password is sent
 * again with that choice, so it is only ever tried against the one account they picked.
 */
export function SignIn({ reason, onSignedIn }: Props) {
  const [directories, setDirectories] = useState<Directory[] | null>(null);
  const [saved] = useState(remembered);
  const [rememberMe, setRememberMe] = useState(!!saved);
  const [directory, setDirectory] = useState('');
  const [name, setName] = useState(saved?.name ?? '');
  const [password, setPassword] = useState('');
  const [candidates, setCandidates] = useState<Candidate[] | null>(null);
  const [choice, setChoice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(ssoError);
  const [busy, setBusy] = useState(false);
  const [others, setOthers] = useState(false);
  const [host, setHost] = useState(saved?.host ?? '');
  const [port, setPort] = useState(saved?.port ?? '636');
  const [offer, setOffer] = useState<Probe | null>(null);
  const [confirm, setConfirm] = useState('');
  const [passwordAnyway, setPasswordAnyway] = useState(false);
  const chosen = directories?.find((d) => d.id === directory);
  const other = directory === OTHER;
  // a directory that is single sign-on only shows the password form on request (or for a remembered name)
  const ssoOnly = !other && !!chosen?.sso && !chosen.direct;
  const passwordForm = !ssoOnly || passwordAnyway || !!candidates || (!!saved && saved.directory === directory);

  useEffect(() => {
    session.directories().then((d) => {
      setDirectories(d);
      // the remembered tree, while it is still offered; otherwise the first
      const keep = saved && (d.some((x) => x.id === saved.directory) || saved.directory === OTHER) ? saved.directory : null;
      setDirectory(keep ?? (d.length > 0 ? d[0].id : OTHER));
    }).catch(() => setError('The console did not answer. Try again in a moment.'));
    session.signInOptions().then((o) => setOthers(o.otherDirectories)).catch(() => setOthers(false));
  }, []);

  /** After a successful sign-in: keep or forget the name, as the person chose. */
  const signedIn = (me: Me) => {
    remember(rememberMe ? { name: name.trim(), directory, ...(directory === OTHER ? { host: host.trim(), port } : {}) } : null);
    onSignedIn(me);
  };

  const forget = () => {
    remember(null);
    setRememberMe(false);
    setName('');
  };

  /** A directory the person entered: an untrusted certificate is offered to them, and accepted for their own sign-ins. */
  const submitOther = async () => {
    try {
      const accept = offer ? { probeId: offer.probeId, confirm: confirm.trim() } : undefined;
      signedIn(await session.signInOther(host.trim(), Number(port), name.trim(), password, accept));
    } catch (x) {
      if (x instanceof ApiError && x.code === 'untrusted-certificate' && x.problem.probe) {
        setOffer(x.problem.probe as unknown as Probe);
        setConfirm('');
        setError(null);
        return;
      }
      if (x instanceof ApiError && x.code === 'configured-directory' && typeof x.problem.directory === 'string') {
        setDirectory(x.problem.directory);
        setOffer(null);
        setError(`${x.message}.`);
        return;
      }
      setPassword('');
      setError(x instanceof ApiError ? (x.code === 'confirmation-mismatch' ? 'Those are not the last 8 digits of the fingerprint.' : message(x)) : 'Sign-in failed.');
    }
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    if (other) {
      await submitOther();
      setBusy(false);
      return;
    }
    try {
      signedIn(await session.signIn(directory, name, password, candidates ? choice ?? undefined : undefined));
    } catch (x) {
      if (x instanceof ApiError && x.code === 'choose-account') {
        setCandidates((x.problem.candidates as Candidate[]) ?? []);
        setChoice(null);
        setError(null);
      } else {
        setCandidates(null);
        setPassword('');
        setError(x instanceof ApiError ? message(x) : 'Sign-in failed.');
      }
    } finally {
      setBusy(false);
    }
  };

  const restart = () => {
    setCandidates(null);
    setChoice(null);
    setPassword('');
  };

  return (
    <>
    {/* PatternFly's login title is an h2: the page's h1 is for screen readers */}
    <section aria-label="Directory Console"><h1 className="pf-v6-screen-reader">Directory Console</h1></section>
    <LoginPage textContent="Directory Console manages eDirectory objects and Identity Manager drivers. It acts with your own directory rights."
      loginTitle={candidates ? 'Choose your account' : 'Sign in to Directory Console'}
      loginSubtitle={candidates ? 'More than one account has this name.' : undefined}>
      <Form onSubmit={submit}>
        {reason && !error && <Alert component="h3" variant="info" isInline isPlain title={reason} />}
        {error && <Alert component="h3" variant="danger" isInline title={error} />}
        {!candidates && (
          <>
            {directories && (directories.length > 1 || others) && (
              <FormGroup label="Directory" fieldId="directory" isRequired>
                <FormSelect id="directory" value={directory} onChange={(_e, v) => { setDirectory(v); setOffer(null); }}>
                  {directories.map((d) => <FormSelectOption key={d.id} value={d.id} label={d.name} />)}
                  {others && <FormSelectOption value={OTHER} label="Another directory…" />}
                </FormSelect>
              </FormGroup>
            )}
            {other && (
              <>
                <FormGroup label="Address" fieldId="other-host" isRequired>
                  <TextInput id="other-host" value={host} onChange={(_e, v) => { setHost(v); setOffer(null); }} isRequired aria-describedby="other-host-help" />
                  <FormHelperText><HelperText id="other-host-help"><HelperTextItem>An eDirectory server's host name or IP address. You work there with your own rights.</HelperTextItem></HelperText></FormHelperText>
                </FormGroup>
                <FormGroup label="LDAPS port" fieldId="other-port" isRequired>
                  <TextInput id="other-port" type="number" value={port} onChange={(_e, v) => { setPort(v); setOffer(null); }} isRequired />
                </FormGroup>
              </>
            )}
            {!other && chosen?.sso && (
              <>
                <Button component="a" variant="primary" isBlock href={session.ssoUrl(chosen.id, location.pathname + location.search)}>
                  Sign in with {chosen.sso}
                </Button>
                <Divider />
                {chosen.direct
                  ? <p className="dc-subtle">Or sign in with your directory name and password:</p>
                  : passwordForm
                    ? <p className="dc-subtle">This directory uses single sign-on. Only <Hint text={explain('passwordSignIn')}><span tabIndex={0} className="dc-term">accounts an administrator has listed</span></Hint> sign in with a password:</p>
                    : <p className="dc-subtle">This directory uses single sign-on. <Button variant="link" isInline onClick={() => setPasswordAnyway(true)}>Administrator sign-in with a password</Button></p>}
              </>
            )}
            {passwordForm && <FormGroup label="Name" fieldId="name" isRequired>
              <TextInput id="name" value={name} onChange={(_e, v) => setName(v)} autoComplete="username"
                aria-describedby="name-help" isRequired autoFocus={!saved} />
              <FormHelperText>
                <HelperText id="name-help">
                  <HelperTextItem>{other ? 'Your full name (DN), such as cn=jsmith,ou=sales,o=acme' : 'Your user name, or your full name such as jsmith.sales.acme'}</HelperTextItem>
                </HelperText>
              </FormHelperText>
            </FormGroup>}
            {other && offer && (
              <section aria-labelledby="offer-title" className="dc-tab-body">
                <Alert id="offer-title" component="h3" variant="warning" isInline title="The console does not trust this directory's certificate">
                  {offer.status === 'pin-changed'
                    ? 'This address now presents a different certificate from the one you accepted before. Unless you know it was renewed, do not go on.'
                    : 'It was not issued by a certificate authority the console trusts for you.'}
                  {' '}If it is the certificate you expect (check its fingerprint with the directory's administrator), type the last 8 digits: it is then trusted for your own sign-ins to this address, once your password is accepted.
                  {!offer.hostnameMatches && ` It names ${offer.chain[0].names.join(', ') || 'no host'}, not ${offer.host}; that is accepted for you too.`}
                </Alert>
                <CertificateDetails cert={offer.chain[offer.status === 'hostname' || offer.status === 'pin-changed' ? 0 : offer.recommended]} />
                <p className="dc-subtle">{offer.confirm}</p>
                <FormGroup label="Last 8 digits of the fingerprint" fieldId="offer-confirm" isRequired>
                  <TextInput id="offer-confirm" className="dc-mono" value={confirm} onChange={(_e, v) => setConfirm(v)} isRequired />
                </FormGroup>
              </section>
            )}
          </>
        )}
        {candidates && (
          <FormGroup role="radiogroup" label={`Accounts named ${name}`} fieldId="choice" isRequired>
            {candidates.map((c) => (
              <Radio key={c.choice} id={`c-${c.choice}`} name="choice" isChecked={choice === c.choice}
                onChange={() => setChoice(c.choice)} label={c.context || '(top of the directory)'} description={c.label} />
            ))}
          </FormGroup>
        )}
        {passwordForm && <FormGroup label="Password" fieldId="password" isRequired>
          <TextInput id="password" type="password" value={password} onChange={(_e, v) => setPassword(v)}
            autoComplete="current-password" isRequired autoFocus={!!saved} />
        </FormGroup>}
        {passwordForm && !candidates && (
          <FormGroup fieldId="remember">
            <Checkbox id="remember" label="Remember my name on this computer" isChecked={rememberMe} onChange={(_e, v) => setRememberMe(v)}
              description={saved ? <Button variant="link" isInline onClick={forget}>Forget {saved.name}</Button> : 'Your name and directory are kept in this browser; your password never is.'} />
          </FormGroup>
        )}
        {passwordForm && <ActionGroup>
          <Button type="submit" variant={!other && chosen?.sso ? 'secondary' : 'primary'} isBlock isLoading={busy}
            isDisabled={busy || !directory || !password || (!candidates && !name) || (!!candidates && !choice)
              || (other && (!host.trim() || !(Number(port) > 0))) || (other && !!offer && confirm.replace(/[^0-9a-fA-F]/g, '').length !== 8)}>
            {other && offer ? 'Trust and sign in' : 'Sign in'}
          </Button>
          {candidates && <Button variant="link" onClick={restart}>Use a different name</Button>}
        </ActionGroup>}
      </Form>
    </LoginPage>
    </>
  );
}

function message(e: ApiError): string {
  switch (e.code) {
    case 'too-many-attempts':
      return 'Too many failed sign-ins. Wait a few minutes and try again.';
    case 'untrusted-certificate':
      return e.problem.reason === 'pin-changed'
        ? 'The directory presented a different certificate from the one the console was told to trust. Administrators have been alerted; sign in again once they have reviewed it.'
        : 'The directory\'s certificate is not trusted. An administrator can probe the directory and trust it.';
    default:
      return e.message;
  }
}
