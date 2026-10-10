import { useEffect, useState } from 'react';
import {
  ActionGroup, Alert, Button, Form, FormGroup, FormHelperText, FormSelect, FormSelectOption, HelperText, HelperTextItem,
  LoginPage, Radio, TextInput,
} from '@patternfly/react-core';
import { ApiError, type Candidate, type Directory, type Me, session } from '../api';

interface Props {
  reason?: string;
  onSignedIn: (me: Me) => void;
}

/**
 * Direct sign-in (section 7.2). A bare name is resolved by the console; when it matches several
 * accounts and the directory's policy is "choose", the person picks theirs and the password is sent
 * again with that choice, so it is only ever tried against the one account they picked.
 */
export function SignIn({ reason, onSignedIn }: Props) {
  const [directories, setDirectories] = useState<Directory[] | null>(null);
  const [directory, setDirectory] = useState('');
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [candidates, setCandidates] = useState<Candidate[] | null>(null);
  const [choice, setChoice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    session.directories().then((d) => {
      setDirectories(d);
      if (d.length > 0) {
        setDirectory(d[0].id);
      }
    }).catch(() => setError('The console did not answer. Try again in a moment.'));
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onSignedIn(await session.signIn(directory, name, password, candidates ? choice ?? undefined : undefined));
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
    <LoginPage textContent="Directory Console manages eDirectory objects and Identity Manager drivers. It acts with your own directory rights."
      loginTitle={candidates ? 'Choose your account' : 'Sign in to Directory Console'}
      loginSubtitle={candidates ? 'More than one account has this name.' : undefined}>
      <Form onSubmit={submit}>
        {reason && !error && <Alert variant="info" isInline isPlain title={reason} />}
        {error && <Alert variant="danger" isInline title={error} />}
        {!candidates && (
          <>
            {directories && directories.length > 1 && (
              <FormGroup label="Directory" fieldId="directory" isRequired>
                <FormSelect id="directory" value={directory} onChange={(_e, v) => setDirectory(v)}>
                  {directories.map((d) => <FormSelectOption key={d.id} value={d.id} label={d.name} />)}
                </FormSelect>
              </FormGroup>
            )}
            <FormGroup label="Name" fieldId="name" isRequired>
              <TextInput id="name" value={name} onChange={(_e, v) => setName(v)} autoComplete="username"
                aria-describedby="name-help" isRequired autoFocus />
              <FormHelperText>
                <HelperText id="name-help">
                  <HelperTextItem>Your user name, or your full name such as jsmith.sales.acme</HelperTextItem>
                </HelperText>
              </FormHelperText>
            </FormGroup>
          </>
        )}
        {candidates && (
          <FormGroup role="radiogroup" label={`Accounts named ${name}`} fieldId="choice" isRequired>
            {candidates.map((c) => (
              <Radio key={c.choice} id={`c-${c.choice}`} name="choice" isChecked={choice === c.choice}
                onChange={() => setChoice(c.choice)} label={c.context || '(top of the tree)'} description={c.label} />
            ))}
          </FormGroup>
        )}
        <FormGroup label="Password" fieldId="password" isRequired>
          <TextInput id="password" type="password" value={password} onChange={(_e, v) => setPassword(v)}
            autoComplete="current-password" isRequired />
        </FormGroup>
        <ActionGroup>
          <Button type="submit" variant="primary" isBlock isLoading={busy}
            isDisabled={busy || !directory || !password || (!candidates && !name) || (!!candidates && !choice)}>
            Sign in
          </Button>
          {candidates && <Button variant="link" onClick={restart}>Use a different name</Button>}
        </ActionGroup>
      </Form>
    </LoginPage>
  );
}

function message(e: ApiError): string {
  switch (e.code) {
    case 'too-many-attempts':
      return 'Too many failed sign-ins. Wait a few minutes and try again.';
    case 'untrusted-certificate':
      return 'The directory\'s certificate is not trusted. An administrator can probe the directory and trust it.';
    default:
      return e.message;
  }
}
