import { useCallback, useState } from 'react';
import { Alert, Button, Form, FormGroup, Modal, ModalBody, ModalFooter, ModalHeader, TextInput } from '@patternfly/react-core';
import { ApiError, session } from '../api';
import { useSession } from '../session';

/**
 * Run a sensitive change; when the console answers "step-up-required" (no sign-in in the last 10
 * minutes), ask for the password, sign in again on this session, and run the change again.
 */
export function useStepUp() {
  const { me } = useSession();
  const [pending, setPending] = useState<null | { retry: () => void; cancel: () => void }>(null);

  const run = useCallback(<T,>(op: () => Promise<T>): Promise<T> => op().catch((e) => {
    if (!(e instanceof ApiError) || e.code !== 'step-up-required') {
      throw e;
    }
    return new Promise<T>((resolve, reject) => {
      setPending({
        retry: () => { setPending(null); op().then(resolve, reject); },
        cancel: () => { setPending(null); reject(new Error('Not saved: sign in again to make this change.')); },
      });
    });
  }), []);

  const dialog = pending ? <StepUpDialog sso={me.via === 'oidc'} onDone={pending.retry} onCancel={pending.cancel} /> : null;
  return { run, dialog };
}

function StepUpDialog({ sso, onDone, onCancel }: { sso: boolean; onDone: () => void; onCancel: () => void }) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await session.stepUp(password);
      onDone();
    } catch (x) {
      setPassword('');
      setError(x instanceof ApiError && x.status === 401 ? 'The password is incorrect.' : x instanceof Error ? x.message : 'Sign-in failed.');
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal variant="small" isOpen onClose={onCancel} aria-labelledby="stepup-title">
      <ModalHeader title="Confirm it is you" labelId="stepup-title" />
      <ModalBody>
        {sso ? (
          <p>Changing sign-in and authorization settings needs a sign-in within the last 10 minutes. Sign out and sign in again through single sign-on, then make the change.</p>
        ) : (
          <Form id="stepup-form" onSubmit={submit}>
            <p>Changing sign-in and authorization settings needs a sign-in within the last 10 minutes. Enter your password to continue.</p>
            <FormGroup label="Password" fieldId="stepup-password" isRequired>
              <TextInput id="stepup-password" type="password" autoComplete="current-password" value={password} onChange={(_e, v) => setPassword(v)} autoFocus isRequired />
            </FormGroup>
            {error && <Alert variant="danger" isInline isPlain title={error} />}
          </Form>
        )}
      </ModalBody>
      <ModalFooter>
        {!sso && <Button type="submit" form="stepup-form" variant="primary" isLoading={busy} isDisabled={busy || !password}>Continue</Button>}
        <Button variant="link" onClick={onCancel}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}
