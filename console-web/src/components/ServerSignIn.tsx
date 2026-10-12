import { useCallback, useState } from 'react';
import { Alert, Button, Form, FormGroup, Modal, ModalBody, ModalFooter, ModalHeader, TextInput } from '@patternfly/react-core';
import { ApiError, session } from '../api';

type Pending = { server: { guid: string; name: string }; retry: () => void; cancel: () => void };

/**
 * Run an operation on another server's replica; when the console answers "server-sign-in-required"
 * (a direct sign-in reaches each further server once, with the password, which is not kept), ask for
 * the password, sign in to that server and run the operation again.
 */
export function useServerSignIn() {
  const [pending, setPending] = useState<Pending | null>(null);

  const run = useCallback(<T,>(op: () => Promise<T>): Promise<T> => op().catch((e) => {
    if (!(e instanceof ApiError) || e.code !== 'server-sign-in-required') {
      throw e;
    }
    const server = e.problem.server as { guid: string; name: string };
    return new Promise<T>((resolve, reject) => {
      setPending({
        server,
        retry: () => { setPending(null); op().then(resolve, reject); },
        cancel: () => { setPending(null); reject(new Error(`Not signed in to ${server.name}.`)); },
      });
    });
  }), []);

  const dialog = pending ? <ServerSignInDialog server={pending.server} onDone={pending.retry} onCancel={pending.cancel} /> : null;
  return { run, dialog };
}

function ServerSignInDialog({ server, onDone, onCancel }: { server: { guid: string; name: string }; onDone: () => void; onCancel: () => void }) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <Modal variant="small" isOpen onClose={onCancel} aria-labelledby="server-signin-title">
      <ModalHeader title={`Sign in to ${server.name}`} labelId="server-signin-title" />
      <ModalBody>
        <Form id="server-signin-form" onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(null);
          try {
            await session.signInServer(server.guid, password);
            onDone();
          } catch (x) {
            setPassword('');
            setError(x instanceof ApiError && x.code === 'bad-credentials' ? 'The password is incorrect.' : x instanceof Error ? x.message : 'Sign-in failed.');
          } finally {
            setBusy(false);
          }
        }}>
          <p>Some values, such as a driver's start option and named passwords, are kept by each server separately. To work with {server.name}'s, sign in to it once for this session with your password. It is not kept.</p>
          <FormGroup label="Password" fieldId="server-signin-password" isRequired>
            <TextInput id="server-signin-password" type="password" autoComplete="current-password" value={password} onChange={(_e, v) => setPassword(v)} autoFocus isRequired />
          </FormGroup>
          {error && <Alert component="h3" variant="danger" isInline isPlain title={error} />}
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="server-signin-form" variant="primary" isLoading={busy} isDisabled={busy || !password}>Sign in</Button>
        <Button variant="link" onClick={onCancel}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}
