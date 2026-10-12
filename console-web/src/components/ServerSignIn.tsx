import { useCallback, useState } from 'react';
import { Alert, Button, Form, FormGroup, Modal, ModalBody, ModalFooter, ModalHeader, TextInput } from '@patternfly/react-core';
import { ApiError, type Probe, session, trust } from '../api';
import { useSession } from '../session';
import { TrustCertificateModal } from './Certificates';

type Pending = { server: { guid: string; name: string }; retry: () => void; cancel: () => void };

/**
 * Run an operation on another server's replica; when the console answers "server-sign-in-required"
 * (a direct sign-in reaches each further server once, with the password, which is not kept), ask for
 * the password, sign in to that server and run the operation again. A server whose certificate the
 * console does not trust yet (often one reached through NAT or a tunnel, by another name than its
 * certificate's) can be accepted here by an administrator, as in setup: probe, check, type the
 * fingerprint's last 8 digits.
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
  const { me, can } = useSession();
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [probe, setProbe] = useState<Probe | null>(null);

  const signIn = async () => {
    setBusy(true);
    setError(null);
    try {
      await session.signInServer(server.guid, password);
      onDone();
    } catch (x) {
      if (x instanceof ApiError && x.code === 'untrusted-certificate') {
        const { host, port } = x.problem as unknown as { host: string; port: number };
        if (!can('admin')) {
          setError(`${x.message} An administrator can accept ${server.name}'s certificate when signing in to it, or on the Certificates page.`);
          return;
        }
        setProbe(await trust.probe(host, port, me.directory));
        return;
      }
      setPassword('');
      setError(x instanceof ApiError && x.code === 'bad-credentials' ? 'The password is incorrect.' : x instanceof Error ? x.message : 'Sign-in failed.');
    } finally {
      setBusy(false);
    }
  };

  if (probe) {
    // the password is still here: once the certificate is accepted, the sign-in goes on by itself
    return <TrustCertificateModal probe={probe} directory={me.directory} name={server.name}
      onDone={() => { setProbe(null); void signIn(); }} onCancel={onCancel} />;
  }
  return (
    <Modal variant="small" isOpen onClose={onCancel} aria-labelledby="server-signin-title">
      <ModalHeader title={`Sign in to ${server.name}`} labelId="server-signin-title" />
      <ModalBody>
        <Form id="server-signin-form" onSubmit={(e) => { e.preventDefault(); void signIn(); }}>
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
