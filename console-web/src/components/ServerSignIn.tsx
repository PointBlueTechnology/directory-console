import { useCallback, useState } from 'react';
import { Alert, Button, DescriptionList, DescriptionListDescription, DescriptionListGroup, DescriptionListTerm, Form, FormGroup, Modal, ModalBody,
  ModalFooter, ModalHeader, TextInput } from '@patternfly/react-core';
import { ApiError, Probe, session, trust } from '../api';
import { useSession } from '../session';
import { useStepUp } from './StepUp';

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
  const stepUp = useStepUp();
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [probe, setProbe] = useState<Probe | null>(null);
  const [confirm, setConfirm] = useState('');
  const [hostname, setHostname] = useState(false);

  const signIn = async () => {
    try {
      await session.signInServer(server.guid, password);
      onDone();
    } catch (x) {
      if (x instanceof ApiError && x.code === 'untrusted-certificate') {
        const { host, port, reason } = x.problem as unknown as { host: string; port: number; reason: string };
        if (!can('admin')) {
          setError(`${x.message} An administrator can accept ${server.name}'s certificate from this dialog.`);
          return;
        }
        setHostname(reason === 'hostname');
        setProbe(await trust.probe(host, port, me.directory));
        return;
      }
      setPassword('');
      setError(x instanceof ApiError && x.code === 'bad-credentials' ? 'The password is incorrect.' : x instanceof Error ? x.message : 'Sign-in failed.');
    }
  };

  const cert = probe ? probe.chain[hostname ? 0 : probe.recommended] : null;
  const accept = async () => {
    if (!probe || !cert) {
      return;
    }
    await stepUp.run(() => hostname
      ? trust.hostException(probe.probeId, confirm.trim())
      : trust.add(probe.probeId, cert.index, confirm.trim(), me.directory));
    setProbe(null);
    setConfirm('');
    await signIn();
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await (probe ? accept() : signIn());
    } catch (x) {
      setError(x instanceof ApiError && x.code === 'confirmation-mismatch' ? 'Those are not the last 8 digits of the fingerprint.' : x instanceof Error ? x.message : 'Failed.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal variant={probe ? 'medium' : 'small'} isOpen onClose={onCancel} aria-labelledby="server-signin-title">
      <ModalHeader title={probe ? `Accept ${server.name}'s certificate?` : `Sign in to ${server.name}`} labelId="server-signin-title" />
      <ModalBody>
        <Form id="server-signin-form" onSubmit={submit}>
          {probe && cert ? <>
            <p>{probe.message}</p>
            {hostname
              ? <p>The console reaches {server.name} at {probe.host}:{probe.port}, which its certificate does not name; this is usual behind NAT or a tunnel. Accepting adds a host exception: this certificate, at exactly this address, is trusted though it names others.</p>
              : <p>Trusting this certificate lets the console connect to {server.name}, and to other servers of this directory that it signed.</p>}
            <DescriptionList isHorizontal isCompact>
              <DescriptionListGroup><DescriptionListTerm>Subject</DescriptionListTerm><DescriptionListDescription className="dc-mono">{cert.subject}</DescriptionListDescription></DescriptionListGroup>
              <DescriptionListGroup><DescriptionListTerm>Names</DescriptionListTerm><DescriptionListDescription>{cert.names.join(', ') || 'none'}</DescriptionListDescription></DescriptionListGroup>
              <DescriptionListGroup><DescriptionListTerm>Issuer</DescriptionListTerm><DescriptionListDescription className="dc-mono">{cert.issuer}</DescriptionListDescription></DescriptionListGroup>
              <DescriptionListGroup><DescriptionListTerm>Valid until</DescriptionListTerm><DescriptionListDescription>{new Date(cert.notAfter).toLocaleDateString()}</DescriptionListDescription></DescriptionListGroup>
              <DescriptionListGroup><DescriptionListTerm>SHA-256</DescriptionListTerm><DescriptionListDescription className="dc-mono">{cert.sha256}</DescriptionListDescription></DescriptionListGroup>
            </DescriptionList>
            <p>{probe.confirm}</p>
            <FormGroup label="Last 8 digits of the fingerprint" fieldId="server-signin-confirm" isRequired>
              <TextInput id="server-signin-confirm" className="dc-mono" value={confirm} onChange={(_e, v) => setConfirm(v)} autoFocus isRequired />
            </FormGroup>
          </> : <>
            <p>Some values, such as a driver's start option and named passwords, are kept by each server separately. To work with {server.name}'s, sign in to it once for this session with your password. It is not kept.</p>
            <FormGroup label="Password" fieldId="server-signin-password" isRequired>
              <TextInput id="server-signin-password" type="password" autoComplete="current-password" value={password} onChange={(_e, v) => setPassword(v)} autoFocus isRequired />
            </FormGroup>
          </>}
          {error && <Alert component="h3" variant="danger" isInline isPlain title={error} />}
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="server-signin-form" variant="primary" isLoading={busy}
          isDisabled={busy || (probe ? confirm.trim().length !== 8 : !password)}>{probe ? (hostname ? 'Accept at this address' : 'Trust and sign in') : 'Sign in'}</Button>
        <Button variant="link" onClick={onCancel}>Cancel</Button>
      </ModalFooter>
      {stepUp.dialog}
    </Modal>
  );
}
