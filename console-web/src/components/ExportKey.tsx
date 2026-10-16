import { useState } from 'react';
import {
  Alert, Button, Form, FormGroup, FormHelperText, FormSelect, FormSelectOption, HelperText, HelperTextItem, Modal, ModalBody, ModalFooter,
  ModalHeader, TextInput,
} from '@patternfly/react-core';
import { type ExportedKey, type KeyExport } from '../api';
import { useStepUp } from './StepUp';

/** Save a base64-encoded file under its name. */
function save({ fileName, pkcs12 }: ExportedKey) {
  const bytes = Uint8Array.from(atob(pkcs12), (c) => c.charCodeAt(0));
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([bytes], { type: 'application/x-pkcs12' }));
  a.download = fileName;
  a.click();
  URL.revokeObjectURL(a.href);
}

/**
 * Export a certificate with its private key, as a password-protected PKCS#12 (.pfx) file. It needs a recent
 * sign-in; eDirectory refuses a key that was not made exportable.
 */
export function ExportKeyModal({ name, onExport, onClose }: {
  name: string;
  onExport: (body: KeyExport) => Promise<ExportedKey>;
  onClose: () => void;
}) {
  const [password, setPassword] = useState('');
  const [again, setAgain] = useState('');
  const [scheme, setScheme] = useState<KeyExport['scheme']>('pbes2');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const stepUp = useStepUp();
  const short = password.length > 0 && password.length < 6;
  const differs = again.length > 0 && again !== password;
  const ready = password.length >= 6 && again === password;
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ready) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      save(await stepUp.run(() => onExport({ password, scheme })));
      onClose();
    } catch (x) {
      setError(x instanceof Error ? x.message : 'Not exported.');
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal variant="small" isOpen onClose={onClose} aria-labelledby="export-key-title">
      <ModalHeader title={`Export ${name} with its private key`} labelId="export-key-title" titleIconVariant="warning" />
      <ModalBody>
        <Form id="export-key-form" onSubmit={submit}>
          <p>The file holds the private key and the certificate chain. Anyone with the file and its password can act as this certificate, so keep both safe. The export is recorded in the audit log.</p>
          <FormGroup label="Password for the file" fieldId="export-key-password" isRequired>
            <TextInput id="export-key-password" type="password" autoComplete="new-password" value={password} onChange={(_e, v) => setPassword(v)}
              validated={short ? 'error' : 'default'} autoFocus />
            <FormHelperText><HelperText><HelperTextItem variant={short ? 'error' : 'default'}>At least 6 characters. It is not stored anywhere.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <FormGroup label="Password again" fieldId="export-key-again" isRequired>
            <TextInput id="export-key-again" type="password" autoComplete="new-password" value={again} onChange={(_e, v) => setAgain(v)}
              validated={differs ? 'error' : 'default'} />
            {differs && <FormHelperText><HelperText><HelperTextItem variant="error">The passwords differ.</HelperTextItem></HelperText></FormHelperText>}
          </FormGroup>
          <FormGroup label="Protection" fieldId="export-key-scheme">
            <FormSelect id="export-key-scheme" value={scheme} onChange={(_e, v) => setScheme(v as KeyExport['scheme'])}>
              <FormSelectOption value="pbes2" label="PBES2 with AES-256 (recommended)" />
              <FormSelectOption value="pbes1" label="PBES1 with 3DES (older software)" />
            </FormSelect>
            <FormHelperText><HelperText><HelperTextItem>
              PBES1 is for software that cannot read PBES2, such as Java 8 or Windows Server 2016. OpenSSL 3 opens it only with -legacy.
            </HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          {error && <Alert variant="danger" isInline isPlain title={error} />}
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="export-key-form" isLoading={busy} isDisabled={busy || !ready}>Export</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
      {stepUp.dialog}
    </Modal>
  );
}
