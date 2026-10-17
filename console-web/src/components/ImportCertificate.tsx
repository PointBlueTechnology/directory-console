import { useState } from 'react';
import {
  Button, FileUpload, Form, FormGroup, FormHelperText, FormSelect, FormSelectOption, HelperText, HelperTextItem, Modal, ModalBody, ModalFooter, ModalHeader,
  TextInput,
} from '@patternfly/react-core';
import { ProblemAlert } from './Problem';

/**
 * Import a server certificate with its private key from a PKCS#12 (.pfx/.p12) file. eDirectory reads only files
 * protected the way it exports them, so the console refuses others before asking it.
 */
export function ImportCertificateModal({ servers, onImport, onClose }: {
  servers: { guid: string; name: string }[];
  onImport: (server: string, name: string, pkcs12: string, password: string) => Promise<void>;
  onClose: () => void;
}) {
  const [server, setServer] = useState(servers[0]?.guid ?? '');
  const [name, setName] = useState('');
  const [file, setFile] = useState('');
  const [data, setData] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const pick = (f: File) => {
    setFile(f.name);
    if (!name) {
      setName(f.name.replace(/\.(pfx|p12)$/i, '').replace(/[^A-Za-z0-9 _.-]/g, '_').slice(0, 64));
    }
    const r = new FileReader();
    r.onload = () => setData(String(r.result).replace(/^data:[^,]*,/, ''));
    r.readAsDataURL(f);
  };
  const ready = server && /^[A-Za-z0-9 _.-]{1,64}$/.test(name.trim()) && data && password;
  const go = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onImport(server, name.trim(), data, password);
      onClose();
    } catch (x) {
      setError(x);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal variant="small" isOpen onClose={onClose} aria-labelledby="import-cert-title">
      <ModalHeader title="Import a server certificate" labelId="import-cert-title"
        description="A key and its certificate chain from a PKCS#12 file become a new certificate on the server." />
      <ModalBody>
        <Form id="import-cert-form" onSubmit={go}>
          <FormGroup label="Server" fieldId="import-server" isRequired>
            <FormSelect id="import-server" value={server} onChange={(_e, v) => setServer(v)}>
              {servers.map((s) => <FormSelectOption key={s.guid} value={s.guid} label={s.name} />)}
            </FormSelect>
          </FormGroup>
          <FormGroup label="File" fieldId="import-file" isRequired>
            <FileUpload id="import-file" filename={file} filenamePlaceholder="Choose a .pfx or .p12 file" browseButtonText="Choose" hideDefaultPreview
              value={data ? '(read)' : ''} onFileInputChange={(_e, f) => pick(f)} onClearClick={() => { setFile(''); setData(''); }} />
            <FormHelperText><HelperText><HelperTextItem>
              eDirectory imports only files protected the way it exports them (3DES for the key, RC2-40 for the certificates): an export from eDirectory
              (this console's PBES1 export, Identity Console or iManager). Other files are refused before eDirectory is asked.
            </HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <FormGroup label="The file's password" fieldId="import-password" isRequired>
            <TextInput id="import-password" type="password" autoComplete="off" value={password} onChange={(_e, v) => setPassword(v)} />
          </FormGroup>
          <FormGroup label="Name for it" fieldId="import-name" isRequired>
            <TextInput id="import-name" value={name} onChange={(_e, v) => setName(v)} />
            <FormHelperText><HelperText><HelperTextItem>A name this server does not use yet.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <ProblemAlert error={error} />
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="import-cert-form" isLoading={busy} isDisabled={busy || !ready}>Import</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}
