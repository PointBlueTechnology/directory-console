import { useState } from 'react';
import {
  Alert, Button, Checkbox, Form, FormGroup, FormHelperText, FormSelect, FormSelectOption, HelperText, HelperTextItem, Modal, ModalBody,
  ModalFooter, ModalHeader, TextArea, TextInput,
} from '@patternfly/react-core';
import { ApiError, type CertificateRequest } from '../api';

const KEYS: { value: string; label: string; algorithm: CertificateRequest['algorithm']; rsaBits?: number }[] = [
  { value: 'rsa2048', label: 'RSA 2048 bits', algorithm: 'rsa', rsaBits: 2048 },
  { value: 'rsa3072', label: 'RSA 3072 bits', algorithm: 'rsa', rsaBits: 3072 },
  { value: 'rsa4096', label: 'RSA 4096 bits', algorithm: 'rsa', rsaBits: 4096 },
  { value: 'ec256', label: 'ECDSA P-256', algorithm: 'ec256' },
  { value: 'ec384', label: 'ECDSA P-384', algorithm: 'ec384' },
];

/**
 * A new certificate from the tree's Organizational CA, made by eDirectory (the private key never
 * leaves it): a server certificate (with {@code servers} to choose from) or a user certificate.
 */
export function NewCertificateModal({ kind, servers, defaultName, onCreate, onClose }: {
  kind: 'server' | 'user';
  servers?: { guid: string; name: string }[];
  defaultName?: string;
  onCreate: (body: CertificateRequest, server?: string) => Promise<unknown>;
  onClose: () => void;
}) {
  const [name, setName] = useState(defaultName ?? '');
  const [server, setServer] = useState(servers?.[0]?.guid ?? '');
  const [key, setKey] = useState('rsa2048');
  const [signature, setSignature] = useState<CertificateRequest['signature']>('sha256');
  const [years, setYears] = useState('2');
  const [subject, setSubject] = useState('');
  const [names, setNames] = useState('');
  const [exportable, setExportable] = useState(kind === 'server');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const k = KEYS.find((x) => x.value === key)!;
  const nameList = names.split(/[\n,]/).map((n) => n.trim()).filter(Boolean)
    // a bare host or address is a DNS name or an IP address
    .map((n) => (/^(dns|ip|email|uri):/.test(n) ? n : /^[0-9.]+$|:/.test(n) ? `ip:${n}` : n.includes('@') ? `email:${n}` : `dns:${n}`));

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onCreate({
        name: name.trim(), algorithm: k.algorithm, rsaBits: k.rsaBits, signature, validityYears: Number(years),
        subject: subject.trim() || undefined, names: nameList, exportable,
      }, kind === 'server' ? server : undefined);
      onClose();
    } catch (x) {
      setError(x instanceof ApiError || x instanceof Error ? x.message : 'Not created.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal variant="medium" isOpen onClose={onClose} aria-labelledby="new-cert-title">
      <ModalHeader title={kind === 'server' ? 'New server certificate' : 'New user certificate'} labelId="new-cert-title"
        description="Issued by the tree's Organizational CA. eDirectory makes the key pair; the private key stays in the directory." />
      <ModalBody>
        <Form id="new-cert-form" onSubmit={submit}>
          <FormGroup label="Certificate name" fieldId="new-cert-name" isRequired>
            <TextInput id="new-cert-name" value={name} onChange={(_e, v) => setName(v)} isRequired autoFocus />
            {kind === 'server' && <FormHelperText><HelperText><HelperTextItem>Kept as "{name || 'name'} - server". An LDAP server chooses its certificate by this name.</HelperTextItem></HelperText></FormHelperText>}
          </FormGroup>
          {kind === 'server' && (
            <FormGroup label="Server" fieldId="new-cert-server" isRequired>
              <FormSelect id="new-cert-server" value={server} onChange={(_e, v) => setServer(v)}>
                {(servers ?? []).map((s) => <FormSelectOption key={s.guid} value={s.guid} label={s.name} />)}
              </FormSelect>
            </FormGroup>
          )}
          <FormGroup label="Key" fieldId="new-cert-key">
            <FormSelect id="new-cert-key" value={key} onChange={(_e, v) => setKey(v)}>
              {KEYS.map((x) => <FormSelectOption key={x.value} value={x.value} label={x.label} />)}
            </FormSelect>
          </FormGroup>
          <FormGroup label="Signature" fieldId="new-cert-sig">
            <FormSelect id="new-cert-sig" value={signature} onChange={(_e, v) => setSignature(v as CertificateRequest['signature'])}>
              <FormSelectOption value="sha256" label="SHA-256" />
              <FormSelectOption value="sha384" label="SHA-384" />
              <FormSelectOption value="sha512" label="SHA-512" />
            </FormSelect>
          </FormGroup>
          <FormGroup label="Valid for (years)" fieldId="new-cert-years">
            <TextInput id="new-cert-years" type="number" min={1} max={10} value={years} onChange={(_e, v) => setYears(v)} />
          </FormGroup>
          <FormGroup label="Subject" fieldId="new-cert-subject">
            <TextInput id="new-cert-subject" className="dc-mono" value={subject} onChange={(_e, v) => setSubject(v)}
              placeholder={kind === 'server' ? 'cn=<server name>' : "the user's DN"} />
          </FormGroup>
          <FormGroup label={kind === 'server' ? 'Host names and addresses' : 'Alternative names'} fieldId="new-cert-names">
            <TextArea id="new-cert-names" className="dc-mono" value={names} onChange={(_e, v) => setNames(v)} rows={3} resizeOrientation="vertical"
              aria-describedby="new-cert-names-help" />
            <FormHelperText><HelperText id="new-cert-names-help"><HelperTextItem>
              One per line: the names and addresses clients use to reach {kind === 'server' ? 'this server' : 'the person'} (host names, IP addresses{kind === 'user' ? ', e-mail addresses' : ''}).
              {kind === 'user' && ' The user\'s mail address is added on its own.'}
            </HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <Checkbox id="new-cert-export" label="Allow the private key to be exported" isChecked={exportable} onChange={(_e, v) => setExportable(v)} />
          {error && <Alert component="h3" variant="danger" isInline isPlain title={error} />}
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="new-cert-form" variant="primary" isLoading={busy}
          isDisabled={busy || !/^[A-Za-z0-9 _.-]{1,64}$/.test(name.trim()) || !(Number(years) >= 1 && Number(years) <= 10) || (kind === 'server' && !server)}>Create</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}
