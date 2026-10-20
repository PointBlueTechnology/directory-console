import { useState } from 'react';
import {
  Alert, Button, Card, CardBody, CardTitle, FileUpload, Flex, FlexItem, Form, FormGroup, FormHelperText, HelperText, HelperTextItem, Modal, ModalBody,
  ModalFooter, ModalHeader, TextArea, TextInput, Title,
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type Pki, type security } from '../api';
import { ExpiryLabel } from './Certificates';
import { useAreYouSure, useConfirmed } from './Confirm';
import { ProblemAlert } from './Problem';

/**
 * The directory's trusted roots, by container: services set up to use a container (NMAS, SSL clients) accept what its
 * roots sign. Editors add containers and roots and remove them; a container goes only when empty.
 */
export function TrustedRootsCard({ pki, api, editor, onChanged }: {
  pki: Pki;
  api: ReturnType<typeof security>;
  editor: boolean;
  onChanged: (p: Pki) => void;
}) {
  const confirmed = useConfirmed();
  const sure = useAreYouSure();
  const [adding, setAdding] = useState<null | { guid: string; name: string }>(null);
  const [making, setMaking] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const containers = pki.trustedRootContainers ?? [];
  const done = (what: string) => (p: Pki) => { onChanged(p); setNotice(what); setError(null); };
  return (
    <Card className="dc-tab-body">
      <CardTitle><Title headingLevel="h2" size="lg">Trusted roots</Title></CardTitle>
      <CardBody>
        <p className="dc-subtle">Certificates kept in trusted root containers. Services set up to use a container (such as NMAS, or SSL clients configured with it) accept
          certificates its roots have signed. The console's own trust is separate (Settings &gt; Trusted certificates).</p>
        {notice && <Alert variant="success" isInline isPlain title={notice} className="dc-tab-body" />}
        <ProblemAlert error={error} />
        {editor && <Button variant="secondary" size="sm" className="dc-tab-body" onClick={() => setMaking(true)}>New container</Button>}
        {containers.length === 0 && pki.trustedRoots.length === 0 ? <p>None.</p> : containers.map((c) => {
          const roots = pki.trustedRoots.filter((t) => t.container.toLowerCase() === c.dn.toLowerCase());
          return (
            <div key={c.dn} className="dc-tab-body">
              <Flex alignItems={{ default: 'alignItemsCenter' }}>
                <FlexItem grow={{ default: 'grow' }}><strong>{c.name}</strong> <span className="dc-subtle dc-mono">{c.dn}</span></FlexItem>
                {editor && <FlexItem><Button variant="link" isInline onClick={() => setAdding({ guid: c.guid!, name: c.name })}>Add a root</Button></FlexItem>}
                {editor && roots.length === 0 && (
                  <FlexItem><Button variant="link" isInline isDanger onClick={() => sure.ask(`Delete the container ${c.name}?`, 'It holds no roots.', 'Delete',
                    () => confirmed.run((x) => api.deleteTrustedRootContainer(c.guid!, x)).then(done(`${c.name} deleted.`), setError))}>Delete</Button></FlexItem>
                )}
              </Flex>
              {roots.length === 0 ? <p className="dc-subtle">No roots.</p> : (
                <Table aria-label={`Trusted roots in ${c.name}`} variant="compact">
                  <Thead><Tr><Th>Root</Th><Th>Subject</Th><Th>Valid until</Th>{editor && <Th screenReaderText="Remove" />}</Tr></Thead>
                  <Tbody>
                    {roots.map((t) => (
                      <Tr key={t.dn}>
                        <Td dataLabel="Root">{t.name}</Td>
                        <Td dataLabel="Subject" className="dc-mono">{t.certificate?.subject ?? '—'}</Td>
                        <Td dataLabel="Valid until"><ExpiryLabel notAfter={t.certificate?.notAfter} /></Td>
                        {editor && (
                          <Td isActionCell>
                            <Button variant="link" isInline isDanger onClick={() => sure.ask(`Remove the trusted root ${t.name}?`,
                              `Services using ${c.name} stop accepting certificates it signed.`, 'Remove',
                              () => confirmed.run((x) => api.deleteTrustedRoot(t.guid!, x)).then(done(`${t.name} removed.`), setError))}>Remove</Button>
                          </Td>
                        )}
                      </Tr>
                    ))}
                  </Tbody>
                </Table>
              )}
            </div>
          );
        })}
        {making && <NewContainerModal onClose={() => setMaking(false)}
          onSave={(parent, name) => confirmed.run((x) => api.createTrustedRootContainer(parent, name, x)).then((p) => { done(`${name} made.`)(p); setMaking(false); })} />}
        {adding && <AddRootModal container={adding.name} onClose={() => setAdding(null)}
          onSave={(cert, name) => confirmed.run((x) => api.addTrustedRoot(adding.guid, cert, name, x)).then((p) => { done(`Root added to ${adding.name}.`)(p); setAdding(null); })} />}
        {confirmed.dialog}
        {sure.dialog}
      </CardBody>
    </Card>
  );
}

function NewContainerModal({ onSave, onClose }: { onSave: (parent: string, name: string) => Promise<void>; onClose: () => void }) {
  const [parent, setParent] = useState('');
  const [name, setName] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onSave(parent.trim(), name.trim());
    } catch (x) {
      setError(x);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal variant="small" isOpen onClose={onClose} aria-labelledby="trc-title">
      <ModalHeader title="New trusted root container" labelId="trc-title" />
      <ModalBody>
        <Form id="trc-form" onSubmit={save}>
          <FormGroup label="In" fieldId="trc-parent" isRequired>
            <TextInput id="trc-parent" className="dc-mono" value={parent} onChange={(_e, v) => setParent(v)} placeholder="cn=Security, or an organization or OU" />
            <FormHelperText><HelperText><HelperTextItem>The Security container, an Organization or an OU.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <FormGroup label="Name" fieldId="trc-name" isRequired>
            <TextInput id="trc-name" value={name} onChange={(_e, v) => setName(v)} />
          </FormGroup>
          <ProblemAlert error={error} />
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="trc-form" isLoading={busy} isDisabled={busy || !parent.trim() || !name.trim()}>Make it</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}

function AddRootModal({ container, onSave, onClose }: { container: string; onSave: (cert: string, name?: string) => Promise<void>; onClose: () => void }) {
  const [cert, setCert] = useState('');
  const [file, setFile] = useState('');
  const [name, setName] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onSave(cert.trim(), name.trim() || undefined);
    } catch (x) {
      setError(x);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal variant="medium" isOpen onClose={onClose} aria-labelledby="tr-title">
      <ModalHeader title={`Add a trusted root to ${container}`} labelId="tr-title"
        description="Services using this container then accept certificates it signs: check it is the certificate you mean." />
      <ModalBody>
        <Form id="tr-form" onSubmit={save}>
          <FormGroup label="Certificate" fieldId="tr-file" isRequired>
            <FileUpload id="tr-file" type="text" value={cert} filename={file} filenamePlaceholder="Choose a .pem, .cer or .crt file, or paste below"
              onFileInputChange={(_e, f) => setFile(f.name)} onDataChange={(_e, v) => setCert(v)} onClearClick={() => { setCert(''); setFile(''); }}
              browseButtonText="Choose" hideDefaultPreview />
            <TextArea aria-label="Certificate (PEM)" className="dc-mono dc-tab-body" rows={6} value={cert} onChange={(_e, v) => setCert(v)}
              placeholder="-----BEGIN CERTIFICATE-----" resizeOrientation="vertical" />
          </FormGroup>
          <FormGroup label="Name" fieldId="tr-name">
            <TextInput id="tr-name" value={name} onChange={(_e, v) => setName(v)} placeholder="from the certificate's CN or OU" />
          </FormGroup>
          <ProblemAlert error={error} />
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="tr-form" isLoading={busy} isDisabled={busy || !cert.includes('BEGIN CERTIFICATE') && cert.trim().length < 100}>Add it</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}
