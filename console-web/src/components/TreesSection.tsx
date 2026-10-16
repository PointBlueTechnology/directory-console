import { useCallback, useEffect, useState } from 'react';
import {
  Alert, Button, Form, FormGroup, FormHelperText, HelperText, HelperTextItem, Label, Modal, ModalBody, ModalFooter, ModalHeader, Radio, Spinner, TextInput,
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { ApiError, type ConsoleTree, type Probe, trees } from '../api';
import { CertificateOffer, confirmed } from './CertificateOffer';
import { ProblemAlert } from './Problem';
import { useStepUp } from './StepUp';

type Tier = 'production' | 'lab';

function TierChoice({ id, tier, onChange }: { id: string; tier: Tier; onChange: (t: Tier) => void }) {
  return (
    <FormGroup role="radiogroup" label="Tier" fieldId={id} isStack>
      <Radio id={`${id}-production`} name={id} label="Production" description="Changes ask for the directory's name to be typed first." isChecked={tier === 'production'} onChange={() => onChange('production')} />
      <Radio id={`${id}-lab`} name={id} label="Lab" description="Dev and test directories: changes go ahead without that extra step." isChecked={tier === 'lab'} onChange={() => onChange('lab')} />
    </FormGroup>
  );
}

/**
 * Add a tree: proven as at first sign-in, by the new tree's own administrator (who becomes its
 * break-glass account), with its certificate confirmed when the console does not trust it yet.
 */
function AddTreeModal({ onClose, onAdded }: { onClose: () => void; onAdded: (t: ConsoleTree) => void }) {
  const { run, dialog } = useStepUp();
  const [name, setName] = useState('');
  const [tier, setTier] = useState<Tier>('lab');
  const [host, setHost] = useState('');
  const [port, setPort] = useState('636');
  const [dn, setDn] = useState('');
  const [password, setPassword] = useState('');
  const [offer, setOffer] = useState<Probe | null>(null);
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const ready = name.trim() && host.trim() && Number(port) > 0 && dn.trim() && password && (!offer || confirmed(confirm));

  const add = () => {
    setBusy(true);
    setError(null);
    run(() => trees.add({
      name: name.trim(), tier, host: host.trim(), port: Number(port), dn: dn.trim(), password,
      accept: offer ? { probeId: offer.probeId, confirm: confirm.replace(/[^0-9a-fA-F]/g, '') } : undefined,
    })).then((t) => { onAdded(t); onClose(); }, (x) => {
      if (x instanceof ApiError && x.code === 'untrusted-certificate' && x.problem.probe) {
        setOffer(x.problem.probe as Probe);
        setConfirm('');
      } else {
        setError(x);
      }
    }).finally(() => setBusy(false));
  };

  return (
    <Modal isOpen onClose={onClose} variant="medium" aria-labelledby="add-tree-title">
      <ModalHeader title="Add a directory" labelId="add-tree-title" description="Sign in to the new directory as its administrator. People then choose it from the list when they sign in." />
      <ModalBody>
        <Form id="add-tree-form" onSubmit={(e) => { e.preventDefault(); if (ready) add(); }}>
          <FormGroup label="Name" fieldId="tree-name" isRequired>
            <TextInput id="tree-name" value={name} onChange={(_e, v) => setName(v)} placeholder="Test" autoFocus isRequired />
            <FormHelperText><HelperText><HelperTextItem>As people see it in the sign-in list, such as Dev, Test or Production.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <TierChoice id="tree-tier" tier={tier} onChange={setTier} />
          <FormGroup label="Directory address" fieldId="tree-host" isRequired>
            <TextInput id="tree-host" value={host} onChange={(_e, v) => { setHost(v); setOffer(null); }} isRequired />
            <FormHelperText><HelperText><HelperTextItem>An eDirectory server's host name or IP address, as the console reaches it.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <FormGroup label="LDAPS port" fieldId="tree-port" isRequired>
            <TextInput id="tree-port" type="number" value={port} onChange={(_e, v) => { setPort(v); setOffer(null); }} isRequired />
          </FormGroup>
          <FormGroup label="Administrator of that directory" fieldId="tree-dn" isRequired>
            <TextInput id="tree-dn" value={dn} onChange={(_e, v) => setDn(v)} autoComplete="off" isRequired />
            <FormHelperText><HelperText><HelperTextItem>Its full name (DN), such as cn=admin,o=system. It becomes the directory's break-glass account.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <FormGroup label="Password" fieldId="tree-password" isRequired>
            <TextInput id="tree-password" type="password" value={password} onChange={(_e, v) => setPassword(v)} autoComplete="new-password" isRequired />
          </FormGroup>
          {offer && <CertificateOffer id="tree-offer" offer={offer} confirm={confirm} onConfirm={setConfirm} />}
        </Form>
        <ProblemAlert error={error} />
        {dialog}
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="add-tree-form" isLoading={busy} isDisabled={busy || !ready}>{offer ? 'Trust and add' : 'Add'}</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}

/** Rename a tree or change its tier. */
function EditTreeModal({ tree, onClose, onSaved }: { tree: ConsoleTree; onClose: () => void; onSaved: (t: ConsoleTree) => void }) {
  const { run, dialog } = useStepUp();
  const [name, setName] = useState(tree.name);
  const [tier, setTier] = useState<Tier>(tree.tier);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const save = () => {
    setBusy(true);
    setError(null);
    run(() => trees.change(tree.id, { ...(name.trim() !== tree.name ? { name: name.trim() } : {}), ...(tier !== tree.tier ? { tier } : {}) }))
      .then((t) => { onSaved(t); onClose(); }, setError).finally(() => setBusy(false));
  };
  return (
    <Modal isOpen onClose={onClose} variant="small" aria-labelledby="edit-tree-title">
      <ModalHeader title={`Change ${tree.name}`} labelId="edit-tree-title" />
      <ModalBody>
        <Form id="edit-tree-form" onSubmit={(e) => { e.preventDefault(); save(); }}>
          <FormGroup label="Name" fieldId="edit-tree-name" isRequired>
            <TextInput id="edit-tree-name" value={name} onChange={(_e, v) => setName(v)} isRequired />
          </FormGroup>
          <TierChoice id="edit-tree-tier" tier={tier} onChange={setTier} />
        </Form>
        <ProblemAlert error={error} />
        {dialog}
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="edit-tree-form" isLoading={busy} isDisabled={busy || !name.trim() || (name.trim() === tree.name && tier === tree.tier)}>Save</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}

/** Remove a tree, its name typed: its sessions end and the certificates trusted for it alone go. */
function RemoveTreeModal({ tree, onClose, onRemoved }: { tree: ConsoleTree; onClose: () => void; onRemoved: () => void }) {
  const { run, dialog } = useStepUp();
  const [typed, setTyped] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const remove = () => {
    setBusy(true);
    setError(null);
    run(() => trees.remove(tree.id, typed)).then(() => { onRemoved(); onClose(); }, setError).finally(() => setBusy(false));
  };
  return (
    <Modal isOpen onClose={onClose} variant="small" aria-labelledby="remove-tree-title">
      <ModalHeader title={`Remove ${tree.name}?`} labelId="remove-tree-title" titleIconVariant="warning" />
      <ModalBody>
        <p>People can no longer sign in to it here, and anyone signed in to it now is signed out. Its role mappings, presets,
          single sign-on and service account go with it, as do the certificates trusted for it alone. The directory itself is not touched.</p>
        <FormGroup label={`Type ${tree.name} to confirm`} fieldId="remove-tree-typed" className="dc-tab-body">
          <TextInput id="remove-tree-typed" value={typed} onChange={(_e, v) => setTyped(v)} />
        </FormGroup>
        <ProblemAlert error={error} />
        {dialog}
      </ModalBody>
      <ModalFooter>
        <Button variant="danger" onClick={remove} isLoading={busy} isDisabled={busy || typed !== tree.name}>Remove</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}

/**
 * Console-wide: the trees people choose from at sign-in (dev, test, production…). Each keeps its own
 * settings, managed while signed in to it; this list adds, renames and removes them.
 */
export function TreesSection() {
  const [list, setList] = useState<ConsoleTree[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<ConsoleTree | null>(null);
  const [removing, setRemoving] = useState<ConsoleTree | null>(null);
  const load = useCallback(() => { trees.list().then(setList, setError); }, []);
  useEffect(load, [load]);

  return (
    <div className="dc-tab-body">
      <p>
        This applies to the whole console. People choose one of these directories when they sign in. Each directory keeps its own tier,
        service account, role mappings, presets and single sign-on: sign in to a directory to change those under the other tabs.
      </p>
      <Button variant="secondary" size="sm" className="dc-gap-bottom" onClick={() => setAdding(true)}>Add a directory</Button>
      {notice && <Alert variant="success" isInline isPlain title={notice} />}
      <ProblemAlert error={error} onRetry={load} />
      {!list && !error && <Spinner size="md" aria-label="Loading the directories" />}
      {list && (
        <Table aria-label="Directories" variant="compact">
          <Thead><Tr><Th>Name</Th><Th>Address</Th><Th>Tier</Th><Th screenReaderText="Actions" /></Tr></Thead>
          <Tbody>
            {list.map((t) => (
              <Tr key={t.id}>
                <Td dataLabel="Name">{t.name} {t.current && <Label isCompact color="blue">signed in</Label>}</Td>
                <Td dataLabel="Address" className="dc-mono">{t.host}:{t.port}</Td>
                <Td dataLabel="Tier"><Label isCompact color={t.tier === 'production' ? 'orange' : 'grey'}>{t.tier}</Label></Td>
                <Td isActionCell>
                  <Button variant="link" isInline onClick={() => setEditing(t)}>Change</Button>{' '}
                  {!t.current && <Button variant="link" isInline isDanger onClick={() => setRemoving(t)}>Remove</Button>}
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}
      {adding && <AddTreeModal onClose={() => setAdding(false)} onAdded={(t) => { setNotice(`${t.name} added. People can now choose it at sign-in.`); load(); }} />}
      {editing && <EditTreeModal tree={editing} onClose={() => setEditing(null)} onSaved={(t) => { setNotice(`${t.name} saved.`); load(); }} />}
      {removing && <RemoveTreeModal tree={removing} onClose={() => setRemoving(null)} onRemoved={() => { setNotice(`${removing.name} removed.`); load(); }} />}
    </div>
  );
}
