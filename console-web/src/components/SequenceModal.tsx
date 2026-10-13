import { useState } from 'react';
import {
  Alert, Button, Form, FormGroup, FormSelect, FormSelectOption, Modal, ModalBody, ModalFooter, ModalHeader, Radio, TextInput,
} from '@patternfly/react-core';
import { ArrowDownIcon, ArrowUpIcon, TimesIcon } from '@patternfly/react-icons';
import { type LoginPolicy, type SequenceRequest } from '../api';

/** A login sequence: its methods in order, and whether every one runs in turn or any one will do. */
export function SequenceModal({ policy, editing, onSave, onClose }: {
  policy: LoginPolicy;
  editing?: LoginPolicy['sequences'][number];
  onSave: (body: SequenceRequest) => Promise<unknown>;
  onClose: () => void;
}) {
  const [name, setName] = useState(editing?.name ?? '');
  const [methods, setMethods] = useState<string[]>(editing?.methods ?? []);
  const [any, setAny] = useState(editing?.any ?? false);
  const [adding, setAdding] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const available = policy.methods.map((m) => m.name).filter((m) => !methods.includes(m));
  const nameOk = name.trim().length > 0 && name.trim().length <= 64 && !/[;|]/.test(name);
  const move = (i: number, d: number) => {
    const next = methods.slice();
    [next[i], next[i + d]] = [next[i + d], next[i]];
    setMethods(next);
  };
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onSave({ name: editing ? undefined : name.trim(), methods, any });
      onClose();
    } catch (x) {
      setError(x instanceof Error ? x.message : 'Not saved.');
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal variant="medium" isOpen onClose={onClose} aria-labelledby="seq-title">
      <ModalHeader title={editing ? `Change ${editing.name}` : 'New login sequence'} labelId="seq-title"
        description="The NMAS methods a person goes through to log in with this sequence. The other sequences are not changed." />
      <ModalBody>
        <Form id="seq-form" onSubmit={submit}>
          {!editing && (
            <FormGroup label="Name" fieldId="seq-name" isRequired>
              <TextInput id="seq-name" value={name} onChange={(_e, v) => setName(v)} isRequired autoFocus validated={name && !nameOk ? 'error' : 'default'} />
            </FormGroup>
          )}
          <FormGroup label="Methods" fieldId="seq-add" isRequired>
            <ol className="dc-tab-body">
              {methods.map((m, i) => (
                <li key={m}>
                  {m}
                  <Button variant="plain" aria-label={`Move ${m} up`} isDisabled={i === 0} onClick={() => move(i, -1)} icon={<ArrowUpIcon />} />
                  <Button variant="plain" aria-label={`Move ${m} down`} isDisabled={i === methods.length - 1} onClick={() => move(i, 1)} icon={<ArrowDownIcon />} />
                  <Button variant="plain" aria-label={`Remove ${m}`} onClick={() => setMethods(methods.filter((x) => x !== m))} icon={<TimesIcon />} />
                </li>
              ))}
            </ol>
            {available.length > 0 && (
              <FormSelect id="seq-add" value={adding} aria-label="Add a method"
                onChange={(_e, v) => { if (v) { setMethods([...methods, v]); } setAdding(''); }}>
                <FormSelectOption value="" label="Add a method…" />
                {available.map((m) => <FormSelectOption key={m} value={m} label={m} />)}
              </FormSelect>
            )}
          </FormGroup>
          <FormGroup role="radiogroup" label="A person must pass" fieldId="seq-any" isStack>
            <Radio id="seq-all" name="seq-any" isChecked={!any} onChange={() => setAny(false)} label="Every method, in this order" />
            <Radio id="seq-anyone" name="seq-any" isChecked={any} onChange={() => setAny(true)} label="Any one of them" />
          </FormGroup>
          {error && <Alert component="h3" variant="danger" isInline isPlain title={error} />}
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="seq-form" variant="primary" isLoading={busy} isDisabled={busy || methods.length === 0 || (!editing && !nameOk)}>Save</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}
