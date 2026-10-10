import { useEffect, useMemo, useState } from 'react';
import {
  Alert, Button, DescriptionList, DescriptionListDescription, DescriptionListGroup, DescriptionListTerm, Form,
  FormGroup, FormHelperText, FormSelect, FormSelectOption, HelperText, HelperTextItem, Modal, ModalBody,
  ModalFooter, ModalHeader, TextArea, TextInput,
} from '@patternfly/react-core';
import { type DirObject, type Row, type SchemaClass, ApiError } from '../api';
import { useSession } from '../session';
import { ProblemAlert } from './Problem';

/** Every write names its exact target before it runs (section 13). */
export function Target({ obj, label = 'Object' }: { obj: Pick<Row, 'name' | 'dn' | 'guid'>; label?: string }) {
  return (
    <DescriptionList isCompact isHorizontal aria-label={label}>
      <DescriptionListGroup>
        <DescriptionListTerm>{label}</DescriptionListTerm>
        <DescriptionListDescription><strong>{obj.name}</strong></DescriptionListDescription>
      </DescriptionListGroup>
      <DescriptionListGroup>
        <DescriptionListTerm>DN</DescriptionListTerm>
        <DescriptionListDescription><span className="dc-mono">{obj.dn}</span></DescriptionListDescription>
      </DescriptionListGroup>
      <DescriptionListGroup>
        <DescriptionListTerm>GUID</DescriptionListTerm>
        <DescriptionListDescription><span className="dc-mono">{obj.guid}</span></DescriptionListDescription>
      </DescriptionListGroup>
    </DescriptionList>
  );
}

interface EditProps {
  obj: DirObject;
  etag: string;
  onClose: () => void;
  onDone: (obj: DirObject, etag?: string) => void;
}

/** Add, remove or replace one attribute's values. One value per line; binary values are not edited here. */
export function AttributeModal({ obj, etag, onClose, onDone, allowed, initial }: EditProps & { allowed: string[]; initial?: string }) {
  const { tree } = useSession();
  const [attribute, setAttribute] = useState(initial ?? '');
  const [op, setOp] = useState<'replace' | 'add' | 'remove'>('replace');
  const current = attribute ? obj.attributes[attribute] : undefined;
  const editable = !current || current.every((v) => typeof v === 'string' || ('dn' in v && !('privileges' in v)));
  const [text, setText] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const v = attribute ? obj.attributes[attribute] : undefined;
    setText(v ? v.map((x) => (typeof x === 'string' ? x : 'dn' in x ? x.dn : '')).join('\n') : '');
  }, [attribute, obj]);

  const values = text.split('\n').map((s) => s.trim()).filter((s) => s.length > 0);
  const names = useMemo(() => [...new Set([...Object.keys(obj.attributes), ...allowed])].sort((a, b) => a.localeCompare(b)), [obj, allowed]);

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await tree.modify(obj.guid, etag, [{ op, attribute, values: op === 'remove' && values.length === 0 ? undefined : values }]);
      onDone(r.data, r.etag);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal isOpen onClose={onClose} variant="medium" aria-labelledby="attr-title">
      <ModalHeader title="Edit an attribute" labelId="attr-title" />
      <ModalBody>
        <Form id="attr-form" onSubmit={(e) => { e.preventDefault(); save(); }}>
          <Target obj={obj} />
          <FormGroup label="Attribute" fieldId="attr" isRequired>
            <FormSelect id="attr" value={attribute} onChange={(_e, v) => setAttribute(v)}>
              <FormSelectOption value="" label="Choose an attribute" isPlaceholder />
              {names.map((n) => <FormSelectOption key={n} value={n} label={obj.attributes[n] ? `${n} (has values)` : n} />)}
            </FormSelect>
          </FormGroup>
          <FormGroup label="Change" fieldId="op" isRequired>
            <FormSelect id="op" value={op} onChange={(_e, v) => setOp(v as typeof op)}>
              <FormSelectOption value="replace" label="Replace all values with these" />
              <FormSelectOption value="add" label="Add these values" />
              <FormSelectOption value="remove" label="Remove these values (none listed: remove the attribute)" />
            </FormSelect>
          </FormGroup>
          <FormGroup label="Values" fieldId="values">
            <TextArea id="values" value={text} onChange={(_e, v) => setText(v)} rows={6} isDisabled={!editable} resizeOrientation="vertical" />
            <FormHelperText>
              <HelperText>
                <HelperTextItem>{editable ? 'One value per line. A reference to another object is its DN.' : 'Binary and ACL values are not edited here.'}</HelperTextItem>
              </HelperText>
            </FormHelperText>
          </FormGroup>
          <ProblemAlert error={error} />
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button variant="primary" type="submit" form="attr-form" isLoading={busy}
          isDisabled={busy || !attribute || !editable || (op !== 'remove' && values.length === 0)}>
          {op === 'replace' ? 'Replace' : op === 'add' ? 'Add' : 'Remove'}
        </Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}

export function RenameModal({ obj, etag, onClose, onDone }: EditProps) {
  const { tree } = useSession();
  const [name, setName] = useState(obj.name);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await tree.rename(obj.guid, etag, name);
      onDone(r.data, r.etag);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  const type = obj.rdns[0]?.[0]?.type ?? 'cn';
  return (
    <Modal isOpen onClose={onClose} variant="small" aria-labelledby="rename-title">
      <ModalHeader title="Rename" labelId="rename-title" />
      <ModalBody>
        <Form id="rename-form" onSubmit={(e) => { e.preventDefault(); save(); }}>
          <Target obj={obj} />
          <FormGroup label={`New name (${type})`} fieldId="new-name" isRequired>
            <TextInput id="new-name" value={name} onChange={(_e, v) => setName(v)} autoFocus />
            <FormHelperText>
              <HelperText>
                <HelperTextItem>Type the name as it should read; commas, plus signs and other characters are escaped for you.</HelperTextItem>
              </HelperText>
            </FormHelperText>
          </FormGroup>
          <ProblemAlert error={error} />
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button variant="primary" type="submit" form="rename-form" isLoading={busy} isDisabled={busy || !name.trim() || name === obj.name}>Rename</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}

export function MoveModal({ obj, etag, onClose, onDone }: EditProps) {
  const { tree } = useSession();
  const [dn, setDn] = useState('');
  const [target, setTarget] = useState<DirObject | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const check = async () => {
    setError(null);
    setTarget(null);
    try {
      const r = await tree.resolve(dn.trim());
      if (!r.data.container) {
        setError(new Error(`${r.data.name} is not a container.`));
      } else {
        setTarget(r.data);
      }
    } catch (e) {
      setError(e instanceof ApiError && e.status === 404 ? new Error('No object has that DN.') : e);
    }
  };
  const move = async () => {
    if (!target) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const r = await tree.move(obj.guid, etag, target.guid);
      onDone(r.data, r.etag);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal isOpen onClose={onClose} variant="medium" aria-labelledby="move-title">
      <ModalHeader title="Move" labelId="move-title" />
      <ModalBody>
        <Form id="move-form" onSubmit={(e) => { e.preventDefault(); if (target) { move(); } else { check(); } }}>
          <Target obj={obj} />
          <FormGroup label="New container (DN)" fieldId="parent" isRequired>
            <TextInput id="parent" value={dn} onChange={(_e, v) => { setDn(v); setTarget(null); }} placeholder="ou=sales,o=acme" autoFocus />
          </FormGroup>
          {target && <Target obj={target} label="Into" />}
          {target && <Alert variant="info" isInline isPlain title="eDirectory finishes a move in the background; the object may be busy for a few seconds." />}
          <ProblemAlert error={error} />
        </Form>
      </ModalBody>
      <ModalFooter>
        {target
          ? <Button variant="primary" type="submit" form="move-form" isLoading={busy} isDisabled={busy}>Move</Button>
          : <Button variant="secondary" type="submit" form="move-form" isDisabled={!dn.trim()}>Find container</Button>}
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}

export function DeleteModal({ obj, etag, onClose, onDeleted }: Omit<EditProps, 'onDone'> & { onDeleted: () => void }) {
  const { tree } = useSession();
  const [typed, setTyped] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const remove = async () => {
    setBusy(true);
    setError(null);
    try {
      await tree.remove(obj.guid, etag);
      onDeleted();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal isOpen onClose={onClose} variant="small" aria-labelledby="delete-title">
      <ModalHeader title="Delete this object?" titleIconVariant="danger" labelId="delete-title" />
      <ModalBody>
        <Form id="delete-form" onSubmit={(e) => { e.preventDefault(); remove(); }}>
          <Target obj={obj} />
          <FormGroup label={`Type ${obj.name} to confirm`} fieldId="confirm" isRequired>
            <TextInput id="confirm" value={typed} onChange={(_e, v) => setTyped(v)} autoFocus />
          </FormGroup>
          <ProblemAlert error={error} />
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button variant="danger" type="submit" form="delete-form" isLoading={busy} isDisabled={busy || typed !== obj.name}>Delete</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}

/** A new object under {@code parent}: a class that may be contained there, its naming attribute, and its required attributes. */
export function CreateModal({ parent, onClose, onCreated }: { parent: Row; onClose: () => void; onCreated: (o: DirObject) => void }) {
  const { tree } = useSession();
  const [classes, setClasses] = useState<SchemaClass[] | null>(null);
  const [className, setClassName] = useState('');
  const [cls, setCls] = useState<SchemaClass | null>(null);
  const [naming, setNaming] = useState('');
  const [value, setValue] = useState('');
  const [required, setRequired] = useState<Record<string, string>>({});
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    tree.classes().then((all) => {
      const here = parent.objectClasses.map((c) => c.toLowerCase());
      setClasses(all.filter((c) => c.kind === 'structural' && c.naming.length > 0
        && (c.containment.length === 0 || c.containment.some((p) => here.includes(p.toLowerCase()))))
        .sort((a, b) => a.name.localeCompare(b.name)));
    }).catch(setError);
  }, [tree, parent]);

  useEffect(() => {
    setCls(null);
    if (!className) {
      return;
    }
    tree.schemaClass(className).then((c) => {
      setCls(c);
      setNaming(c.naming[0] ?? 'cn');
      setRequired({});
    }).catch(setError);
  }, [tree, className]);

  const mustFill = (cls?.allMust ?? []).filter((a) => a.toLowerCase() !== 'objectclass' && a.toLowerCase() !== naming.toLowerCase());
  const ready = cls && value.trim() && mustFill.every((a) => (required[a] ?? '').trim());

  const create = async () => {
    if (!cls) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const attributes: Record<string, string[]> = {};
      mustFill.forEach((a) => { attributes[a] = [required[a].trim()]; });
      const r = await tree.create(parent.guid, cls.name, { type: naming, value: value.trim() }, attributes);
      onCreated(r.data);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal isOpen onClose={onClose} variant="medium" aria-labelledby="create-title">
      <ModalHeader title="New object" labelId="create-title" />
      <ModalBody>
        <Form id="create-form" onSubmit={(e) => { e.preventDefault(); create(); }}>
          <Target obj={parent} label="In" />
          <FormGroup label="Class" fieldId="class" isRequired>
            <FormSelect id="class" value={className} onChange={(_e, v) => setClassName(v)} isDisabled={!classes}>
              <FormSelectOption value="" label={classes ? 'Choose a class' : 'Loading classes…'} isPlaceholder />
              {(classes ?? []).map((c) => <FormSelectOption key={c.name} value={c.name} label={c.name} />)}
            </FormSelect>
          </FormGroup>
          {cls && (
            <>
              <FormGroup label="Name" fieldId="value" isRequired>
                <div className="dc-name-row">
                  <FormSelect id="naming" aria-label="Naming attribute" value={naming} onChange={(_e, v) => setNaming(v)}>
                    {cls.naming.map((n) => <FormSelectOption key={n} value={n} label={n} />)}
                  </FormSelect>
                  <TextInput id="value" aria-label="Name" value={value} onChange={(_e, v) => setValue(v)} />
                </div>
              </FormGroup>
              {mustFill.map((a) => (
                <FormGroup key={a} label={a} fieldId={`req-${a}`} isRequired>
                  <TextInput id={`req-${a}`} value={required[a] ?? ''} onChange={(_e, v) => setRequired({ ...required, [a]: v })} />
                </FormGroup>
              ))}
            </>
          )}
          <ProblemAlert error={error} />
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button variant="primary" type="submit" form="create-form" isLoading={busy} isDisabled={busy || !ready}>Create</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}
