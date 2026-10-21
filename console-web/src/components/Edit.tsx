import { useEffect, useMemo, useState } from 'react';
import {
  ClipboardCopy, Flex, FlexItem, Alert, Button, Checkbox, DescriptionList, DescriptionListDescription, DescriptionListGroup, DescriptionListTerm, Form,
  FormGroup, FormHelperText, FormSelect, FormSelectOption, HelperText, HelperTextItem, Modal, ModalBody,
  ModalFooter, ModalHeader, TextArea, TextInput,
} from '@patternfly/react-core';
import { type DirObject, type Row, type SchemaAttribute, type SchemaClass, ApiError, security } from '../api';
import { generatePassword } from '../passwordgen';
import { useSession } from '../session';
import { ProblemAlert } from './Problem';
import { BrowseContainers } from './ContainerChooser';
import { type InputValue, ValueInput } from './ValueInput';
import { explain } from '../help/glossary';

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
  const [alias, setAlias] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await tree.rename(obj.guid, etag, name, alias);
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
          <Checkbox id="rename-alias" label="Leave an alias at the old name" description={explain('aliasObject')}
            isChecked={alias} onChange={(_e, v) => setAlias(v)} />
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
  const [alias, setAlias] = useState(false);
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
      const r = await tree.move(obj.guid, etag, target.guid, alias);
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
            <Flex flexWrap={{ default: 'nowrap' }} spaceItems={{ default: 'spaceItemsSm' }}>
              <FlexItem grow={{ default: 'grow' }}>
                <TextInput id="parent" value={dn} onChange={(_e, v) => { setDn(v); setTarget(null); }} placeholder="ou=sales,o=acme" autoFocus />
              </FlexItem>
              <FlexItem><BrowseContainers title="Move into" onChoose={(v) => { setDn(v); setTarget(null); }} /></FlexItem>
            </Flex>
          </FormGroup>
          {target && <Target obj={target} label="Into" />}
          {target && (
            <Checkbox id="move-alias" label="Leave an alias at the old place" description={explain('aliasObject')}
              isChecked={alias} onChange={(_e, v) => setAlias(v)} />
          )}
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
  const [below, setBelow] = useState<{ count: number; capped: boolean } | null>(null);
  const [everything, setEverything] = useState(false);
  useEffect(() => {
    if (obj.container) {
      tree.subtree(obj.guid).then(setBelow).catch(() => setBelow(null));
    }
  }, [tree, obj]);
  const others = below ? below.count - 1 : 0;
  const remove = async () => {
    setBusy(true);
    setError(null);
    try {
      if (others > 0) {
        await tree.removeSubtree(obj.guid, etag, below!.count);
      } else {
        await tree.remove(obj.guid, etag);
      }
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
          {others > 0 && (
            <Alert variant="danger" isInline title={below!.capped ? `More than ${below!.count - 1} objects are under it` : `${others} object${others === 1 ? ' is' : 's are'} under it`}>
              {below!.capped
                ? 'Too many to delete at once. Delete smaller parts first.'
                : <Checkbox id="everything" label={`Delete it and all ${others} object${others === 1 ? '' : 's'} under it`} isChecked={everything} onChange={(_e, v) => setEverything(v)} />}
            </Alert>
          )}
          <FormGroup label={`Type ${obj.name} to confirm`} fieldId="confirm" isRequired>
            <TextInput id="confirm" value={typed} onChange={(_e, v) => setTyped(v)} autoFocus />
          </FormGroup>
          <ProblemAlert error={error} />
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button variant="danger" type="submit" form="delete-form" isLoading={busy}
          isDisabled={busy || typed !== obj.name || (others > 0 && (!everything || below!.capped))}>{others > 0 ? `Delete ${below!.count} objects` : 'Delete'}</Button>
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
  const [required, setRequired] = useState<Record<string, InputValue>>({});
  const [attrTypes, setAttrTypes] = useState<SchemaAttribute[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    tree.classes().then((all) => {
      const here = parent.objectClasses.map((c) => c.toLowerCase());
      setClasses(all.filter((c) => c.kind === 'structural' && c.naming.length > 0
        && (c.containment.length === 0 || c.containment.some((p) => here.includes(p.toLowerCase()))))
        .sort((a, b) => a.name.localeCompare(b.name)));
    }).catch(setError);
    tree.attributes().then(setAttrTypes).catch(() => undefined);
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
  const ready = cls && value.trim() && mustFill.every((a) => required[a] !== undefined);

  const create = async () => {
    if (!cls) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const attributes: Record<string, unknown[]> = {};
      mustFill.forEach((a) => { attributes[a] = [required[a]]; });
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
                <FormGroup key={`${cls.name}-${a}`} label={a} fieldId={`req-${a}`} isRequired>
                  <ValueInput id={`req-${a}`} attribute={attrTypes.find((t) => t.names.some((n) => n.toLowerCase() === a.toLowerCase()))}
                    onChange={(v) => setRequired((old) => ({ ...old, [a]: v }))} />
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

/** Set a user's password; optionally expire it so the person must choose a new one at the next login. */
export function PasswordModal({ obj, onClose, onDone }: { obj: DirObject; onClose: () => void; onDone: () => void }) {
  const { tree, me } = useSession();
  const [pw, setPw] = useState('');
  const [again, setAgain] = useState('');
  const [shown, setShown] = useState<string | null>(null);
  const [made, setMade] = useState<string | null>(null);
  const [making, setMaking] = useState(false);
  // a random password from the rules of the policy that governs this user, confirmed by NMAS (a few tries)
  const generate = async () => {
    setMaking(true);
    setError(null);
    setMade(null);
    try {
      const sec = security(me.directory);
      const governing = (await sec.policyFor(obj.guid)).governing;
      const rules = governing?.guid ? (await sec.policy(governing.guid)).rules : { minLength: 12 };
      let candidate = '';
      let ok = false;
      for (let i = 0; i < 5 && !ok; i++) {
        candidate = generatePassword(rules);
        ok = (await sec.passwordCheck(obj.guid, candidate)).passes;
      }
      if (!ok) {
        throw new Error('NMAS refused five generated passwords: the policy may need rules the generator cannot see (such as excluded attribute values).');
      }
      setPw(candidate);
      setAgain(candidate);
      setShown(candidate);
      setMade(governing ? `Made from ${governing.name}, and checked against it.` : 'No password policy governs this user; made 12 or more characters long.');
    } catch (e) {
      setError(e);
    } finally {
      setMaking(false);
    }
  };
  const [mustChange, setMustChange] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      await tree.password(obj.guid, pw, mustChange);
      setPw('');
      setAgain('');
      onDone();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  const mismatch = again.length > 0 && again !== pw;
  return (
    <Modal isOpen onClose={onClose} variant="small" aria-labelledby="pw-title">
      <ModalHeader title="Set password" labelId="pw-title" />
      <ModalBody>
        <Form id="pw-form" onSubmit={(e) => { e.preventDefault(); save(); }}>
          <Target obj={obj} />
          <FormGroup label="New password" fieldId="pw" isRequired>
            <Flex flexWrap={{ default: 'nowrap' }} spaceItems={{ default: 'spaceItemsSm' }}>
              <FlexItem grow={{ default: 'grow' }}>
                <TextInput id="pw" type="password" autoComplete="new-password" value={pw} onChange={(_e, v) => { setPw(v); setShown(null); setMade(null); }} autoFocus />
              </FlexItem>
              <FlexItem><Button variant="secondary" onClick={() => void generate()} isLoading={making} isDisabled={making}>Generate</Button></FlexItem>
            </Flex>
            {shown && <ClipboardCopy isReadOnly hoverTip="Copy" clickTip="Copied" className="dc-tab-body dc-mono">{shown}</ClipboardCopy>}
            {made && <FormHelperText><HelperText><HelperTextItem>{made} Copy it before you set it: it is not shown again.</HelperTextItem></HelperText></FormHelperText>}
          </FormGroup>
          <FormGroup label="Type it again" fieldId="pw2" isRequired>
            <TextInput id="pw2" type="password" autoComplete="new-password" value={again} onChange={(_e, v) => { setAgain(v); setShown(null); }} validated={mismatch ? 'error' : 'default'} />
            {mismatch && <FormHelperText><HelperText><HelperTextItem variant="error">The passwords differ</HelperTextItem></HelperText></FormHelperText>}
          </FormGroup>
          <Checkbox id="must-change" label="Must change it at the next login" isChecked={mustChange} onChange={(_e, v) => setMustChange(v)} />
          <HelperText><HelperTextItem>The directory's password policy applies; a refusal shows its reason here.</HelperTextItem></HelperText>
          <ProblemAlert error={error} />
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button variant="primary" type="submit" form="pw-form" isLoading={busy} isDisabled={busy || !pw || pw !== again}>Set password</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}

/**
 * Add or remove auxiliary classes. Adding one also adds its auxiliary superiors and asks for every
 * attribute they require that the object lacks, each entered as its syntax needs. Removing one also
 * removes the attributes only it allowed (eDirectory refuses the class change otherwise), after saying
 * which.
 */
export function AuxClassModal({ obj, etag, onClose, onDone }: EditProps) {
  const { tree } = useSession();
  const [all, setAll] = useState<SchemaClass[] | null>(null);
  const [attrTypes, setAttrTypes] = useState<SchemaAttribute[]>([]);
  const [chosen, setChosen] = useState('');
  const [cls, setCls] = useState<SchemaClass | null>(null);
  const [values, setValues] = useState<Record<string, InputValue>>({});
  const [removing, setRemoving] = useState<{ cls: string; attributes: string[] } | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const have = obj.objectClasses.map((c) => c.toLowerCase());
  const named = (c: SchemaClass, n: string) => c.names.some((x) => x.toLowerCase() === n.toLowerCase());

  useEffect(() => {
    tree.classes().then(setAll).catch(setError);
    tree.attributes().then(setAttrTypes).catch(() => undefined);
  }, [tree]);
  useEffect(() => {
    setCls(null);
    setValues({});
    if (chosen) {
      tree.schemaClass(chosen).then(setCls).catch(setError);
    }
  }, [tree, chosen]);

  const aux = (all ?? []).filter((c) => c.kind === 'auxiliary').sort((a, b) => a.name.localeCompare(b.name));
  const present = aux.filter((c) => c.names.some((n) => have.includes(n.toLowerCase())));
  // auxiliary superiors the object lacks: they come with the class
  const superiors: string[] = [];
  const walk = (c: SchemaClass) => c.superiors.forEach((n) => {
    const sup = (all ?? []).find((x) => named(x, n));
    if (sup && sup.kind === 'auxiliary' && !have.includes(sup.name.toLowerCase()) && !superiors.includes(sup.name)) {
      superiors.push(sup.name);
      walk(sup);
    }
  });
  if (cls) {
    walk(cls);
  }
  const hasAttr = (a: string) => Object.keys(obj.attributes).some((k) => k.toLowerCase() === a.toLowerCase());
  const missing = (cls?.allMust ?? []).filter((a) => a.toLowerCase() !== 'objectclass' && !hasAttr(a));
  const typeOf = (a: string) => attrTypes.find((t) => t.names.some((n) => n.toLowerCase() === a.toLowerCase()));

  const change = async (changes: Parameters<typeof tree.modify>[2]) => {
    setBusy(true);
    setError(null);
    try {
      const r = await tree.modify(obj.guid, etag, changes);
      onDone(r.data, r.etag);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  const add = () => change([
    { op: 'add', attribute: 'objectClass', values: [chosen, ...superiors] },
    ...missing.map((a) => ({ op: 'add' as const, attribute: a, values: [values[a]] })),
  ]);

  /** The attributes on the object that no other class of it allows. */
  const askRemove = async (c: SchemaClass) => {
    setError(null);
    try {
      const [gone, ...others] = await Promise.all([c.name, ...obj.objectClasses.filter((n) => !named(c, n))].map((n) => tree.schemaClass(n)));
      const kept = new Set(others.flatMap((o) => [...(o.allMust ?? o.must), ...(o.allMay ?? o.may)]).map((a) => a.toLowerCase()));
      const only = [...(gone.allMust ?? gone.must), ...(gone.allMay ?? gone.may)].filter((a) => !kept.has(a.toLowerCase()) && hasAttr(a));
      const attributes = Object.keys(obj.attributes).filter((k) => only.some((a) => a.toLowerCase() === k.toLowerCase()));
      if (attributes.length === 0) {
        await change([{ op: 'remove', attribute: 'objectClass', values: [c.name] }]);
      } else {
        setRemoving({ cls: c.name, attributes });
      }
    } catch (e) {
      setError(e);
    }
  };

  return (
    <Modal isOpen onClose={onClose} variant="medium" aria-labelledby="aux-title">
      <ModalHeader title="Auxiliary classes" labelId="aux-title" />
      <ModalBody>
        <Target obj={obj} />
        <Form id="aux-form" className="dc-tab-body" onSubmit={(e) => { e.preventDefault(); add(); }}>
          <FormGroup label="On this object" fieldId="present">
            {present.length === 0 ? <span className="dc-subtle">None</span> : (
              <ul className="dc-values">
                {present.map((c) => (
                  <li key={c.name}>
                    {c.name}{' '}
                    <Button variant="link" isInline isDanger isDisabled={busy || !!removing} onClick={() => askRemove(c)}>Remove</Button>
                  </li>
                ))}
              </ul>
            )}
          </FormGroup>
          {removing && (
            <Alert variant="warning" isInline title={`Removing ${removing.cls} also removes ${removing.attributes.length === 1 ? 'an attribute' : 'attributes'} only it allows`}
              actionLinks={<>
                <Button variant="link" isInline isDanger isLoading={busy} onClick={() => change([
                  ...removing.attributes.map((a) => ({ op: 'remove' as const, attribute: a })),
                  { op: 'remove', attribute: 'objectClass', values: [removing.cls] },
                ])}>Remove the class and {removing.attributes.join(', ')}</Button>
                <Button variant="link" isInline onClick={() => setRemoving(null)}>Keep it</Button>
              </>}>
              Their values are deleted: {removing.attributes.join(', ')}.
            </Alert>
          )}
          <FormGroup label="Add a class" fieldId="aux-add">
            <FormSelect id="aux-add" value={chosen} onChange={(_e, v) => setChosen(v)} isDisabled={!all}>
              <FormSelectOption value="" label={all ? 'Choose an auxiliary class' : 'Loading…'} isPlaceholder />
              {aux.filter((c) => !present.includes(c)).map((c) => <FormSelectOption key={c.name} value={c.name} label={c.name} />)}
            </FormSelect>
            {superiors.length > 0 && (
              <FormHelperText><HelperText><HelperTextItem>Also adds the classes it builds on: {superiors.join(', ')}.</HelperTextItem></HelperText></FormHelperText>
            )}
          </FormGroup>
          {cls && missing.length === 0 && <p className="dc-subtle">The object already has every attribute this class requires.</p>}
          {missing.map((a) => (
            <FormGroup key={`${chosen}-${a}`} label={a} fieldId={`aux-${a}`} isRequired>
              <ValueInput id={`aux-${a}`} attribute={typeOf(a)} onChange={(v) => setValues((old) => ({ ...old, [a]: v }))} />
            </FormGroup>
          ))}
          <ProblemAlert error={error} />
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button variant="primary" type="submit" form="aux-form" isLoading={busy}
          isDisabled={busy || !cls || missing.some((a) => values[a] === undefined)}>Add class</Button>
        <Button variant="link" onClick={onClose}>Close</Button>
      </ModalFooter>
    </Modal>
  );
}
