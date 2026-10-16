import { useState } from 'react';
import {
  Button, Checkbox, Form, FormGroup, FormHelperText, FormSelect, FormSelectOption, HelperText, HelperTextItem, Modal, ModalBody, ModalFooter,
  ModalHeader, NumberInput, TextArea, TextInput,
} from '@patternfly/react-core';
import { type Edir } from '../api';
import { ProblemAlert } from './Problem';

const NAME = /^[A-Za-z][A-Za-z0-9-]{0,62}$/;
const OID = /^[0-2](\.(0|[1-9][0-9]*))+$/;
const names = (s: string) => s.split(/[\s,$]+/).map((x) => x.trim()).filter(Boolean);

export const SYNTAX_CHOICES: { oid: string; label: string }[] = [
  { oid: '1.3.6.1.4.1.1466.115.121.1.15', label: 'Directory string' },
  { oid: '1.3.6.1.4.1.1466.115.121.1.26', label: 'IA5 string (ASCII)' },
  { oid: '1.3.6.1.4.1.1466.115.121.1.27', label: 'Integer' },
  { oid: '1.3.6.1.4.1.1466.115.121.1.7', label: 'Boolean' },
  { oid: '1.3.6.1.4.1.1466.115.121.1.24', label: 'Generalized time' },
  { oid: '1.3.6.1.4.1.1466.115.121.1.12', label: 'DN (a reference to an object)' },
  { oid: '1.3.6.1.4.1.1466.115.121.1.40', label: 'Octet string (binary)' },
  { oid: '1.3.6.1.4.1.1466.115.121.1.50', label: 'Telephone number' },
];

type Run = (op: (c?: string) => Promise<unknown>) => Promise<unknown>;

/** A new attribute type. The OID may be left empty: the console makes one under 2.25. */
export function NewAttributeModal({ api, run, onClose, onDone }: { api: Edir; run: Run; onClose: () => void; onDone: (name: string) => void }) {
  const [name, setName] = useState('');
  const [oid, setOid] = useState('');
  const [syntax, setSyntax] = useState(SYNTAX_CHOICES[0].oid);
  const [single, setSingle] = useState(false);
  const [bound, setBound] = useState<number | ''>('');
  const [description, setDescription] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const problem = !NAME.test(name) ? 'A name starts with a letter and has letters, digits and hyphens.' : oid && !OID.test(oid) ? 'An OID is a dotted number.' : null;
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (problem) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await run((c) => api.addAttribute({ name, oid: oid || undefined, syntax, singleValue: single, upperBound: bound === '' ? undefined : bound, description: description || undefined }, c));
      onDone(name);
    } catch (x) {
      setError(x);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal variant="medium" isOpen onClose={onClose} aria-labelledby="attr-new-title">
      <ModalHeader title="New attribute" labelId="attr-new-title" description="Schema changes reach every server in the directory; an attribute in use cannot be deleted." />
      <ModalBody>
        <Form id="attr-new-form" onSubmit={submit}>
          <FormGroup label="Name" fieldId="attr-new-name" isRequired>
            <TextInput id="attr-new-name" value={name} onChange={(_e, v) => setName(v)} className="dc-mono" />
          </FormGroup>
          <FormGroup label="Syntax" fieldId="attr-new-syntax" isRequired>
            <FormSelect id="attr-new-syntax" value={syntax} onChange={(_e, v) => setSyntax(v)}>
              {SYNTAX_CHOICES.map((s) => <FormSelectOption key={s.oid} value={s.oid} label={s.label} />)}
            </FormSelect>
          </FormGroup>
          <Checkbox id="attr-new-single" label="Single value" isChecked={single} onChange={(_e, v) => setSingle(v)} />
          <FormGroup label="Maximum length" fieldId="attr-new-bound">
            <NumberInput id="attr-new-bound" value={bound} min={1} onMinus={() => setBound(Math.max(1, (bound || 2) - 1))} onPlus={() => setBound((bound || 0) + 1)}
              onChange={(e) => { const v = (e.target as HTMLInputElement).value; setBound(v === '' ? '' : Math.max(1, Number(v))); }} inputName="bound" inputAriaLabel="Maximum length" />
          </FormGroup>
          <FormGroup label="OID" fieldId="attr-new-oid">
            <TextInput id="attr-new-oid" value={oid} onChange={(_e, v) => setOid(v.trim())} className="dc-mono" />
            <FormHelperText><HelperText><HelperTextItem>Your organisation's OID for it, or empty for one under 2.25.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <FormGroup label="Description" fieldId="attr-new-desc">
            <TextInput id="attr-new-desc" value={description} onChange={(_e, v) => setDescription(v)} />
          </FormGroup>
          {name && problem && <HelperText><HelperTextItem variant="error">{problem}</HelperTextItem></HelperText>}
          <ProblemAlert error={error} />
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="attr-new-form" variant="primary" isLoading={busy} isDisabled={busy || !!problem}>Create</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}

/** A new class: auxiliary (to add to objects) or structural (to create objects of). */
export function NewClassModal({ api, run, onClose, onDone }: { api: Edir; run: Run; onClose: () => void; onDone: (name: string) => void }) {
  const [name, setName] = useState('');
  const [oid, setOid] = useState('');
  const [kind, setKind] = useState('auxiliary');
  const [superior, setSuperior] = useState('top');
  const [must, setMust] = useState('');
  const [may, setMay] = useState('');
  const [naming, setNaming] = useState('cn');
  const [containment, setContainment] = useState('organizationalUnit organization');
  const [container, setContainer] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const problem = !NAME.test(name) ? 'A name starts with a letter and has letters, digits and hyphens.' : oid && !OID.test(oid) ? 'An OID is a dotted number.' : null;
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (problem) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await run((c) => api.addClass({
        name, oid: oid || undefined, kind, superior: names(superior), must: names(must), may: names(may),
        ...(kind === 'auxiliary' ? {} : { container, naming: names(naming), containment: names(containment) }),
      }, c));
      onDone(name);
    } catch (x) {
      setError(x);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal variant="medium" isOpen onClose={onClose} aria-labelledby="class-new-title">
      <ModalHeader title="New class" labelId="class-new-title" description="Schema changes reach every server in the directory; a class in use cannot be deleted." />
      <ModalBody>
        <Form id="class-new-form" onSubmit={submit}>
          <FormGroup label="Name" fieldId="class-new-name" isRequired>
            <TextInput id="class-new-name" value={name} onChange={(_e, v) => setName(v)} className="dc-mono" />
          </FormGroup>
          <FormGroup label="Kind" fieldId="class-new-kind" isRequired>
            <FormSelect id="class-new-kind" value={kind} onChange={(_e, v) => setKind(v)}>
              <FormSelectOption value="auxiliary" label="Auxiliary: extra attributes for existing objects" />
              <FormSelectOption value="structural" label="Structural: objects are created of this class" />
              <FormSelectOption value="abstract" label="Abstract: only for other classes to inherit" />
            </FormSelect>
          </FormGroup>
          <FormGroup label="Inherits from" fieldId="class-new-sup">
            <TextInput id="class-new-sup" value={superior} onChange={(_e, v) => setSuperior(v)} className="dc-mono" />
          </FormGroup>
          <FormGroup label="Required attributes" fieldId="class-new-must">
            <TextArea id="class-new-must" value={must} onChange={(_e, v) => setMust(v)} className="dc-mono" resizeOrientation="vertical" />
          </FormGroup>
          <FormGroup label="Optional attributes" fieldId="class-new-may">
            <TextArea id="class-new-may" value={may} onChange={(_e, v) => setMay(v)} className="dc-mono" resizeOrientation="vertical" />
            <FormHelperText><HelperText><HelperTextItem>Attribute names, separated by spaces or commas.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          {kind !== 'auxiliary' && (
            <>
              <FormGroup label="Named by" fieldId="class-new-naming">
                <TextInput id="class-new-naming" value={naming} onChange={(_e, v) => setNaming(v)} className="dc-mono" />
              </FormGroup>
              <FormGroup label="Can be created in" fieldId="class-new-cont">
                <TextInput id="class-new-cont" value={containment} onChange={(_e, v) => setContainment(v)} className="dc-mono" />
              </FormGroup>
              <Checkbox id="class-new-container" label="Objects of this class can hold other objects (a container)" isChecked={container} onChange={(_e, v) => setContainer(v)} />
            </>
          )}
          <FormGroup label="OID" fieldId="class-new-oid">
            <TextInput id="class-new-oid" value={oid} onChange={(_e, v) => setOid(v.trim())} className="dc-mono" />
            <FormHelperText><HelperText><HelperTextItem>Your organisation's OID for it, or empty for one under 2.25.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          {name && problem && <HelperText><HelperTextItem variant="error">{problem}</HelperTextItem></HelperText>}
          <ProblemAlert error={error} />
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="class-new-form" variant="primary" isLoading={busy} isDisabled={busy || !!problem}>Create</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}

/** Add optional attributes to an existing class (eDirectory allows only this change to a class). */
export function AddOptionalModal({ api, run, cls, onClose, onDone }: { api: Edir; run: Run; cls: string; onClose: () => void; onDone: () => void }) {
  const [attrs, setAttrs] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  return (
    <Modal variant="small" isOpen onClose={onClose} aria-labelledby="may-title">
      <ModalHeader title={`Add optional attributes to ${cls}`} labelId="may-title" />
      <ModalBody>
        <Form id="may-form" onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(null);
          try {
            await run((c) => api.addOptional(cls, names(attrs), c));
            onDone();
          } catch (x) {
            setError(x);
          } finally {
            setBusy(false);
          }
        }}>
          <FormGroup label="Attributes" fieldId="may-attrs" isRequired>
            <TextArea id="may-attrs" value={attrs} onChange={(_e, v) => setAttrs(v)} className="dc-mono" resizeOrientation="vertical" />
            <FormHelperText><HelperText><HelperTextItem>Attribute names, separated by spaces or commas.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <ProblemAlert error={error} />
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="may-form" variant="primary" isLoading={busy} isDisabled={busy || names(attrs).length === 0}>Add</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}
