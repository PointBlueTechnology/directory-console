import { useState } from 'react';
import {
  Button, Checkbox, Form, FormGroup, FormHelperText, HelperText, HelperTextItem, Modal, ModalBody, ModalFooter, ModalHeader, TextInput,
} from '@patternfly/react-core';
import { PlusIcon, TrashIcon } from '@patternfly/react-icons';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type Preset, type PresetAction, type PresetField } from '../api';

const ACTIONS: { id: PresetAction; label: string }[] = [
  { id: 'password', label: 'Set a password' },
  { id: 'unlock', label: 'Clear an intruder lockout' },
  { id: 'enable', label: 'Enable login' },
  { id: 'disable', label: 'Disable login' },
  { id: 'attributes', label: 'Change the attributes below' },
];

/** A preset as the configuration stores it (the id is the key). */
export function presetJson(p: Preset): Record<string, unknown> {
  return {
    name: p.name,
    ...(p.description ? { description: p.description } : {}),
    objectClass: p.objectClass,
    actions: p.actions,
    attributes: p.attributes.map((f) => ({
      name: f.name,
      ...(f.label && f.label !== f.name ? { label: f.label } : {}),
      ...(f.required ? { required: true } : {}),
      ...(f.readOnly ? { readOnly: true } : {}),
      ...(f.pattern ? { pattern: f.pattern } : {}),
      ...(f.value !== undefined && f.value !== '' ? { value: f.value } : {}),
    })),
  };
}

/** Edit one task preset: its name, class, actions and fields with their rules. */
export function PresetEditor({ initial, taken, onClose, onSave }: {
  initial: Preset | null; taken: string[]; onClose: () => void; onSave: (p: Preset) => void;
}) {
  const [id, setId] = useState(initial?.id ?? '');
  const [name, setName] = useState(initial?.name ?? '');
  const [description, setDescription] = useState(initial?.description ?? '');
  const [objectClass, setObjectClass] = useState(initial?.objectClass ?? 'inetOrgPerson');
  const [actions, setActions] = useState<PresetAction[]>(initial?.actions ?? []);
  const [fields, setFields] = useState<PresetField[]>(initial?.attributes ?? []);
  const [touched, setTouched] = useState(false);

  const idProblem = !/^[a-z0-9][a-z0-9-]{0,62}$/.test(id) ? 'Lowercase letters, digits and hyphens.'
    : !initial && taken.includes(id) ? 'Another preset has this id.' : null;
  const fieldProblem = fields.find((f) => !/^[A-Za-z][A-Za-z0-9-]*$/.test(f.name)) ? 'Each field needs an attribute name.'
    : fields.find((f) => f.pattern && !validRegex(f.pattern)) ? 'A pattern is not a valid regular expression.' : null;
  const problem = idProblem ?? (!name.trim() ? 'A name is required.' : actions.length === 0 ? 'Choose at least one action.'
    : actions.includes('attributes') && fields.length === 0 ? 'Changing attributes needs at least one field.' : fieldProblem);
  const set = (i: number, f: Partial<PresetField>) => setFields(fields.map((x, j) => (j === i ? { ...x, ...f } : x)));

  return (
    <Modal variant="large" isOpen onClose={onClose} aria-labelledby="preset-edit-title">
      <ModalHeader title={initial ? `Edit ${initial.name}` : 'New task preset'} labelId="preset-edit-title" />
      <ModalBody>
        <Form id="preset-edit-form" onSubmit={(e) => {
          e.preventDefault();
          setTouched(true);
          if (!problem) {
            onSave({ id, name: name.trim(), description: description.trim() || undefined, objectClass: objectClass.trim() || 'inetOrgPerson', actions, attributes: fields });
          }
        }}>
          <FormGroup label="Id" fieldId="preset-id" isRequired>
            <TextInput id="preset-id" value={id} onChange={(_e, v) => setId(v)} isDisabled={!!initial} className="dc-mono" />
            <FormHelperText><HelperText><HelperTextItem>Role mappings grant the preset by this id.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <FormGroup label="Name" fieldId="preset-name" isRequired>
            <TextInput id="preset-name" value={name} onChange={(_e, v) => setName(v)} />
          </FormGroup>
          <FormGroup label="Description" fieldId="preset-description">
            <TextInput id="preset-description" value={description} onChange={(_e, v) => setDescription(v)} />
          </FormGroup>
          <FormGroup label="Object class" fieldId="preset-class" isRequired>
            <TextInput id="preset-class" value={objectClass} onChange={(_e, v) => setObjectClass(v)} className="dc-mono" />
          </FormGroup>
          <FormGroup role="group" label="Actions" fieldId="preset-actions" isRequired>
            {ACTIONS.map((a) => (
              <Checkbox key={a.id} id={`preset-action-${a.id}`} label={a.label} isChecked={actions.includes(a.id)}
                onChange={(_e, on) => setActions(on ? [...actions, a.id] : actions.filter((x) => x !== a.id))} />
            ))}
          </FormGroup>
          <FormGroup role="group" label="Fields" fieldId="preset-fields">
            <Table aria-label="Fields" variant="compact">
              <Thead><Tr><Th>Attribute</Th><Th>Label</Th><Th>Required</Th><Th>Read-only</Th><Th>Pattern</Th><Th>Fixed value</Th><Th screenReaderText="Remove" /></Tr></Thead>
              <Tbody>
                {fields.map((f, i) => (
                  <Tr key={i}>
                    <Td dataLabel="Attribute"><TextInput aria-label={`Field ${i + 1} attribute`} value={f.name} onChange={(_e, v) => set(i, { name: v })} className="dc-mono" /></Td>
                    <Td dataLabel="Label"><TextInput aria-label={`Field ${i + 1} label`} value={f.label === f.name ? '' : f.label} onChange={(_e, v) => set(i, { label: v || f.name })} /></Td>
                    <Td dataLabel="Required"><Checkbox id={`f${i}-req`} aria-label={`Field ${i + 1} required`} isChecked={f.required} onChange={(_e, v) => set(i, { required: v })} /></Td>
                    <Td dataLabel="Read-only"><Checkbox id={`f${i}-ro`} aria-label={`Field ${i + 1} read-only`} isChecked={f.readOnly} onChange={(_e, v) => set(i, { readOnly: v })} /></Td>
                    <Td dataLabel="Pattern"><TextInput aria-label={`Field ${i + 1} pattern`} value={f.pattern ?? ''} onChange={(_e, v) => set(i, { pattern: v || undefined })} className="dc-mono" /></Td>
                    <Td dataLabel="Fixed value"><TextInput aria-label={`Field ${i + 1} fixed value`} value={f.value ?? ''} onChange={(_e, v) => set(i, { value: v || undefined })} /></Td>
                    <Td isActionCell><Button variant="plain" aria-label={`Remove field ${i + 1}`} icon={<TrashIcon />} onClick={() => setFields(fields.filter((_x, j) => j !== i))} /></Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
            <Button variant="link" icon={<PlusIcon />} onClick={() => setFields([...fields, { name: '', label: '', required: false, readOnly: false }])}>Add a field</Button>
            <FormHelperText><HelperText><HelperTextItem>
              A pattern is a regular expression the whole value must match. A fixed value is written whenever the preset changes the object.
            </HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          {touched && problem && <HelperText><HelperTextItem variant="error">{problem}</HelperTextItem></HelperText>}
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="preset-edit-form" variant="primary">Done</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}

function validRegex(p: string): boolean {
  try {
    new RegExp(p);
    return true;
  } catch {
    return false;
  }
}
