import { useState } from 'react';
import {
  Button, Checkbox, EmptyState, EmptyStateBody, Form, FormGroup, FormHelperText, FormSelect, FormSelectOption, HelperText, HelperTextItem,
  Label, LabelGroup, Modal, ModalBody, ModalFooter, ModalHeader, TextArea, TextInput, Toolbar, ToolbarContent, ToolbarItem,
} from '@patternfly/react-core';
import { PlusIcon } from '@patternfly/react-icons';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type Preset, type RoleId, type RoleMappingJson } from '../api';
import { useHeading } from '../heading';

const ROLES: { id: RoleId; label: string }[] = [
  { id: 'viewer', label: 'Viewer: read objects, schema and IDM status' },
  { id: 'editor', label: 'Editor: change directory objects' },
  { id: 'operator', label: 'Operator: Identity Manager operations' },
  { id: 'admin', label: 'Admin: console settings (console-wide)' },
];

const lines = (s: string) => s.split('\n').map((x) => x.trim()).filter(Boolean);

/**
 * Role mappings: a group (an eDirectory group DN, or for single sign-on the provider's group name)
 * and what it grants: a role, task presets, or both, optionally limited to containers.
 */
export function RoleMappings({ value, onChange, presets, idp }: {
  value: RoleMappingJson[]; onChange: (v: RoleMappingJson[]) => void; presets: Preset[]; idp?: boolean;
}) {
  const [editing, setEditing] = useState<null | { index: number; mapping: RoleMappingJson }>(null);
  const level = useHeading();
  const what = idp ? 'Provider group' : 'Group';
  return (
    <>
      <Toolbar>
        <ToolbarContent>
          <ToolbarItem>
            <Button variant="secondary" icon={<PlusIcon />} onClick={() => setEditing({ index: -1, mapping: { group: '', role: 'viewer', scopes: [], presets: [] } })}>
              Add a mapping
            </Button>
          </ToolbarItem>
        </ToolbarContent>
      </Toolbar>
      {value.length === 0 ? (
        <EmptyState titleText="No role mappings" headingLevel={level}>
          <EmptyStateBody>{idp ? 'Nobody who signs in through single sign-on gets a role yet.' : 'Only break-glass accounts can sign in until a group is mapped to a role.'}</EmptyStateBody>
        </EmptyState>
      ) : (
        <Table aria-label="Role mappings" variant="compact">
          <Thead><Tr><Th>{what}</Th><Th>Role</Th><Th>Task presets</Th><Th>Where</Th><Th screenReaderText="Actions" /></Tr></Thead>
          <Tbody>
            {value.map((m, i) => (
              <Tr key={i}>
                <Td dataLabel={what} className={idp ? undefined : 'dc-mono'}>{m.group}</Td>
                <Td dataLabel="Role">{m.role ?? '—'}</Td>
                <Td dataLabel="Task presets">
                  {m.presets?.length ? <LabelGroup>{m.presets.map((p) => <Label key={p} isCompact>{presets.find((x) => x.id === p)?.name ?? p}</Label>)}</LabelGroup> : '—'}
                </Td>
                <Td dataLabel="Where">{m.scopes?.length ? m.scopes.map((s) => <div key={s} className="dc-mono">{s}</div>) : 'Everywhere'}</Td>
                <Td isActionCell modifier="nowrap">
                  <Button variant="link" isInline onClick={() => setEditing({ index: i, mapping: m })}>Edit</Button>{' '}
                  <Button variant="link" isInline isDanger onClick={() => onChange(value.filter((_x, j) => j !== i))}>Remove</Button>
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}
      {editing && (
        <MappingModal initial={editing.mapping} presets={presets} idp={idp} onClose={() => setEditing(null)}
          onSave={(m) => {
            onChange(editing.index < 0 ? [...value, m] : value.map((x, j) => (j === editing.index ? m : x)));
            setEditing(null);
          }} />
      )}
    </>
  );
}

function MappingModal({ initial, presets, idp, onClose, onSave }: {
  initial: RoleMappingJson; presets: Preset[]; idp?: boolean; onClose: () => void; onSave: (m: RoleMappingJson) => void;
}) {
  const [group, setGroup] = useState(initial.group);
  const [role, setRole] = useState<string>(initial.role ?? '');
  const [scopes, setScopes] = useState((initial.scopes ?? []).join('\n'));
  const [chosen, setChosen] = useState<string[]>(initial.presets ?? []);
  const [touched, setTouched] = useState(false);
  const problem = !group.trim() ? 'A group is required.'
    : !role && chosen.length === 0 ? 'Grant a role, task presets, or both.'
      : role === 'admin' && lines(scopes).length > 0 ? 'Admin is console-wide; it cannot be limited to containers.' : null;
  return (
    <Modal variant="medium" isOpen onClose={onClose} aria-labelledby="mapping-title">
      <ModalHeader title={initial.group ? 'Edit the role mapping' : 'Add a role mapping'} labelId="mapping-title" />
      <ModalBody>
        <Form id="mapping-form" onSubmit={(e) => {
          e.preventDefault();
          setTouched(true);
          if (!problem) {
            onSave({ group: group.trim(), ...(role ? { role: role as RoleId } : {}), scopes: lines(scopes), presets: chosen });
          }
        }}>
          <FormGroup label={idp ? 'Provider group' : 'Group'} fieldId="mapping-group" isRequired>
            <TextInput id="mapping-group" value={group} onChange={(_e, v) => setGroup(v)} className={idp ? undefined : 'dc-mono'} />
            <FormHelperText><HelperText><HelperTextItem>
              {idp ? 'The group name as the identity provider sends it in the groups claim.' : 'The eDirectory group\'s DN, for example cn=Help Desk,ou=Groups,o=acme.'}
            </HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <FormGroup label="Role" fieldId="mapping-role">
            <FormSelect id="mapping-role" value={role} onChange={(_e, v) => setRole(v)}>
              <FormSelectOption value="" label="No role (task presets only)" />
              {ROLES.map((r) => <FormSelectOption key={r.id} value={r.id} label={r.label} />)}
            </FormSelect>
          </FormGroup>
          <FormGroup role="group" label="Task presets" fieldId="mapping-presets">
            {presets.length === 0 ? <span className="dc-subtle">No task presets are defined.</span>
              : presets.map((p) => (
                <Checkbox key={p.id} id={`mapping-preset-${p.id}`} label={p.name} description={p.description}
                  isChecked={chosen.includes(p.id)} onChange={(_e, on) => setChosen(on ? [...chosen, p.id] : chosen.filter((x) => x !== p.id))} />
              ))}
          </FormGroup>
          <FormGroup label="Only under these containers" fieldId="mapping-scopes">
            <TextArea id="mapping-scopes" value={scopes} onChange={(_e, v) => setScopes(v)} resizeOrientation="vertical" className="dc-mono" />
            <FormHelperText><HelperText><HelperTextItem>One container DN per line. Empty means the whole directory. eDirectory rights still apply.</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          {touched && problem && <HelperText><HelperTextItem variant="error">{problem}</HelperTextItem></HelperText>}
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="mapping-form" variant="primary">Done</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}
