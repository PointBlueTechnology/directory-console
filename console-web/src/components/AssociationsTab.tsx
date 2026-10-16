import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert, Button, Form, FormGroup, FormHelperText, FormSelect, FormSelectOption, FormSelectOptionGroup, HelperText, HelperTextItem, Label, Modal,
  ModalBody, ModalFooter, ModalHeader, Spinner, TextInput, Title,
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type AssociationState, type DirObject, type ObjectAssociations, idm } from '../api';
import { useSession } from '../session';
import { linkProps } from '../router';
import { useAreYouSure, useConfirmed } from './Confirm';
import { ProblemAlert } from './Problem';
import { tip } from '../help/glossary';
import { Hint } from '../help/Help';

const STATES: { state: AssociationState; label: string; help: string; color: 'green' | 'blue' | 'orange' | 'grey' | 'purple' }[] = [
  { state: 'processed', label: 'Processed', help: 'Associated: the driver keeps the two in step.', color: 'green' },
  { state: 'pending', label: 'Pending', help: 'Waiting for the driver to process it.', color: 'blue' },
  { state: 'manual', label: 'Manual', help: 'Set by hand; the driver treats the object as associated.', color: 'purple' },
  { state: 'migrate', label: 'Migrate', help: 'Marked for migration.', color: 'orange' },
  { state: 'disabled', label: 'Disabled', help: 'The driver ignores this object.', color: 'grey' },
];
const meta = (s?: string) => STATES.find((x) => x.state === s);

/**
 * The Object Inspector: the object's Identity Manager associations, one per driver, read over LDAP.
 * An operator may add one, change its state or value, or remove it; each change names the value as it
 * was read, so a change made meanwhile by the engine or someone else is not overwritten.
 */
export function AssociationsTab({ obj }: { obj: DirObject }) {
  const { me, canAt } = useSession();
  const api = useMemo(() => idm(me.directory), [me.directory]);
  const [data, setData] = useState<ObjectAssociations | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [opError, setOpError] = useState<unknown>(null);
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<ObjectAssociations['associations'][number] | null>(null);
  const confirmed = useConfirmed();
  const sure = useAreYouSure();
  const operator = canAt('operator', obj.dn);
  const load = useCallback(() => { setError(null); api.associations(obj.guid).then(setData, setError); }, [api, obj.guid]);
  useEffect(load, [load]);

  const act = (op: (c?: string) => Promise<ObjectAssociations>) => {
    setOpError(null);
    return confirmed.run(op).then(setData, (e) => { setOpError(e); load(); });
  };
  const remove = (a: ObjectAssociations['associations'][number]) => sure.ask(`Remove the association with ${a.driver?.name ?? a.driverDn}?`,
    'The driver then treats this object as not associated: its next change may create or match an account in the connected system. The account there is not touched now.',
    'Remove', () => { act((c) => api.removeAssociation(obj.guid, a.raw, c)); });

  if (!data) {
    return <div className="dc-tab-body">{error ? <ProblemAlert error={error} onRetry={load} /> : <Spinner aria-label="Reading associations" />}</div>;
  }
  const taken = new Set(data.associations.map((a) => (a.driverDn ?? '').toLowerCase()));
  const free = data.drivers.filter((d) => !taken.has(d.dn.toLowerCase()));
  return (
    <div className="dc-tab-body">
      <ProblemAlert error={opError} />
      {data.associations.length === 0 ? <p>No Identity Manager driver is associated with this object.</p> : (
        <Table aria-label="Associations" variant="compact">
          <Thead><Tr><Th>Driver</Th><Th>Driver set</Th><Th>State</Th><Th info={tip('association')}>Association</Th>{operator && <Th screenReaderText="Actions" />}</Tr></Thead>
          <Tbody>
            {data.associations.map((a) => {
              const m = meta(a.state);
              return (
                <Tr key={a.raw}>
                  <Td dataLabel="Driver">
                    {a.driver ? (a.driver.guid ? <a {...linkProps(`/idm/drivers/${a.driver.guid}`)}>{a.driver.name}</a> : a.driver.name)
                      : a.driverDn ? <><span className="dc-mono">{a.driverDn}</span> <Label color="red" isCompact>no such driver</Label></>
                        : <span className="dc-mono">{a.raw}</span>}
                  </Td>
                  <Td dataLabel="Driver set">{a.driver?.driverSet.name ?? '—'}</Td>
                  <Td dataLabel="State">{m ? <Hint text={m.help}><Label color={m.color} isCompact>{m.label}</Label></Hint> : a.state ?? '—'}</Td>
                  <Td dataLabel="Association" className="dc-mono">{a.value || <span className="dc-subtle">(empty)</span>}</Td>
                  {operator && (
                    <Td isActionCell>
                      {a.driverDn && <Button variant="link" isInline onClick={() => setEditing(a)}>Change</Button>}
                      <Button variant="link" isInline isDanger className="dc-gap-left" onClick={() => remove(a)}>Remove</Button>
                    </Td>
                  )}
                </Tr>
              );
            })}
          </Tbody>
        </Table>
      )}
      {operator && (
        <div className="dc-tab-body">
          {free.length === 0 ? (
            <Hint text="Every driver already has an association with this object."><Button variant="secondary" isAriaDisabled>Add an association</Button></Hint>
          ) : <Button variant="secondary" onClick={() => setAdding(true)}>Add an association</Button>}
        </div>
      )}
      <p className="dc-subtle dc-tab-body">Read from {obj.servedBy?.dn ?? 'the connected server'}; associations replicate with the object.</p>
      <Title headingLevel="h3" size="md" className="dc-tab-body">Password synchronization</Title>
      {data.passwordSync.length === 0 ? <p className="dc-subtle">No driver has recorded a password synchronization for this object.</p> : (
        <Table aria-label="Password synchronization" variant="compact">
          <Thead><Tr><Th>Driver</Th><Th>Last result</Th><Th>When</Th><Th>Message</Th></Tr></Thead>
          <Tbody>
            {data.passwordSync.map((p) => (
              <Tr key={p.raw}>
                <Td dataLabel="Driver">{p.driver ? (p.driver.guid ? <a {...linkProps(`/idm/drivers/${p.driver.guid}`)}>{p.driver.name}</a> : p.driver.name)
                  : <span className="dc-subtle dc-mono">{p.driverGuid ?? '?'}</span>}</Td>
                <Td dataLabel="Last result">{p.status
                  ? <Label isCompact color={p.status === 'succeeded' ? 'green' : p.status === 'failed' ? 'red' : p.status === 'pending' ? 'blue' : 'grey'}>{p.status}</Label>
                  : <span className="dc-mono">{p.raw}</span>}</Td>
                <Td dataLabel="When">{p.when ? new Date(p.when).toLocaleString() : '—'}</Td>
                <Td dataLabel="Message">{p.message || <span className="dc-subtle">—</span>}</Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}
      {adding && (
        <AssociationModal title="Add an association" drivers={free} onClose={() => setAdding(false)}
          onSave={(v) => act((c) => api.addAssociation(obj.guid, { driver: v.driver!, state: v.state, value: v.value }, c)).then(() => setAdding(false))} />
      )}
      {editing && (
        <AssociationModal title={`Association with ${editing.driver?.name ?? editing.driverDn}`} initial={{ state: (meta(editing.state)?.state ?? 'processed'), value: editing.value ?? '' }}
          onClose={() => setEditing(null)}
          onSave={(v) => act((c) => api.changeAssociation(obj.guid, { raw: editing.raw, state: v.state, value: v.value }, c)).then(() => setEditing(null))} />
      )}
      {confirmed.dialog}
      {sure.dialog}
    </div>
  );
}

function AssociationModal({ title, drivers, initial, onClose, onSave }: {
  title: string;
  /** Present when adding: the drivers to choose from. */
  drivers?: ObjectAssociations['drivers'];
  initial?: { state: AssociationState; value: string };
  onClose: () => void;
  onSave: (v: { driver?: string; state: AssociationState; value: string }) => Promise<unknown>;
}) {
  const [driver, setDriver] = useState('');
  const [state, setState] = useState<AssociationState>(initial?.state ?? 'manual');
  const [value, setValue] = useState(initial?.value ?? '');
  const [busy, setBusy] = useState(false);
  const sets = [...new Set((drivers ?? []).map((d) => d.driverSet.name))].sort();
  const valueChanged = initial && value !== initial.value;
  const save = () => {
    setBusy(true);
    onSave({ driver: driver || undefined, state, value }).finally(() => setBusy(false));
  };
  return (
    <Modal isOpen onClose={onClose} variant="small" aria-labelledby="assoc-title">
      <ModalHeader title={title} labelId="assoc-title" />
      <ModalBody>
        <Form id="assoc-form" onSubmit={(e) => { e.preventDefault(); save(); }}>
          {drivers && (
            <FormGroup label="Driver" fieldId="assoc-driver" isRequired>
              <FormSelect id="assoc-driver" value={driver} onChange={(_e, v) => setDriver(v)}>
                <FormSelectOption value="" label="Choose a driver" isPlaceholder />
                {sets.map((set) => (
                  <FormSelectOptionGroup key={set} label={set}>
                    {drivers.filter((d) => d.driverSet.name === set).map((d) => <FormSelectOption key={d.dn} value={d.guid ?? ''} label={d.name} />)}
                  </FormSelectOptionGroup>
                ))}
              </FormSelect>
            </FormGroup>
          )}
          <FormGroup label="State" fieldId="assoc-state">
            <FormSelect id="assoc-state" value={state} onChange={(_e, v) => setState(v as AssociationState)}>
              {STATES.map((s) => <FormSelectOption key={s.state} value={s.state} label={s.label} />)}
            </FormSelect>
            <FormHelperText><HelperText><HelperTextItem>{meta(state)?.help}</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          <FormGroup label="Association" fieldId="assoc-value">
            <TextInput id="assoc-value" className="dc-mono" value={value} onChange={(_e, v) => setValue(v)} />
            <FormHelperText><HelperText><HelperTextItem>The connected system's key for this object, as the driver writes it (a GUID, a DN, an employee number…).</HelperTextItem></HelperText></FormHelperText>
          </FormGroup>
          {valueChanged && (
            <Alert variant="warning" isInline isPlain title="The driver will match this object to whatever the new value names in the connected system." />
          )}
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="assoc-form" isLoading={busy} isDisabled={busy || (drivers !== undefined && !driver)}>Save</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}
