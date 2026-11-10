import { useCallback, useEffect, useState } from 'react';
import {
  Alert, Button, Checkbox, DescriptionList, DescriptionListDescription, DescriptionListGroup, DescriptionListTerm, Form, FormGroup,
  FormHelperText, FormSelect, FormSelectOption, HelperText, HelperTextItem, Label, Modal, ModalBody, ModalFooter, ModalHeader, Radio,
  Spinner, TextArea, TextInput,
} from '@patternfly/react-core';
import { PlusIcon } from '@patternfly/react-icons';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type DriverRow, type WorkOrder, type WorkOrderDriver, type WorkOrderFields, idm } from '../api';
import { useSession } from '../session';
import { linkProps } from '../router';
import { useAreYouSure, useConfirmed } from './Confirm';
import { ProblemAlert } from './Problem';
import { StateLabel } from './IdmParts';

type Idm = ReturnType<typeof idm>;

const STATUS: Record<string, { label: string; color: 'blue' | 'grey' | 'green' | 'red' }> = {
  pending: { label: 'Pending', color: 'blue' },
  onhold: { label: 'On hold', color: 'grey' },
  configured: { label: 'Done', color: 'green' },
  error: { label: 'Error', color: 'red' },
};

function StatusLabel({ status }: { status: string | null | undefined }) {
  const s = status ? STATUS[status] : undefined;
  return s ? <Label isCompact color={s.color}>{s.label}</Label> : <span className="dc-subtle">{status ?? '—'}</span>;
}

const when = (w: WorkOrder) => (w.due ? new Date(w.due).toLocaleString() : w.now ? 'At the next poll' : '—');
const repeats = (m: string | null | undefined) => (!m || m === '0' ? 'Once' : `Every ${m} minute${m === '1' ? '' : 's'}`);

/** An ISO time as a datetime-local input's value, in the browser's time zone. */
function toLocal(iso: string | null | undefined): string {
  if (!iso) {
    return '';
  }
  const d = new Date(iso);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}
const fromLocal = (v: string) => (v ? new Date(v).toISOString() : null);

/**
 * A driver set's work orders: what its Work Order drivers will run and when, in the containers they poll. The driver
 * runs a due one at its next poll (every minute by default): it adds a WorkToDo object for the policies that act on it,
 * marks the work order done or in error, logs, and writes the time it ran as the due date.
 */
export function WorkOrdersPanel({ api, setGuid, drivers }: { api: Idm; setGuid: string; drivers: DriverRow[] }) {
  const { can } = useSession();
  const [state, setState] = useState<{ drivers: WorkOrderDriver[]; items: WorkOrder[] } | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const load = useCallback(() => { setError(null); api.workOrders(setGuid).then(setState, setError); }, [api, setGuid]);
  useEffect(load, [load]);

  if (!state) {
    return <div className="dc-tab-body">{error ? <ProblemAlert error={error} onRetry={load} /> : <Spinner size="md" aria-label="Reading work orders" />}</div>;
  }
  if (state.drivers.length === 0) {
    return (
      <div className="dc-tab-body">
        <p className="dc-subtle">This driver set has no Work Order driver. Work orders are run by one: it polls a container for work orders that are due.</p>
      </div>
    );
  }
  const containers = [...new Set(state.drivers.map((d) => d.container))];
  return (
    <div className="dc-tab-body">
      {state.drivers.map((d) => {
        const row = drivers.find((r) => r.dn.toLowerCase() === d.dn.toLowerCase());
        const running = row?.state.toLowerCase() === 'running';
        return (
          <div key={d.dn} className="dc-tab-body">
            {d.guid ? <a {...linkProps(`/idm/drivers/${d.guid}`)}>{d.name}</a> : d.name} {row && <StateLabel state={row.state} />}
            {' '}polls <span className="dc-mono">{d.container}</span>
            {d.containerFrom === 'driver' && <span className="dc-subtle"> (no container GCV, so it polls the driver object itself)</span>}
            {d.containerFrom === 'gcv-unresolved' && (
              <Alert variant="warning" isInline isPlain title={`Its idv.workorder.container GCV names ${d.gcv}, which is not in the tree; the driver finds no work orders there.`} />
            )}
            {row && !running && <Alert variant="info" isInline isPlain title="It is not running: due work orders wait until it runs." />}
          </div>
        );
      })}
      {can('operator') && <Button variant="secondary" size="sm" icon={<PlusIcon />} onClick={() => setCreating(true)}>New work order</Button>}
      {state.items.length === 0 ? <p className="dc-subtle dc-tab-body">No work orders.</p> : (
        <Table aria-label="Work orders" variant="compact" className="dc-tab-body">
          <Thead><Tr><Th>Work order</Th><Th>Status</Th><Th>When</Th><Th>Repeats</Th><Th>Description</Th></Tr></Thead>
          <Tbody>
            {state.items.map((w) => (
              <Tr key={w.dn}>
                <Td dataLabel="Work order"><Button variant="link" isInline onClick={() => setOpen(w.guid)}>{w.name}</Button></Td>
                <Td dataLabel="Status"><StatusLabel status={w.status} /></Td>
                <Td dataLabel="When">{when(w)}</Td>
                <Td dataLabel="Repeats">{repeats(w.repeatMinutes)}</Td>
                <Td dataLabel="Description">{w.description ?? ''}</Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}
      {open && <WorkOrderEditor api={api} setGuid={setGuid} guid={open} others={state.items} onClose={() => setOpen(null)} onChanged={load} />}
      {creating && <WorkOrderEditor api={api} setGuid={setGuid} containers={containers} others={state.items} onClose={() => setCreating(false)} onChanged={load} />}
    </div>
  );
}

/** One work order's fields, its driver's log and its WorkToDo objects; with {@code containers} instead of {@code guid}, a new one. */
function WorkOrderEditor({ api, setGuid, guid, containers, others, onClose, onChanged }: {
  api: Idm; setGuid: string; guid?: string; containers?: string[]; others: WorkOrder[]; onClose: () => void; onChanged: () => void;
}) {
  const { can, tree } = useSession();
  const operator = can('operator');
  const { run, dialog } = useConfirmed();
  const sure = useAreYouSure();
  const creating = !guid;
  const [wo, setWo] = useState<WorkOrder | null>(null);
  const [name, setName] = useState('');
  const [container, setContainer] = useState(containers?.[0] ?? '');
  const [f, setF] = useState<WorkOrderFields>(creating ? { status: 'pending', now: true, repeatMinutes: '0', dependents: [] } : {});
  const [at, setAt] = useState('');
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const take = (w: WorkOrder) => {
    setWo(w);
    setF({
      description: w.description, status: w.status, now: !!w.now && !w.due, due: w.due, deleteDate: w.deleteDate, repeatMinutes: w.repeatMinutes ?? '0',
      deleteOnError: w.deleteOnError, dependents: w.dependents ?? [], type: w.type, number: w.number, contact: w.contact, content: w.content,
    });
    setAt(toLocal(w.due));
    setDirty(false);
  };
  const reload = useCallback(() => { if (guid) { api.workOrder(guid).then(take, setError); } }, [api, guid]);
  useEffect(reload, [reload]);

  const set = (patch: WorkOrderFields) => { setF({ ...f, ...patch }); setDirty(true); setNotice(null); };
  const text = (k: 'description' | 'type' | 'number' | 'contact', label: string) => (
    <FormGroup label={label} fieldId={`wo-${k}`}>
      <TextInput id={`wo-${k}`} value={f[k] ?? ''} isDisabled={!operator} onChange={(_e, v) => set({ [k]: v })} />
    </FormGroup>
  );
  const minutes = f.repeatMinutes ?? '';
  const problem = creating && !name.trim() ? 'The work order needs a name.'
    : !/^\d+$/.test(minutes) ? 'Repeat every must be a whole number of minutes; 0 runs it once.'
      : !f.now && !at ? 'Say when it runs: at the next poll, or at a time.' : null;
  const statuses = ['pending', 'onhold', ...(f.status && !['pending', 'onhold'].includes(f.status) ? [f.status] : [])];
  const candidates = others.filter((o) => o.guid !== guid);

  const body = (): WorkOrderFields => ({
    ...f,
    now: !!f.now,
    due: f.now ? null : fromLocal(at),
    dependents: (f.dependents ?? []).map((d) => ({ dn: d.dn })),
  });
  const save = () => {
    setBusy(true);
    setError(null);
    const op = creating
      ? run((c) => api.createWorkOrder(setGuid, { name: name.trim(), container: containers && containers.length > 1 ? container : undefined, ...body() }, c))
      : run((c) => api.saveWorkOrder(guid!, { version: wo!.version!, ...body() }, c));
    op.then((w) => { onChanged(); if (creating) { onClose(); } else { take(w); setNotice('Saved. The driver picks it up at its next poll.'); } }, setError)
      .finally(() => setBusy(false));
  };
  const remove = () => {
    setBusy(true);
    run((c) => api.deleteWorkOrder(guid!, c)).then(() => { onChanged(); onClose(); }, setError).finally(() => setBusy(false));
  };
  const removeTodo = (todo: string) => {
    setError(null);
    tree.read(todo).then((r) => tree.remove(todo, r.etag ?? '*')).then(reload, setError);
  };

  const last = wo?.log.length ? wo.log[wo.log.length - 1] : null;
  return (
    <Modal isOpen onClose={onClose} variant="medium" aria-labelledby="wo-title">
      <ModalHeader title={creating ? 'New work order' : wo?.name ?? 'Work order'} labelId="wo-title"
        description={wo ? <span className="dc-mono">{wo.container}</span> : undefined} />
      <ModalBody>
        {!creating && !wo && !error && <Spinner size="md" aria-label="Reading the work order" />}
        {(creating || wo) && (
          <>
            {wo?.status === 'error' && <Alert variant="danger" isInline isPlain className="dc-tab-body" title={`The driver could not run it${last ? `: ${last.replace(/^-+/, '').trim()}` : '.'}`} />}
            {wo && (wo.todos?.length ?? 0) > 0 && (
              <Alert variant="info" isInline className="dc-tab-body" title="The driver's WorkToDo for its last run is still there">
                <p>The policies that act on work orders work from it. While it is there, running this work order again fails: whatever acts on it usually removes it.</p>
                {wo.todos!.map((t) => (
                  <div key={t.guid}>
                    <span className="dc-mono">{t.name}</span>{t.type ? <span className="dc-subtle"> ({t.type})</span> : null}
                    {operator && <> <Button variant="link" isInline isDanger onClick={() => sure.ask(`Remove ${t.name}?`, 'The policies that act on it won\'t see it.', 'Remove', () => removeTodo(t.guid))}>Remove</Button></>}
                  </div>
                ))}
              </Alert>
            )}
            <Form onSubmit={(e) => e.preventDefault()}>
              {creating && (
                <FormGroup label="Name" isRequired fieldId="wo-name">
                  <TextInput id="wo-name" value={name} onChange={(_e, v) => { setName(v); setDirty(true); }} />
                </FormGroup>
              )}
              {creating && containers && containers.length > 1 && (
                <FormGroup label="Container" fieldId="wo-container">
                  <FormSelect id="wo-container" value={container} onChange={(_e, v) => setContainer(v)}>
                    {containers.map((c) => <FormSelectOption key={c} value={c} label={c} />)}
                  </FormSelect>
                </FormGroup>
              )}
              {text('description', 'Description')}
              <FormGroup label="Status" fieldId="wo-status">
                <FormSelect id="wo-status" value={f.status ?? 'pending'} isDisabled={!operator} onChange={(_e, v) => set({ status: v })}>
                  {statuses.map((s) => <FormSelectOption key={s} value={s} label={STATUS[s]?.label ?? s} isDisabled={!['pending', 'onhold'].includes(s)} />)}
                </FormSelect>
                <FormHelperText><HelperText><HelperTextItem>Pending runs when due; on hold waits. The driver marks it done or in error when it runs it.</HelperTextItem></HelperText></FormHelperText>
              </FormGroup>
              <FormGroup role="radiogroup" label="Runs" fieldId="wo-when" isInline>
                <Radio id="wo-now" name="wo-when" label="At the driver's next poll" isChecked={!!f.now} isDisabled={!operator} onChange={() => set({ now: true })} />
                <Radio id="wo-at" name="wo-when" label="At" isChecked={!f.now} isDisabled={!operator} onChange={() => set({ now: false })} />
                <TextInput type="datetime-local" aria-label="Run at" value={at} isDisabled={!operator || !!f.now}
                  onChange={(_e, v) => { setAt(v); setDirty(true); }} style={{ maxWidth: '16rem' }} />
              </FormGroup>
              <FormGroup label="Repeat every (minutes)" fieldId="wo-repeat">
                <TextInput id="wo-repeat" type="number" min={0} value={minutes} isDisabled={!operator} onChange={(_e, v) => set({ repeatMinutes: v })} style={{ maxWidth: '10rem' }} />
                <FormHelperText><HelperText><HelperTextItem>0 runs it once. After each run the driver moves the due date on by this much.</HelperTextItem></HelperText></FormHelperText>
              </FormGroup>
              <FormGroup label="Content" fieldId="wo-content">
                <TextArea id="wo-content" className="dc-mono" rows={5} value={f.content ?? ''} isDisabled={!operator} onChange={(_e, v) => set({ content: v })} />
                <FormHelperText><HelperText><HelperTextItem>What the work is: the driver copies it to the WorkToDo object for the policies that act on it.</HelperTextItem></HelperText></FormHelperText>
              </FormGroup>
              {text('type', 'Type')}
              {text('number', 'Number')}
              {text('contact', 'Contact')}
              <FormGroup label="Delete at" fieldId="wo-delete">
                <TextInput type="datetime-local" id="wo-delete" aria-label="Delete at" value={toLocal(f.deleteDate)} isDisabled={!operator}
                  onChange={(_e, v) => set({ deleteDate: fromLocal(v) })} style={{ maxWidth: '16rem' }} />
                <Checkbox id="wo-delete-error" label="Even after an error" isChecked={!!f.deleteOnError} isDisabled={!operator}
                  onChange={(_e, v) => set({ deleteOnError: v })} />
              </FormGroup>
              {candidates.length > 0 && (
                <FormGroup label="Waits for" fieldId="wo-deps">
                  {candidates.map((o) => (
                    <Checkbox key={o.guid} id={`wo-dep-${o.guid}`} label={o.name} isDisabled={!operator}
                      isChecked={(f.dependents ?? []).some((d) => d.dn.toLowerCase() === o.dn.toLowerCase())}
                      onChange={(_e, v) => set({ dependents: v ? [...(f.dependents ?? []), { dn: o.dn, name: o.name }] : (f.dependents ?? []).filter((d) => d.dn.toLowerCase() !== o.dn.toLowerCase()) })} />
                  ))}
                </FormGroup>
              )}
            </Form>
            {wo && (
              <DescriptionList isHorizontal isCompact className="dc-tab-body">
                {wo.created && <DescriptionListGroup><DescriptionListTerm>Created</DescriptionListTerm><DescriptionListDescription>{new Date(wo.created).toLocaleString()}{wo.creator ? ` by ${wo.creator}` : ''}</DescriptionListDescription></DescriptionListGroup>}
                <DescriptionListGroup>
                  <DescriptionListTerm>Driver's log</DescriptionListTerm>
                  <DescriptionListDescription>{wo.log.length === 0 ? <span className="dc-subtle">Not run yet.</span> : wo.log.map((l, i) => <div key={i} className="dc-mono">{l.trim()}</div>)}</DescriptionListDescription>
                </DescriptionListGroup>
              </DescriptionList>
            )}
            {problem && dirty && <Alert variant="danger" isInline isPlain className="dc-tab-body" title={problem} />}
            {notice && <Alert variant="success" isInline isPlain className="dc-tab-body" title={notice} />}
          </>
        )}
        <ProblemAlert error={error} />
        {dialog}
        {sure.dialog}
      </ModalBody>
      <ModalFooter>
        {operator && (creating || wo) && <Button onClick={save} isLoading={busy} isDisabled={busy || !dirty || !!problem}>{creating ? 'Create' : 'Save'}</Button>}
        {operator && wo && (
          <Button variant="link" isDanger isDisabled={busy} onClick={() => sure.ask(`Delete ${wo.name}?`, 'The driver will not run it again. Its WorkToDo objects stay.', 'Delete', remove)}>Delete</Button>
        )}
        <Button variant="link" onClick={onClose}>{dirty ? 'Close without saving' : 'Close'}</Button>
      </ModalFooter>
    </Modal>
  );
}
