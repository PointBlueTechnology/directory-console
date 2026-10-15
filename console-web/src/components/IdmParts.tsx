import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Alert, Button, Form, FormGroup, FormSelect, FormSelectOption, Label, Modal, ModalBody, ModalFooter, ModalHeader, Spinner, TextInput,
  Toolbar, ToolbarContent, ToolbarItem,
} from '@patternfly/react-core';
import { PlusIcon } from '@patternfly/react-icons';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type Idm, type Job, type PasswordKind } from '../api';
import { useSession } from '../session';
import { useHeading } from '../heading';
import { ProblemAlert } from './Problem';
import { useConfirmed } from './Confirm';
import { JobDetailsModal } from './JobDetails';
import { NewJobModal } from './NewJob';

/** A driver's state as a coloured label. */
export function StateLabel({ state }: { state: string }) {
  const s = state.toLowerCase();
  const color = s === 'running' ? 'green' : s === 'stopped' ? 'grey' : s.includes('start') || s.includes('stop') ? 'blue' : 'orange';
  return <Label color={color} isCompact>{state}</Label>;
}

/** Jobs of a driver or driver set, each startable and abortable by an operator. */
export function JobsTable({ api, load, owner }: { api: Idm; load: () => Promise<{ jobs: Job[] }>; owner?: { kind: 'drivers' | 'driversets'; guid: string } }) {
  const level = useHeading();
  const { can, tree } = useSession();
  const { run, dialog } = useConfirmed();
  const [jobs, setJobs] = useState<Job[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  // callers pass an inline loader; load once per mount, not on every parent render
  const loader = useRef(load);
  loader.current = load;
  const refresh = useCallback(() => { loader.current().then((r) => setJobs(r.jobs)).catch(setError); }, []);
  useEffect(refresh, [refresh]);

  const act = async (j: Job, action: 'start' | 'abort') => {
    setError(null);
    try {
      const guid = (await tree.resolve(j.dn)).data.guid;
      await run((c) => api.job(guid, action, c));
      setNotice(`${j.name}: ${action === 'start' ? 'started' : 'aborted'}`);
      refresh();
    } catch (e) {
      setError(e);
    }
  };

  if (!jobs) {
    return error ? <ProblemAlert error={error} /> : <Spinner size="md" aria-label="Loading jobs" />;
  }
  return (
    <div className="dc-tab-body">
      {notice && <Alert component={level} variant="success" isInline isPlain title={notice} />}
      <ProblemAlert error={error} />
      {owner && can('operator') && <Button variant="secondary" size="sm" className="dc-gap-bottom" onClick={() => setCreating(true)}>New job</Button>}
      {jobs.length === 0 ? <p className="dc-subtle">No jobs.</p> : (
        <Table aria-label="Jobs" variant="compact">
          <Thead><Tr><Th>Job</Th><Th>Owner</Th><Th>Running</Th><Th>Scheduled</Th><Th>Next run</Th>{can('operator') && <Th screenReaderText="Actions" />}</Tr></Thead>
          <Tbody>
            {jobs.map((j) => (
              <Tr key={j.dn}>
                <Td dataLabel="Job"><Button variant="link" isInline onClick={() => tree.resolve(j.dn).then((r) => setOpen(r.data.guid), setError)}>{j.name}</Button>{' '}{j.disabled && <Label isCompact>disabled</Label>}<div className="dc-subtle dc-mono">{j.javaClass.replace(/^com\.novell\.nds\.dirxml\.job\./, '')}</div></Td>
                <Td dataLabel="Owner">{j.owner}</Td>
                <Td dataLabel="Running">{j.running}</Td>
                <Td dataLabel="Scheduled">{j.scheduled}</Td>
                <Td dataLabel="Next run">{j.nextRun ? new Date(j.nextRun).toLocaleString() : '—'}</Td>
                {can('operator') && (
                  <Td isActionCell>
                    <Button variant="link" isInline isDisabled={j.disabled} onClick={() => act(j, 'start')}>Run now</Button>{' '}
                    <Button variant="link" isInline isDanger onClick={() => act(j, 'abort')}>Abort</Button>
                  </Td>
                )}
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}
      {open && <JobDetailsModal api={api} guid={open} onClose={() => setOpen(null)} onChanged={refresh} />}
      {creating && owner && (
        <NewJobModal api={api} kind={owner.kind} guid={owner.guid} onClose={() => setCreating(false)}
          onCreated={(name, notified) => { setNotice(`${name}: created${notified ? '' : '; the engine schedules it when it next reads its jobs'}`); refresh(); }} />
      )}
      {dialog}
    </div>
  );
}

const KIND_LABEL: Record<PasswordKind, string> = {
  named: 'Named password', 'remote-loader': 'Remote Loader password', key: 'Mutual authentication key password', keystore: 'Mutual authentication keystore password',
};

/** Named passwords (and, on a driver, the Remote Loader and mutual-authentication passwords): set or remove, never shown. */
export function PasswordsPanel({ api, kind, guid }: { api: Idm; kind: 'drivers' | 'driversets'; guid: string }) {
  const level = useHeading();
  const { can } = useSession();
  const { run, dialog } = useConfirmed();
  const [named, setNamed] = useState<string[] | null>(null);
  const [setting, setSetting] = useState<PasswordKind | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const refresh = useCallback(() => { api.passwords(kind, guid).then((r) => setNamed(r.named)).catch(setError); }, [api, kind, guid]);
  useEffect(refresh, [refresh]);
  const operator = can('operator');

  const remove = async (k: PasswordKind, name?: string) => {
    setError(null);
    try {
      await run((c) => api.removePassword(kind, guid, { kind: k, name }, c));
      setNotice(name ? `Removed ${name}.` : `${KIND_LABEL[k]} cleared.`);
      refresh();
    } catch (e) {
      setError(e);
    }
  };

  return (
    <div className="dc-tab-body">
      <Alert component={level} variant="info" isInline isPlain title="Passwords are written to the engine and can never be read back here." />
      {operator && (
        <Toolbar>
          <ToolbarContent>
            <ToolbarItem><Button variant="secondary" icon={<PlusIcon />} onClick={() => setSetting('named')}>Set a named password</Button></ToolbarItem>
            {kind === 'drivers' && (['remote-loader', 'key', 'keystore'] as PasswordKind[]).map((k) => (
              <ToolbarItem key={k}><Button variant="link" onClick={() => setSetting(k)}>Set the {KIND_LABEL[k].toLowerCase()}</Button></ToolbarItem>
            ))}
          </ToolbarContent>
        </Toolbar>
      )}
      {notice && <Alert component={level} variant="success" isInline isPlain title={notice} />}
      <ProblemAlert error={error} />
      {!named ? <Spinner size="md" aria-label="Loading" /> : named.length === 0 ? <p className="dc-subtle">No named passwords.</p> : (
        <Table aria-label="Named passwords" variant="compact">
          <Thead><Tr><Th>Named password</Th>{operator && <Th screenReaderText="Remove" />}</Tr></Thead>
          <Tbody>
            {named.map((n) => (
              <Tr key={n}>
                <Td dataLabel="Named password"><span className="dc-mono">{n}</span></Td>
                {operator && <Td isActionCell><Button variant="link" isInline isDanger onClick={() => remove('named', n)}>Remove</Button></Td>}
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}
      {operator && kind === 'drivers' && (
        <p className="dc-tab-body">
          {(['remote-loader', 'key', 'keystore'] as PasswordKind[]).map((k) => (
            <Button key={k} variant="link" isInline isDanger onClick={() => remove(k)} className="dc-gap-right">Clear the {KIND_LABEL[k].toLowerCase()}</Button>
          ))}
        </p>
      )}
      {setting && (
        <SetPasswordModal kindLabel={KIND_LABEL[setting]} named={setting === 'named'} onClose={() => setSetting(null)}
          onSave={async (name, value) => {
            await run((c) => api.setPassword(kind, guid, { kind: setting, name: setting === 'named' ? name : undefined, value }, c));
            setSetting(null);
            setNotice(`${setting === 'named' ? name : KIND_LABEL[setting]} set.`);
            refresh();
          }} />
      )}
      {dialog}
    </div>
  );
}

function SetPasswordModal({ kindLabel, named, onClose, onSave }: { kindLabel: string; named: boolean; onClose: () => void; onSave: (name: string, value: string) => Promise<void> }) {
  const [name, setName] = useState('');
  const [value, setValue] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      await onSave(name.trim(), value);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal isOpen onClose={onClose} variant="small" aria-labelledby="np-title">
      <ModalHeader title={`Set ${kindLabel.toLowerCase()}`} labelId="np-title" />
      <ModalBody>
        <Form id="np-form" onSubmit={(e) => { e.preventDefault(); save(); }}>
          {named && (
            <FormGroup label="Name" fieldId="np-name" isRequired>
              <TextInput id="np-name" value={name} onChange={(_e, v) => setName(v)} autoFocus />
            </FormGroup>
          )}
          <FormGroup label="Value" fieldId="np-value" isRequired>
            <TextInput id="np-value" type="password" autoComplete="new-password" value={value} onChange={(_e, v) => setValue(v)} autoFocus={!named} />
          </FormGroup>
          <ProblemAlert error={error} />
        </Form>
      </ModalBody>
      <ModalFooter>
        <Button variant="primary" type="submit" form="np-form" isLoading={busy} isDisabled={busy || !value || (named && !name.trim())}>Set</Button>
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}

export const LOG_LEVELS: { value: number; label: string }[] = [
  { value: 3, label: 'Off' },
  { value: 0, label: 'Errors' },
  { value: 1, label: 'Errors and warnings' },
  { value: 2, label: 'Only update the last log time' },
];

/** The log level of a driver (or "use the driver set's") or of a driver set. */
export function LogLevelPanel({ load, save }: {
  load: () => Promise<{ inherits?: boolean; level: number | null; levelName: string; limit: number | null }>;
  save?: (level: number | null) => Promise<unknown>;
}) {
  const level = useHeading();
  const { can } = useSession();
  const [current, setCurrent] = useState<{ inherits?: boolean; level: number | null; levelName: string; limit: number | null } | null>(null);
  const [choice, setChoice] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const loader = useRef(load);
  loader.current = load;
  const refresh = useCallback(() => {
    loader.current().then((r) => { setCurrent(r); setChoice(r.inherits ? 'inherit' : String(r.level ?? '')); }).catch(setError);
  }, []);
  useEffect(refresh, [refresh]);
  if (!current) {
    return error ? <ProblemAlert error={error} /> : <Spinner size="md" aria-label="Loading" />;
  }
  return (
    <Form className="dc-tab-body" onSubmit={async (e) => {
      e.preventDefault();
      setError(null);
      try {
        await save!(choice === 'inherit' ? null : Number(choice));
        setNotice('Saved.');
        refresh();
      } catch (x) {
        setError(x);
      }
    }}>
      <FormGroup label="Log level" fieldId="log-level">
        <FormSelect id="log-level" value={choice} onChange={(_e, v) => setChoice(v)} isDisabled={!save || !can('operator')}>
          {current.inherits !== undefined && <FormSelectOption value="inherit" label="Use the driver set's level" />}
          {LOG_LEVELS.map((l) => <FormSelectOption key={l.value} value={String(l.value)} label={l.label} />)}
          {current.level !== null && !LOG_LEVELS.some((l) => l.value === current.level) && <FormSelectOption value={String(current.level)} label={current.levelName} />}
        </FormSelect>
      </FormGroup>
      {current.limit !== null && <p className="dc-subtle">Keeps up to {current.limit} entries.</p>}
      {notice && <Alert component={level} variant="success" isInline isPlain title={notice} />}
      <ProblemAlert error={error} />
      {save && can('operator') && <div><Button type="submit" variant="primary">Save</Button></div>}
    </Form>
  );
}
