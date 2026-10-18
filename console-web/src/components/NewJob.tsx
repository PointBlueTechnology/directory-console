import { useEffect, useMemo, useState } from 'react';
import {
  Alert, Button, Checkbox, Flex, FlexItem, Form, FormGroup, FormHelperText, FormSelect, FormSelectOption, HelperText, HelperTextItem,
  Modal, ModalBody, ModalFooter, ModalHeader, Radio, Spinner, Switch, TextArea, TextInput,
} from '@patternfly/react-core';
import { type EdirServer, type Idm, type JobParameter, type JobScopeKind, type JobType, edir, idm } from '../api';
import { describeCron } from '../cron';
import { useSession } from '../session';
import { useConfirmed } from './Confirm';
import { ProblemAlert } from './Problem';

export const SCOPES: { value: JobScopeKind; label: string }[] = [
  { value: 'subtree', label: 'the object and everything under it' },
  { value: 'subordinates', label: 'the objects directly under it' },
  { value: 'entry', label: 'the object itself' },
  { value: 'members', label: "the group's members" },
];

export type Values = Record<string, string | string[]>;

/** Which parameters are in use: those at the top, and those under a parameter that is in use and has their active value. */
export function activeParameters(params: JobParameter[], values: Values): Set<string> {
  const on = new Set<string>();
  for (const p of params) {
    if (!p.parent || (on.has(p.parent) && String(values[p.parent]) === p.activeValue)) {
      on.add(p.name);
    }
  }
  return on;
}

export function ParameterInput({ p, value, onChange }: { p: JobParameter; value: string | string[]; onChange: (v: string | string[]) => void }) {
  const id = `job-param-${p.name}`;
  switch (p.type) {
    case 'boolean':
      return <Switch id={id} label={p.label} isChecked={value === 'true'} onChange={(_e, on) => onChange(on ? 'true' : 'false')} />;
    case 'enum':
      return (
        <FormSelect id={id} value={String(value)} onChange={(_e, v) => onChange(v)} aria-label={p.label}>
          {(p.choices ?? []).map((c) => <FormSelectOption key={c.value} value={c.value} label={c.label} />)}
        </FormSelect>
      );
    case 'list':
      return <TextArea id={id} aria-label={p.label} value={(value as string[]).join('\n')} onChange={(_e, v) => onChange(v.split('\n'))} resizeOrientation="vertical" />;
    default:
      return (
        <TextInput id={id} aria-label={p.label} value={String(value)} className={p.type.startsWith('dn') ? 'dc-mono' : undefined}
          type={p.type === 'integer' ? 'number' : 'text'} onChange={(_e, v) => onChange(v)} />
      );
  }
}

/** The objects a job works on: rows of a DN and which objects from it. */
export function ScopeEditor({ scope, setScope, required, disabled }: {
  scope: { dn: string; scope: JobScopeKind }[]; setScope: (s: { dn: string; scope: JobScopeKind }[]) => void; required: boolean; disabled?: boolean;
}) {
  return (
    <FormGroup label={required ? 'Objects (this job needs some)' : 'Objects'} fieldId="job-scope" role="group">
      {scope.map((s, i) => (
        <Flex key={i} alignItems={{ default: 'alignItemsCenter' }} flexWrap={{ default: 'wrap' }}>
          <FlexItem grow={{ default: 'grow' }}>
            <TextInput aria-label="Object DN" className="dc-mono" placeholder="ou=users,o=data" value={s.dn} isDisabled={disabled}
              onChange={(_e, v) => setScope(scope.map((x, j) => (j === i ? { ...x, dn: v } : x)))} />
          </FlexItem>
          <FlexItem>
            <FormSelect aria-label="Which objects" value={s.scope} isDisabled={disabled} onChange={(_e, v) => setScope(scope.map((x, j) => (j === i ? { ...x, scope: v as JobScopeKind } : x)))}>
              {SCOPES.map((o) => <FormSelectOption key={o.value} value={o.value} label={o.label} />)}
            </FormSelect>
          </FlexItem>
          {!disabled && <FlexItem><Button variant="link" isInline onClick={() => setScope(scope.filter((_x, j) => j !== i))}>Remove</Button></FlexItem>}
        </Flex>
      ))}
      {!disabled && <Button variant="link" isInline onClick={() => setScope([...scope, { dn: '', scope: 'subtree' }])}>Add objects</Button>}
      {scope.length === 0 && <FormHelperText><HelperText><HelperTextItem>No objects: the job runs once, not once per object.</HelperTextItem></HelperText></FormHelperText>}
    </FormGroup>
  );
}

/**
 * Set a job's named passwords on each server that runs it: each server's engine keeps its own. Answers the
 * servers it could not set them on, with why.
 */
export async function setJobPasswords(directory: string, job: string, servers: (string | undefined)[], entries: { name: string; label: string; value: string }[],
  confirm?: string): Promise<string[]> {
  const failed: string[] = [];
  for (const server of servers) {
    const on = idm(directory, server);
    for (const e of entries) {
      try {
        await on.setJobPassword(job, { name: e.name, displayName: e.label, value: e.value }, confirm);
      } catch (x) {
        failed.push(`${e.label}: ${x instanceof Error ? x.message : String(x)}`);
      }
    }
  }
  return failed;
}

/**
 * A new job under a driver or driver set, of a type the chosen server's engine offers: name, enabled,
 * schedule, servers, scope and the type's parameters (those under an option not chosen are hidden).
 * The job is written with the type's own definition and the values chosen.
 */
export function NewJobModal({ api, kind, guid, onClose, onCreated }: {
  api: Idm; kind: 'drivers' | 'driversets'; guid: string; onClose: () => void; onCreated: (name: string, notified: boolean) => void;
}) {
  const { me } = useSession();
  const { run, dialog } = useConfirmed();
  const [types, setTypes] = useState<JobType[] | null>(null);
  const [onServer, setOnServer] = useState<{ dn: string; name: string } | null>(null);
  const [allServers, setAllServers] = useState<EdirServer[]>([]);
  const [type, setType] = useState<JobType | null>(null);
  const [name, setName] = useState('');
  const [enabled, setEnabled] = useState(true);
  const [schedule, setSchedule] = useState('');
  const [servers, setServers] = useState<string[]>([]);
  const [scope, setScope] = useState<{ dn: string; scope: JobScopeKind }[]>([]);
  const [values, setValues] = useState<Values>({});
  const [secrets, setSecrets] = useState<Record<string, string>>({});
  const [partial, setPartial] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.jobTypes(kind, guid).then((r) => { setTypes(r.types); setOnServer(r.server); setServers([r.server.dn.toLowerCase()]); }, setError);
  }, [api, kind, guid]);
  useEffect(() => { edir(me.directory).servers().then(setAllServers).catch(() => setAllServers([])); }, [me.directory]);

  const choose = (t: JobType) => {
    setType(t);
    setSchedule(t.schedule ?? '');
    setValues(Object.fromEntries(t.parameters.map((p) => [p.name, p.value])));
    setScope(t.scopeRequired ? [{ dn: '', scope: 'subtree' }] : []);
  };
  const active = useMemo(() => (type ? activeParameters(type.parameters, values) : new Set<string>()), [type, values]);
  const cronOk = !schedule.trim() || schedule.trim().split(/\s+/).length === 5;
  const words = schedule.trim() ? describeCron(schedule) : null;
  const scopeOk = scope.every((s) => s.dn.trim()) && (!type?.scopeRequired || scope.length > 0);
  const ready = !!type && name.trim() !== '' && cronOk && servers.length > 0 && scopeOk;

  const create = () => {
    if (!type) {
      return;
    }
    // only what differs from the type's own values; a named password is never sent
    const changed: Values = {};
    for (const p of type.parameters) {
      const v = values[p.name];
      if (p.type !== 'password-ref' && JSON.stringify(p.type === 'list' ? (v as string[]).filter((x) => x.trim()) : v) !== JSON.stringify(p.value)) {
        changed[p.name] = p.type === 'list' ? (v as string[]).filter((x) => x.trim()) : v;
      }
    }
    const serverDns = allServers.length ? allServers.filter((s) => servers.includes(s.dn.toLowerCase())).map((s) => s.dn) : onServer ? [onServer.dn] : [];
    setBusy(true);
    setError(null);
    const toSet = passwords.filter((p) => secrets[p.name]).map((p) => ({ name: String(p.value), label: p.label, value: secrets[p.name] }));
    const serverGuids = allServers.length ? allServers.filter((s) => servers.includes(s.dn.toLowerCase())).map((s) => s.guid) : [undefined];
    run(async (c) => {
      const j = await api.createJob(kind, guid, {
        type: type.type, name: name.trim(), disabled: !enabled, schedule: schedule.trim() ? schedule.trim().replace(/\s+/g, ' ') : null,
        servers: serverDns, scope: scope.map((s) => ({ dn: s.dn.trim(), scope: s.scope })), parameters: changed,
      }, c);
      const failed = j.guid && toSet.length ? await setJobPasswords(me.directory, j.guid, serverGuids, toSet, c) : [];
      return { j, failed };
    }).then(({ j, failed }) => {
      if (failed.length) {
        // the job exists: say what is left to do rather than leave the form as if nothing happened
        setPartial(`The job ${j.name} was created, but its passwords were not all set (${failed.join('; ')}). Set them from the job.`);
        onCreated(j.name, j.notified);
      } else {
        onCreated(j.name, j.notified);
        onClose();
      }
    }, setError).finally(() => setBusy(false));
  };

  const passwords = type?.parameters.filter((p) => p.type === 'password-ref' && active.has(p.name)) ?? [];
  return (
    <Modal isOpen onClose={onClose} variant="medium" aria-labelledby="new-job-title">
      <ModalHeader title={type ? `New job: ${type.displayName}` : 'New job'} labelId="new-job-title"
        description={onServer ? `Job types offered by the engine on ${onServer.name}.` : undefined} />
      <ModalBody>
        {!types && !error && <Spinner size="md" aria-label="Reading the job types" />}
        {types && !type && (
          types.length === 0 ? <p>The engine offers no job types here.</p> : (
            <Form>
              <FormGroup label="Type of job" role="radiogroup" fieldId="job-type" isStack>
                {types.map((t) => (
                  <Radio key={t.type} id={`job-type-${t.type}`} name="job-type" label={t.displayName} description={t.description ?? undefined}
                    isChecked={false} onChange={() => choose(t)} />
                ))}
              </FormGroup>
            </Form>
          )
        )}
        {type && (
          <Form onSubmit={(e) => { e.preventDefault(); if (ready) create(); }}>
            <FormGroup label="Name" isRequired fieldId="job-name">
              <TextInput id="job-name" value={name} onChange={(_e, v) => setName(v)} autoFocus />
            </FormGroup>
            <Switch id="new-job-enabled" label="Enabled" isChecked={enabled} onChange={(_e, on) => setEnabled(on)} />
            <FormGroup label="Schedule" fieldId="new-job-schedule">
              <TextInput id="new-job-schedule" className="dc-mono" value={schedule} placeholder="none: runs only when started"
                validated={cronOk ? 'default' : 'error'} onChange={(_e, v) => setSchedule(v)} />
              <FormHelperText><HelperText><HelperTextItem variant={cronOk ? 'default' : 'error'}>
                {!cronOk ? 'Five fields: minute hour day-of-month month day-of-week, such as 0 2 * * 6.'
                  : !schedule.trim() ? 'No schedule: the job runs only when started.'
                    : `${words ?? 'A custom schedule'}, in each server's local time.`}
              </HelperTextItem></HelperText></FormHelperText>
            </FormGroup>
            <FormGroup label="Runs on" fieldId="new-job-servers" role="group" isRequired>
              {(allServers.length ? allServers : onServer ? [{ dn: onServer.dn, name: onServer.name, guid: 'on' } as EdirServer] : []).map((s) => (
                <Checkbox key={s.dn} id={`new-job-srv-${s.guid}`} label={s.name} isChecked={servers.includes(s.dn.toLowerCase())}
                  onChange={(_e, on) => setServers(on ? [...servers, s.dn.toLowerCase()] : servers.filter((d) => d !== s.dn.toLowerCase()))} />
              ))}
            </FormGroup>
            <ScopeEditor scope={scope} setScope={setScope} required={type.scopeRequired} />
            {type.parameters.filter((p) => active.has(p.name) && p.type !== 'password-ref').map((p) => (
              <FormGroup key={p.name} label={p.type === 'boolean' ? undefined : p.label} fieldId={`job-param-${p.name}`} style={{ marginLeft: `${p.depth * 1.5}rem` }}>
                <ParameterInput p={p} value={values[p.name]} onChange={(v) => setValues({ ...values, [p.name]: v })} />
                {p.description && <FormHelperText><HelperText><HelperTextItem>{p.description}</HelperTextItem></HelperText></FormHelperText>}
              </FormGroup>
            ))}
            {passwords.map((p) => (
              <FormGroup key={p.name} label={p.label} fieldId={`job-pw-${p.name}`} style={{ marginLeft: `${p.depth * 1.5}rem` }}>
                <TextInput id={`job-pw-${p.name}`} type="password" autoComplete="new-password" value={secrets[p.name] ?? ''}
                  onChange={(_e, v) => setSecrets({ ...secrets, [p.name]: v })} />
                <FormHelperText><HelperText><HelperTextItem>
                  {p.description ? `${p.description} ` : ''}Kept as the job's named password {String(p.value)} on each server it runs on; leave it empty to set it later.
                </HelperTextItem></HelperText></FormHelperText>
              </FormGroup>
            ))}
          </Form>
        )}
        <ProblemAlert error={error} />
        {partial && <Alert variant="warning" isInline title={partial} />}
        {dialog}
      </ModalBody>
      <ModalFooter>
        {type && !partial && <Button onClick={create} isLoading={busy} isDisabled={busy || !ready}>Create</Button>}
        {type && <Button variant="secondary" onClick={() => setType(null)}>Back</Button>}
        <Button variant="link" onClick={onClose}>Cancel</Button>
      </ModalFooter>
    </Modal>
  );
}
