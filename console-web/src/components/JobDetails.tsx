import { useEffect, useMemo, useState } from 'react';
import {
  Alert, Button, Checkbox, DescriptionList, DescriptionListDescription, DescriptionListGroup, DescriptionListTerm, Form, FormGroup, FormHelperText,
  Flex, FlexItem, HelperText, HelperTextItem, Modal, ModalBody, ModalFooter, ModalHeader, Spinner, Switch, TextInput,
} from '@patternfly/react-core';
import { type EdirServer, type Idm, type JobDefinition, type JobScopeKind, edir, idm } from '../api';
import { describeCron } from '../cron';
import { useSession } from '../session';
import { useConfirmed } from './Confirm';
import { ProblemAlert } from './Problem';
import { ParameterInput, ScopeEditor, type Values, activeParameters, setJobPasswords } from './NewJob';

type Scope = { dn: string; scope: JobScopeKind }[];
const listed = (v: string | string[]) => (Array.isArray(v) ? v.map((x) => x.trim()).filter(Boolean) : v);
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

function Item({ term, children }: { term: string; children: React.ReactNode }) {
  return <DescriptionListGroup><DescriptionListTerm>{term}</DescriptionListTerm><DescriptionListDescription>{children}</DescriptionListDescription></DescriptionListGroup>;
}

/**
 * A job: what it is, and for an operator its enabled state, schedule, servers, objects and parameters, then
 * Save; its named passwords, set on each server that runs it; or Delete, with the job's name typed.
 */
export function JobDetailsModal({ api, guid, onClose, onChanged }: { api: Idm; guid: string; onClose: () => void; onChanged: () => void }) {
  const { me, can } = useSession();
  const { run, dialog } = useConfirmed();
  const [job, setJob] = useState<JobDefinition | null>(null);
  const [servers, setServers] = useState<EdirServer[]>([]);
  const [disabled, setDisabled] = useState(false);
  const [schedule, setSchedule] = useState('');
  const [chosen, setChosen] = useState<string[]>([]);
  const [values, setValues] = useState<Values>({});
  const [scope, setScope] = useState<Scope>([]);
  const [secrets, setSecrets] = useState<Record<string, string>>({});
  const [held, setHeld] = useState<Record<string, string[] | null>>({});
  const [notice, setNotice] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [typed, setTyped] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const operator = can('operator');

  const take = (j: JobDefinition) => {
    setJob(j);
    setDisabled(!!j.disabled);
    setSchedule(j.schedule ?? '');
    setChosen(j.servers.map((s) => s.dn.toLowerCase()));
    setValues(Object.fromEntries((j.parameters ?? []).map((p) => [p.name, p.value])));
    setScope(j.scope.map((x) => ({ dn: x.dn ?? x.raw, scope: (x.scope ?? 'subtree') as JobScopeKind })));
  };
  // a scope value the console cannot read is shown, not offered for editing
  const scopeReadable = !!job && job.scope.every((x) => x.dn && x.scope);
  useEffect(() => { api.jobDefinition(guid).then(take, setError); }, [api, guid]);
  useEffect(() => { edir(me.directory).servers().then(setServers).catch(() => setServers([])); }, [me.directory]);

  // each server that runs the job keeps its own copy of the job's named passwords
  const runsOn = useMemo(() => (job ? job.servers.map((js) => servers.find((s) => s.dn.toLowerCase() === js.dn.toLowerCase()) ?? { ...js, guid: undefined }) : []), [job, servers]);
  const readHeld = () => {
    for (const s of runsOn) {
      idm(me.directory, s.guid).jobPasswords(guid).then((n) => setHeld((h) => ({ ...h, [s.dn]: n })), () => setHeld((h) => ({ ...h, [s.dn]: null })));
    }
  };
  useEffect(readHeld, [runsOn, me.directory, guid]); // eslint-disable-line react-hooks/exhaustive-deps

  const changes = useMemo(() => {
    if (!job) {
      return {};
    }
    const c: { disabled?: boolean; schedule?: string | null; servers?: string[]; parameters?: Values; scope?: Scope } = {};
    if (disabled !== !!job.disabled) {
      c.disabled = disabled;
    }
    if (schedule.trim().replace(/\s+/g, ' ') !== (job.schedule ?? '')) {
      c.schedule = schedule.trim() ? schedule.trim().replace(/\s+/g, ' ') : null;
    }
    const before = job.servers.map((s) => s.dn.toLowerCase()).sort().join('|');
    if ([...chosen].sort().join('|') !== before) {
      c.servers = servers.filter((s) => chosen.includes(s.dn.toLowerCase())).map((s) => s.dn);
    }
    const params: Values = {};
    for (const p of job.parameters ?? []) {
      if (p.type !== 'password-ref' && values[p.name] !== undefined && !same(listed(values[p.name]), listed(p.value))) {
        params[p.name] = listed(values[p.name]);
      }
    }
    if (Object.keys(params).length > 0) {
      c.parameters = params;
    }
    const tidy = scope.map((x) => ({ dn: x.dn.trim(), scope: x.scope }));
    if (scopeReadable && !same(tidy, job.scope.map((x) => ({ dn: x.dn, scope: x.scope })))) {
      c.scope = tidy;
    }
    return c;
  }, [job, disabled, schedule, chosen, servers, values, scope, scopeReadable]);
  const active = useMemo(() => activeParameters(job?.parameters ?? [], values), [job, values]);
  const passwords = (job?.parameters ?? []).filter((p) => p.type === 'password-ref' && active.has(p.name));
  const scopeOk = scope.every((x) => x.dn.trim()) && (!job?.scopeRequired || scope.length > 0);
  const cronOk = !schedule.trim() || schedule.trim().split(/\s+/).length === 5;
  const words = schedule.trim() ? describeCron(schedule) : null;

  const save = () => {
    setBusy(true);
    setError(null);
    setNotice(null);
    run((c) => api.changeJob(guid, { version: job!.version, ...changes }, c)).then((j) => { take(j); onChanged(); }, setError).finally(() => setBusy(false));
  };
  const setPassword = (name: string, label: string, key: string) => {
    setBusy(true);
    setError(null);
    setNotice(null);
    run((c) => setJobPasswords(me.directory, guid, runsOn.map((s) => s.guid), [{ name, label, value: secrets[key] }], c)).then((failed) => {
      setSecrets({ ...secrets, [key]: '' });
      setNotice(failed.length ? null : `${label} is set on ${runsOn.map((s) => s.name).join(' and ')}.`);
      if (failed.length) {
        setError(new Error(failed.join('; ')));
      }
      readHeld();
    }, setError).finally(() => setBusy(false));
  };
  const remove = () => {
    setBusy(true);
    setError(null);
    run((c) => api.deleteJob(guid, typed, c)).then(() => { onChanged(); onClose(); }, setError).finally(() => setBusy(false));
  };

  return (
    <Modal isOpen onClose={onClose} variant="medium" aria-labelledby="job-title">
      <ModalHeader title={job ? job.name : 'Job'} labelId="job-title" description={job?.displayName} />
      <ModalBody>
        {!job && !error && <Spinner size="md" aria-label="Reading the job" />}
        {job && (
          <>
            <DescriptionList isHorizontal isCompact>
              <Item term="Owner">{job.owner.name} <span className="dc-subtle">({job.owner.kind})</span></Item>
              {job.description && <Item term="Does">{job.description}</Item>}
              {job.javaClass && <Item term="Class"><span className="dc-mono">{job.javaClass}</span></Item>}
              {!scopeReadable && (
                <Item term="Objects">
                  {job.scope.map((x) => <div key={x.raw} className="dc-mono">{x.raw}</div>)}
                </Item>
              )}
            </DescriptionList>
            <Form className="dc-tab-body" onSubmit={(e) => { e.preventDefault(); save(); }}>
              <Switch id="job-enabled" label="Enabled" isChecked={!disabled} isDisabled={!operator} onChange={(_e, on) => setDisabled(!on)} />
              <FormGroup label="Schedule" fieldId="job-schedule">
                <TextInput id="job-schedule" className="dc-mono" value={schedule} isDisabled={!operator} placeholder="none: runs only when started"
                  validated={cronOk ? 'default' : 'error'} onChange={(_e, v) => setSchedule(v)} />
                <FormHelperText><HelperText><HelperTextItem variant={cronOk ? 'default' : 'error'}>
                  {!cronOk ? 'Five fields: minute hour day-of-month month day-of-week, such as 0 2 * * 6.'
                    : !schedule.trim() ? 'No schedule: the job runs only when started.'
                      : `${words ?? 'A custom schedule'}, in each server's local time.`}
                </HelperTextItem></HelperText></FormHelperText>
              </FormGroup>
              <FormGroup label="Runs on" fieldId="job-servers" role="group">
                {servers.length === 0 ? job.servers.map((s) => <div key={s.dn}>{s.name}</div>) : servers.map((s) => (
                  <Checkbox key={s.dn} id={`job-srv-${s.guid}`} label={s.name} isDisabled={!operator} isChecked={chosen.includes(s.dn.toLowerCase())}
                    onChange={(_e, on) => setChosen(on ? [...chosen, s.dn.toLowerCase()] : chosen.filter((d) => d !== s.dn.toLowerCase()))} />
                ))}
              </FormGroup>
              {scopeReadable && <ScopeEditor scope={scope} setScope={setScope} required={!!job.scopeRequired} disabled={!operator} />}
              {(job.parameters ?? []).filter((p) => active.has(p.name) && p.type !== 'password-ref').map((p) => (
                <FormGroup key={p.name} label={p.type === 'boolean' ? undefined : p.label} fieldId={`job-param-${p.name}`} style={{ marginLeft: `${p.depth * 1.5}rem` }}>
                  {operator && !(p.type === 'enum' && !p.choices?.length) ? <ParameterInput p={p} value={values[p.name] ?? p.value} onChange={(v) => setValues({ ...values, [p.name]: v })} />
                    : <span className="dc-mono">{Array.isArray(p.value) ? p.value.join('; ') : p.value}</span>}
                  {p.description && <FormHelperText><HelperText><HelperTextItem>{p.description}</HelperTextItem></HelperText></FormHelperText>}
                </FormGroup>
              ))}
            </Form>
            {passwords.length > 0 && (
              <Form className="dc-tab-body" onSubmit={(e) => e.preventDefault()}>
                {passwords.map((p) => {
                  const name = String(p.value);
                  const where = runsOn.map((s) => `${s.name}: ${held[s.dn] === undefined ? '…' : held[s.dn] === null ? 'could not be read' : held[s.dn]!.includes(name) ? 'set' : 'not set'}`);
                  return (
                    <FormGroup key={p.name} label={p.label} fieldId={`job-pw-${p.name}`}>
                      {operator && (
                        <Flex alignItems={{ default: 'alignItemsCenter' }}>
                          <FlexItem grow={{ default: 'grow' }}>
                            <TextInput id={`job-pw-${p.name}`} type="password" autoComplete="new-password" value={secrets[p.name] ?? ''}
                              onChange={(_e, v) => setSecrets({ ...secrets, [p.name]: v })} />
                          </FlexItem>
                          <FlexItem>
                            <Button variant="secondary" isDisabled={busy || !secrets[p.name] || runsOn.length === 0} onClick={() => setPassword(name, p.label, p.name)}>Set</Button>
                          </FlexItem>
                        </Flex>
                      )}
                      <FormHelperText><HelperText><HelperTextItem>
                        The job's named password {name}, kept by each server that runs it. {where.join('; ')}.
                      </HelperTextItem></HelperText></FormHelperText>
                    </FormGroup>
                  );
                })}
              </Form>
            )}
            {notice && <Alert variant="success" isInline isPlain title={notice} className="dc-tab-body" />}
            {deleting && (
              <Alert variant="danger" isInline title={`Delete the job ${job.name}?`} className="dc-tab-body">
                <p>Its schedule and settings go with it. Type its name to confirm.</p>
                <TextInput aria-label="The job's name" value={typed} onChange={(_e, v) => setTyped(v)} />
              </Alert>
            )}
          </>
        )}
        <ProblemAlert error={error} />
        {dialog}
      </ModalBody>
      <ModalFooter>
        {job && operator && !deleting && (
          <>
            <Button onClick={save} isLoading={busy} isDisabled={busy || Object.keys(changes).length === 0 || !cronOk || chosen.length === 0 || !scopeOk}>Save</Button>
            <Button variant="link" isDanger onClick={() => setDeleting(true)}>Delete</Button>
          </>
        )}
        {deleting && <Button variant="danger" onClick={remove} isLoading={busy} isDisabled={busy || typed !== job?.name}>Delete the job</Button>}
        <Button variant="link" onClick={deleting ? () => { setDeleting(false); setTyped(''); } : onClose}>{deleting ? 'Keep it' : 'Close'}</Button>
      </ModalFooter>
    </Modal>
  );
}
