import { useEffect, useMemo, useState } from 'react';
import {
  Alert, Button, Checkbox, DescriptionList, DescriptionListDescription, DescriptionListGroup, DescriptionListTerm, Form, FormGroup, FormHelperText,
  HelperText, HelperTextItem, Modal, ModalBody, ModalFooter, ModalHeader, Spinner, Switch, TextInput,
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type EdirServer, type Idm, type JobDefinition, edir } from '../api';
import { describeCron } from '../cron';
import { useSession } from '../session';
import { useConfirmed } from './Confirm';
import { ProblemAlert } from './Problem';

function Item({ term, children }: { term: string; children: React.ReactNode }) {
  return <DescriptionListGroup><DescriptionListTerm>{term}</DescriptionListTerm><DescriptionListDescription>{children}</DescriptionListDescription></DescriptionListGroup>;
}

/**
 * A job: what it is, and for an operator its enabled state, schedule and servers, then Save; or Delete,
 * with the job's name typed. Scope and parameters are shown as they are.
 */
export function JobDetailsModal({ api, guid, onClose, onChanged }: { api: Idm; guid: string; onClose: () => void; onChanged: () => void }) {
  const { me, can } = useSession();
  const { run, dialog } = useConfirmed();
  const [job, setJob] = useState<JobDefinition | null>(null);
  const [servers, setServers] = useState<EdirServer[]>([]);
  const [disabled, setDisabled] = useState(false);
  const [schedule, setSchedule] = useState('');
  const [chosen, setChosen] = useState<string[]>([]);
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
  };
  useEffect(() => { api.jobDefinition(guid).then(take, setError); }, [api, guid]);
  useEffect(() => { edir(me.directory).servers().then(setServers).catch(() => setServers([])); }, [me.directory]);

  const changes = useMemo(() => {
    if (!job) {
      return {};
    }
    const c: { disabled?: boolean; schedule?: string | null; servers?: string[] } = {};
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
    return c;
  }, [job, disabled, schedule, chosen, servers]);
  const cronOk = !schedule.trim() || schedule.trim().split(/\s+/).length === 5;
  const words = schedule.trim() ? describeCron(schedule) : null;

  const save = () => {
    setBusy(true);
    setError(null);
    run((c) => api.changeJob(guid, { version: job!.version, ...changes }, c)).then((j) => { take(j); onChanged(); }, setError).finally(() => setBusy(false));
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
              <Item term="Objects">
                {job.scope.length === 0 ? <span className="dc-subtle">{job.scopeRequired ? 'none (this job needs one)' : 'none'}</span>
                  : job.scope.map((s) => <div key={s.raw} className="dc-mono">{s.dn ?? s.raw}{s.scope ? <span className="dc-subtle"> · {s.scope}</span> : null}</div>)}
              </Item>
            </DescriptionList>
            {job.parameters && job.parameters.length > 0 && (
              <Table aria-label="Parameters" variant="compact" className="dc-tab-body">
                <Thead><Tr><Th>Parameter</Th><Th>Value</Th></Tr></Thead>
                <Tbody>
                  {job.parameters.map((p) => (
                    <Tr key={p.name}><Td dataLabel="Parameter">{p.label || p.name}</Td><Td dataLabel="Value" className="dc-mono">{p.value ?? '—'}</Td></Tr>
                  ))}
                </Tbody>
              </Table>
            )}
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
            </Form>
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
            <Button onClick={save} isLoading={busy} isDisabled={busy || Object.keys(changes).length === 0 || !cronOk || chosen.length === 0}>Save</Button>
            <Button variant="link" isDanger onClick={() => setDeleting(true)}>Delete</Button>
          </>
        )}
        {deleting && <Button variant="danger" onClick={remove} isLoading={busy} isDisabled={busy || typed !== job?.name}>Delete the job</Button>}
        <Button variant="link" onClick={deleting ? () => { setDeleting(false); setTyped(''); } : onClose}>{deleting ? 'Keep it' : 'Close'}</Button>
      </ModalFooter>
    </Modal>
  );
}
