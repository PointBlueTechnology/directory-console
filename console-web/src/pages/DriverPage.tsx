import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert, Breadcrumb, BreadcrumbItem, Button, Card, CardBody, DescriptionList, DescriptionListDescription, DescriptionListGroup,
  DescriptionListTerm, Flex, FlexItem, Form, FormGroup, FormSelect, FormSelectOption, PageSection, Spinner, Tab, Tabs, TabTitleText,
  TextInput, Title, ToggleGroup, ToggleGroupItem,
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type Comparison, type Job, type ServerChoice, idm } from '../api';
import { useServerSignIn } from '../components/ServerSignIn';
import { useSession } from '../session';
import { useHeading } from '../heading';
import { linkProps, useLocation } from '../router';
import { ProblemAlert } from '../components/Problem';
import { useAreYouSure, useConfirmed } from '../components/Confirm';
import { JobsTable, LogLevelPanel, PasswordsPanel, StateLabel } from '../components/IdmParts';
import { TracePanel } from '../components/TracePanel';
import { MappingTablesPanel } from '../components/MappingTables';

type Idm = ReturnType<typeof idm>;
type Status = Record<string, unknown> & { servedBy?: { dn: string }; dn: string; name: string; state?: string; startOption?: string; driverSetDn?: string; ancestors?: { dn: string; name: string }[] };

const show = (v: unknown) => (v === null || v === undefined || v === '' ? '—' : typeof v === 'object' ? JSON.stringify(v) : String(v));

/** One driver: state and lifecycle, and the operations an IDM administrator runs on it day to day. */
export function DriverPage({ guid }: { guid: string }) {
  const { me } = useSession();
  // the server whose engine and replica the page works on: undefined is the connected server
  const { query } = useLocation();
  const [server, setServer] = useState<string | undefined>(query.get('server') ?? undefined);
  const [servers, setServers] = useState<ServerChoice[]>([]);
  const api = useMemo(() => idm(me.directory, server), [me.directory, server]);
  const signIn = useServerSignIn();
  const [status, setStatus] = useState<Status | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [tab, setTab] = useState<string | number>('overview');
  const load = useCallback(() => {
    setError(null);
    signIn.run(() => api.driver(guid)).then((s) => setStatus(s as Status)).catch((e) => {
      setError(e);
      if (server) {
        setServer(undefined);
      }
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [api, guid]);
  useEffect(load, [load]);
  useEffect(() => { idm(me.directory).driverServers(guid).then(setServers).catch(() => setServers([])); }, [me.directory, guid]);

  if (!status) {
    return <PageSection>{error ? <ProblemAlert error={error} onRetry={load} /> : <Spinner aria-label="Loading the driver" />}</PageSection>;
  }
  return (
    <PageSection isFilled>
      <Breadcrumb>
        <BreadcrumbItem><a {...linkProps('/idm')}>Identity Manager</a></BreadcrumbItem>
        <BreadcrumbItem isActive>{status.name}</BreadcrumbItem>
      </Breadcrumb>
      <Flex alignItems={{ default: 'alignItemsCenter' }} spaceItems={{ default: 'spaceItemsMd' }} className="dc-tab-body">
        <FlexItem><Title headingLevel="h1">{status.name}</Title></FlexItem>
        {status.state && <FlexItem><StateLabel state={status.state} /></FlexItem>}
        {servers.length > 1 && (
          <FlexItem>
            <FormSelect id="driver-server" aria-label="Server" value={server ?? ''} onChange={(_e, v) => setServer(v || undefined)}>
              {servers.map((x) => <FormSelectOption key={x.guid} value={x.connected ? '' : x.guid} label={`On ${x.name}${x.connected ? ' (connected)' : ''}`} />)}
            </FormSelect>
          </FlexItem>
        )}
      </Flex>
      <div className="dc-subtle dc-mono">{status.dn}</div>
      {servers.length > 1 && <p className="dc-subtle">Each server runs its own copy of this driver: state, starting and stopping, the start option, jobs, the cache and named passwords all apply to {(servers.find((x) => x.guid === server) ?? servers.find((x) => x.connected))?.name} only.</p>}
      <Card className="dc-tab-body">
        <CardBody>
          <Tabs activeKey={tab} onSelect={(_e, k) => setTab(k)} aria-label="Driver" mountOnEnter unmountOnExit>
            <Tab eventKey="overview" title={<TabTitleText>Overview</TabTitleText>}>
              <Overview api={api} guid={guid} status={status} onChanged={load} />
              {servers.length > 1 && <ServerComparison guid={guid} />}
            </Tab>
            <Tab eventKey="jobs" title={<TabTitleText>Jobs</TabTitleText>}>
              <JobsTable api={api} load={() => api.driverPart<{ jobs: Job[] }>(guid, 'jobs')} />
            </Tab>
            <Tab eventKey="associations" title={<TabTitleText>Associations</TabTitleText>}><Associations api={api} guid={guid} /></Tab>
            <Tab eventKey="cache" title={<TabTitleText>Cache</TabTitleText>}><Cache api={api} guid={guid} onChanged={load} /></Tab>
            <Tab eventKey="health" title={<TabTitleText>Health</TabTitleText>}><Health api={api} guid={guid} /></Tab>
            <Tab eventKey="trace" title={<TabTitleText>Trace</TabTitleText>}><TracePanel kind="drivers" guid={guid} /></Tab>
            <Tab eventKey="mapping-tables" title={<TabTitleText>Mapping tables</TabTitleText>}><MappingTablesPanel under={guid} canCreate /></Tab>
            <Tab eventKey="log" title={<TabTitleText>Log level</TabTitleText>}>
              <LogLevelSave api={api} guid={guid} />
            </Tab>
            <Tab eventKey="passwords" title={<TabTitleText>Passwords</TabTitleText>}><PasswordsPanel api={api} kind="drivers" guid={guid} /></Tab>
            <Tab eventKey="password-sync" title={<TabTitleText>Password sync</TabTitleText>}><PasswordSync api={api} guid={guid} /></Tab>
          </Tabs>
        </CardBody>
      </Card>
      {signIn.dialog}
    </PageSection>
  );
}

function Overview({ api, guid, status, onChanged }: { api: Idm; guid: string; status: Status; onChanged: () => void }) {
  const level = useHeading();
  const { can } = useSession();
  const { run, dialog } = useConfirmed();
  const sure = useAreYouSure();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const running = (status.state ?? '').toLowerCase() === 'running';
  const option = (status.startOption ?? '').toLowerCase();
  const current = option.includes('auto') ? 'auto' : option.includes('manual') ? 'manual' : option.includes('disabled') ? 'disabled' : '';

  const act = async (what: string, op: (c?: string) => Promise<{ before: string; after: string; error?: string }>) => {
    setBusy(true);
    setError(null);
    try {
      const r = await run(op);
      setNotice(`${what}: ${r.before} → ${r.after}${r.error ? ` (${r.error})` : ''}`);
      onChanged();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  const rows: [string, unknown][] = [
    ['Starts', status.startOption], ['Cache', status.cacheSize], ['Unprocessed', status.unprocessedSize],
    ['Trace level', status.traceLevel], ['Trace file', status.traceFile],
  ];
  return (
    <div className="dc-tab-body">
      {can('operator') && (
        <Flex spaceItems={{ default: 'spaceItemsSm' }} alignItems={{ default: 'alignItemsCenter' }}>
          {running ? (
            <>
              <FlexItem><Button variant="secondary" isDisabled={busy} onClick={() => act('Restart', (c) => api.lifecycle(guid, 'restart', c))}>Restart</Button></FlexItem>
              <FlexItem><Button variant="danger" isDisabled={busy} onClick={() => sure.ask(`Stop ${status.name}?`, 'Events for this driver queue in its cache until it starts again.', 'Stop',
                () => act('Stop', (c) => api.lifecycle(guid, 'stop', c)))}>Stop</Button></FlexItem>
            </>
          ) : current === 'disabled'
            ? <FlexItem><Button variant="primary" isAriaDisabled title="A disabled driver cannot start: choose Automatic or Manual first">Start</Button></FlexItem>
            : <FlexItem><Button variant="primary" isDisabled={busy} onClick={() => act('Start', (c) => api.lifecycle(guid, 'start', c))}>Start</Button></FlexItem>}
          <FlexItem>
            <ToggleGroup aria-label="Start option">
              {(['auto', 'manual', 'disabled'] as const).map((o) => (
                <ToggleGroupItem key={o} text={o === 'auto' ? 'Automatic' : o === 'manual' ? 'Manual' : 'Disabled'} isSelected={current === o} isDisabled={busy}
                  onChange={() => {
                    if (current === o) {
                      return;
                    }
                    const change = () => act('Start option', (c) => api.startOption(guid, o, c));
                    if (o === 'disabled') {
                      sure.ask(`Disable ${status.name}?`, 'Disabling a driver deletes its cache: events already queued for it are discarded, changes made while it is disabled never reach it, and it cannot be started until its start option is Automatic or Manual again. Stopping it instead keeps queueing events.', 'Disable', change);
                    } else {
                      change();
                    }
                  }} />
              ))}
            </ToggleGroup>
          </FlexItem>
          {busy && <FlexItem><Spinner size="md" aria-label="Working" /></FlexItem>}
        </Flex>
      )}
      {notice && <Alert component={level} variant="success" isInline isPlain title={notice} />}
      <ProblemAlert error={error} />
      <DescriptionList isHorizontal isCompact className="dc-tab-body">
        {rows.map(([k, v]) => (
          <DescriptionListGroup key={k}><DescriptionListTerm>{k}</DescriptionListTerm><DescriptionListDescription>{show(v)}</DescriptionListDescription></DescriptionListGroup>
        ))}
        <DescriptionListGroup>
          <DescriptionListTerm>Driver set</DescriptionListTerm>
          <DescriptionListDescription className="dc-mono">{show(status.driverSetDn)}</DescriptionListDescription>
        </DescriptionListGroup>
      </DescriptionList>
      {can('operator') && <Resync api={api} guid={guid} />}
      {dialog}
      {sure.dialog}
    </div>
  );
}

function Resync({ api, guid }: { api: Idm; guid: string }) {
  const level = useHeading();
  const { run, dialog } = useConfirmed();
  const [since, setSince] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  return (
    <Form className="dc-tab-body" onSubmit={async (e) => {
      e.preventDefault();
      setError(null);
      try {
        await run((c) => api.resync(guid, since ? new Date(since).toISOString() : null, c));
        setNotice('Resynchronisation requested.');
      } catch (x) {
        setError(x);
      }
    }}>
      <Title headingLevel="h2" size="md">Resynchronise</Title>
      <FormGroup label="Only objects changed since (optional)" fieldId="resync-since">
        <TextInput id="resync-since" type="datetime-local" value={since} onChange={(_e, v) => setSince(v)} />
      </FormGroup>
      {notice && <Alert component={level} variant="success" isInline isPlain title={notice} />}
      <ProblemAlert error={error} />
      <div><Button type="submit" variant="secondary">Resynchronise</Button></div>
      {dialog}
    </Form>
  );
}

type Assoc = { counts?: Record<string, number>; total?: number; listed?: number; objects?: { dn: string; state: string; value: string }[] };

function Associations({ api, guid }: { api: Idm; guid: string }) {
  const [state, setState] = useState('');
  const [data, setData] = useState<Assoc | null>(null);
  const [error, setError] = useState<unknown>(null);
  useEffect(() => {
    setData(null);
    api.driverPart<Assoc>(guid, `associations?limit=200${state ? `&state=${state}` : ''}`).then(setData).catch(setError);
  }, [api, guid, state]);
  return (
    <div className="dc-tab-body">
      <ProblemAlert error={error} />
      <FormGroup label="State" fieldId="assoc-state">
        <FormSelect id="assoc-state" value={state} onChange={(_e, v) => setState(v)}>
          <FormSelectOption value="" label="All" />
          {['processed', 'pending', 'disabled', 'manual', 'migrate'].map((s) => (
            <FormSelectOption key={s} value={s} label={`${s[0].toUpperCase()}${s.slice(1)}${data?.counts?.[s] !== undefined ? ` (${data.counts[s]})` : ''}`} />
          ))}
        </FormSelect>
      </FormGroup>
      {!data ? <Spinner size="md" aria-label="Loading" /> : (
        <>
          <p className="dc-subtle">{data.listed ?? 0} shown of {data.total ?? 0}.</p>
          {(data.objects ?? []).length > 0 && <Table aria-label="Associations" variant="compact">
            <Thead><Tr><Th>Object</Th><Th>State</Th><Th>Association</Th></Tr></Thead>
            <Tbody>
              {(data.objects ?? []).map((o) => (
                <Tr key={o.dn + o.value}><Td dataLabel="Object" className="dc-mono">{o.dn}</Td><Td dataLabel="State">{o.state}</Td><Td dataLabel="Association" className="dc-mono">{o.value}</Td></Tr>
              ))}
            </Tbody>
          </Table>}
        </>
      )}
    </div>
  );
}

function Cache({ api, guid, onChanged }: { api: Idm; guid: string; onChanged: () => void }) {
  const level = useHeading();
  const { can } = useSession();
  const { run, dialog } = useConfirmed();
  const sure = useAreYouSure();
  const [page, setPage] = useState<{ empty: boolean; xds: string } | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const load = useCallback(() => { setError(null); api.driverPart<{ empty: boolean; xds: string }>(guid, 'cache?count=20').then(setPage).catch(setError); }, [api, guid]);
  useEffect(load, [load]);
  return (
    <div className="dc-tab-body">
      {can('operator') && (
        <div><Button variant="danger" onClick={() => sure.ask('Clear the cache?', 'Every event waiting in this driver\'s cache is discarded; the connected system will not receive them.', 'Clear', async () => {
          setError(null);
          try {
            await run((c) => api.clearCache(guid, c));
            setNotice('Cache cleared.');
            onChanged();
            load();
          } catch (x) {
            setError(x);
          }
        })}>Clear the cache</Button></div>
      )}
      {notice && <Alert component={level} variant="success" isInline isPlain title={notice} />}
      <ProblemAlert error={error} />
      {page && (page.empty ? <p>The cache is empty.</p> : (
        <>
          <p className="dc-subtle">The first 20 events, as XDS.</p>
          <pre className="dc-mono dc-pre">{page.xds}</pre>
        </>
      ))}
      {!page && !error && <Spinner size="md" aria-label="Loading" />}
      {dialog}
      {sure.dialog}
    </div>
  );
}

type HealthData = { states?: unknown[]; configured?: { state: string; conditionGroups: unknown; actions: unknown }[]; jobs?: unknown[] };

function Health({ api, guid }: { api: Idm; guid: string }) {
  const [h, setH] = useState<HealthData | null>(null);
  const [error, setError] = useState<unknown>(null);
  useEffect(() => { api.driverPart<HealthData>(guid, 'health').then(setH).catch(setError); }, [api, guid]);
  if (!h) {
    return error ? <ProblemAlert error={error} /> : <Spinner size="md" aria-label="Loading" />;
  }
  return (
    <div className="dc-tab-body">
      <DescriptionList isHorizontal isCompact>
        <DescriptionListGroup><DescriptionListTerm>Recent states</DescriptionListTerm><DescriptionListDescription>{(h.states ?? []).length ? (h.states ?? []).map((s, i) => <div key={i}>{show(s)}</div>) : 'None recorded'}</DescriptionListDescription></DescriptionListGroup>
        <DescriptionListGroup><DescriptionListTerm>Health jobs</DescriptionListTerm><DescriptionListDescription>{(h.jobs ?? []).length ? (h.jobs ?? []).map((s, i) => <div key={i}>{show(s)}</div>) : 'None'}</DescriptionListDescription></DescriptionListGroup>
      </DescriptionList>
      {(h.configured ?? []).length > 0 && (
        <Table aria-label="Configured health states" variant="compact">
          <Thead><Tr><Th>State</Th><Th>Conditions</Th><Th>Actions</Th></Tr></Thead>
          <Tbody>
            {(h.configured ?? []).map((c) => (
              <Tr key={c.state}><Td dataLabel="State">{c.state}</Td><Td dataLabel="Conditions">{show(c.conditionGroups)}</Td><Td dataLabel="Actions">{show(c.actions)}</Td></Tr>
            ))}
          </Tbody>
        </Table>
      )}
    </div>
  );
}

function LogLevelSave({ api, guid }: { api: Idm; guid: string }) {
  const { run, dialog } = useConfirmed();
  return (
    <>
      <LogLevelPanel load={() => api.driverPart(guid, 'log-level')} save={(level) => run((c) => api.logLevel(guid, level, null, c))} />
      {dialog}
    </>
  );
}

function PasswordSync({ api, guid }: { api: Idm; guid: string }) {
  const [p, setP] = useState<{ driverSetTimeout?: unknown; settings?: { name?: string; value?: unknown }[] } | null>(null);
  const [error, setError] = useState<unknown>(null);
  useEffect(() => { api.driverPart<typeof p>(guid, 'password-sync').then(setP).catch(setError); }, [api, guid]);
  if (!p) {
    return error ? <ProblemAlert error={error} /> : <Spinner size="md" aria-label="Loading" />;
  }
  return (
    <DescriptionList isHorizontal isCompact className="dc-tab-body">
      <DescriptionListGroup><DescriptionListTerm>Driver set timeout</DescriptionListTerm><DescriptionListDescription>{show(p.driverSetTimeout)}</DescriptionListDescription></DescriptionListGroup>
      {(p.settings ?? []).length === 0 && <DescriptionListGroup><DescriptionListTerm>Settings</DescriptionListTerm><DescriptionListDescription>None reported</DescriptionListDescription></DescriptionListGroup>}
      {(p.settings ?? []).map((s, i) => (
        <DescriptionListGroup key={i}><DescriptionListTerm>{s.name ?? `Setting ${i + 1}`}</DescriptionListTerm><DescriptionListDescription>{show(s.value ?? s)}</DescriptionListDescription></DescriptionListGroup>
      ))}
    </DescriptionList>
  );
}

/** The driver's state and start option on every server that runs its driver set. */
function ServerComparison({ guid }: { guid: string }) {
  const { me } = useSession();
  const signIn = useServerSignIn();
  const [c, setC] = useState<Comparison<{ state?: string; startOption?: string }> | null>(null);
  const [error, setError] = useState<unknown>(null);
  const load = useCallback(() => { idm(me.directory).compareDriver(guid).then(setC).catch(setError); }, [me.directory, guid]);
  useEffect(load, [load]);
  return (
    <div className="dc-tab-body">
      <Title headingLevel="h2" size="md">On each server</Title>
      <ProblemAlert error={error} />
      {!c ? <Spinner size="md" aria-label="Loading" /> : (
        <Table aria-label="The driver on each server" variant="compact">
          <Thead><Tr><Th>Server</Th><Th>State</Th><Th>Starts</Th></Tr></Thead>
          <Tbody>
            {c.servers.map((r) => (
              <Tr key={r.server.guid}>
                <Td dataLabel="Server">{r.server.name}</Td>
                {r.status === 'ok' ? (
                  <><Td dataLabel="State">{r.state ? <StateLabel state={r.state} /> : '—'}</Td><Td dataLabel="Starts">{show(r.startOption)}</Td></>
                ) : (
                  <Td dataLabel="State" colSpan={2}>
                    {r.status === 'server-sign-in-required'
                      ? <Button variant="link" isInline onClick={() => signIn.run(() => idm(me.directory, r.server.guid).driver(guid)).then(load, setError)}>Sign in to see it</Button>
                      : <span className="dc-subtle">{r.detail ?? r.status}</span>}
                  </Td>
                )}
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}
      {signIn.dialog}
    </div>
  );
}
