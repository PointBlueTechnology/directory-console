import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert, Button, Card, CardBody, CardTitle, DescriptionList, DescriptionListDescription, DescriptionListGroup, DescriptionListTerm,
  EmptyState, EmptyStateBody, Flex, FlexItem, Label, PageSection, Spinner, Tab, Tabs, TabTitleText, Title,
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type DriverRow, type DriverSet, type IdmStatus, type Job, type Row, idm } from '../api';
import { useSession } from '../session';
import { HeadingLevel, useHeading } from '../heading';
import { linkProps, navigate } from '../router';
import { ProblemAlert } from '../components/Problem';
import { useAreYouSure, useConfirmed } from '../components/Confirm';
import { JobsTable, LogLevelPanel, PasswordsPanel, StateLabel } from '../components/IdmParts';

/** Identity Manager: the engine, the driver sets, and each set's drivers with their state. */
export function IdmPage({ driverSet }: { driverSet?: string }) {
  const { me } = useSession();
  const api = useMemo(() => idm(me.directory), [me.directory]);
  const [status, setStatus] = useState<IdmStatus | null>(null);
  const [sets, setSets] = useState<Row[] | null>(null);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    api.status().then((s) => {
      setStatus(s);
      if (s.available) {
        api.driverSets().then((r) => {
          setSets(r);
          if (!driverSet && r.length > 0 && r[0].guid) {
            navigate(`/idm/driversets/${r[0].guid}`, true);
          }
        }).catch(setError);
      }
    }).catch(setError);
  }, [api, driverSet]);

  return (
    <PageSection isFilled>
      <Flex alignItems={{ default: 'alignItemsCenter' }} spaceItems={{ default: 'spaceItemsMd' }}>
        <FlexItem><Title headingLevel="h1">Identity Manager</Title></FlexItem>
        {status?.engineVersion && <FlexItem><Label>Engine {status.engineVersion}</Label></FlexItem>}
      </Flex>
      <ProblemAlert error={error} />
      {status && !status.available && (
        <EmptyState titleText="Identity Manager is unavailable" headingLevel="h2">
          <EmptyStateBody>{status.problem}</EmptyStateBody>
        </EmptyState>
      )}
      {status?.available && !sets && <Spinner aria-label="Loading driver sets" />}
      {sets && sets.length === 0 && <EmptyState titleText="No driver sets in this tree" headingLevel="h2" />}
      {sets && sets.length > 1 && (
        <Flex className="dc-tab-body" spaceItems={{ default: 'spaceItemsSm' }}>
          {sets.map((s) => (
            <FlexItem key={s.guid}>
              <Button variant={s.guid === driverSet ? 'primary' : 'secondary'} onClick={() => navigate(`/idm/driversets/${s.guid}`)}>{s.name}</Button>
            </FlexItem>
          ))}
        </Flex>
      )}
      {driverSet && status?.available && <DriverSetView key={driverSet} api={api} guid={driverSet} />}
    </PageSection>
  );
}

function DriverSetView({ api, guid }: { api: ReturnType<typeof idm>; guid: string }) {
  const [set, setSet] = useState<DriverSet | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [tab, setTab] = useState<string | number>('drivers');
  const load = useCallback(() => { setError(null); api.driverSet(guid).then(setSet).catch(setError); }, [api, guid]);
  useEffect(load, [load]);

  if (!set) {
    return error ? <ProblemAlert error={error} onRetry={load} /> : <Spinner aria-label="Loading the driver set" />;
  }
  const running = set.drivers.filter((d) => d.state.toLowerCase() === 'running').length;
  return (
    <Card className="dc-tab-body">
      <CardTitle>
        <Title headingLevel="h2">{set.name}</Title>
        <span className="dc-subtle">{running} of {set.drivers.length} drivers running · <span className="dc-mono">{set.dn}</span></span>
      </CardTitle>
      <CardBody>
        <HeadingLevel.Provider value="h3">
        <Tabs activeKey={tab} onSelect={(_e, k) => setTab(k)} aria-label="Driver set" mountOnEnter>
          <Tab eventKey="drivers" title={<TabTitleText>Drivers</TabTitleText>}><DriversTable api={api} drivers={set.drivers} onChanged={load} /></Tab>
          <Tab eventKey="jobs" title={<TabTitleText>Jobs</TabTitleText>}>
            <JobsTable api={api} load={() => api.setPart<{ jobs: Job[] }>(guid, 'jobs')} />
          </Tab>
          <Tab eventKey="servers" title={<TabTitleText>Servers and activation</TabTitleText>}><ServersPanel api={api} guid={guid} /></Tab>
          <Tab eventKey="log" title={<TabTitleText>Log level</TabTitleText>}>
            <LogLevelPanel load={() => api.setPart(guid, 'log-level')} />
          </Tab>
          <Tab eventKey="passwords" title={<TabTitleText>Named passwords</TabTitleText>}><PasswordsPanel api={api} kind="driversets" guid={guid} /></Tab>
        </Tabs>
        </HeadingLevel.Provider>
      </CardBody>
    </Card>
  );
}

function DriversTable({ api, drivers, onChanged }: { api: ReturnType<typeof idm>; drivers: DriverRow[]; onChanged: () => void }) {
  const level = useHeading();
  const { can } = useSession();
  const { run, dialog } = useConfirmed();
  const sure = useAreYouSure();
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const act = async (d: DriverRow, action: 'start' | 'stop' | 'restart') => {
    if (!d.guid) {
      return;
    }
    setBusy(d.guid);
    setError(null);
    try {
      const r = await run((c) => api.lifecycle(d.guid!, action, c));
      setNotice(`${d.name}: ${r.before} → ${r.after}${r.error ? ` (${r.error})` : ''}`);
      onChanged();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(null);
    }
  };
  return (
    <div className="dc-tab-body">
      {notice && <Alert component={level} variant="success" isInline isPlain title={notice} />}
      <ProblemAlert error={error} />
      <Table aria-label="Drivers" variant="compact">
        <Thead><Tr><Th>Driver</Th><Th>State</Th><Th>Starts</Th><Th>Cache</Th><Th>Unprocessed</Th><Th>Trace</Th>{can('operator') && <Th screenReaderText="Actions" />}</Tr></Thead>
        <Tbody>
          {drivers.map((d) => {
            const running = d.state.toLowerCase() === 'running';
            return (
              <Tr key={d.dn}>
                <Td dataLabel="Driver">{d.guid ? <a {...linkProps(`/idm/drivers/${d.guid}`)}>{d.name}</a> : d.name}</Td>
                <Td dataLabel="State"><StateLabel state={d.state} /></Td>
                <Td dataLabel="Starts">{d.startOption}</Td>
                <Td dataLabel="Cache">{d.cacheSize}</Td>
                <Td dataLabel="Unprocessed">{d.unprocessedSize}</Td>
                <Td dataLabel="Trace">{d.traceLevel ?? '—'}</Td>
                {can('operator') && (
                  <Td isActionCell modifier="nowrap">
                    {busy === d.guid ? <Spinner size="sm" aria-label="Working" /> : running ? (
                      <>
                        <Button variant="link" isInline onClick={() => act(d, 'restart')}>Restart</Button>{' '}
                        <Button variant="link" isInline isDanger onClick={() => sure.ask(`Stop ${d.name}?`, 'Events for this driver queue in its cache until it starts again.', 'Stop', () => act(d, 'stop'))}>Stop</Button>
                      </>
                    ) : <Button variant="link" isInline onClick={() => act(d, 'start')}>Start</Button>}
                  </Td>
                )}
              </Tr>
            );
          })}
        </Tbody>
      </Table>
      {dialog}
      {sure.dialog}
    </div>
  );
}

function ServersPanel({ api, guid }: { api: ReturnType<typeof idm>; guid: string }) {
  const [servers, setServers] = useState<{ servers: string[]; connectedServerRuns?: string } | null>(null);
  const [activation, setActivation] = useState<{ attributes?: { attribute: string; value: string }[]; activation?: string; viewError?: string } | null>(null);
  const [error, setError] = useState<unknown>(null);
  useEffect(() => {
    api.setPart<{ servers: string[]; connectedServerRuns?: string }>(guid, 'servers').then(setServers).catch(setError);
    api.setPart<{ attributes?: { attribute: string; value: string }[]; activation?: string; viewError?: string }>(guid, 'activation').then(setActivation).catch(setError);
  }, [api, guid]);
  return (
    <div className="dc-tab-body">
      <ProblemAlert error={error} />
      <DescriptionList isHorizontal>
        <DescriptionListGroup>
          <DescriptionListTerm>Servers</DescriptionListTerm>
          <DescriptionListDescription>{servers ? servers.servers.map((s) => <div key={s} className="dc-mono">{s}</div>) : <Spinner size="sm" aria-label="Loading" />}</DescriptionListDescription>
        </DescriptionListGroup>
        <DescriptionListGroup>
          <DescriptionListTerm>Activation</DescriptionListTerm>
          <DescriptionListDescription>
            {!activation ? <Spinner size="sm" aria-label="Loading" /> : (
              <>
                {(activation.attributes ?? []).map((a) => <div key={a.attribute}><span className="dc-mono">{a.attribute}</span>: {a.value}</div>)}
                {activation.activation && <pre className="dc-mono dc-pre">{activation.activation}</pre>}
                {activation.viewError && <div className="dc-subtle">The engine would not show the activation details ({activation.viewError}).</div>}
              </>
            )}
          </DescriptionListDescription>
        </DescriptionListGroup>
      </DescriptionList>
    </div>
  );
}
