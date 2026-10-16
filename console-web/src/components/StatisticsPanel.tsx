import { Fragment, useEffect, useState } from 'react';
import { Button, DescriptionList, DescriptionListDescription, DescriptionListGroup, DescriptionListTerm, Flex, FlexItem, Label, Spinner, Switch, Title } from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type ChannelStats, type DriverSetStatistics, type Idm } from '../api';
import { linkProps } from '../router';
import { StateLabel } from './IdmParts';
import { ProblemAlert } from './Problem';
import { explain } from '../help/glossary';
import { Hint } from '../help/Help';

const GROUP: Record<string, string> = {
  'reported-events': 'Reported events', 'post-event-transformation': 'After event transformation', 'post-input-transformation': 'After input transformation',
  'pre-output-transformation': 'Before output transformation', commands: 'Commands', 'command-results': 'Command results',
};
const bytes = (n?: number | null) => (n === null || n === undefined ? '—' : n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`);
const when = (t?: string | null) => (t ? new Date(t).toLocaleString() : '—');

function Channel({ name, c }: { name: string; c?: ChannelStats }) {
  const groups = Object.entries(c?.groups ?? {}).filter(([, v]) => Object.keys(v).length > 0);
  return (
    <div className="dc-tab-body">
      <Title headingLevel="h4" size="md"><Hint text={explain(name === 'Subscriber' ? 'subscriber' : 'publisher')}><span tabIndex={0}>{name}</span></Hint>{c?.lastReset ? <span className="dc-subtle"> · since {when(c.lastReset)}</span> : null}</Title>
      {groups.length === 0 ? <p className="dc-subtle">No operations counted.</p> : (
        <Table aria-label={`${name} operations`} variant="compact">
          <Tbody>
            {groups.map(([g, ops]) => (
              <Tr key={g}>
                <Td width={30}>{GROUP[g] ?? g}</Td>
                <Td>{Object.entries(ops).map(([op, n]) => <Label key={op} isCompact className="dc-gap-right">{n.toLocaleString()} {op}</Label>)}</Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}
    </div>
  );
}

/**
 * The driver set's statistics on the chosen server: the engine's JVM, and for each driver its state,
 * cache (size, oldest and newest event, what is waiting by type) and, opened, each channel's operation
 * counters since they were last reset. From the engine's driver statistics.
 */
export function StatisticsPanel({ api, guid }: { api: Idm; guid: string }) {
  const [s, setS] = useState<DriverSetStatistics | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [waitingOnly, setWaitingOnly] = useState(false);
  const [open, setOpen] = useState<string[]>([]);
  const load = () => { setS(null); setError(null); api.setPart<DriverSetStatistics>(guid, 'statistics').then(setS, setError); };
  useEffect(load, [api, guid]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!s) {
    return <div className="dc-tab-body">{error ? <ProblemAlert error={error} onRetry={load} /> : <Spinner size="md" aria-label="Asking the engine for each driver's statistics" />}</div>;
  }
  const shown = s.drivers.filter((d) => !waitingOnly || (d.cache?.size ?? 0) > 0);
  const totalWaiting = s.drivers.reduce((n, d) => n + (d.cache?.unprocessedSize ?? 0), 0);
  return (
    <div className="dc-tab-body">
      <DescriptionList isHorizontal isCompact>
        <DescriptionListGroup><DescriptionListTerm>Server</DescriptionListTerm><DescriptionListDescription>{s.server.name}</DescriptionListDescription></DescriptionListGroup>
        {s.jvm && s.jvm.heapUsed && s.jvm.heapUsed !== '?' && <DescriptionListGroup><DescriptionListTerm>Engine JVM</DescriptionListTerm><DescriptionListDescription>
          {s.jvm.heapUsed} of {s.jvm.heapTotal} heap used · {s.jvm.threadsCurrent} threads (peak {s.jvm.threadsPeak})
        </DescriptionListDescription></DescriptionListGroup>}
        <DescriptionListGroup><DescriptionListTerm>Waiting</DescriptionListTerm><DescriptionListDescription>{bytes(totalWaiting)} in {s.drivers.filter((d) => (d.cache?.unprocessedSize ?? 0) > 0).length} drivers' caches</DescriptionListDescription></DescriptionListGroup>
      </DescriptionList>
      <Flex className="dc-tab-body" alignItems={{ default: 'alignItemsCenter' }}>
        <FlexItem><Switch id="waiting-only" label="Only drivers with events waiting" isChecked={waitingOnly} onChange={(_e, v) => setWaitingOnly(v)} /></FlexItem>
        <FlexItem><Button variant="link" onClick={() => setOpen(open.length ? [] : shown.map((d) => d.name))}>{open.length ? 'Collapse all' : 'Expand all'}</Button></FlexItem>
        <FlexItem><Button variant="link" onClick={load}>Refresh</Button></FlexItem>
      </Flex>
      <Table aria-label="Driver statistics" variant="compact">
        <Thead><Tr><Th screenReaderText="Show" /><Th>Driver</Th><Th>State</Th><Th>Cache</Th><Th>Waiting</Th><Th>Oldest</Th><Th>Newest</Th></Tr></Thead>
        <Tbody>
          {shown.map((d, i) => {
            const isOpen = open.includes(d.name);
            return (
              <Fragment key={d.name}>
                <Tr>
                  <Td expand={{ rowIndex: i, isExpanded: isOpen, onToggle: () => setOpen(isOpen ? open.filter((x) => x !== d.name) : [...open, d.name]) }} />
                  <Td dataLabel="Driver">{d.guid ? <a {...linkProps(`/idm/drivers/${d.guid}`)}>{d.name}</a> : d.name}</Td>
                  <Td dataLabel="State">{d.state ? <StateLabel state={d.state} /> : <span className="dc-subtle">{d.error ?? '—'}</span>}</Td>
                  <Td dataLabel="Cache">{bytes(d.cache?.size)}</Td>
                  <Td dataLabel="Waiting">{Object.entries(d.cache?.counts ?? {}).map(([k, n]) => <Label key={k} isCompact className="dc-gap-right">{n.toLocaleString()} {k}</Label>)}</Td>
                  <Td dataLabel="Oldest">{when(d.cache?.oldest)}</Td>
                  <Td dataLabel="Newest">{when(d.cache?.newest)}</Td>
                </Tr>
                {isOpen && (
                  <Tr isExpanded>
                    <Td colSpan={7}><Channel name="Subscriber" c={d.subscriber} /><Channel name="Publisher" c={d.publisher} /></Td>
                  </Tr>
                )}
              </Fragment>
            );
          })}
        </Tbody>
      </Table>
    </div>
  );
}
