import { Fragment, useCallback, useEffect, useState } from 'react';
import { Alert, Button, DescriptionList, DescriptionListDescription, DescriptionListGroup, DescriptionListTerm, Flex, FlexItem, Label, Spinner } from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { ApiError, type CacheEvent, type CacheSummary, type Idm } from '../api';
import { useSession } from '../session';
import { useAreYouSure, useConfirmed } from './Confirm';
import { ProblemAlert } from './Problem';

const PAGE = 25;
const bytes = (n?: number | null) => (n === null || n === undefined ? '—' : n < 1024 ? `${n} bytes` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`);

/**
 * The driver's cache on the chosen server: a summary (size, oldest and newest event, counts by type), which
 * the engine gives for a running driver too; and, for a stopped driver, the events themselves, a page at a
 * time, each opening to its XDS. An operator may delete chosen events (each must still be the one shown,
 * or it is skipped) or clear the whole cache.
 */
export function CacheInspector({ api, guid, onChanged }: { api: Idm; guid: string; onChanged: () => void }) {
  const { can } = useSession();
  const { run, dialog } = useConfirmed();
  const sure = useAreYouSure();
  const [summary, setSummary] = useState<CacheSummary | null>(null);
  const [events, setEvents] = useState<CacheEvent[] | null>(null);
  const [starts, setStarts] = useState<number[]>([0]);
  const [next, setNext] = useState<number | null>(null);
  const [unreadable, setUnreadable] = useState<string | null>(null);
  const [selected, setSelected] = useState<number[]>([]);
  const [open, setOpen] = useState<number[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const operator = can('operator');
  const position = starts[starts.length - 1];

  const load = useCallback((from: number) => {
    setError(null);
    setSelected([]);
    api.cacheSummary(guid).then(setSummary, setError);
    api.cacheEvents(guid, from, PAGE).then((r) => { setEvents(r.events); setNext(r.next); setUnreadable(null); }, (e) => {
      if (e instanceof ApiError && e.code === 'cache-unreadable') {
        setEvents(null);
        setUnreadable(e.message);
      } else {
        setError(e);
      }
    });
  }, [api, guid]);
  useEffect(() => load(0), [load]);

  const reload = () => { setStarts([0]); load(0); onChanged(); };
  const remove = () => {
    const chosen = (events ?? []).filter((e) => selected.includes(e.position) && e.eventId).map((e) => ({ position: e.position, eventId: e.eventId! }));
    sure.ask(`Delete ${chosen.length} event${chosen.length === 1 ? '' : 's'}?`,
      'The connected system will never receive them. An event that changed since this page was read is left alone.', 'Delete', async () => {
        setBusy(true);
        setError(null);
        try {
          const r = await run((c) => api.deleteCacheEvents(guid, chosen, c));
          const skipped = r.results.filter((x) => x.status !== 'deleted');
          setNotice(`Deleted ${r.deleted}.${skipped.length ? ` Left alone: ${skipped.map((x) => x.detail ?? x.status).join('; ')}.` : ''}`);
          reload();
        } catch (e) {
          setError(e);
        } finally {
          setBusy(false);
        }
      });
  };
  const clear = () => sure.ask('Clear the cache?', 'Every event waiting in this driver\'s cache is discarded; the connected system will not receive them.', 'Clear', async () => {
    setError(null);
    try {
      await run((c) => api.clearCache(guid, c));
      setNotice('Cache cleared.');
      reload();
    } catch (x) {
      setError(x);
    }
  });

  const counts = Object.entries(summary?.counts ?? {});
  return (
    <div className="dc-tab-body">
      {summary && (
        <DescriptionList isHorizontal isCompact>
          <DescriptionListGroup><DescriptionListTerm>Size</DescriptionListTerm><DescriptionListDescription>{bytes(summary.size)}{summary.unprocessedSize !== summary.size ? ` · ${bytes(summary.unprocessedSize)} unprocessed` : ''}</DescriptionListDescription></DescriptionListGroup>
          <DescriptionListGroup><DescriptionListTerm>Events</DescriptionListTerm><DescriptionListDescription>
            {counts.length === 0 ? 'none' : counts.map(([k, n]) => <Label key={k} isCompact className="dc-gap-right">{n} {k}</Label>)}
          </DescriptionListDescription></DescriptionListGroup>
          {summary.oldest && <DescriptionListGroup><DescriptionListTerm>Oldest</DescriptionListTerm><DescriptionListDescription>{new Date(summary.oldest).toLocaleString()}</DescriptionListDescription></DescriptionListGroup>}
          {summary.newest && <DescriptionListGroup><DescriptionListTerm>Newest</DescriptionListTerm><DescriptionListDescription>{new Date(summary.newest).toLocaleString()}</DescriptionListDescription></DescriptionListGroup>}
        </DescriptionList>
      )}
      {notice && <Alert variant="success" isInline isPlain title={notice} className="dc-tab-body" />}
      <ProblemAlert error={error} />
      {unreadable && <Alert variant="info" isInline isPlain className="dc-tab-body" title="The events can be read only while the driver is stopped." />}
      {operator && (
        <Flex className="dc-tab-body">
          {events && <FlexItem><Button variant="danger" size="sm" isDisabled={busy || selected.length === 0} onClick={remove}>Delete {selected.length || ''} selected</Button></FlexItem>}
          <FlexItem><Button variant="secondary" size="sm" isDanger onClick={clear}>Clear the cache</Button></FlexItem>
        </Flex>
      )}
      {!events && !unreadable && !error && <Spinner size="md" aria-label="Reading the cache" />}
      {events && events.length === 0 && position === 0 && <p className="dc-tab-body">The cache is empty.</p>}
      {events && events.length > 0 && (
        <>
          <Table aria-label="Cached events" variant="compact" className="dc-tab-body">
            <Thead><Tr>{operator && <Th screenReaderText="Choose" />}<Th screenReaderText="Show" /><Th>Event</Th><Th>Class</Th><Th>Object</Th><Th>Attributes</Th><Th>Cached</Th></Tr></Thead>
            <Tbody>
              {events.map((e, i) => {
                const isOpen = open.includes(e.position);
                return (
                  <Fragment key={e.position}>
                    <Tr>
                      {operator && <Td select={{ rowIndex: i, isSelected: selected.includes(e.position), isDisabled: !e.eventId,
                        onSelect: (_x, on) => setSelected(on ? [...selected, e.position] : selected.filter((p) => p !== e.position)) }} />}
                      <Td expand={{ rowIndex: i, isExpanded: isOpen, onToggle: () => setOpen(isOpen ? open.filter((p) => p !== e.position) : [...open, e.position]) }} />
                      <Td dataLabel="Event"><Label isCompact>{e.type}</Label></Td>
                      <Td dataLabel="Class">{e.className ?? '—'}</Td>
                      <Td dataLabel="Object" className="dc-mono">{e.srcDn ?? '—'}</Td>
                      <Td dataLabel="Attributes">{e.attributes.length ? e.attributes.join(', ') : <span className="dc-subtle">—</span>}</Td>
                      <Td dataLabel="Cached">{e.cachedTime ? new Date(e.cachedTime).toLocaleString() : '—'}</Td>
                    </Tr>
                    {isOpen && (
                      <Tr isExpanded>
                        <Td colSpan={operator ? 7 : 6}><pre className="dc-mono dc-pre">{e.xml}</pre><div className="dc-subtle dc-mono">{e.eventId}</div></Td>
                      </Tr>
                    )}
                  </Fragment>
                );
              })}
            </Tbody>
          </Table>
          <Flex className="dc-tab-body">
            <FlexItem><Button variant="secondary" size="sm" isDisabled={starts.length === 1} onClick={() => { const s = starts.slice(0, -1); setStarts(s); load(s[s.length - 1]); }}>Previous</Button></FlexItem>
            <FlexItem><Button variant="secondary" size="sm" isDisabled={next === null} onClick={() => { setStarts([...starts, next!]); load(next!); }}>Next</Button></FlexItem>
            <FlexItem className="dc-subtle">Page {starts.length}</FlexItem>
          </Flex>
        </>
      )}
      {dialog}
      {sure.dialog}
    </div>
  );
}
