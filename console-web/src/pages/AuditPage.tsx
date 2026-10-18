import { useCallback, useEffect, useState } from 'react';
import {
  Alert, Button, ExpandableSection, Flex, FlexItem, FormSelect, FormSelectOption, Label, PageSection, Spinner, TextInput, Title, Toolbar, ToolbarContent, ToolbarItem,
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type AuditEntry, type AuditFilter, records } from '../api';
import { ProblemAlert } from '../components/Problem';
import { useHelpTopic } from '../help/Help';

const OUTCOME_COLOR = (o: string) => (o.startsWith('ok') ? 'green' : o.includes('refused') || o.includes('denied') ? 'orange' : 'red');

/** The console's audit log, for admins: newest first, filtered, paged, exported; and a check of its hash chain. */
export function AuditPage() {
  useHelpTopic('audit');
  const [filter, setFilter] = useState<AuditFilter>({});
  const [applied, setApplied] = useState<AuditFilter>({});
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [more, setMore] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [chain, setChain] = useState<null | { intact: boolean; lines: number; problem: string }>(null);
  const load = useCallback((f: AuditFilter, before?: number) => {
    setBusy(true);
    setError(null);
    records.audit(f, before).then((r) => {
      setEntries((old) => (before && old ? [...old, ...r.entries] : r.entries));
      setMore(r.more);
    }, setError).finally(() => setBusy(false));
  }, []);
  useEffect(() => load({}), [load]);
  const apply = () => { setApplied(filter); load(filter); };
  const set = (k: keyof AuditFilter, v: string) => setFilter({ ...filter, [k]: v });
  return (
    <PageSection isFilled>
      <Title headingLevel="h1">Audit log</Title>
      <p className="dc-subtle">What was done through the console: sign-ins, changes, refusals, exports. Each entry carries the hash of the one before, so a
        change to the file shows. Entries can also go to syslog as they are written (Settings &gt; Syslog).</p>
      <Toolbar className="dc-tab-body">
        <ToolbarContent>
          <ToolbarItem><TextInput aria-label="Event" placeholder="Event, such as sign-in or pki." value={filter.event ?? ''} onChange={(_e, v) => set('event', v)} /></ToolbarItem>
          <ToolbarItem><TextInput aria-label="Who" placeholder="Who" value={filter.actor ?? ''} onChange={(_e, v) => set('actor', v)} /></ToolbarItem>
          <ToolbarItem>
            <FormSelect aria-label="Outcome" value={filter.outcome ?? ''} onChange={(_e, v) => set('outcome', v)}>
              <FormSelectOption value="" label="Any outcome" />
              <FormSelectOption value="ok" label="Went through" />
              <FormSelectOption value="refused" label="Refused" />
              <FormSelectOption value="failed" label="Failed" />
            </FormSelect>
          </ToolbarItem>
          <ToolbarItem><TextInput aria-label="From" type="date" value={filter.from ?? ''} onChange={(_e, v) => set('from', v)} /></ToolbarItem>
          <ToolbarItem><TextInput aria-label="To" type="date" value={filter.to ?? ''} onChange={(_e, v) => set('to', v)} /></ToolbarItem>
          <ToolbarItem><TextInput aria-label="Containing" placeholder="Containing" value={filter.text ?? ''} onChange={(_e, v) => set('text', v)}
            onKeyDown={(e) => { if (e.key === 'Enter') apply(); }} /></ToolbarItem>
          <ToolbarItem><Button onClick={apply} isDisabled={busy}>Show</Button></ToolbarItem>
          <ToolbarItem><Button variant="link" onClick={() => { setFilter({}); setApplied({}); load({}); }}>Clear</Button></ToolbarItem>
        </ToolbarContent>
      </Toolbar>
      <Flex className="dc-tab-body">
        <FlexItem><Button variant="secondary" size="sm" onClick={() => records.exportAudit(applied, 'csv').catch(setError)}>Export CSV</Button></FlexItem>
        <FlexItem><Button variant="secondary" size="sm" onClick={() => records.exportAudit(applied, 'jsonl').catch(setError)}>Export JSON Lines</Button></FlexItem>
        <FlexItem><Button variant="link" size="sm" onClick={() => records.verify().then(setChain, setError)}>Check the chain</Button></FlexItem>
        {chain && <FlexItem>{chain.intact ? <Label color="green">Intact: {chain.lines} entries</Label> : <Label color="red">Broken: {chain.problem}</Label>}</FlexItem>}
      </Flex>
      <ProblemAlert error={error} />
      {!entries ? <Spinner aria-label="Reading the audit log" /> : entries.length === 0 ? <Alert variant="info" isInline isPlain title="No entries match." /> : (
        <Table aria-label="Audit log" variant="compact">
          <Thead><Tr><Th>When</Th><Th>Event</Th><Th>Who</Th><Th>Target</Th><Th>Outcome</Th><Th>Details</Th></Tr></Thead>
          <Tbody>
            {entries.map((e) => (
              <Tr key={e.seq}>
                <Td dataLabel="When">{new Date(e.time).toLocaleString()}</Td>
                <Td dataLabel="Event" className="dc-mono">{e.event}</Td>
                <Td dataLabel="Who"><span className="dc-mono">{e.actor.dn ?? e.actor.subject}</span> <span className="dc-subtle">({e.actor.via})</span></Td>
                <Td dataLabel="Target" className="dc-mono" modifier="breakWord">{e.target ?? ''}</Td>
                <Td dataLabel="Outcome"><Label isCompact color={OUTCOME_COLOR(e.outcome)}>{e.outcome}</Label></Td>
                <Td dataLabel="Details">
                  {Object.keys(e.details ?? {}).length > 0 && (
                    <ExpandableSection toggleText="Show" isIndented><pre className="dc-mono" style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', maxWidth: '40rem' }}>{JSON.stringify(e.details, null, 2)}</pre></ExpandableSection>
                  )}
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}
      {more && entries && <Button variant="secondary" className="dc-tab-body" isLoading={busy} onClick={() => load(applied, entries[entries.length - 1].seq)}>Older entries</Button>}
    </PageSection>
  );
}
