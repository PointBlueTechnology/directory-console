import { useCallback, useEffect, useMemo, useState } from 'react';
import { Button, Flex, FlexItem, FormSelect, FormSelectOption, Label, Pagination, Spinner, ToggleGroup, ToggleGroupItem } from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type AssociationState, type DirObject, idm } from '../api';
import { useSession } from '../session';
import { linkProps } from '../router';
import { useAreYouSure, useConfirmed } from './Confirm';
import { ProblemAlert } from './Problem';

const STATES: AssociationState[] = ['processed', 'pending', 'manual', 'migrate', 'disabled'];
const CODE: Record<AssociationState, number> = { disabled: 0, processed: 1, pending: 2, manual: 3, migrate: 4 };
const COLOR: Record<string, 'green' | 'blue' | 'purple' | 'orange' | 'grey' | 'red'> = {
  processed: 'green', pending: 'blue', manual: 'purple', migrate: 'orange', disabled: 'grey', undefined: 'red',
};

/** An LDAP filter value: \ * ( ) and NUL escaped (RFC 4515). */
const esc = (v: string) => v.replace(/[\\*()\0]/g, (c) => `\\${c.charCodeAt(0).toString(16).padStart(2, '0')}`);

type Row = { obj: DirObject; raw: string; state: string; value: string };

/**
 * The driver's associations across the tree: how many objects are in each state (eDirectory matches
 * DirXML-Associations on "<driver DN>#*", and on "<driver DN>#<state>#*" for a state; ig4), the objects
 * a page at a time, filtered by state, each linked to its object; an operator may delete the chosen
 * associations or set their state, each through the object inspector's checked change. Read over LDAP,
 * so it needs no engine and has no cap.
 */
export function AssociationInspector({ driverDn }: { driverDn: string }) {
  const { me, tree, canAt } = useSession();
  const api = useMemo(() => idm(me.directory), [me.directory]);
  const { run, dialog } = useConfirmed();
  const sure = useAreYouSure();
  const [counts, setCounts] = useState<Record<string, number> | null>(null);
  const [exact, setExact] = useState(true);
  const [state, setState] = useState<AssociationState | ''>('');
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(50);
  const [rows, setRows] = useState<Row[] | null>(null);
  const [total, setTotal] = useState(0);
  const [selected, setSelected] = useState<string[]>([]);
  const [newState, setNewState] = useState<AssociationState>('disabled');
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const operator = canAt('operator', driverDn);

  // "<driver DN>#*" matched every association of the driver on ig4, as the bare DN does
  const filter = useCallback((s: AssociationState | '') => `(DirXML-Associations=${esc(driverDn)}#${s ? `${CODE[s]}#` : ''}*)`, [driverDn]);
  const countAll = useCallback(() => {
    Promise.all(['' as const, ...STATES].map((s) => tree.search({ ldapFilter: filter(s), scope: 'subtree', page: { offset: 1, count: 1 } })))
      .then((pages) => {
        const c: Record<string, number> = { all: pages[0].total };
        STATES.forEach((s, i) => { c[s] = pages[i + 1].total; });
        c.undefined = Math.max(0, c.all - STATES.reduce((n, s) => n + c[s], 0));
        setCounts(c);
        setExact(pages.every((p) => p.exact));
      }, setError);
  }, [tree, filter]);
  const list = useCallback(() => {
    setRows(null);
    setSelected([]);
    tree.search({ ldapFilter: filter(state), scope: 'subtree', attributes: ['DirXML-Associations', 'objectClass'], sort: { attribute: 'cn' },
      page: { offset: (page - 1) * perPage + 1, count: perPage } })
      .then((p) => {
        setTotal(p.total);
        const out: Row[] = [];
        for (const item of p.items as DirObject[]) {
          for (const v of (item.attributes?.['DirXML-Associations'] ?? []) as unknown[]) {
            const raw = String(v);
            const [dn, code, ...rest] = raw.split('#');
            if (dn.toLowerCase() === driverDn.toLowerCase()) {
              const n = Number(code);
              out.push({ obj: item, raw, state: STATES.find((s) => CODE[s] === n) ?? 'undefined', value: rest.join('#') });
            }
          }
        }
        setRows(out);
      }, setError);
  }, [tree, filter, state, page, perPage, driverDn]);
  useEffect(countAll, [countAll]);
  useEffect(list, [list]);

  const act = (verb: 'delete' | 'state') => {
    const chosen = (rows ?? []).filter((r) => selected.includes(r.raw));
    const title = verb === 'delete' ? `Remove ${chosen.length} association${chosen.length === 1 ? '' : 's'}?` : `Set ${chosen.length} association${chosen.length === 1 ? '' : 's'} to ${newState}?`;
    const text = verb === 'delete'
      ? 'The driver then treats these objects as not associated: their next change may create or match an account in the connected system. The accounts there are not touched now.'
      : 'Each association keeps its value; an association changed meanwhile is left alone.';
    sure.ask(title, text, verb === 'delete' ? 'Remove' : 'Set', async () => {
      setBusy(true);
      setError(null);
      let done = 0;
      const failed: string[] = [];
      let typed: string | undefined;
      for (const r of chosen) {
        try {
          await run((c) => {
            typed = c ?? typed;
            return verb === 'delete' ? api.removeAssociation(r.obj.guid, r.raw, typed) : api.changeAssociation(r.obj.guid, { raw: r.raw, state: newState }, typed);
          });
          done++;
        } catch (e) {
          failed.push(`${r.obj.name}: ${e instanceof Error ? e.message : String(e)}`);
          if (e instanceof Error && e.message === 'Not confirmed.') {
            break;
          }
        }
      }
      setNotice(`${verb === 'delete' ? 'Removed' : 'Changed'} ${done}.${failed.length ? ` Not done: ${failed.join('; ')}` : ''}`);
      setBusy(false);
      countAll();
      list();
    });
  };

  const fmt = (n?: number) => (n === undefined ? '…' : `${exact ? '' : '~'}${n}`);
  return (
    <div className="dc-tab-body">
      {!counts && !error && <Spinner size="md" aria-label="Counting associations" />}
      {counts && (
        <ToggleGroup aria-label="State">
          <ToggleGroupItem text={`All (${fmt(counts.all)})`} isSelected={state === ''} onChange={() => { setState(''); setPage(1); }} />
          {STATES.map((s) => (
            <ToggleGroupItem key={s} text={`${s[0].toUpperCase()}${s.slice(1)} (${fmt(counts[s])})`} isSelected={state === s} onChange={() => { setState(s); setPage(1); }} />
          ))}
        </ToggleGroup>
      )}
      {counts && counts.undefined > 0 && <p className="dc-subtle dc-tab-body">{counts.undefined} with a state outside these five (shown under All).</p>}
      {notice && <p className="dc-tab-body">{notice}</p>}
      <ProblemAlert error={error} />
      {operator && (
        <Flex className="dc-tab-body" alignItems={{ default: 'alignItemsCenter' }}>
          <FlexItem><Button variant="danger" size="sm" isDisabled={busy || selected.length === 0} onClick={() => act('delete')}>Remove {selected.length || ''} selected</Button></FlexItem>
          <FlexItem>
            <FormSelect aria-label="New state" value={newState} onChange={(_e, v) => setNewState(v as AssociationState)}>
              {STATES.map((s) => <FormSelectOption key={s} value={s} label={`Set to ${s}`} />)}
            </FormSelect>
          </FlexItem>
          <FlexItem><Button variant="secondary" size="sm" isDisabled={busy || selected.length === 0} onClick={() => act('state')}>Apply to {selected.length || ''} selected</Button></FlexItem>
        </Flex>
      )}
      {!rows && !error && <Spinner size="md" aria-label="Reading associations" />}
      {rows && rows.length === 0 && <p className="dc-tab-body">No objects{state ? ` in ${state}` : ''}.</p>}
      {rows && rows.length > 0 && (
        <Table aria-label="Associations" variant="compact" className="dc-tab-body">
          <Thead><Tr>{operator && <Th screenReaderText="Choose" />}<Th>Object</Th><Th>Class</Th><Th>State</Th><Th>Association</Th></Tr></Thead>
          <Tbody>
            {rows.map((r, i) => (
              <Tr key={r.raw + r.obj.guid}>
                {operator && <Td select={{ rowIndex: i, isSelected: selected.includes(r.raw), onSelect: (_e, on) => setSelected(on ? [...selected, r.raw] : selected.filter((x) => x !== r.raw)) }} />}
                <Td dataLabel="Object"><a {...linkProps(`/objects/${r.obj.guid}`)}>{r.obj.name}</a><div className="dc-subtle dc-mono">{r.obj.dn}</div></Td>
                <Td dataLabel="Class">{r.obj.objectClass}</Td>
                <Td dataLabel="State"><Label isCompact color={COLOR[r.state]}>{r.state}</Label></Td>
                <Td dataLabel="Association" className="dc-mono">{r.value || <span className="dc-subtle">(empty)</span>}</Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}
      {total > perPage && (
        <Pagination itemCount={total} page={page} perPage={perPage} isCompact onSetPage={(_e, p) => setPage(p)} onPerPageSelect={(_e, pp) => { setPerPage(pp); setPage(1); }} />
      )}
      {dialog}
      {sure.dialog}
    </div>
  );
}
