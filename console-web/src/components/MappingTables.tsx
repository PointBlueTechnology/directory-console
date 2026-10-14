import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Alert, Button, Flex, FlexItem, FormSelect, FormSelectOption, Label, Modal, ModalBody, ModalFooter, ModalHeader, SearchInput, Spinner, TextInput,
} from '@patternfly/react-core';
import { PlusIcon, TrashIcon } from '@patternfly/react-icons';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { type MappingColumn, type MappingTable, type MappingTableRef, idm } from '../api';
import { fromCsv, toCsv } from '../csv';
import { useSession } from '../session';
import { linkProps } from '../router';
import { useConfirmed } from './Confirm';
import { ProblemAlert } from './Problem';

const TYPES: { type: string; label: string }[] = [
  { type: 'nocase', label: 'Text, any case' },
  { type: 'case', label: 'Text, exact case' },
  { type: 'numeric', label: 'Number' },
  { type: 'interval-closed', label: 'Range [a, b]' },
  { type: 'interval-open', label: 'Range (a, b)' },
  { type: 'interval-rightopen', label: 'Range [a, b)' },
  { type: 'interval-leftopen', label: 'Range (a, b]' },
];

/** The restart note: a table is read when a driver starts, so a change reaches a driver only when it restarts. */
function RestartNote({ table }: { table: MappingTableRef }) {
  const { tree } = useSession();
  const [driver, setDriver] = useState<string | null>(null);
  useEffect(() => {
    if (table.owner.kind === 'driver') {
      tree.resolve(table.owner.dn).then((r) => setDriver(r.data.guid), () => setDriver(null));
    }
  }, [tree, table.owner]);
  return (
    <Alert variant="info" isInline isPlain className="dc-tab-body"
      title="Changes take effect only when the drivers that use this table are restarted.">
      {table.owner.kind === 'driver'
        ? <>It belongs to {driver ? <a {...linkProps(`/idm/drivers/${driver}`)}>{table.owner.name}</a> : table.owner.name}; restart that driver, and any other whose policies name the table.</>
        : <>Restart each driver whose policies name it.</>}
    </Alert>
  );
}

/**
 * The mapping tables under a driver set or driver: a list, each opening an editor; operators may also
 * make a new one here.
 */
export function MappingTablesPanel({ under, canCreate }: { under: string; canCreate: boolean }) {
  const { me, can } = useSession();
  const api = useMemo(() => idm(me.directory), [me.directory]);
  const [tables, setTables] = useState<MappingTableRef[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const load = useCallback(() => { setError(null); api.mappingTables(under).then(setTables, setError); }, [api, under]);
  useEffect(load, [load]);

  if (!tables) {
    return <div className="dc-tab-body">{error ? <ProblemAlert error={error} onRetry={load} /> : <Spinner size="md" aria-label="Reading mapping tables" />}</div>;
  }
  return (
    <div className="dc-tab-body">
      {can('operator') && canCreate && (
        <Button variant="secondary" size="sm" icon={<PlusIcon />} onClick={() => setCreating(true)}>New mapping table</Button>
      )}
      {tables.length === 0 ? <p className="dc-subtle dc-tab-body">No mapping tables here.</p> : (
        <Table aria-label="Mapping tables" variant="compact" className="dc-tab-body">
          <Thead><Tr><Th>Table</Th><Th>Belongs to</Th><Th>Package</Th></Tr></Thead>
          <Tbody>
            {tables.map((t) => (
              <Tr key={t.dn}>
                <Td dataLabel="Table"><Button variant="link" isInline onClick={() => setOpen(t.guid)}>{t.name}</Button></Td>
                <Td dataLabel="Belongs to">{t.owner.name} <span className="dc-subtle">({t.owner.kind})</span></Td>
                <Td dataLabel="Package">{t.package ?? <span className="dc-subtle">—</span>}</Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}
      {open && <MappingTableEditor guid={open} onClose={() => setOpen(null)} onChanged={load} />}
      {creating && <MappingTableEditor parent={under} onClose={() => setCreating(false)} onChanged={load} />}
    </div>
  );
}

/**
 * One mapping table as a grid: columns (name and how values compare) and rows, all editable by an
 * operator, saved whole; CSV out and in (the first line is the column names). Opened with {@code guid}
 * it edits that table; with {@code parent} it makes a new one there.
 */
export function MappingTableEditor({ guid, parent, onClose, onChanged }: { guid?: string; parent?: string; onClose: () => void; onChanged: () => void }) {
  const { me, can } = useSession();
  const api = useMemo(() => idm(me.directory), [me.directory]);
  const { run, dialog } = useConfirmed();
  const [table, setTable] = useState<MappingTable | null>(null);
  const [name, setName] = useState('');
  const [columns, setColumns] = useState<MappingColumn[]>(parent ? [{ name: 'key', type: 'nocase' }, { name: 'value', type: 'nocase' }] : []);
  const [rows, setRows] = useState<string[][]>(parent ? [['', '']] : []);
  const [filter, setFilter] = useState('');
  const [dirty, setDirty] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [typed, setTyped] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const file = useRef<HTMLInputElement>(null);
  const operator = can('operator');

  const take = (t: MappingTable) => {
    setTable(t);
    setColumns(t.columns);
    setRows(t.rows);
    setDirty(false);
  };
  useEffect(() => {
    if (guid) {
      api.mappingTable(guid).then(take, setError);
    }
  }, [api, guid]);

  const edit = (f: () => void) => { f(); setDirty(true); setNotice(null); };
  const setCell = (r: number, c: number, v: string) => edit(() => setRows(rows.map((row, i) => (i === r ? row.map((x, j) => (j === c ? v : x)) : row))));
  const addColumn = () => edit(() => { setColumns([...columns, { name: `column${columns.length + 1}`, type: 'nocase' }]); setRows(rows.map((r) => [...r, ''])); });
  const removeColumn = (c: number) => edit(() => { setColumns(columns.filter((_, j) => j !== c)); setRows(rows.map((r) => r.filter((_, j) => j !== c))); });
  const names = columns.map((c) => c.name.trim().toLowerCase());
  const problem = columns.length === 0 ? 'A table needs at least one column.'
    : names.some((n) => !n) ? 'Every column needs a name.'
      : new Set(names).size !== names.length ? 'Two columns have the same name.'
        : parent && !name.trim() ? 'The table needs a name.' : null;
  const f = filter.trim().toLowerCase();
  const shown = rows.map((r, i) => ({ r, i })).filter(({ r }) => !f || r.some((v) => v.toLowerCase().includes(f)));

  const exportCsv = () => {
    const blob = new Blob([toCsv([columns.map((c) => c.name), ...rows])], { type: 'text/csv;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${(table?.name ?? (name || 'mapping-table')).replace(/[^\w.-]+/g, '_')}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
  };
  const importCsv = (text: string) => {
    const all = fromCsv(text).filter((r) => r.some((v) => v !== ''));
    if (all.length === 0) {
      setError(new Error('The file has no rows.'));
      return;
    }
    const [head, ...body] = all;
    // keep each column's type when the name is the same; a new column compares as text, any case
    const cols = head.map((h) => ({ name: h.trim(), type: columns.find((c) => c.name.toLowerCase() === h.trim().toLowerCase())?.type ?? 'nocase' }));
    edit(() => { setColumns(cols); setRows(body.map((r) => cols.map((_, j) => r[j] ?? ''))); });
    setNotice(`Read ${body.length} row${body.length === 1 ? '' : 's'} and ${cols.length} column${cols.length === 1 ? '' : 's'}; save to keep them.`);
  };

  const save = () => {
    setBusy(true);
    setError(null);
    const body = { columns: columns.map((c) => ({ name: c.name.trim(), type: c.type })), rows };
    const op = parent
      ? run((c) => api.createMappingTable({ parent, name: name.trim(), ...body }, c))
      : run((c) => api.saveMappingTable(guid!, { version: table!.version, ...body }, c));
    op.then((t) => { take(t); onChanged(); setNotice('Saved.'); if (parent) { onClose(); } }, setError).finally(() => setBusy(false));
  };
  const remove = () => {
    setBusy(true);
    run((c) => api.deleteMappingTable(guid!, typed, c)).then(() => { onChanged(); onClose(); }, setError).finally(() => setBusy(false));
  };

  const title = parent ? 'New mapping table' : table?.name ?? 'Mapping table';
  return (
    <Modal isOpen onClose={onClose} variant="large" aria-labelledby="mt-title">
      <ModalHeader title={title} labelId="mt-title"
        description={table ? <>{table.owner.name} ({table.owner.kind}) · {rows.length} row{rows.length === 1 ? '' : 's'}</> : undefined} />
      <ModalBody>
        {guid && !table && !error && <Spinner size="md" aria-label="Reading the table" />}
        {(table || parent) && (
          <>
            {table && <RestartNote table={table} />}
            {parent && <Alert variant="info" isInline isPlain className="dc-tab-body" title="A new table is used once a driver's policies name it and the driver restarts." />}
            {table?.package && operator && (
              <Alert variant="warning" isInline isPlain className="dc-tab-body"
                title={`This table came from the package ${table.package}. Changing it here makes it differ from the package; Designer reports that, and a package upgrade may replace it.`} />
            )}
            {parent && (
              <TextInput aria-label="Table name" placeholder="Table name" value={name} onChange={(_e, v) => { setName(v); setDirty(true); }} className="dc-tab-body" />
            )}
            <Flex className="dc-tab-body" alignItems={{ default: 'alignItemsCenter' }}>
              <FlexItem><SearchInput placeholder="Filter rows" aria-label="Filter rows" value={filter} onChange={(_e, v) => setFilter(v)} onClear={() => setFilter('')} /></FlexItem>
              {operator && <FlexItem><Button variant="secondary" size="sm" icon={<PlusIcon />} onClick={() => edit(() => setRows([...rows, columns.map(() => '')]))}>Row</Button></FlexItem>}
              {operator && <FlexItem><Button variant="secondary" size="sm" icon={<PlusIcon />} onClick={addColumn}>Column</Button></FlexItem>}
              <FlexItem><Button variant="link" size="sm" onClick={exportCsv}>Export CSV</Button></FlexItem>
              {operator && (
                <FlexItem>
                  <Button variant="link" size="sm" onClick={() => file.current?.click()}>Import CSV…</Button>
                  <input ref={file} type="file" accept=".csv,text/csv" hidden
                    onChange={(e) => { const fl = e.target.files?.[0]; if (fl) { fl.text().then(importCsv); } e.target.value = ''; }} />
                </FlexItem>
              )}
            </Flex>
            <div style={{ overflowX: 'auto' }} className="dc-tab-body">
              <Table aria-label="Rows" variant="compact" isStickyHeader>
                <Thead>
                  <Tr>
                    {columns.map((c, j) => (
                      <Th key={j} modifier="fitContent">
                        {operator ? (
                          <Flex direction={{ default: 'column' }} spaceItems={{ default: 'spaceItemsXs' }}>
                            <Flex flexWrap={{ default: 'nowrap' }} spaceItems={{ default: 'spaceItemsXs' }}>
                              <TextInput aria-label={`Column ${j + 1} name`} value={c.name} className="dc-mono"
                                onChange={(_e, v) => edit(() => setColumns(columns.map((x, k) => (k === j ? { ...x, name: v } : x))))} />
                              <Button variant="plain" aria-label={`Remove column ${c.name}`} isDisabled={columns.length === 1} onClick={() => removeColumn(j)}><TrashIcon /></Button>
                            </Flex>
                            <FormSelect aria-label={`Column ${c.name} compares as`} value={c.type}
                              onChange={(_e, v) => edit(() => setColumns(columns.map((x, k) => (k === j ? { ...x, type: v } : x))))}>
                              {TYPES.map((t) => <FormSelectOption key={t.type} value={t.type} label={t.label} />)}
                              {!TYPES.some((t) => t.type === c.type) && <FormSelectOption value={c.type} label={c.type} />}
                            </FormSelect>
                          </Flex>
                        ) : <>{c.name} <Label isCompact>{TYPES.find((t) => t.type === c.type)?.label ?? c.type}</Label></>}
                      </Th>
                    ))}
                    {operator && <Th screenReaderText="Remove" />}
                  </Tr>
                </Thead>
                <Tbody>
                  {shown.map(({ r, i }) => (
                    <Tr key={i}>
                      {r.map((v, j) => (
                        <Td key={j} dataLabel={columns[j]?.name}>
                          {operator ? <TextInput aria-label={`Row ${i + 1}, ${columns[j]?.name}`} value={v} onChange={(_e, x) => setCell(i, j, x)} />
                            : <span className="dc-mono">{v}</span>}
                        </Td>
                      ))}
                      {operator && (
                        <Td isActionCell>
                          <Button variant="plain" aria-label={`Remove row ${i + 1}`} onClick={() => edit(() => setRows(rows.filter((_, k) => k !== i)))}><TrashIcon /></Button>
                        </Td>
                      )}
                    </Tr>
                  ))}
                </Tbody>
              </Table>
              {rows.length === 0 && <p className="dc-subtle">No rows.</p>}
              {f && shown.length < rows.length && <p className="dc-subtle">{shown.length} of {rows.length} rows match.</p>}
            </div>
            {problem && dirty && <Alert variant="danger" isInline isPlain title={problem} className="dc-tab-body" />}
            {notice && <Alert variant="success" isInline isPlain title={notice} className="dc-tab-body" />}
            {deleting && table && (
              <Alert variant="danger" isInline title={`Delete the table ${table.name}?`} className="dc-tab-body">
                <p>Policies that name it will fail to find it. Type its name to confirm.</p>
                <TextInput aria-label="The table's name" value={typed} onChange={(_e, v) => setTyped(v)} />
              </Alert>
            )}
          </>
        )}
        <ProblemAlert error={error} />
        {dialog}
      </ModalBody>
      <ModalFooter>
        {operator && !deleting && (table || parent) && (
          <Button onClick={save} isLoading={busy} isDisabled={busy || !dirty || !!problem}>{parent ? 'Create' : 'Save'}</Button>
        )}
        {operator && table && !deleting && <Button variant="link" isDanger onClick={() => setDeleting(true)}>Delete</Button>}
        {deleting && <Button variant="danger" onClick={remove} isLoading={busy} isDisabled={busy || typed !== table?.name}>Delete the table</Button>}
        <Button variant="link" onClick={deleting ? () => { setDeleting(false); setTyped(''); } : onClose}>{deleting ? 'Keep it' : dirty ? 'Close without saving' : 'Close'}</Button>
      </ModalFooter>
    </Modal>
  );
}
